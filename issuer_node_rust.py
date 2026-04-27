"""
Authoritative Issuer Node for the DID:IIoT framework (Rust DHT backend).

Drop-in replacement for issuer_node.py that uses RustDHTHandler instead of
DHTHandler.  All DHT I/O goes through the PyO3-bound auth-kademlia-rs library,
which handles authenticated Kademlia internally.

Key differences from the Python issuer node:
  - Signing uses dilith_key_manager.sign() (Rust pqcrypto_dilithium key format).
  - Update verification is delegated to the Rust layer via dht_node.update().
  - Revocation signature verification is done manually via
    dilith_key_manager.verify_signature() because signature_verifier_handler is
    not exposed by the PyO3 binding.
  - Network readiness is checked with bootstrappable_neighbors() instead of
    inspecting protocol.router.buckets.

Threading model (same as issuer_node.py):
    DHT event loop runs in a daemon thread (conf_issuer_node).
    FastAPI handlers cross the thread boundary with
    asyncio.run_coroutine_threadsafe() + asyncio.wrap_future().

HTTP endpoints:
    GET  /get-vc            Issue a JWT-VC for a device after verifying its public key.
    POST /update-vc         Handle a key-rotation request from a device.
    POST /revoke-vc         Revoke a device's VC from the status list.
    GET  /debug-status-list Return the current status list from the DHT (debug only).
"""

from dht_handler import RustDHTHandler
from did_iiot.modules import Service
from utils import get_vc
import asyncio
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional
import uvicorn
import threading
import utils
import hashlib
import base64
from pathlib import Path
from concurrent.futures import TimeoutError as FuturesTimeoutError
import time


class RustIssuerNode(RustDHTHandler):

    def __init__(
        self,
        dilith_keys_dir="issuer_node_keys_dilithium",
        kyber_keys_dir="issuer_node_keys_kyber",
    ):
        super().__init__(dilith_keys_dir, kyber_keys_dir)
        self.status_list = []
        did_uri = "status-list"
        main_service = Service(f"{did_uri}#IssuerNode", "vc-issuer", "172.29.0.2:5007").get_dict()
        self.status_list_struct = {
            "id": did_uri,
            "status_list": self.status_list,
            "service": [main_service],
        }
        self.dht_loop = None


    def _load_private_key(self):
        key_path = Path(__file__).resolve().parent / "issuer_node_private_key.txt"
        try:
            with open(key_path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            print(f"[ERRORE] File non trovato: {key_path}")
            return None
        except Exception as e:
            print(f"[ERRORE] Errore durante la lettura della chiave privata: {e}")
            return None

    def _load_iss_pub_key(self):
        key_path = Path(__file__).resolve().parent / "issuer_node_public_key.bin"
        try:
            with open(key_path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            print(f"[ERRORE] File non trovato: {key_path}")
            return None
        except Exception as e:
            print(f"[ERRORE] Errore durante la lettura della chiave pubblica: {e}")
            return None

    # ── signed record builder for the status-list key ────────────────────────
    # Uses the issuer's on-disk private key (not the key-manager directory),
    # so we call dilith_key_manager.sign() directly with the raw key bytes.

    def _build_signed_status_list_record(self, sk: bytes) -> bytes:
        raw_doc = utils.encode_did_document(self.status_list_struct)
        alg = b"Dilithium-2\x00"          # 12 bytes, null-padded
        signature = self._ensure_bytes(
            self.dilith_key_manager.sign(self._ensure_bytes(sk), bytes(raw_doc))
        )
        return alg + signature + raw_doc

    # ── DHT operations ────────────────────────────────────────────────────────

    async def insert_status_list_into_DHT(self):
        sk = self._load_private_key()
        value = self._build_signed_status_list_record(sk)
        await self.dht_node.set("status-list", value)

    async def update_status_list(self, auth_signature: bytes, key: str, value: bytes):
        """
        Called by POST /update-vc (device key-rotation flow).

        The Rust server verifies auth_signature internally when dht_node.update()
        is called — no need to call a separate handler method.
        value = new signed DID record sent by the device.
        """
        # Try to push the update to the DHT; the Rust layer verifies auth_signature.
        update_ok = await self.dht_node.update(key, list(value), list(auth_signature))
        if not update_ok:
            print("[IssuerNode] update rejected by DHT (bad auth_signature or key not found)")
            return None

        # Extract DID and new public key from the updated record.
        raw_did_document = value[12 + 2420:]
        did_document = utils.decode_did_document(raw_did_document)
        did = did_document["id"]
        pub_key_node_jwk = did_document["verificationMethod"][0]["publicKeyJwk"]["x"]
        pub_key_node = utils.base64_decode_publickey(pub_key_node_jwk)
        new_pub_key_hashed_b64 = base64.urlsafe_b64encode(
            hashlib.sha256(pub_key_node).digest()
        ).decode()

        sk = self._load_private_key()
        new_vc = get_vc(did, new_pub_key_hashed_b64, "Dilithium-2", sk)

        for i, elem in enumerate(self.status_list):
            if elem["did"] == did:
                self.status_list[i] = {
                    "did": did,
                    "jwt-vc": base64.urlsafe_b64encode(
                        hashlib.sha256(new_vc["verifiable-credential"].encode()).digest()
                    ).decode(),
                    "valid": True,
                    "version": elem["version"] + 1,
                }
                status_list_record = self._build_signed_status_list_record(sk)
                print("[IssuerNode] Sending update status-list request")
                await self.dht_node.update("status-list", list(status_list_record), None)
                return new_vc

        return None

    async def call_update_list(self):
        sk = self._load_private_key()
        record = self._build_signed_status_list_record(sk)
        await self.dht_node.update("status-list", list(record), None)
        return True

    async def generate_vc_v2(
        self,
        did_sub: str,
        pub_key_hashed_bytes: bytes,
        result_did_document: bytes,
        modbus_operations: list = None,
    ):
        if not result_did_document:
            return None

        raw_did_document = result_did_document[12 + 2420:]
        did_document = utils.decode_did_document(raw_did_document)
        pub_key_node_jwk = did_document["verificationMethod"][0]["publicKeyJwk"]["x"]
        pub_key_node = utils.base64_decode_publickey(pub_key_node_jwk)
        retrieved_pub_key_hashed = hashlib.sha256(pub_key_node).digest()

        if pub_key_hashed_bytes != retrieved_pub_key_hashed:
            print("[IssuerNode] Public key hash does not match")
            return None

        sk = self._load_private_key()
        vc = get_vc(
            did_sub=did_sub,
            pub_key_hash=base64.urlsafe_b64encode(pub_key_hashed_bytes).decode(),
            algorithm="Dilithium-2",
            vc_issuer_sk=sk,
            modbus_operations=modbus_operations,
        )
        self.status_list.append({
            "did": did_sub,
            "jwt-vc": base64.urlsafe_b64encode(
                hashlib.sha256(vc["verifiable-credential"].encode()).digest()
            ).decode(),
            "valid": True,
            "version": 1,
        })

        status_list_record = self._build_signed_status_list_record(sk)
        await self.dht_node.update("status-list", list(status_list_record), None)
        return vc

    async def revoke_vc_from_status_list(
        self, auth_signature: bytes, key: str, msg: bytes
    ):
        """
        Verify that msg is signed by the owner of DID key, then remove the
        VC from the status list.

        Since signature_verifier_handler is not exposed by the Rust binding,
        we extract the public key from the stored record and verify manually
        via dilith_key_manager.verify_signature().
        """
        stored_record = await self.get_record_from_DHT(key)
        if not stored_record:
            return None

        raw_did_document = stored_record[12 + 2420:]
        did_document = utils.decode_did_document(raw_did_document)
        pub_key_jwk = did_document["verificationMethod"][0]["publicKeyJwk"]["x"]
        pub_key = utils.base64_decode_publickey(pub_key_jwk)

        is_verified = self.dilith_key_manager.verify_signature(
            self._ensure_bytes(pub_key),
            bytes(msg),
            self._ensure_bytes(auth_signature),
        )
        if not is_verified:
            print("[IssuerNode] Revoke request: invalid signature")
            return None

        sk = self._load_private_key()
        did = f"did:iiot:{key}"
        for elem in self.status_list:
            if elem["did"] == did:
                self.status_list = [s for s in self.status_list if s["did"] != did]
                status_list_record = self._build_signed_status_list_record(sk)
                print("[IssuerNode] Sending update status-list request (revocation)")
                await self.dht_node.update("status-list", list(status_list_record), None)
                return True

        return None


# ── FastAPI app ───────────────────────────────────────────────────────────────

issuer_node_service = FastAPI()
issuer_node = RustIssuerNode()


class UpdateVCRequest(BaseModel):
    auth_signature: str
    key: str
    value: str


def fix_base64_padding(s: str) -> str:
    return s + "=" * (-len(s) % 4)


@issuer_node_service.get("/get-vc")
async def generate_vc(
    did_sub: str,
    pub_key_hashed_b64: str,
    modbus_operations: Optional[List[str]] = Query(default=[]),
):
    if not did_sub or not pub_key_hashed_b64:
        raise HTTPException(status_code=400, detail="Missing 'did_sub' parameter")
    try:
        pub_key_hashed_bytes = base64.urlsafe_b64decode(fix_base64_padding(pub_key_hashed_b64))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding for pub_key_hashed")

    future_did_document = asyncio.run_coroutine_threadsafe(
        issuer_node.get_record_from_DHT(utils.extract_did_suffix(did_sub)),
        issuer_node.dht_loop,
    )
    result_did_document = await asyncio.wrap_future(future_did_document)

    future_vc = asyncio.run_coroutine_threadsafe(
        issuer_node.generate_vc_v2(
            did_sub, pub_key_hashed_bytes, result_did_document, modbus_operations
        ),
        issuer_node.dht_loop,
    )
    result = await asyncio.wrap_future(future_vc)

    if result is None:
        raise HTTPException(status_code=404, detail="No result found")
    return JSONResponse(content=result)


@issuer_node_service.post("/update-vc")
async def handle_update_status_list(data: UpdateVCRequest):
    try:
        auth_signature_bytes = base64.urlsafe_b64decode(data.auth_signature)
        value_bytes = base64.urlsafe_b64decode(data.value)
        key = data.key
    except Exception:
        raise HTTPException(
            status_code=400, detail="Invalid base64 encoding for auth_signature or value"
        )

    try:
        future_updated = asyncio.run_coroutine_threadsafe(
            issuer_node.update_status_list(auth_signature_bytes, key, value_bytes),
            issuer_node.dht_loop,
        )
        updated = await asyncio.wrap_future(future_updated)

        if updated:
            return JSONResponse(content=updated)
        return JSONResponse(content={"error": "Unauthenticated request"}, status_code=401)

    except FuturesTimeoutError:
        raise HTTPException(status_code=504, detail="DHT operation timed out")
    except Exception as e:
        print(f"Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@issuer_node_service.post("/revoke-vc")
async def handle_revocation(auth_signature: str, key: str, msg: str):
    if not key or not auth_signature or not msg:
        raise HTTPException(status_code=400, detail="Missing parameters")
    try:
        auth_sig_bytes = base64.urlsafe_b64decode(fix_base64_padding(auth_signature))
        msg_bytes = msg.encode()
        future_revoked = asyncio.run_coroutine_threadsafe(
            issuer_node.revoke_vc_from_status_list(auth_sig_bytes, key, msg_bytes),
            issuer_node.dht_loop,
        )
        revoked = await asyncio.wrap_future(future_revoked)

        if revoked:
            return JSONResponse(content="Success")
        return JSONResponse(content="Unauthenticated request!!", status_code=401)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@issuer_node_service.get("/debug-status-list")
async def debug_dht():
    future_result = asyncio.run_coroutine_threadsafe(
        issuer_node.get_record_from_DHT("status-list"),
        issuer_node.dht_loop,
    )
    result = await asyncio.wrap_future(future_result)
    if result is None:
        raise HTTPException(status_code=404, detail="No result found")
    raw_did_document = result[12 + 2420:]
    status_list = utils.decode_did_document(raw_did_document)
    return JSONResponse(content=status_list)


# ── startup ───────────────────────────────────────────────────────────────────

async def configure_issuer_node(issuer_node: RustIssuerNode, peers):
    await issuer_node.start_dht_service(5000)

    # Bootstrap to known peers if provided.
    if peers:
        await issuer_node.dht_node.bootstrap(peers)

    # Wait until at least 2 neighbours are known.
    # bootstrappable_neighbors() is the Rust-binding equivalent of
    # inspecting protocol.router in the Python DHT.
    while True:
        neighbours = await issuer_node.dht_node.bootstrappable_neighbors()
        if len(neighbours) >= 2:
            break
        await asyncio.sleep(0.5)

    print(f"[IssuerNode] Network ready — {len(neighbours)} neighbours known")
    await asyncio.sleep(60)
    await issuer_node.insert_status_list_into_DHT()
    await asyncio.sleep(2)


def conf_issuer_node(issuer_node: RustIssuerNode, bootstrap_nodes, loop_holder):
    print("[IssuerNode] Starting DHT service")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop_holder["loop_dht"] = loop
    loop.run_until_complete(configure_issuer_node(issuer_node, bootstrap_nodes))
    loop.run_forever()


if __name__ == "__main__":
    print("[IssuerNode] Rust-backed issuer node starting!")
    loop_holder = {}

    bootstrap_nodes = [("172.29.0.181", 5000), ("172.29.0.63", 5000)]

    dht_thread = threading.Thread(
        target=conf_issuer_node,
        args=(issuer_node, bootstrap_nodes, loop_holder),
        daemon=True,
    )
    dht_thread.start()

    while "loop_dht" not in loop_holder:
        time.sleep(0.1)

    issuer_node.dht_loop = loop_holder["loop_dht"]
    uvicorn.run(issuer_node_service, host="0.0.0.0", port=5007)
