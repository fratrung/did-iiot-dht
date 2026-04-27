"""
Authoritative Issuer Node for the DID:IIoT framework (Python DHT backend).

Extends DHTHandler to act as a Verifiable Credential (VC) issuer.  Maintains an
in-memory status list that is published on the DHT under the reserved key
"status-list".  Exposes a FastAPI HTTP service on port 5007.

Threading model:
    The DHT event loop runs in a dedicated daemon thread (conf_issuer_node).
    FastAPI handlers run on the uvicorn event loop and use
    asyncio.run_coroutine_threadsafe() to dispatch coroutines onto the DHT loop,
    then await the resulting concurrent.futures.Future via asyncio.wrap_future().

HTTP endpoints:
    GET  /get-vc            Issue a JWT-VC for a device after verifying its public key.
    POST /update-vc         Handle a key-rotation request from a device.
    POST /revoke-vc         Revoke a device's VC from the status list.
    GET  /debug-status-list Return the current status list from the DHT (debug only).
"""

from dht_handler import DHTHandler
from did_iiot.modules import Service
from utils import get_vc
import asyncio
from fastapi import FastAPI, HTTPException, Query, Request
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


class IssuerNode(DHTHandler):
    """DHT-backed Verifiable Credential issuer (Python implementation).

    Inherits all DHT operations from DHTHandler and adds:
      - An in-memory status list of issued VCs.
      - Methods to publish, update, and revoke entries in that list via the DHT.
      - A dedicated asyncio event loop reference (dht_loop) used by FastAPI handlers
        to safely cross the thread boundary.
    """
    
    def __init__(self, dilith_keys_dir: str = "issuer_node_keys_dilithium",
                 kyber_keys_dir: str = "issuer_node_keys_kyber"):
        """
        Args:
            dilith_keys_dir: Directory for the issuer's Dilithium-2 key files.
            kyber_keys_dir:  Directory for the issuer's Kyber-512 key files.
        """
        super().__init__(dilith_keys_dir, kyber_keys_dir)
        self.status_list = []
        did_uri = "status-list"
        main_service = Service(f"{did_uri}#IssuerNode", "vc-issuer", "172.29.0.2:5007").get_dict()
        service = []
        service.append(main_service)
        # status_list_struct is the document stored in the DHT under "status-list".
        # It references self.status_list by object identity so mutations are reflected
        # automatically without reassigning the field.
        self.status_list_struct = {
            "id": did_uri,
            "status_list": self.status_list,
            "service": service
        }
        self.dht_loop = None  # set by the startup thread after the DHT loop is running

    def _load_private_key(self) -> bytes | None:
        """Load the issuer's raw Dilithium-2 secret key from disk."""
        key_path = Path(__file__).resolve().parent.parent / "issuer_node_private_key.txt"
        try:
            with open(key_path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            print(f"[ERRORE] File non trovato: {key_path}")
            return None
        except Exception as e:
            print(f"[ERRORE] Errore durante la lettura della chiave pubblica: {e}")
            return None

    def _load_iss_pub_key(self) -> bytes | None:
        """Load the issuer's raw Dilithium-2 public key from disk."""
        key_path = Path(__file__).resolve().parent.parent / "issuer_node_public_key.txt"
        try:
            with open(key_path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            print(f"[ERRORE] File non trovato: {key_path}")
            return None
        except Exception as e:
            print(f"[ERRORE] Errore durante la lettura della chiave pubblica: {e}")
            return None

    async def insert_status_list_into_DHT(self):
        """Sign and publish the current status list to the DHT under "status-list"."""
        iss_node_private_key = self._load_private_key()
        key = "status-list"
        value = utils.get_signed_did_document_record(self.status_list_struct,
                                                      iss_node_private_key, "Dilithium-2")
        await self.dht_node.set(key, value)

    async def update_status_list(self, auth_signature: bytes, key: str, value: bytes):
        """Process a key-rotation request from a device node.

        Verifies that the new DID record (value) is signed by the old key stored in
        the DHT, issues a fresh VC for the rotated key, updates the status list entry,
        and pushes the new status list to the DHT.

        Args:
            auth_signature: Signature of value produced with the device's OLD secret key.
            key:            DID UUID suffix (DHT key for the device's record).
            value:          New signed DID record bytes.

        Returns:
            New VC dict on success, None if verification fails or the DID is not listed.
        """
        old_value = await self.get_record_from_DHT(key)
        if not old_value:
            return None

        is_verified = self.dht_node.signature_verifier_handler.handle_update_verification(
            value, old_value, auth_signature
        )
        print("Verified update request !")
        if not is_verified:
            return None

        raw_did_document = value[12 + 2420:]
        did_document = utils.decode_did_document(raw_did_document)
        var_method = did_document['verificationMethod'][0]
        pub_key_node_jwk = var_method['publicKeyJwk']['x']
        pub_key_node = utils.base64_decode_publickey(pub_key_node_jwk)
        did = did_document['id']
        new_pub_key_hashed = hashlib.sha256(pub_key_node).digest()
        new_pub_key_hashed_b64 = base64.urlsafe_b64encode(new_pub_key_hashed).decode()
        iss_node_private_key = self._load_private_key()
        new_vc = get_vc(did, new_pub_key_hashed_b64, "Dilithium-2", iss_node_private_key)

        for i, elem in enumerate(self.status_list):
            if elem["did"] == did:
                new_version = elem["version"] + 1
                self.status_list[i] = {
                    "did": did,
                    "jwt-vc": base64.urlsafe_b64encode(
                        hashlib.sha256(new_vc['verifiable-credential'].encode()).digest()
                    ).decode(),
                    "valid": True,
                    "version": new_version
                }
                record_status_list = utils.get_signed_did_document_record(
                    self.status_list_struct, iss_node_private_key, "Dilithium-2"
                )
                print("Sending update status list request")
                await self.dht_node.update("status-list", record_status_list, None)
                return new_vc

        return None

    async def call_update_list(self) -> bool:
        """Force-push the current in-memory status list to the DHT (utility / debug)."""
        sk = self._load_private_key()
        record_status_list = utils.get_signed_did_document_record(
            self.status_list_struct, sk, "Dilithium-2"
        )
        await self.dht_node.update("status-list", record_status_list, None)
        return True

    async def generate_vc_v2(self, did_sub: str, pub_key_hashed_bytes: bytes,
                              result_did_document: bytes, modbus_operations: list = None):
        """Issue a Verifiable Credential for a device after verifying its public key.

        Retrieves the device's DID Document from the DHT, hashes the embedded public
        key, and compares it against the hash provided by the caller.  On match, a
        JWT-VC is issued, added to the status list, and the status list is updated
        in the DHT.

        Args:
            did_sub:              Full DID URI of the device requesting the VC.
            pub_key_hashed_bytes: SHA-256 hash of the device's Dilithium-2 public key.
            result_did_document:  Raw DHT record bytes for the device (already fetched).
            modbus_operations:    Optional Modbus operation list to embed in the VC.

        Returns:
            VC dict on success, None if the public key hash does not match.
        """
        sk = self._load_private_key()
        algorithm = "Dilithium-2"

        if not result_did_document:
            return None

        raw_did_document = result_did_document[12 + 2420:]
        did_document = utils.decode_did_document(raw_did_document)
        var_method = did_document['verificationMethod'][0]
        pub_key_node_jwk = var_method['publicKeyJwk']['x']
        pub_key_node = utils.base64_decode_publickey(pub_key_node_jwk)
        retrieved_pub_key_hashed = hashlib.sha256(pub_key_node).digest()

        if pub_key_hashed_bytes == retrieved_pub_key_hashed:
            vc = get_vc(
                did_sub=did_sub,
                pub_key_hash=base64.urlsafe_b64encode(pub_key_hashed_bytes).decode(),
                algorithm=algorithm,
                vc_issuer_sk=sk,
                modbus_operations=modbus_operations
            )
            self.status_list.append({
                "did": did_sub,
                "jwt-vc": base64.urlsafe_b64encode(
                    hashlib.sha256(vc['verifiable-credential'].encode()).digest()
                ).decode(),
                "valid": True,
                "version": 1
            })
            if vc:
                record_status_list = utils.get_signed_did_document_record(
                    self.status_list_struct, sk, "Dilithium-2"
                )
                await self.dht_node.update("status-list", record_status_list, None)
                return vc
            return None

        print("Public key hash does not match")
        return None

    async def revoke_vc_from_status_list(self, auth_signature: bytes, key: str, msg: bytes):
        """Revoke a device's VC from the status list.

        Verifies that msg is signed by the device's private key (owner-authorised
        revocation), removes the entry from the in-memory list, and publishes the
        updated status list to the DHT.

        Args:
            auth_signature: Signature of msg produced with the device's secret key.
            key:            DID UUID suffix (DHT key for the device's record).
            msg:            Message that was signed (e.g. b"delete-did").

        Returns:
            True on success, None if the key is not found or the signature is invalid.
        """
        old_value = await self.get_record_from_DHT(key)
        if not old_value:
            return None

        is_verified = self.dht_node.signature_verifier_handler.handle_signature_delete_operation(
            auth_signature, msg
        )
        print("Verified delete request")
        if not is_verified:
            return None

        iss_node_private_key = self._load_private_key()
        did = f"did:iiot:{key}"
        for i, elem in enumerate(self.status_list):
            if elem["did"] == did:
                self.status_list = [s for s in self.status_list if s["did"] != did]
                record_status_list = utils.get_signed_did_document_record(
                    self.status_list_struct, iss_node_private_key, "Dilithium-2"
                )
                print("Sending update status list request")
                await self.dht_node.update("status-list", record_status_list, None)
                return True

        return None

    def generate_vc(self, did_sub: str, modbus_operations: list = None) -> dict:
        """Issue a VC using the key-manager keypair stored at 'k0' (legacy helper)."""
        sk = self.dilith_key_manager.get_private_key("k0")
        algorithm = "Dilithium-2"
        return get_vc(did_sub=did_sub, algorithm=algorithm, vc_issuer_sk=sk,
                      modbus_operations=modbus_operations)
        
        


# ── FastAPI app ───────────────────────────────────────────────────────────────

issuer_node_service = FastAPI()
issuer_node = IssuerNode()


class VCRequest(BaseModel):
    did_sub: str
    modbus_operations: Optional[List[str]] = []

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
    """Issue a JWT-VC for a device.

    Fetches the device's DID Document from the DHT, verifies the public-key hash,
    then signs and returns a Verifiable Credential.
    """
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

    future_generate_vc = asyncio.run_coroutine_threadsafe(
        issuer_node.generate_vc_v2(
            did_sub,
            pub_key_hashed_bytes,
            result_did_document,
            modbus_operations,
        ),
        issuer_node.dht_loop,
    )
    result = await asyncio.wrap_future(future_generate_vc)

    if result is None:
        raise HTTPException(status_code=404, detail="No result found")
    return JSONResponse(content=result)


@issuer_node_service.post("/update-vc")
async def handle_update_status_list(data: UpdateVCRequest):
    """Handle a device key-rotation request.

    Decodes the base64-encoded auth signature and new DID record, delegates
    verification and status-list update to IssuerNode.update_status_list, and
    returns the newly issued VC.
    """
    try:
        auth_signature_bytes = base64.urlsafe_b64decode(data.auth_signature)
        value_bytes = base64.urlsafe_b64decode(data.value)
        key = data.key
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding for auth_signature or value")

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
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@issuer_node_service.post("/revoke-vc")
def handle_revocation(auth_signature: str, key: str, msg: str):
    """Revoke a device's VC.

    Verifies the device's ownership signature over msg, removes the entry from
    the status list, and publishes the updated list to the DHT.
    """
    if not key or not auth_signature or not msg:
        raise HTTPException(status_code=400, detail="Missing parameters")
    try:
        revoked = asyncio.run_coroutine_threadsafe(
            issuer_node.revoke_vc_from_status_list(auth_signature, key, msg),
            issuer_node.dht_loop,
        ).result(timeout=0.7)

        if revoked:
            return JSONResponse(content="Success")
        return JSONResponse(content="Unauthenticated request!!")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@issuer_node_service.get("/debug-status-list")
def debug_dht():
    """Return the current status list stored in the DHT (debug only)."""
    result = asyncio.run_coroutine_threadsafe(
        issuer_node.get_record_from_DHT("status-list"),
        issuer_node.dht_loop,
    ).result(timeout=0.7)
    if result is None:
        raise HTTPException(status_code=404, detail="No result found")
    raw_did_document = result[12 + 2420:]
    status_list = utils.decode_did_document(raw_did_document)
    return JSONResponse(content=status_list)


# ── startup ───────────────────────────────────────────────────────────────────

async def configure_issuer_node(issuer_node: IssuerNode, peers):
    """Bootstrap the DHT node, wait for neighbours, then publish the status list."""
    await issuer_node.start_dht_service(5000)

    if peers:
        await issuer_node.dht_node.bootstrap(peers)

    # Wait until at least 2 routing-table neighbours are known.
    while True:
        routing_table_kademlia = issuer_node.dht_node.protocol.router
        all_nodes = []
        for bucket in routing_table_kademlia.buckets:
            all_nodes.extend(bucket.get_nodes())
        if len(all_nodes) >= 2:
            break
        await asyncio.sleep(0.5)

    print(f"[IssuerNode] Network ready — {len(all_nodes)} neighbours known")
    await asyncio.sleep(60)
    await issuer_node.insert_status_list_into_DHT()
    await issuer_node.dht_node._refresh_table()
    await asyncio.sleep(2)


def conf_issuer_node(issuer_node: IssuerNode, bootstrap_nodes, loop_holder: dict):
    """Entry point for the DHT daemon thread.

    Creates a new event loop, stores it in loop_holder so the main thread can
    pick it up, runs configure_issuer_node to completion, then keeps the loop
    alive with run_forever().
    """
    print("[IssuerNode] Starting DHT service")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop_holder["loop_dht"] = loop
    loop.run_until_complete(configure_issuer_node(issuer_node, bootstrap_nodes))
    loop.run_forever()


if __name__ == "__main__":
    print("[IssuerNode] Python-backed issuer node starting!")
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