"""
Integration tests for RustDHTHandler — Rust authkademlia_py binding.

Use cases tested:
    - Routing table after bootstrap
    - GET/SET round-trip with implicit signature verification
    - Cross-node retrieval (DHT routing)
    - Tampered record rejected by SET (signature check)
    - Replication: record survives after inserting node stops
    - Key rotation via authenticated UPDATE
    - Unauthorized UPDATE rejected (wrong auth signature)
    - DID revocation via authenticated DELETE
    - Unauthorized DELETE rejected (wrong key)

Wire record layout:
    bytes  0–11   : algorithm tag, null-padded UTF-8  ("Dilithium-2\\x00")
    bytes  12–2431: Dilithium-2 signature (2420 bytes)
    bytes  2432+  : canonical DID Document JSON (sorted keys, no spaces)
"""

import asyncio
import copy
import pytest_asyncio
import logging
from did_iiot.modules import VerificationMethod
from rust_dht_handler import RustDHTHandler
import utils

logger = logging.getLogger(__name__)

ALG_LEN = 12
SIG_LEN = 2420
PAYLOAD_OFFSET = ALG_LEN + SIG_LEN

_next_port = 8470


def _alloc_ports(n=2):
    global _next_port
    ports = list(range(_next_port, _next_port + n))
    _next_port += n
    return ports


def _make_node(tmp_path, name):
    return RustDHTHandler(
        dilith_keys_dir=str(tmp_path / f"{name}_dil"),
        kyber_keys_dir=str(tmp_path / f"{name}_kyb"),
    )


async def _stop(*nodes):
    for node in nodes:
        try:
            await node.dht_node.stop()
        except Exception:
            pass


async def _wait_for_neighbors(node, timeout: float = 3.0, interval: float = 0.05):
    """Poll until the node has at least one entry in its routing table."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if await node.dht_node.bootstrappable_neighbors():
            return True
        await asyncio.sleep(interval)
    return False


async def _wait_for_key(node, key: str, timeout: float = 3.0, interval: float = 0.05):
    """Poll until the key is present in the DHT. Returns the record or None on timeout."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        record = await node.get_record_from_DHT(key)
        if record is not None:
            return record
        await asyncio.sleep(interval)
    return None


async def _wait_for_absent(node, key: str, timeout: float = 2.0, interval: float = 0.05):
    """Poll until the key is gone from the DHT. Returns True when absent, False on timeout."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if await node.get_record_from_DHT(key) is None:
            return True
        await asyncio.sleep(interval)
    return False


@pytest_asyncio.fixture
async def two_nodes(tmp_path):
    """Two bootstrapped nodes. Teardown is safe even if a test stops one early."""
    pa, pb = _alloc_ports(2)
    node_a = _make_node(tmp_path, "a")
    node_b = _make_node(tmp_path, "b")

    await node_a.start_dht_service(pa)
    await node_b.start_dht_service(pb)
    await node_b.dht_node.bootstrap([("127.0.0.1", pa)])
    await _wait_for_neighbors(node_b)

    yield node_a, node_b
    await _stop(node_a, node_b)


@pytest_asyncio.fixture
async def three_nodes(tmp_path):
    """Three bootstrapped nodes for replication tests."""
    pa, pb, pc = _alloc_ports(3)
    node_a = _make_node(tmp_path, "a")
    node_b = _make_node(tmp_path, "b")
    node_c = _make_node(tmp_path, "c")

    await node_a.start_dht_service(pa)
    await node_b.start_dht_service(pb)
    await node_c.start_dht_service(pc)

    await node_b.dht_node.bootstrap([("127.0.0.1", pa)])
    await node_c.dht_node.bootstrap([("127.0.0.1", pa)])
    await asyncio.gather(
        _wait_for_neighbors(node_b),
        _wait_for_neighbors(node_c),
    )

    yield node_a, node_b, node_c
    await _stop(node_a, node_b, node_c)



def _insert_did(node, service_id, service_type, endpoint):
    node.generate_did_iiot(service_id, service_type, endpoint)
    return node.get_did_iiot_suffix()


def _parse_did_doc(record):
    return utils.decode_did_document(record[PAYLOAD_OFFSET:])



async def test_routing_table_after_bootstrap(two_nodes):
    """After bootstrap both nodes should see each other in their routing tables."""
    node_a, node_b = two_nodes

    nb_a = await node_a.dht_node.bootstrappable_neighbors()
    nb_b = await node_b.dht_node.bootstrappable_neighbors()

    assert len(nb_a) >= 1, "Node A routing table is empty after bootstrap"
    assert len(nb_b) >= 1, "Node B routing table is empty after bootstrap"



async def test_get_nonexistent_key_returns_none(two_nodes):
    """GET on a key that was never inserted must return None."""
    node_a, _ = two_nodes
    result = await node_a.get_record_from_DHT("00000000-0000-0000-0000-000000000000")
    assert result is None



async def test_did_registration_and_resolution(two_nodes):
    """Core use case: device registers its DID, verifier resolves it from another node.

    The Rust layer verifies the embedded Dilithium-2 signature before returning
    the record — if GET returns data, the signature is already valid.
    """
    node_a, node_b = two_nodes

    key = _insert_did(node_a, "plc-1", "PLC", "192.168.1.10:502")
    await node_a.insert_did_document_in_the_DHT()

    record = await _wait_for_key(node_b, key)

    assert record is not None, "Verifier node could not resolve the DID"
    did_doc = _parse_did_doc(record)
    assert did_doc["id"] == node_a.get_did_iiot()
    assert did_doc["service"][0]["serviceEndpoint"] == "192.168.1.10:502"
    assert len(did_doc["verificationMethod"]) == 2

    alg = record[:ALG_LEN].rstrip(b"\x00").decode()
    assert alg == "Dilithium-2"



async def test_tampered_signature_rejected_by_set(two_nodes):
    """SET must reject a record whose Dilithium-2 signature has been corrupted."""
    node_a, _ = two_nodes
    _insert_did(node_a, "sensor", "Sensor", "10.0.0.1:9000")
    key = node_a.get_did_iiot_suffix()

    sk = node_a.dilith_key_manager.get_private_key("k0")
    valid_record = node_a._build_signed_record(node_a.get_did_document(), sk)

    tampered = bytearray(valid_record)
    tampered[ALG_LEN + 100] ^= 0xFF          # corrupt a byte inside the signature

    ok = await node_a.dht_node.set(key, bytes(tampered))
    assert not ok, "SET should reject a record with a corrupted signature"

    # The key should remain absent from the DHT.
    assert await node_a.get_record_from_DHT(key) is None


async def test_tampered_payload_rejected_by_set(two_nodes):
    """SET must reject a record whose DID Document JSON has been altered after signing."""
    node_a, _ = two_nodes
    _insert_did(node_a, "sensor", "Sensor", "10.0.0.1:9000")
    key = node_a.get_did_iiot_suffix()

    sk = node_a.dilith_key_manager.get_private_key("k0")
    valid_record = node_a._build_signed_record(node_a.get_did_document(), sk)

    tampered = bytearray(valid_record)
    tampered[-5] ^= 0xFF                      # corrupt a byte in the JSON payload

    ok = await node_a.dht_node.set(key, bytes(tampered))
    assert not ok, "SET should reject a record whose payload was altered post-signing"



async def test_replication_survives_inserter_stop(three_nodes):
    """Data inserted by A must remain retrievable via C after A is stopped.

    Kademlia sends STORE RPCs to the k closest nodes on SET; with k=20 and
    three nodes, all three store a copy so the record outlives the inserter.
    """
    node_a, node_b, node_c = three_nodes

    key = _insert_did(node_a, "pump", "Pump", "10.0.0.1:8080")
    did = node_a.get_did_iiot()
    await node_a.insert_did_document_in_the_DHT()
    # Wait until B has a local copy (STORE RPC received), confirming replication.
    assert await _wait_for_key(node_b, key) is not None, "B did not receive STORE RPC"

    await node_a.dht_node.stop()               # take the inserter offline

    record = await _wait_for_key(node_c, key)
    assert record is not None, "Record should survive after inserting node stops"
    assert _parse_did_doc(record)["id"] == did



async def test_key_rotation(two_nodes):
    """UPDATE with a valid auth_signature (signed by the current private key) succeeds."""
    node_a, node_b = two_nodes

    key = _insert_did(node_a, "device", "IoT-Device", "10.0.0.1:9000")
    old_sk = node_a.dilith_key_manager.get_private_key("k0")
    await node_a.insert_did_document_in_the_DHT()
    assert await _wait_for_key(node_a, key) is not None, "Initial record not stored"

    # Generate fresh keypair for the rotation
    new_dil_pk, new_dil_sk = node_a.dilith_key_manager.generate_keypair()
    new_kyber_pk, _         = node_a.kyber_key_manager.generate_keypair()

    did = node_a.get_did_iiot()
    rotated_doc = copy.deepcopy(node_a.get_did_document())
    rotated_doc["verificationMethod"] = [
        VerificationMethod(
            f"{did}#k0", type="Authentication",
            public_jwkey=utils.get_dilithium_pub_key_for_did_doc(did, new_dil_pk, 2, "k0"),
        ).get_dict(),
        VerificationMethod(
            f"{did}#k1", type="KeySessionExchange",
            public_jwkey=utils.get_kyber_pub_key_for_did_doc(did, new_kyber_pk, "Kyber-512", "k1"),
        ).get_dict(),
    ]

    new_record = node_a._build_signed_record(rotated_doc, new_dil_sk)
    # auth_signature proves ownership of the current (old) key
    auth_sig = node_a.dilith_key_manager.sign(old_sk, bytes(new_record))

    ok = await node_a.dht_node.update(key, new_record, auth_sig)
    assert ok, "Key rotation should succeed with a valid auth_signature"

    updated = await _wait_for_key(node_b, key)
    assert updated is not None
    assert _parse_did_doc(updated)["id"] == did



async def test_unauthorized_update_rejected(two_nodes):
    """UPDATE without a valid auth_signature must be rejected."""
    node_a, node_b = two_nodes

    key = _insert_did(node_a, "device", "IoT-Device", "10.0.0.1:9000")
    await node_a.insert_did_document_in_the_DHT()
    assert await _wait_for_key(node_a, key) is not None

    # Node B tries to overwrite Node A's record; it has no auth over A's key.
    _insert_did(node_b, "attacker", "Attacker", "10.0.0.2:9000")
    b_sk = node_b.dilith_key_manager.get_private_key("k0")
    fake_record = node_b._build_signed_record(node_b.get_did_document(), b_sk)
    wrong_auth  = node_b.dilith_key_manager.sign(b_sk, bytes(fake_record))

    ok = await node_b.dht_node.update(key, fake_record, wrong_auth)
    assert not ok, "UPDATE with a wrong auth_signature should be rejected"

    # Original record must be unchanged
    record = await node_a.get_record_from_DHT(key)
    assert record is not None
    assert _parse_did_doc(record)["id"] == node_a.get_did_iiot()



async def test_revocation(two_nodes):
    """Authenticated DELETE removes the record; subsequent GET returns None."""
    node_a, node_b = two_nodes

    key = _insert_did(node_a, "device", "IoT-Device", "10.0.0.1:9000")
    await node_a.insert_did_document_in_the_DHT()
    assert await _wait_for_key(node_b, key) is not None

    delete_msg = b"delete-did"
    sk         = node_a.dilith_key_manager.get_private_key("k0")
    auth_sig   = node_a.dilith_key_manager.sign(sk, delete_msg)

    ok = await node_a.dht_node.delete(key, auth_sig, delete_msg)
    assert ok, "Revocation should succeed with a valid auth_signature"

    assert await _wait_for_absent(node_b, key), "Revoked DID must not be resolvable"



async def test_unauthorized_delete_rejected(two_nodes):
    """DELETE signed by a foreign key must be rejected; record must survive."""
    node_a, node_b = two_nodes

    key = _insert_did(node_a, "device", "IoT-Device", "10.0.0.1:9000")
    await node_a.insert_did_document_in_the_DHT()
    assert await _wait_for_key(node_a, key) is not None

    # Node B tries to revoke Node A's DID with its own key
    _insert_did(node_b, "b", "B", "10.0.0.2:9000")
    delete_msg = b"delete-did"
    wrong_sk   = node_b.dilith_key_manager.get_private_key("k0")
    wrong_sig  = node_b.dilith_key_manager.sign(wrong_sk, delete_msg)

    ok = await node_b.dht_node.delete(key, wrong_sig, delete_msg)
    assert not ok, "DELETE with a foreign key should be rejected"

    record = await node_a.get_record_from_DHT(key)
    assert record is not None, "DID must still be resolvable after a rejected DELETE"


# ── standalone runner ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import tempfile
    import pathlib

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )

    TESTS = [
        test_routing_table_after_bootstrap,
        test_get_nonexistent_key_returns_none,
        test_did_registration_and_resolution,
        test_tampered_signature_rejected_by_set,
        test_tampered_payload_rejected_by_set,
        test_replication_survives_inserter_stop,
        test_key_rotation,
        test_unauthorized_update_rejected,
        test_revocation,
        test_unauthorized_delete_rejected,
    ]

    async def _run_all():
        passed = failed = 0
        for test_fn in TESTS:
            name = test_fn.__name__
            tmp = pathlib.Path(tempfile.mkdtemp())
            needs_three = "three_nodes" in test_fn.__code__.co_varnames

            if needs_three:
                pa, pb, pc = _alloc_ports(3)
                na = _make_node(tmp, "a")
                nb = _make_node(tmp, "b")
                nc = _make_node(tmp, "c")
                await na.start_dht_service(pa)
                await nb.start_dht_service(pb)
                await nc.start_dht_service(pc)
                await nb.dht_node.bootstrap([("127.0.0.1", pa)])
                await nc.dht_node.bootstrap([("127.0.0.1", pa)])
                await asyncio.gather(_wait_for_neighbors(nb), _wait_for_neighbors(nc))
                nodes = (na, nb, nc)
            else:
                pa, pb = _alloc_ports(2)
                na = _make_node(tmp, "a")
                nb = _make_node(tmp, "b")
                await na.start_dht_service(pa)
                await nb.start_dht_service(pb)
                await nb.dht_node.bootstrap([("127.0.0.1", pa)])
                await _wait_for_neighbors(nb)
                nodes = (na, nb)

            print(f"\n{'='*60}\n▶  {name}\n{'='*60}")
            try:
                await test_fn(nodes)
                print(f"✅  PASSED")
                passed += 1
            except Exception as exc:
                print(f"❌  FAILED: {exc}")
                failed += 1
            finally:
                await _stop(*nodes)

        print(f"\n{'='*60}")
        print(f"Results: {passed} passed, {failed} failed out of {len(TESTS)}")
        return failed

    sys.exit(asyncio.run(_run_all()))
