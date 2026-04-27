"""
Integration tests for DID:IIoT DHT set/get round-trips using the pure-Python
DHTHandler (AuthKademlia + dilithium_py backend).

Tests:
  TestPythonDHT.test_did_generation_and_retrieval
      pytest + asyncio version.  Node A inserts a DID; Node B retrieves it.

  test_did_generation_and_retrieval_simple_python
      Standalone verbose version.  Both nodes generate and insert their own
      DIDs, then each retrieves the other's record.  Runnable directly:
          python test_python_dht.py

Wire record format reminder:
    bytes  0–11   : algorithm tag (null-padded UTF-8, e.g. b"Dilithium-2\\x00")
    bytes 12–2431 : Dilithium-2 signature (2420 bytes)
    bytes 2432+   : canonical DID Document JSON (sorted keys, no spaces)
"""

import asyncio
import pytest
import logging
from dht_handler import DHTHandler
import utils


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class TestPythonDHT:
    """Two-node integration tests for the pure-Python DHTHandler."""

    @pytest.mark.asyncio
    async def test_did_generation_and_retrieval(self):
        """Node A generates a DID and inserts it; Node B retrieves and verifies it."""
        node_a = DHTHandler(
            dilith_keys_dir="test_py_node_a_dilithium",
            kyber_keys_dir="test_py_node_a_kyber",
        )
        node_b = DHTHandler(
            dilith_keys_dir="test_py_node_b_dilithium",
            kyber_keys_dir="test_py_node_b_kyber",
        )

        port_a = 8474
        port_b = 8475

        try:
            logger.info(f"Starting Node A on port {port_a}")
            await node_a.start_dht_service(port_a)
            await asyncio.sleep(1)

            logger.info(f"Starting Node B on port {port_b}")
            await node_b.start_dht_service(port_b)
            await asyncio.sleep(1)

            logger.info("Node B bootstrapping to Node A")
            await node_b.dht_node.bootstrap([("127.0.0.1", port_a)])
            await asyncio.sleep(2)

            # Node A generates and publishes its DID.
            node_a.generate_did_iiot(
                id_service="py-device-1",
                service_type="IoT-Device",
                service_endpoint="192.168.1.100:5000",
            )
            did_a = node_a.get_did_iiot()
            did_suffix_a = node_a.get_did_iiot_suffix()
            did_document_a = node_a.get_did_document()

            assert did_a is not None, "DID should be generated"
            assert did_suffix_a is not None, "DID suffix should be available"
            assert did_document_a is not None, "DID document should be created"

            await node_a.insert_did_document_in_the_DHT()
            await asyncio.sleep(2)

            # Node B retrieves and validates the record.
            retrieved = await node_b.get_record_from_DHT(did_suffix_a)
            assert retrieved is not None, f"Node B should retrieve DID with key {did_suffix_a}"

            raw_doc = retrieved[12 + 2420:]
            retrieved_doc = utils.decode_did_document(raw_doc)

            assert retrieved_doc["id"] == did_a, "Retrieved DID must match the original"
            assert "verificationMethod" in retrieved_doc
            assert len(retrieved_doc["verificationMethod"]) == 2, \
                "DID must have exactly 2 verification methods (Dilithium-2 + Kyber-512)"
            assert retrieved_doc["service"][0]["serviceEndpoint"] == "192.168.1.100:5000"

            logger.info("Test passed: DID generated on Node A and retrieved on Node B")

        finally:
            node_a.dht_node.stop()
            node_b.dht_node.stop()


@pytest.mark.asyncio
async def test_did_generation_and_retrieval_simple_python():
    """
    Verbose standalone test (runnable without pytest).

    Both nodes generate and publish their own DIDs, then each retrieves the
    other's record from the DHT and verifies the content.
    """
    node_a = DHTHandler(
        dilith_keys_dir="test_py_simple_node_a_dilithium",
        kyber_keys_dir="test_py_simple_node_a_kyber",
    )
    node_b = DHTHandler(
        dilith_keys_dir="test_py_simple_node_b_dilithium",
        kyber_keys_dir="test_py_simple_node_b_kyber",
    )

    port_a = 8476
    port_b = 8477

    try:
        print("\n" + "=" * 60)
        print("BOOTSTRAP PHASE")
        print("=" * 60)

        logger.info("=== Node A: Starting DHT service (Bootstrap Node) ===")
        await node_a.start_dht_service(port_a)
        await asyncio.sleep(1)
        print(f"✓ Node A started on port {port_a} (Bootstrap)")

        logger.info("=== Node B: Starting DHT service ===")
        await node_b.start_dht_service(port_b)
        await asyncio.sleep(1)
        print(f"✓ Node B started on port {port_b}")

        logger.info("=== Node B: Bootstrapping to Node A ===")
        await node_b.dht_node.bootstrap([("127.0.0.1", port_a)])
        await asyncio.sleep(2)
        print("✓ Node B successfully bootstrapped to Node A")

        print("\n" + "=" * 60)
        print("DID GENERATION PHASE")
        print("=" * 60)

        node_a.generate_did_iiot(
            id_service="py-pump-controller",
            service_type="Industrial-Pump",
            service_endpoint="192.168.1.50:8080",
        )
        did_a = node_a.get_did_iiot()
        did_suffix_a = node_a.get_did_iiot_suffix()
        print(f"✓ Node A — Generated DID: {did_a}")
        print(f"  Suffix (key): {did_suffix_a}")

        node_b.generate_did_iiot(
            id_service="py-temperature-sensor",
            service_type="Temperature-Sensor",
            service_endpoint="192.168.1.60:8081",
        )
        did_b = node_b.get_did_iiot()
        did_suffix_b = node_b.get_did_iiot_suffix()
        print(f"✓ Node B — Generated DID: {did_b}")
        print(f"  Suffix (key): {did_suffix_b}")

        print("\n" + "=" * 60)
        print("DID INSERTION INTO DHT")
        print("=" * 60)

        await node_a.insert_did_document_in_the_DHT()
        await asyncio.sleep(1.5)
        print("✓ Node A inserted its DID into DHT")

        await node_b.insert_did_document_in_the_DHT()
        await asyncio.sleep(1.5)
        print("✓ Node B inserted its DID into DHT")

        print("\n" + "=" * 60)
        print("DID RETRIEVAL FROM DHT")
        print("=" * 60)

        retrieved_a = await node_b.get_record_from_DHT(did_suffix_a)
        if retrieved_a is None:
            logger.warning("Node B failed to retrieve Node A's DID")
            return False
        print("✓ Node B successfully retrieved Node A's DID from DHT")

        doc_a = utils.decode_did_document(retrieved_a[12 + 2420:])
        print(f"\n  Retrieved DID:     {doc_a['id']}")
        print(f"  Service Endpoint:  {doc_a['service'][0]['serviceEndpoint']}")
        print(f"  Verification Methods: {len(doc_a['verificationMethod'])}")

        assert doc_a["id"] == did_a, "Retrieved DID must match Node A's DID"
        assert doc_a["service"][0]["serviceEndpoint"] == "192.168.1.50:8080"

        retrieved_b = await node_a.get_record_from_DHT(did_suffix_b)
        if retrieved_b is None:
            logger.warning("Node A failed to retrieve Node B's DID")
            return False
        print("✓ Node A successfully retrieved Node B's DID from DHT")

        doc_b = utils.decode_did_document(retrieved_b[12 + 2420:])
        print(f"\n  Retrieved DID:     {doc_b['id']}")
        print(f"  Service Endpoint:  {doc_b['service'][0]['serviceEndpoint']}")
        print(f"  Verification Methods: {len(doc_b['verificationMethod'])}")

        assert doc_b["id"] == did_b, "Retrieved DID must match Node B's DID"
        assert doc_b["service"][0]["serviceEndpoint"] == "192.168.1.60:8081"

        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"✅ Node A generated:  {did_a}")
        print(f"✅ Node B generated:  {did_b}")
        print("✅ Node B retrieved Node A's DID from DHT")
        print("✅ Node A retrieved Node B's DID from DHT")
        print("\n✅ ALL TESTS PASSED!")
        return True

    except Exception as e:
        logger.error(f"Test failed with error: {e}", exc_info=True)
        print(f"\n❌ TEST FAILED: {e}")
        return False
    finally:
        logger.info("=== Cleaning up ===")
        node_a.dht_node.stop()
        node_b.dht_node.stop()


if __name__ == "__main__":
    print("Starting Python DHT test: Two nodes, DID generation and retrieval\n")
    result = asyncio.run(test_did_generation_and_retrieval_simple_python())
    exit(0 if result else 1)
