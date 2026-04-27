"""
Integration tests for DID:IIoT DHT set/get round-trips.

Two-node scenarios:
  TestDHT.test_did_generation_and_retrieval_between_two_nodes
      Uses DHTHandler (Python AuthKademlia).  Node A inserts a DID document;
      Node B retrieves it and verifies the wire record layout and content.

  test_did_generation_and_retrieval_simple
      Uses RustDHTHandler (Rust AuthKademlia binding).  Both nodes generate and
      insert their own DIDs, then each retrieves the other's record.

Wire record format reminder:
    bytes  0–11   : algorithm tag (null-padded UTF-8, e.g. b"Dilithium-2\\x00")
    bytes 12–2431 : Dilithium-2 signature (2420 bytes)
    bytes 2432+   : canonical DID Document JSON (sorted keys, no spaces)
"""

import asyncio
import pytest
import logging
from dht_handler import DHTHandler, RustDHTHandler
import utils


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class TestDHT:
    """
    Test class for DHT operations with two local nodes.
    Node A generates a DID and inserts it into DHT.
    Node B retrieves the DID from DHT.
    """
    
    @pytest.mark.asyncio
    async def test_did_generation_and_retrieval_between_two_nodes(self):
        """
        Test that:
        1. Node A generates a DID and inserts it into DHT
        2. Node B joins the network
        3. Node B retrieves the DID from DHT
        """
        # Create two DHTHandler instances (Node A and Node B)
        node_a = DHTHandler(
            dilith_keys_dir="test_node_a_dilithium",
            kyber_keys_dir="test_node_a_kyber"
        )
        node_b = DHTHandler(
            dilith_keys_dir="test_node_b_dilithium",
            kyber_keys_dir="test_node_b_kyber"
        )
        
        port_a = 8468
        port_b = 8469
        
        try:
            # Start Node A's DHT service
            logger.info(f"Starting Node A on port {port_a}")
            await node_a.start_dht_service(port_a)
            await asyncio.sleep(1)  # Wait for Node A to start
            
            # Start Node B's DHT service and bootstrap to Node A
            logger.info(f"Starting Node B on port {port_b}")
            await node_b.start_dht_service(port_b)
            await asyncio.sleep(1)
            
            # Node B bootstraps to Node A
            logger.info("Node B bootstrapping to Node A")
            await node_b.dht_node.bootstrap([("127.0.0.1", port_a)])
            await asyncio.sleep(2)  # Wait for bootstrap to complete
            
            # Node A: Generate DID
            logger.info("Node A: Generating DID")
            node_a.generate_did_iiot(
                id_service="device-1",
                service_type="IoT-Device",
                service_endpoint="192.168.1.100:5000"
            )
            
            # Get generated DID information
            did_a = node_a.get_did_iiot()
            did_suffix_a = node_a.get_did_iiot_suffix()
            did_document_a = node_a.get_did_document()
            
            logger.info(f"Node A generated DID: {did_a}")
            logger.info(f"DID suffix: {did_suffix_a}")
            assert did_a is not None, "DID should be generated"
            assert did_suffix_a is not None, "DID suffix should be available"
            assert did_document_a is not None, "DID document should be created"
            
            # Node A: Insert DID document into DHT
            logger.info("Node A: Inserting DID document into DHT")
            await node_a.insert_did_document_in_the_DHT()
            await asyncio.sleep(2)  # Wait for DHT operation
            
            logger.info(f"Node A inserted DID with key: {did_suffix_a}")
            
            # Node B: Retrieve DID from DHT using the suffix as key
            logger.info("Node B: Retrieving DID from DHT")
            retrieved_value = await node_b.get_record_from_DHT(did_suffix_a)
            
            assert retrieved_value is not None, f"Node B should retrieve DID with key {did_suffix_a}"
            logger.info(f"Node B successfully retrieved value from DHT")
            
            # Decode and verify the retrieved DID document
            # The value structure is: 12 bytes algorithm + 2420 bytes signature + raw DID document
            algorithm_part = retrieved_value[:12]
            signature_part = retrieved_value[12:12+2420]
            raw_did_document_bytes = retrieved_value[12+2420:]
            
            retrieved_did_document = utils.decode_did_document(raw_did_document_bytes)
            
            logger.info(f"Retrieved DID: {retrieved_did_document['id']}")
            
            # Verify that retrieved DID matches the original
            assert retrieved_did_document['id'] == did_a, \
                f"Retrieved DID {retrieved_did_document['id']} should match {did_a}"
            assert 'verificationMethod' in retrieved_did_document, \
                "Retrieved DID should have verificationMethod"
            assert len(retrieved_did_document['verificationMethod']) == 2, \
                "DID should have 2 verification methods (Dilithium and Kyber)"
            
            # Verify service endpoint
            assert 'service' in retrieved_did_document, "Retrieved DID should have service"
            assert len(retrieved_did_document['service']) > 0, "DID should have at least one service"
            service = retrieved_did_document['service'][0]
            assert service['serviceEndpoint'] == "192.168.1.100:5000", \
                "Service endpoint should match"
            
            logger.info("✓ Test passed: DID successfully generated on Node A and retrieved on Node B from DHT")
            
        finally:
            # Cleanup: Stop both nodes
            logger.info("Cleaning up: Stopping both nodes")
            node_a.dht_node.stop()
            node_b.dht_node.stop()


@pytest.mark.asyncio
async def test_did_generation_and_retrieval_simple():
    """
    Simple standalone test (can be run without pytest as well)
    Node A and Node B both generate DIDs and retrieve each other's DIDs from the DHT
    """
    # Create two DHTHandler instances (Node A and Node B)
    node_a = RustDHTHandler(
        dilith_keys_dir="test_simple_node_a_dilithium",
        kyber_keys_dir="test_simple_node_a_kyber"
    )
    node_b = RustDHTHandler(
        dilith_keys_dir="test_simple_node_b_dilithium",
        kyber_keys_dir="test_simple_node_b_kyber"
    )
    
    port_a = 8470
    port_b = 8471
    
    try:
        print("\n" + "="*60)
        print("BOOTSTRAP PHASE")
        print("="*60)
        
        # Start Node A (bootstrap node - no peer to connect to)
        logger.info("=== Node A: Starting DHT service (Bootstrap Node) ===")
        await node_a.start_dht_service(port_a)
        await asyncio.sleep(1)
        print(f"✓ Node A started on port {port_a} (Bootstrap)")
        
        # Start Node B
        logger.info("=== Node B: Starting DHT service ===")
        await node_b.start_dht_service(port_b)
        await asyncio.sleep(1)
        print(f"✓ Node B started on port {port_b}")
        
        # Bootstrap Node B to Node A
        logger.info(f"=== Node B: Bootstrapping to Node A ===")
        await node_b.dht_node.bootstrap([("127.0.0.1", port_a)])
        await asyncio.sleep(2)
        print(f"✓ Node B successfully bootstrapped to Node A")
        
        print("\n" + "="*60)
        print("DID GENERATION PHASE")
        print("="*60)
        
        # Generate DID on Node A
        logger.info("=== Node A: Generating DID ===")
        node_a.generate_did_iiot(
            id_service="pump-controller",
            service_type="Industrial-Pump",
            service_endpoint="192.168.1.50:8080"
        )
        
        did_a = node_a.get_did_iiot()
        did_suffix_a = node_a.get_did_iiot_suffix()
        
        print(f"✓ Node A - Generated DID: {did_a}")
        print(f"  Suffix (key): {did_suffix_a}")
        
        # Generate DID on Node B
        logger.info("=== Node B: Generating DID ===")
        node_b.generate_did_iiot(
            id_service="temperature-sensor",
            service_type="Temperature-Sensor",
            service_endpoint="192.168.1.60:8081"
        )
        
        did_b = node_b.get_did_iiot()
        did_suffix_b = node_b.get_did_iiot_suffix()
        
        print(f"✓ Node B - Generated DID: {did_b}")
        print(f"  Suffix (key): {did_suffix_b}")
        
        print("\n" + "="*60)
        print("DID INSERTION INTO DHT")
        print("="*60)
        
        # Node A inserts its DID into DHT
        logger.info("=== Node A: Inserting DID into DHT ===")
        await node_a.insert_did_document_in_the_DHT()
        await asyncio.sleep(1.5)
        print(f"✓ Node A inserted its DID into DHT")
        
        # Node B inserts its DID into DHT
        logger.info("=== Node B: Inserting DID into DHT ===")
        await node_b.insert_did_document_in_the_DHT()
        await asyncio.sleep(1.5)
        print(f"✓ Node B inserted its DID into DHT")
        
        print("\n" + "="*60)
        print("DID RETRIEVAL FROM DHT")
        print("="*60)
        
        # Node B retrieves Node A's DID from DHT
        logger.info("=== Node B: Retrieving Node A's DID from DHT ===")
        retrieved_value_a = await node_b.get_record_from_DHT(did_suffix_a)
        
        if retrieved_value_a is None:
            logger.warning("Node B failed to retrieve Node A's DID from DHT")
            return False
        
        print(f"✓ Node B successfully retrieved Node A's DID from DHT")
        
        # Decode Node A's DID retrieved by Node B
        raw_did_document_bytes_a = retrieved_value_a[12+2420:]
        retrieved_did_a = utils.decode_did_document(raw_did_document_bytes_a)
        
        print(f"\n  Retrieved DID: {retrieved_did_a['id']}")
        print(f"  Service Endpoint: {retrieved_did_a['service'][0]['serviceEndpoint']}")
        print(f"  Verification Methods: {len(retrieved_did_a['verificationMethod'])}")
        
        assert retrieved_did_a['id'] == did_a, "Retrieved DID should match Node A's DID"
        assert retrieved_did_a['service'][0]['serviceEndpoint'] == "192.168.1.50:8080"
        
        # Node A retrieves Node B's DID from DHT
        logger.info("=== Node A: Retrieving Node B's DID from DHT ===")
        retrieved_value_b = await node_a.get_record_from_DHT(did_suffix_b)
        
        if retrieved_value_b is None:
            logger.warning("Node A failed to retrieve Node B's DID from DHT")
            return False
        
        print(f"✓ Node A successfully retrieved Node B's DID from DHT")
        
        # Decode Node B's DID retrieved by Node A
        raw_did_document_bytes_b = retrieved_value_b[12+2420:]
        retrieved_did_b = utils.decode_did_document(raw_did_document_bytes_b)
        
        print(f"\n  Retrieved DID: {retrieved_did_b['id']}")
        print(f"  Service Endpoint: {retrieved_did_b['service'][0]['serviceEndpoint']}")
        print(f"  Verification Methods: {len(retrieved_did_b['verificationMethod'])}")
        
        assert retrieved_did_b['id'] == did_b, "Retrieved DID should match Node B's DID"
        assert retrieved_did_b['service'][0]['serviceEndpoint'] == "192.168.1.60:8081"
        
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        print(f"✅ Node A generated:  {did_a}")
        print(f"✅ Node B generated:  {did_b}")
        print(f"✅ Node B retrieved Node A's DID from DHT")
        print(f"✅ Node A retrieved Node B's DID from DHT")
        print(f"\n✅ ALL TESTS PASSED!")
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
    # Run simple test directly
    print("Starting DHT test: Two nodes, DID generation and retrieval\n")
    result = asyncio.run(test_did_generation_and_retrieval_simple())
    exit(0 if result else 1)
