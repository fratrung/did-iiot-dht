# Self-Sovereign Identity System Based on DID and DHT with Post-Quantum Support

This repository contains a Python implementation of a **Self-Sovereign Identity (SSI)** system designed for decentralized and resilient environments such as the Internet of Things (IoT). The system uses a **modified Distributed Hash Table (DHT)** that acts as a **Verifiable Data Registry**.

## Key Features

- **Decentralized Identifiers (DIDs)** based on the `did:IIoT` method
- **Modified DHT** to store only DID Documents signed with the post-quantum **Dilithium** algorithm
- **Secure session key exchange** using the post-quantum **Kyber** algorithm
- **Verifiable Credentials (VCs)** used as authorization to enable node communication
- **Issuer Node discovery** using its DID Document stored in the DHT

## Architecture

### DID and DHT

- Each node in the system has a unique `did:IIoT` identifier and participates as a peer in the DHT network.
- The DHT is modified to only store **Dilithium-signed** DID Documents, ensuring post-quantum integrity and authenticity.
- Every node's **public key** is embedded within its DID Document, which is saved in the DHT.

### Verifiable Credentials (VCs)

- To communicate with other nodes, each participant must first obtain **authorization credentials** in the form of VCs.
- These credentials are issued by a manually initialized **Issuer Node**, which:
  - Receives and verifies DID-based requests
  - Issues a VC targeting the requester's `did:IIoT`

### Issuer Node Discovery

- The IP address and public keys of the Issuer Node are discoverable via a DHT query.
- Nodes can retrieve this information by querying the DHT with the key `did:IIoT:vc-issuer` to obtain the Issuer’s DID Document, which includes the required metadata to initiate communication and request credentials.

## Technologies Used

- **Python**: Main programming language
- **Dilithium**: Post-quantum digital signature algorithm for DID Document integrity
- **Kyber**: Post-quantum algorithm for secure key exchange
- **Custom DHT**: Modified to support secure and verified DID Document storage

## Getting Started

(*This section can be expanded with installation steps, usage examples, and requirements.*)

