# Python Library for Building Post-Quantum SSI Systems Using DIDs and Custom DHT

This repository provides a Python library containing core classes and components for building **Self-Sovereign Identity (SSI)** systems that leverage **Decentralized Identifiers (DIDs)**, a **custom Distributed Hash Table (DHT)**, and **post-quantum cryptographic primitives**.

It is intended for use in decentralized and resource-constrained environments such as the Internet of Things (IoT), and serves as a foundation for constructing secure, privacy-preserving identity infrastructures.

## External Dependencies

- **Modified DHT Implementation**  
  GitHub: [https://github.com/fratrung/AuthKademlia](https://github.com/fratrung/AuthKademlia)  
  A custom DHT designed to store only DID Documents that are signed with the post-quantum **Dilithium** signature scheme.

- **Custom DID Method – `did:iiot`**  
  GitHub: [https://github.com/fratrung/did-iiot](https://github.com/fratrung/did-iiot)  
  A decentralized identifier method tailored for Indistrial IoT environments.

## Key Features

- Core classes for managing **DIDs** using the `did:iiot` method
- Support for **DID Document** creation and validation using **Dilithium** signatures
- Session key exchange support via the post-quantum **Kyber** algorithm
- Integration with a **custom DHT** acting as a Verifiable Data Registry
- Support for **Verifiable Credentials (VCs)** as a decentralized authorization mechanism
- Built-in discovery of trusted **Issuer Nodes** via DHT lookup

## System Architecture Overview

This library supports building SSI systems with the following reference architecture:

### 1. DID and DHT Integration

- Each node generates a unique identifier using the `did:iiot` method.
- Nodes act as peers in the network and participate in a custom DHT.
- The DHT only accepts **DID Documents** that are cryptographically signed using the **Dilithium** signature scheme.
- Each DID Document includes the node’s **public key**, required for verifying identity and establishing secure sessions.

### 2. Verifiable Credentials for Authorization

- Nodes must request **Verifiable Credentials (VCs)** to be authorized to communicate within the network.
- A trusted **Issuer Node**, launched manually, handles VC issuance by:
  - Receiving DID-based requests
  - Verifying requester identity
  - Issuing a credential that targets the requester’s `did:iiot`

### 3. Issuer Node Discovery

- The Issuer Node’s information (e.g., IP address, public key) is discoverable by querying the DHT with the key `did:iiot:vc-issuer`.
- The response includes the Issuer’s **DID Document**, enabling secure and authenticated communication between nodes and the issuer.

## Example 
- Industrial Control System Cyber Range: [https://github.com/fratrung/ICS_Cyber_Range](https://github.com/fratrung/ICS_Cyber_Range)