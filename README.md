# Python Library for Building Post-Quantum SSI System Using DIDs and Custom DHT

This repository provides a Python library containing core classes and components for building **Self-Sovereign Identity (SSI)** systems that leverage **Decentralized Identifiers (DIDs)**, a **custom Distributed Hash Table (DHT)**, and **post-quantum cryptographic primitives**.

It is intended for use in decentralized and resource-constrained environments such as the Internet of Things (IoT), especially in **Industrial IoT (IIoT)** scenarios, and serves as a foundation for constructing secure, privacy-preserving identity infrastructures.


---

## External Dependencies

- **Modified DHT Implementation**  
  GitHub: [https://github.com/fratrung/AuthKademlia](https://github.com/fratrung/AuthKademlia)  
  A custom DHT designed to store only DID Documents that are signed with the post-quantum **Dilithium** signature scheme.

- **DID-IIoT Method**
  GitHub: [https://github.com/fratrung/did-iiot](https://github.com/fratrung/did-iiot)  
  A decentralized identifier method tailored for Industrial IoT environments.

---

## Key Features

- Core classes for managing **DIDs** using the `did:iiot` method
- Support for **DID Document** creation and validation using **Dilithium** signatures
- Session key exchange support via the post-quantum **Kyber** algorithm
- Integration with a **custom DHT** acting as a Verifiable Data Registry for storing verifiable DID Document
- (Optional) support for **Verifiable Credentials (VCs)** as an authorization mechanism
- (Optional) discovery and communication with **Issuer Nodes** for credential issuance

---

## Decentralized Model

This library supports a **selectively decentralized architecture**:

- **Decentralized**:
  - DID creation and resolution via DHT
  - Public key distribution and session negotiation
- **Controlled (optional)**:
  - Verifiable Credential issuance through an issuer node, for use cases that require authorization policies or regulated onboarding and for manually access control of device in the network 
---

## Example Integration

- **Industrial Control System Cyber Range**:  
  [https://github.com/fratrung/ICS_Cyber_Range](https://github.com/fratrung/ICS_Cyber_Range)  
  A proof-of-concept integration of these components within a simulated IIoT environment.

---




