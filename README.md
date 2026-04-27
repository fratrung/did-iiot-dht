# did-iiot-dht

A Python framework for building **Post-Quantum Self-Sovereign Identity (SSI)** systems using **Decentralized Identifiers (DIDs)**, a cryptographically extended **Distributed Hash Table (DHT)**, and **post-quantum cryptographic primitives**.

Designed for decentralized and resource-constrained environments — with a primary focus on **Industrial IoT (IIoT)** — this library provides the foundational building blocks for constructing secure, privacy-preserving, and sovereign identity infrastructures without reliance on any central authority.

-----

## Overview

This framework integrates three core pillars:

- **Post-quantum cryptography** (Dilithium for signatures, Kyber for key encapsulation) to ensure long-term security against quantum adversaries
- **Decentralized Identifiers** following the `did:iiot` method, tailored for constrained industrial environments
- **A custom DHT** acting as a Verifiable Data Registry (VDR), where only cryptographically signed DID Documents are accepted and stored

The result is a fully decentralized identity layer that devices can use to authenticate, exchange session keys, and optionally obtain Verifiable Credentials — all without a trusted intermediary.

-----

## Key Features

- Core classes for **DID lifecycle management** using the `did:iiot` method
- **DID Document** creation and validation with post-quantum Dilithium signatures
- Secure session key exchange via post-quantum **Kyber** key encapsulation
- Integration with a **custom DHT** acting as a Verifiable Data Registry (VDR)
- *(Optional)* **Verifiable Credential (VC)** support as a flexible authorization mechanism
- *(Optional)* Discovery and communication with **Issuer Nodes** for regulated device onboarding

-----

## Decentralized Architecture

This framework supports a **selectively decentralized model**, separating concerns between fully decentralized operations and optional controlled ones:

|Layer                    |Mode                   |Description                                                                    |
|-------------------------|-----------------------|-------------------------------------------------------------------------------|
|DID creation & resolution|Decentralized          |Operated entirely via DHT, no central registry                                 |
|Public key distribution  |Decentralized          |Embedded in DID Documents stored on the DHT                                    |
|Session key negotiation  |Decentralized          |Peer-to-peer via Kyber KEM                                                     |
|Credential issuance      |Controlled *(optional)*|Delegated to an Issuer Node for regulated onboarding or access control policies|

This design allows the framework to be deployed in fully open environments as well as in scenarios requiring explicit authorization of devices joining the network.

-----

## Installation

### Python dependencies

```bash
git clone --recurse-submodules <repo-url>
cd did-iiot-dht
python -m venv .env
source .env/bin/activate
pip install -r requirements.txt
```

### Rust binding (authkademlia_py) — required for `RustDHTHandler`

`RustDHTHandler` uses a native Python extension built from the `auth-kademlia-rs` submodule.
You need [Rust](https://rustup.rs/) and `maturin` installed (`pip install maturin`).

**Option A — development install** (installs directly into the active virtualenv, no wheel file needed):

```bash
cd auth-kademlia-rs
maturin develop --features python
cd ..
```

**Option B — build a wheel and install it**:

```bash
cd auth-kademlia-rs
maturin build --features python --release
# maturin prints the wheel path, e.g.:
#   📦 Built wheel to auth-kademlia-rs/target/wheels/authkademlia_rs-0.1.0-cp312-cp312-linux_x86_64.whl
pip install target/wheels/authkademlia_rs-*.whl
cd ..
```

After either option, verify the install:

```bash
python -c "import authkademlia_py; print('OK')"
```

> **Note:** `--features python` is mandatory — without it the Rust crate builds
> as a plain library with no Python surface.

-----

## External Dependencies

|Library         |Purpose                                                |Repository                                                             |
|----------------|-------------------------------------------------------|-----------------------------------------------------------------------|
|**AuthKademlia**|Custom DHT — stores only Dilithium-signed DID Documents|[fratrung/AuthKademlia](https://github.com/fratrung/AuthKademlia)      |
|**did:iiot**    |DID method for Industrial IoT environments             |[fratrung/did-iiot](https://github.com/fratrung/did-iiot)              |
|**dilithium-py**|CRYSTALS-Dilithium post-quantum signature scheme       |[GiacomoPope/dilithium-py](https://github.com/GiacomoPope/dilithium-py)|
|**kyber-py**    |CRYSTALS-Kyber post-quantum key encapsulation          |[GiacomoPope/kyber-py](https://github.com/GiacomoPope/kyber-py)        |

-----

## Example Integration

**Industrial Control System Cyber Range** — [fratrung/ICS_Cyber_Range](https://github.com/fratrung/ICS_Cyber_Range)

A proof-of-concept deployment of this framework within a simulated IIoT environment, demonstrating end-to-end identity management, device authentication, and secure session establishment across industrial control system components.

-----

## Related Projects

- [AuthKademlia](https://github.com/fratrung/AuthKademlia) — Python DHT with signed record support
- [AuthKademlia-RS](https://github.com/fratrung/auth-kademlia-rs) — Rust reimplementation of AuthKademlia
- [did:iiot](https://github.com/fratrung/did-iiot) — DID method specification and implementation
- [ICS_Cyber_Range](https://github.com/fratrung/ICS_Cyber_Range) — Full integration reference
