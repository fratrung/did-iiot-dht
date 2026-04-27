# CLAUDE.md — did-iiot-dht

## What this is
Python application that implements a **DID:IIoT** (Decentralised Identifier for
Industrial IoT) registry on top of an authenticated Kademlia DHT. Devices
generate post-quantum keypairs (Dilithium-2 + Kyber-512), build a DID Document,
sign it, and publish it to the DHT. Other nodes can retrieve and verify it.

## Repository layout

```
did-iiot-dht/
├── dht_handler.py          # DHTHandler (Python) and RustDHTHandler (Rust binding)
├── utils.py                # Encoding, signing, VC helpers
├── issuer_node.py          # Authoritative issuer node (issues Verifiable Credentials)
├── test_set_and_get.py     # pytest + standalone tests
├── requirements.txt
│
├── AuthKademlia/           # submodule — pure-Python authenticated Kademlia
├── did_iiot/               # submodule — DID:IIoT data model (DIDDocument, JWK, …)
└── auth-kademlia-rs/       # submodule — Rust re-implementation + Python bindings
```

## Submodules

| Path | Purpose |
|---|---|
| `AuthKademlia/` | Pure-Python DHT used by `DHTHandler` |
| `did_iiot/` | `DIDDocument`, `VerificationMethod`, `Service`, JWK types |
| `auth-kademlia-rs/` | Rust DHT + PyO3 bindings used by `RustDHTHandler` |

Clone with submodules:
```bash
git clone --recurse-submodules <repo-url>
# or, after a plain clone:
git submodule update --init --recursive
```

## Python environment setup

```bash
python -m venv .env
source .env/bin/activate
pip install -r requirements.txt
```

## Building and installing the Rust extension (authkademlia_py)

`RustDHTHandler` requires the `authkademlia_py` native module built from
`auth-kademlia-rs/`. Two workflows:

### Development install (recommended — no manual wheel path needed)
```bash
cd auth-kademlia-rs
maturin develop --features python
# installs authkademlia_py directly into the active virtualenv
cd ..
```

### Build a wheel and pip-install it
```bash
cd auth-kademlia-rs
maturin build --features python --release
# wheel is written to  auth-kademlia-rs/target/wheels/
# filename looks like: authkademlia_rs-0.1.0-cp312-cp312-linux_x86_64.whl
pip install target/wheels/authkademlia_rs-*.whl
cd ..
```

After either step, `import authkademlia_py` should work in the virtualenv.

> The `--features python` flag activates the `pyo3` / `pyo3-asyncio` code
> paths in `auth-kademlia-rs/src/`. Without it the Rust crate builds as a
> plain library with no Python surface.

## Running tests

```bash
# Full test suite (Python)
pytest test_set_and_get.py -v

# Run standalone (no pytest)
python test_set_and_get.py

# Rust unit + integration tests (inside the submodule)
cd auth-kademlia-rs && cargo test
```

## Two DHT handler implementations

### `DHTHandler` (pure Python)
- Uses `AuthKademlia/` (Python Kademlia) and `dilithium_py` for signing.
- Signing: `Dilithium2.sign(sk, raw_did_doc_bytes)` — secret key format is
  `dilithium_py`'s own byte layout.

### `RustDHTHandler` (Rust binding)
- Uses `authkademlia_py` (built from `auth-kademlia-rs/`).
- Signing: `DilithiumKeyManager.sign(sk, raw_did_doc_bytes)` — Rust
  `pqcrypto_dilithium` key format, **incompatible** with `dilithium_py`. Never
  mix keys between the two handlers.
- PyO3 returns `Vec<u8>` as a Python `list`; `_ensure_bytes()` converts it to
  `bytes` before any slicing or `.decode()` call.

## Wire record format

```
| algorithm  (12 B, null-padded UTF-8, e.g. "Dilithium-2\0") |
| signature  (2420 B for Dilithium-2)                         |
| DID Document (JSON, keys sorted, no spaces)                 |
```

The signature covers **only the DID Document JSON bytes** — not the algorithm
header. Parsing: `record[:12]` = alg, `record[12:12+2420]` = sig,
`record[12+2420:]` = JSON.

## Key invariants
- DHT key = UUID suffix of the DID (`did:iiot:<uuid>` → `<uuid>`).
- `DIDDocument` must have exactly two `verificationMethod` entries: index 0 is
  the Dilithium-2 key (`#k0`), index 1 is the Kyber-512 key (`#k1`).
- Key rotation requires an `auth_signature = sign(new_record, old_private_key)`
  passed to `dht_node.update()`.
- Delete requires `auth_signature = sign(b"delete-did", private_key)`.
- `issuer_node_public_key.bin` — raw bytes of the issuer's Dilithium-2 public
  key, embedded at build time. Used by the DHT verifier for the status-list
  key (`did:iiot:status-list`).

## Key files

| File | Role |
|---|---|
| `dht_handler.py` | `DHTHandler`, `RustDHTHandler`, `DIDIIoTHandler` |
| `utils.py` | `encode_did_document`, `decode_did_document`, `get_signed_did_document_record`, VC helpers |
| `issuer_node.py` | FastAPI service that issues JWT-VC and manages the status list |
| `auth-kademlia-rs/src/auth_handler.rs` | Rust signature verification handler |
| `auth-kademlia-rs/src/py_bindings.rs` | PyO3 entry point (`#[pymodule]`) |

## What NOT to do
- Do not pass a Rust-generated Dilithium secret key to `dilithium_py.Dilithium2.sign()` — the key formats are incompatible.
- Do not call `.decode()` on values returned directly from `authkademlia_py` methods without `_ensure_bytes()` first (PyO3 returns `list`, not `bytes`).
- Do not change the signing scheme in `utils.py` without also updating `auth_handler.rs` (`verify_self_signed`, `handle_issuer_node_signature_verification`) and all four copies of `build_signed_record` in `auth-kademlia-rs/` (`common/mod.rs`, `crypto_tests.rs`, `dht_integration.rs`, `scripts/dht_node.rs`).
