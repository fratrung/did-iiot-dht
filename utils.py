"""
Utility helpers for DID:IIoT record encoding, signing, and Verifiable Credential creation.

Wire record format (produced by get_signed_did_document_record):
    | algorithm (12 B, null-padded UTF-8) | Dilithium-2 signature (2420 B) | DID Document JSON |

The DID Document JSON is always serialised with sorted keys and no extra whitespace
so that the byte representation is deterministic across implementations.
"""

import base64
from did_iiot.did_iiot.did_document import DIDDocument, VerificationMethod, Service, ServiceType
from did_iiot.did_iiot.publicjwk import DilithiumPublicJwkey, KyberPublicJwkey
import jwt.utils as jwt_utils
import base64
from AuthKademlia.kademlia.crypto.dilithium.src.dilithium_py.dilithium.default_parameters import Dilithium2
import json
from datetime import datetime, timezone, timedelta


def base64_encode_publickey(pk: bytes) -> str:
    """Encode raw public-key bytes to an unpadded base64url string (JWK 'x' field format)."""
    return base64.urlsafe_b64encode(pk).decode('utf-8').rstrip("=")


def base64_decode_publickey(pk: str) -> bytes:
    """Decode an unpadded base64url string back to raw public-key bytes."""
    padding_needed = len(pk) % 4
    if padding_needed > 0:
        pk += '=' * (4 - padding_needed)
    return base64.urlsafe_b64decode(pk)


def extract_did_suffix(did: str) -> str:
    """Return the UUID suffix of a DID URI (the part after the last ':')."""
    return did.split(":")[-1]


def encode_did_document(did_document: dict) -> bytes:
    """Serialise a DID Document dict to canonical UTF-8 JSON (sorted keys, no spaces)."""
    return json.dumps(did_document, sort_keys=True, separators=(",", ":")).encode('utf-8')


def decode_did_document(encoded_did_document: bytes) -> dict:
    """Deserialise canonical DID Document bytes back to a Python dict."""
    json_string = encoded_did_document.decode('utf-8')
    return json.loads(json_string)


def get_dilithium_pub_key_for_did_doc(did: str, pk: bytes, security_level, kid: str = "k0"):
    """
    Build a DilithiumPublicJwkey object suitable for embedding in a DID Document.

    Args:
        did:            Full DID URI (used to construct the key id).
        pk:             Raw Dilithium public-key bytes.
        security_level: 2, 3, or 5. Any other value returns None.
        kid:            Key fragment identifier (default "k0").

    Returns:
        DilithiumPublicJwkey or None if security_level is unsupported.
    """
    x = base64_encode_publickey(pk)
    if int(security_level) not in (2, 3, 5):
        return None
    return DilithiumPublicJwkey(f"{did}#{kid}", security_level=security_level, x=x)


def get_kyber_pub_key_for_did_doc(did: str, pk: bytes, lat: str, kid: str = "k1"):
    """
    Build a KyberPublicJwkey object suitable for embedding in a DID Document.

    Args:
        did: Full DID URI.
        pk:  Raw Kyber public-key bytes.
        lat: Lattice parameter string — "Kyber-512", "Kyber-768", or "Kyber-1024".
        kid: Key fragment identifier (default "k1").

    Returns:
        KyberPublicJwkey or None if lat is unsupported.
    """
    x = base64_encode_publickey(pk)
    if lat not in ("Kyber-512", "Kyber-768", "Kyber-1024"):
        return None
    return KyberPublicJwkey(lat, x)


def get_signed_did_document_record(did_document: dict, sk: bytes, algorithm: str) -> bytes:
    """
    Assemble a complete AuthKademlia DHT record for a DID Document.

    The signature covers only the canonical DID Document JSON bytes.
    Uses the pure-Python dilithium_py library — do NOT pass keys generated
    by the Rust DilithiumKeyManager (incompatible key format).

    Wire layout:
        algorithm (12 B, null-padded) | Dilithium signature | DID Document JSON

    Args:
        did_document: DID Document as a Python dict.
        sk:           Dilithium-2 secret key bytes (dilithium_py format).
        algorithm:    Algorithm tag string, e.g. "Dilithium-2".

    Returns:
        Assembled record bytes ready to be stored in the DHT via dht_node.set().
    """
    raw_did_doc_encoded = encode_did_document(did_document)
    alg = algorithm.encode('utf-8')[:12].ljust(12, b'\0')
    signature = Dilithium2.sign(sk, raw_did_doc_encoded)
    return alg + signature + raw_did_doc_encoded


def get_vc_payload(did_sub: str, modbus_operations: list = None) -> dict:
    """
    Build the JWT payload for a Verifiable Credential.

    Args:
        did_sub:           DID of the subject (the device being credentialed).
        modbus_operations: Optional list of authorised Modbus operations.

    Returns:
        Dict representing the unsigned JWT claims (iss, sub, iat, exp, vc).
    """
    modbus_op = modbus_operations or []
    return {
        "iss": "did:iiot:vc-issuer",
        "sub": did_sub,
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int((datetime.now(timezone.utc) + timedelta(days=365)).timestamp()),
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "Authorization"],
            "credentialSubject": {
                "id": did_sub,
                "name": "HMI",
                "permissions": {
                    "modbus_operatins": modbus_op
                }
            }
        }
    }


def get_vc_header(algorithm: str) -> dict:
    """Return the JWT header dict for a Verifiable Credential."""
    return {"alg": algorithm, "typ": "JWT-VC"}


def get_authoritative_node_did_document(pk: bytes, service_endpoint: str):
    """
    Build the DID Document for the authoritative Issuer Node.

    Args:
        pk:               Raw Dilithium-2 public-key bytes of the issuer.
        service_endpoint: HTTP address where the issuer's API is reachable.

    Returns:
        Tuple (did_uri: str, did_document: DIDDocument).
    """
    did = "did:iiot:vc-issuer"
    x = base64.urlsafe_b64encode(pk).decode('utf-8').rstrip("=")
    pub_key_jwk = DilithiumPublicJwkey("k0", 2, x)
    method = VerificationMethod(id=f"{did}#k0", type="Authentication", public_jwkey=pub_key_jwk)
    service = Service(id=did, type=ServiceType.DecentralizedWebNode, service_endpoint=service_endpoint)
    did_document = DIDDocument(id=did, verification_methods=[method], service=[service])
    return did, did_document


def get_vc(did_sub: str, algorithm: str, vc_issuer_sk: bytes, modbus_operations: list = None) -> dict:
    """
    Issue a signed JWT-VC (Verifiable Credential) for a device DID.

    The JWT is signed with the issuer's Dilithium-2 secret key using the
    compact serialisation: base64url(header).base64url(payload).base64url(signature).

    Args:
        did_sub:           DID of the credential subject.
        algorithm:         Signature algorithm tag for the JWT header (e.g. "Dilithium-2").
        vc_issuer_sk:      Issuer's Dilithium-2 secret key bytes (dilithium_py format).
        modbus_operations: Optional list of authorised Modbus operations to embed.

    Returns:
        Dict with a single key "verifiable-credential" containing the signed JWT string.
    """
    vc_payload = get_vc_payload(did_sub, modbus_operations)
    header = get_vc_header(algorithm)
    encoded_header = jwt_utils.base64url_encode(jwt_utils.force_bytes(json.dumps(header)))
    encoded_payload = jwt_utils.base64url_encode(jwt_utils.force_bytes(json.dumps(vc_payload)))
    unsigned_jwt = f"{encoded_header.decode()}.{encoded_payload.decode()}"
    signature = Dilithium2.sign(vc_issuer_sk, unsigned_jwt.encode())
    encoded_signature = jwt_utils.base64url_encode(signature)
    signed_jwt = f"{unsigned_jwt}.{encoded_signature.decode()}"
    return {"verifiable-credential": signed_jwt}
