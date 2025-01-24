import base64
from did_iiot.did_iiot.did_iiot import DIDIndustrialIoT
from did_iiot.did_iiot.did_document import DIDDocument, VerificationMethod, Service, ServiceType
from did_iiot.did_iiot.publicjwk import DilithiumPublicJwkey, KyberPublicJwkey
import jwt.utils as jwt_utils
import base64
from AuthKademlia.kademlia.crypto.dilithium.src.dilithium_py.dilithium.default_parameters import Dilithium2
import json
import json
from datetime import datetime, timezone, timedelta

def base64_encode_publickey(pk):
    return base64.urlsafe_b64encode(pk).decode('utf-8').rstrip("=")

def base64_decode_publickey(pk):
    padding_needed = len(pk) % 4
    if padding_needed > 0:
        pk += '=' * (4 - padding_needed)
    return base64.urlsafe_b64decode(pk)

def extract_did_suffix(did: str):
    return did.split(":")[-1]

def encode_did_document(did_document: dict):
    return json.dumps(did_document,sort_keys=True,separators=(",",":")).encode('utf-8')

def decode_did_document(encoded_did_document:bytes):
    json_string = encoded_did_document.decode('utf-8')
    did_document = json.loads(json_string)
    return did_document

    
def get_dilithium_pub_key_for_did_doc(did,pk,security_level,kid="k0"):
    x = base64_encode_publickey(pk)
    if int(security_level) != 2 and int(security_level) != 3 and int(security_level) != 5:
        return None
    return DilithiumPublicJwkey(f"{did}#{kid}",security_level=security_level,x=x)


def get_kyber_pub_key_for_did_doc(did,pk,lat,kid="k1"):
    x = base64_encode_publickey(pk)
    if lat != "Kyber-512" and lat != "Kyber-768" and lat != "Kyber-1024":
        return None
    return KyberPublicJwkey(lat,x)


def get_signed_did_document_record(did_document: dict,sk: bytes,algorithm:str):
    raw_did_doc_encoded = encode_did_document(did_document)
    alg = algorithm.encode('utf-8')[:12].ljust(12, b'\0')
    signature = Dilithium2.sign(sk,raw_did_doc_encoded)
    value = alg + signature + raw_did_doc_encoded
    return value

def get_vc_payload(did_sub:str,modbus_operations: list = None):
    modbus_op = []
    if modbus_operations:
        modbus_op = modbus_operations
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
                "permissions":{
                    "modbus_operatins": modbus_op
                }
            }
        }
    }
    
def get_vc_header(algorithm):
    return {
        "alg":algorithm,
        "typ": "JWT-VC"
    }

def get_authoritative_node_did_document(pk,service_endpoint):
    did = f"did:iiot:vc-issuer"
    x = base64.urlsafe_b64encode(pk).decode('utf-8').rstrip("=")
    pub_key_jwk = DilithiumPublicJwkey("k0",2,x)
    verification_methods = []
    services = []
    method = VerificationMethod(id=f"{did}#k0",type="Authentication",public_jwkey=pub_key_jwk)
    service = Service(id=did,type=ServiceType.DecentralizedWebNode,service_endpoint=service_endpoint)
    services.append(service)
    verification_methods.append(method)
    did_document = DIDDocument(id=did,verification_methods=verification_methods,service=services)
    return did, did_document
    



def get_vc(did_sub: str,algorithm: str, vc_issuer_sk: bytes,modbus_operations: list = None):
    vc_payload = get_vc_payload(did_sub,modbus_operations)
    header = get_vc_header(algorithm)
    encoded_header = jwt_utils.base64url_encode(jwt_utils.force_bytes(json.dumps(header)))
    encoded_payload =  jwt_utils.base64url_encode(jwt_utils.force_bytes(json.dumps(vc_payload)))
    unsigned_jwt = f"{encoded_header.decode()}.{encoded_payload.decode()}"
    signature = Dilithium2.sign(vc_issuer_sk,unsigned_jwt.encode())
    encoded_signature = jwt_utils.base64url_encode(signature)
    signed_jwt = f"{unsigned_jwt}.{encoded_signature.decode()}"
    
    return {"verifiable-credential":signed_jwt}

