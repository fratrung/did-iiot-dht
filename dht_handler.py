from AuthKademlia.modules import DilithiumKeyManager, KyberKeyManager, Server, DIDSignatureVerifierHandler, SIGNATURE_ALG_LENGTHS
from did_iiot.modules import DIDIndustrialIoT, Service, VerificationMethod, DIDDocument
import utils
import requests
import time
import json
from jwt import utils as jwt_utils


class DIDIIoTHandler:
    
    def __init__(self,did, did_document, did_dir):
        self.did = did
        self.did_document = did_document
        self.did_dir = did_dir

    
    def get_did_suffix(self):
        return self.did.split(":")[-1]


class DHTHandler:
    
    def __init__(self,dilith_keys_dir="proxy_keys_dilithium",kyber_keys_dir="proxy_keys_kyber"):
        self.dilith_key_manager = DilithiumKeyManager(dilith_keys_dir)
        self.kyber_key_manager = KyberKeyManager(kyber_keys_dir)
        self.dht_node = Server(signature_verifier_handler=DIDSignatureVerifierHandler())
        self.did_handler = None
        
    def _generate_dilithium_and_kyber_keypairs(self,dilith_key_name="k0",kyber_key_name="k1"):
        dilith_pk,dilith_sk = self.dilith_key_manager.generate_keypair(2)
        self.dilith_key_manager.store_public_key(dilith_key_name,dilith_pk)
        self.dilith_key_manager.store_private_key(dilith_key_name,dilith_sk)
        
        kyber_pk, kyber_sk = self.kyber_key_manager.generate_keypair(512)
        self.kyber_key_manager.store_public_key(kyber_key_name,kyber_pk)
        self.kyber_key_manager.store_private_key(kyber_key_name,kyber_sk)
    
    
    def _prepare_did_iiot_property(self,did,dilith_pk,kyber_pk,id_service,service_type, service_endpoint):
        dilithium_public_jwk_jose = utils.get_dilithium_pub_key_for_did_doc(did,dilith_pk,2,)
        kyber_public_jwk_jose = utils.get_kyber_pub_key_for_did_doc(did,kyber_pk,"Kyber-512","k1")
        dilithium_verification_method = VerificationMethod(f"{did}#k0",type="Authentication",public_jwkey=dilithium_public_jwk_jose)
        kyber_verification_method = VerificationMethod(f"{did}#k1",type="KeySessionExchange",public_jwkey=kyber_public_jwk_jose)
        verification_methods = []
        verification_methods.append(dilithium_verification_method)
        verification_methods.append(kyber_verification_method)
        
        main_service = Service(f"{did}#{id_service}",service_type,service_endpoint)
        service = []
        service.append(main_service)
        return service, verification_methods
      
    def _get_new_keypairs(self):
        self._generate_dilithium_and_kyber_keypairs(dilith_key_name="new-k0",kyber_key_name="new-k1")
        old_sk = self.dilith_key_manager.get_private_key("k0")
        new_sk = self.dilith_key_manager.get_private_key("new-k0")
        new_pk = self.dilith_key_manager.get_public_key("new-k0")
        new_kyber_pk = self.kyber_key_manager.get_public_key("new-k1")
        new_kyber_sk = self.kyber_key_manager.get_private_key("new-k1")
        return old_sk, new_sk, new_pk, new_kyber_pk, new_kyber_sk
    
    
    def generate_did_iiot(self,id_service,service_type,service_endpoint,did_uri=None,):
        self._generate_dilithium_and_kyber_keypairs()
        dilith_pk = self.dilith_key_manager.get_public_key("k0")
        kyber_pk = self.kyber_key_manager.get_public_key("k1")
        if did_uri == None:
            did = DIDIndustrialIoT.generate_did_uri()
        else:
            did = did_uri
        service, verification_methods = self._prepare_did_iiot_property(did,dilith_pk,kyber_pk,id_service,service_type,service_endpoint)
        did_document = DIDDocument(id=did,verification_methods=verification_methods,service=service)
        self.did_handler = DIDIIoTHandler(did,did_document.get_dict(),"did_document")
        
    def get_did_iiot(self):
        if not self.did_handler:
            return None
        return self.did_handler.did
    
    
    def get_did_iiot_suffix(self):
        if not self.did_handler:
            return None
        return self.did_handler.get_did_suffix()
    
    def get_did_document(self):
        if not self.did_handler:
            return None
        return self.did_handler.did_document
        
    
    async def insert_did_document_in_the_DHT(self):
        if self.did_handler is None:
            return None
        dilith_sk = self.dilith_key_manager.get_private_key("k0")
        value = utils.get_signed_did_document_record(self.did_handler.did_document,dilith_sk,algorithm="Dilithium-2")
        key = self.did_handler.did.split(":")[-1]
        print(value)
        await self.dht_node.set(key,value)
        
    
    async def key_rotation(self):
        old_sk, new_sk, new_pk, new_kyber_pk, new_kyber_sk = self._get_new_keypairs()
        new_pk_jwk = utils.get_dilithium_pub_key_for_did_doc(did=self.did_handler.did,pk=new_pk,security_level=2,kid="k0")
        dilith_ver_meth = VerificationMethod(id=f"{self.did_handler.did}#k0",type="Authentication",public_jwkey=new_pk_jwk)
        new_kyber_pk_jwk = utils.get_kyber_pub_key_for_did_doc(did=f"{self.did_handler.did}",pk=new_kyber_pk,lat="Kyber-512")
        kyber_ver_meth = VerificationMethod(id=f"{self.did_handler.did}#k1",type="SessionKeyExchange",public_jwkey=new_kyber_pk_jwk)
        
        did_document = self.did_handler.did_document
        did_document['verificationMethod'][0] = dilith_ver_meth.get_dict()
        did_document['verificationMethod'][1] = kyber_ver_meth.get_dict()
        
        key = self.did_handler.get_did_suffix()
        value = utils.get_signed_did_document_record(did_document,new_sk,algorithm="Dilithium-2")
        auth_signature = self.dilith_key_manager.sign(old_sk,value,2)
        
        update_success = await self.dht_node.update(key=key,value=value,auth_signature=auth_signature)
    
        if update_success:
            self.dilith_key_manager.store_private_key(key_name="k0",private_key=new_sk)
            self.dilith_key_manager.store_public_key(key_name="k0",public_key=new_pk)
            self.kyber_key_manager.store_private_key(key_name="k0",private_key=new_kyber_sk)
            self.kyber_key_manager.store_public_key(key_name="k0",public_key=new_kyber_pk)
            self.did_handler.did_document = did_document
        

    async def get_record_from_DHT(self,key):
        return await self.dht_node.get(key)    
    
    async def revoke_did_iiot(self):
        delete_msg ="delete-did"
        dilith_priv_key = self.dilith_key_manager.get_private_key("k0")
        auth_signature = self.dilith_key_manager.sign(dilith_priv_key,delete_msg)
        key = self.did_handler.did.split(":")[-1]
        return await self.dht_node.delete(key,auth_signature,delete_msg) 
    
    async def start_dht_service(self,port):
        await self.dht_node.listen(port)
        
           
    async def get_vc_from_authoritative_node(self,modbus_operations=None):
        did = self.did_handler.did
        did_auth_node = "did:iiot:vc-issuer"
        result = await self.dht_node.get(key=utils.extract_did_suffix(did_auth_node))
        if not result:
            return None
        raw_did_document = result[12+2420:]
        did_document = utils.decode_did_document(raw_did_document)
        address = (did_document['service'][0])['serviceEndpoint']
        
        var_method = did_document['verificationMethod'][0]
        pub_key_auth_node_jwk = var_method['publicKeyJwk']['x']
        pub_key_auth_node = utils.base64_decode_publickey(pub_key_auth_node_jwk)
        
        while True:
            url = f"http://{address}/get-vc"
            params = {"did_sub":did,"modbus_operations":modbus_operations}
            try:
                response = requests.get(url, params=params)
                response.raise_for_status() 
                if response.status_code == 200:
                    jwt_vc = response.json()
                    break
                print("Risposta ricevuta:", response.json())
            except requests.RequestException as e:
                print("Errore durante la richiesta:", e)
            time.sleep(5)  
        
        vc = jwt_vc['verifiable-credential']
        jwt_array = vc.split(".")
        m = f"{jwt_array[0]}.{jwt_array[1]}".encode('utf-8')
        signature_for_validation = jwt_utils.base64url_decode(jwt_array[2].encode())
        vc_is_valid = self.dilith_key_manager.verify_signature(pub_key_auth_node,m,signature_for_validation,2)
        if vc_is_valid:
            with open("vc.json", "w") as json_file:
                json.dump(jwt_vc, json_file, indent=4)
            print("VC salvato in vc.json")
        else:
            print("Invalid Verifiable Credentials: Invalid Signature")

    
