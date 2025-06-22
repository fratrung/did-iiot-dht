from dht_handler import DHTHandler
from did_iiot.modules import Service
from utils import get_vc
import asyncio
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional
import uvicorn
import threading
import utils
import hashlib
import base64
from pathlib import Path
from concurrent.futures import TimeoutError as FuturesTimeoutError
import time


class IssuerNode(DHTHandler):
    
    def __init__(self,dilith_keys_dir="issuer_node_keys_dilithium",kyber_keys_dir="issuer_node_keys_kyber",):
        super().__init__(dilith_keys_dir,kyber_keys_dir)
        self.status_list = []
        did_uri = "status-list"
        main_service = Service(f"{did_uri}#IssuerNode","vc-issuer","172.29.0.2:5007").get_dict()
        service = []
        service.append(main_service)
        self.status_list_struct = {
            "id":did_uri,
            "status_list": self.status_list,
            "service": service
        }
        self.dht_loop = None
        
    def _load_private_key(self):
        key_path = Path(__file__).resolve().parent.parent / "issuer_node_private_key.txt"
        try:
            with open(key_path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            print(f"[ERRORE] File non trovato: {key_path}")
            return None
        except Exception as e:
            print(f"[ERRORE] Errore durante la lettura della chiave pubblica: {e}")
            return None   
        
    def _load_iss_pub_key(self):
        key_path = Path(__file__).resolve().parent.parent / "issuer_node_public_key.txt"
        try:
            with open(key_path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            print(f"[ERRORE] File non trovato: {key_path}")
            return None
        except Exception as e:
            print(f"[ERRORE] Errore durante la lettura della chiave pubblica: {e}")
            return None
        
    async def insert_status_list_into_DHT(self):
        iss_node_private_key = self._load_private_key()
        key = "status-list"
        value = utils.get_signed_did_document_record(self.status_list_struct,iss_node_private_key,"Dilithium-2")
        await self.dht_node.set(key,value)
    
       
        
    async def update_status_list(self,auth_signature,key,value):
        old_value = await self.get_record_from_DHT(key)
        if not old_value:
            return None
        
        is_verified=self.dht_node.signature_verifier_handler.handle_update_verification(value,old_value,auth_signature)
        print("Verified update request !")
        if not is_verified:
            return None
        
        raw_did_document = value[12+2420:]
        did_document = utils.decode_did_document(raw_did_document) 
        var_method = did_document['verificationMethod'][0]
        pub_key_node_jwk = var_method['publicKeyJwk']['x']
        pub_key_node = utils.base64_decode_publickey(pub_key_node_jwk)
        did = did_document['id']
        new_pub_key_hashed = hashlib.sha256(pub_key_node).digest()
        new_pub_key_hashed_b64 = base64.urlsafe_b64encode(new_pub_key_hashed).decode()
        iss_node_private_key = self._load_private_key()
        new_vc = get_vc(did,new_pub_key_hashed_b64,"Dilithium-2", iss_node_private_key)
        
        for i, elem in enumerate(self.status_list):
            if elem["did"] == did:
                new_version = elem["version"] + 1
                self.status_list[i] = {
                    "did": did,
                    "jwt-vc": base64.urlsafe_b64encode(hashlib.sha256(new_vc['verifiable-credential'].encode()).digest()).decode(),
                    "valid": True,
                    "version": new_version
                }
                record_status_list = utils.get_signed_did_document_record(
                    self.status_list_struct, iss_node_private_key, "Dilithium-2"
                )
                key_status_list = "status-list"
                print("Sending update status list request")
                await self.dht_node.update(key_status_list, record_status_list, None)
                return new_vc
        
        return None
        
    async def call_update_list(self):
        sk = self._load_private_key()
        record_status_list = utils.get_signed_did_document_record(self.status_list_struct,sk,"Dilithium-2")
        key_status_list = "status-list"
        await self.dht_node.update(key_status_list,record_status_list,None)
        return True
    
    async def generate_vc_v2(self,did_sub:str,pub_key_hashed_bytes,result_did_document, modbus_operations: list = None,):
        sk = self._load_private_key()
        algorithm = "Dilithium-2"
        
        if not result_did_document:
            return None
        
        raw_did_document = result_did_document[12+2420:]
        did_document = utils.decode_did_document(raw_did_document)
        var_method = did_document['verificationMethod'][0]
        pub_key_node_jwk = var_method['publicKeyJwk']['x']
        pub_key_node = utils.base64_decode_publickey(pub_key_node_jwk)
        retrieved_pub_key_hashed = hashlib.sha256(pub_key_node).digest()
        
        
        if pub_key_hashed_bytes == retrieved_pub_key_hashed:
            vc = get_vc(
                did_sub=did_sub,
                pub_key_hash=base64.urlsafe_b64encode(pub_key_hashed_bytes).decode(),
                algorithm=algorithm,
                vc_issuer_sk=sk,
                modbus_operations=modbus_operations
            )
            self.status_list.append({
                "did": did_sub,
                "jwt-vc":  base64.urlsafe_b64encode(hashlib.sha256(vc['verifiable-credential'].encode()).digest()).decode(),
                "valid": True,
                "version": 1
            })
            if vc:
                record_status_list = utils.get_signed_did_document_record(self.status_list_struct,sk,"Dilithium-2")
                key_status_list = "status-list"
                await self.dht_node.update(key_status_list,record_status_list,None)
                return vc
            return None 
        print("Public key hash does not match")
        return None
        
     
    async def revoke_vc_from_status_list(self,auth_signature, key, msg):
        old_value = await self.get_record_from_DHT(key)
        if not old_value:
            return None
        
        is_verified=self.dht_node.signature_verifier_handler.handle_signature_delete_operation(auth_signature,msg)
        print("Verified delete request")
        if not is_verified:
            return None
        
        iss_node_private_key = self._load_private_key()
        did = f"did:iiot:{key}"
        for i, elem in enumerate(self.status_list):
            if elem["did"] == did:
                self.status_list = [
                    s for s in self.status_list if s["did"] != did
                ]
                record_status_list = utils.get_signed_did_document_record(
                    self.status_list_struct, iss_node_private_key, "Dilithium-2"
                )
                key_status_list = "status-list"
                print("Sending update status list request")
                await self.dht_node.update(key_status_list, record_status_list, None)
                return True
        
        return None     
    
    def generate_vc(self,did_sub: str,modbus_operations: list = None):
        sk = self.dilith_key_manager.get_private_key("k0")
        algorithm = "Dilithium-2"
        return get_vc(did_sub=did_sub,algorithm=algorithm,vc_issuer_sk=sk,modbus_operations=modbus_operations)
        
        


issuer_node_service = FastAPI()
issuer_node = IssuerNode()


class VCRequest(BaseModel):
    did_sub: str
    modbus_operations: Optional[List[str]] = []
    
class UpdateVCRequest(BaseModel):
    auth_signature: str
    key: str
    value: str
    

def fix_base64_padding(s):
    return s + "=" * (-len(s) % 4)


@issuer_node_service.get("/get-vc")
async def generate_vc(did_sub: str, pub_key_hashed_b64: str,modbus_operations: Optional[List[str]] = Query(default=[])):
    if not did_sub or not pub_key_hashed_b64 :
        raise HTTPException(status_code=400, detail="Missing 'did_sub' parameter")
    try:
        pub_key_hashed_bytes = base64.urlsafe_b64decode(fix_base64_padding(pub_key_hashed_b64))
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding for pub_key_hashed")
    
    future_did_document = asyncio.run_coroutine_threadsafe(
        issuer_node.get_record_from_DHT(utils.extract_did_suffix(did_sub)),
        issuer_node.dht_loop
    )
    result_did_document = await asyncio.wrap_future(future_did_document)
    
    future_generate_vc = asyncio.run_coroutine_threadsafe(
        issuer_node.generate_vc_v2(
            did_sub,
            pub_key_hashed_bytes,
            result_did_document, 
            modbus_operations
        ),
        issuer_node.dht_loop
    )    
    result = await asyncio.wrap_future(future_generate_vc)

    if result is None:
            raise HTTPException(status_code=404, detail="No result found")
    if result:
        return JSONResponse(content=result)
    else:
        return JSONResponse(content="Failed")

                     

@issuer_node_service.post("/update-vc")
async def handle_update_status_list(data: UpdateVCRequest):
    try:
        auth_signature_bytes = base64.urlsafe_b64decode(data.auth_signature)
        value_bytes = base64.urlsafe_b64decode(data.value)
        key = data.key
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding for auth_signature or value")
    
    try:
        future_updated = asyncio.run_coroutine_threadsafe(
            issuer_node.update_status_list(
                auth_signature_bytes,
                key,
                value_bytes,
            ),
            issuer_node.dht_loop
        )
        updated =  await asyncio.wrap_future(future_updated)

        
        if updated:
            return JSONResponse(content=updated)
        return JSONResponse(content={"error": "Unauthenticated request"}, status_code=401)

    except FuturesTimeoutError:
        raise HTTPException(status_code=504, detail="DHT operation timed out")
    except Exception as e:
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@issuer_node_service.post("/revoke-vc")
def handle_revocation(auth_signature,key,msg):
    if not key or not auth_signature or not msg:
        raise HTTPException(status_code=400, detail="Missing parameters")
    try:
        
        revoked = asyncio.run_coroutine_threadsafe(
            issuer_node.revoke_vc_from_status_list(auth_signature, key, msg),
            issuer_node.dht_loop
        ).result(timeout=0.7) 
        
        if revoked:
            return JSONResponse(content="Success")
        return JSONResponse(content="Unauthenticated request!!")                   
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 
    
    
@issuer_node_service.get("/debug-status-list")
def debug_dht():
    result = asyncio.run_coroutine_threadsafe(
        issuer_node.get_record_from_DHT("status-list"),
        issuer_node.dht_loop,
    ).result(timeout=0.7) 
    raw_did_document = result[12+2420:]
    status_list = utils.decode_did_document(raw_did_document)
    if result is None:
        raise HTTPException(status_code=404, detail="No result found")
    return JSONResponse(content=status_list)



     
async def configure_issuer_node(issuer_node: IssuerNode, peers):
    await issuer_node.start_dht_service(5000)
    while True:
        routing_table_kademlia = issuer_node.dht_node.protocol.router
        all_nodes = []
        for bucket in routing_table_kademlia.buckets:
            all_nodes.extend(bucket.get_nodes())
        if len(all_nodes) >= 2:
            break
        await asyncio.sleep(0.5)

    print(all_nodes)
    await asyncio.sleep(60)
    await issuer_node.insert_status_list_into_DHT()
    await issuer_node.dht_node._refresh_table()
    await asyncio.sleep(2)
    
   
      

def conf_issuer_node(issuer_node,bootstrap_nodes,loop_holder):
    print("Starting DHT Service")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop_holder["loop_dht"] = loop 
    loop.run_until_complete(configure_issuer_node(issuer_node,bootstrap_nodes))
    loop.run_forever()

if __name__ == "__main__":
    print("Issuer Node started!")
    loop_holder = {}

    bootstrap_nodes = [("172.29.0.181",5000),("172.29.0.63",5000)] #entry nodes for DHT  
    
    dht_thread = threading.Thread(target=conf_issuer_node,args=(issuer_node,bootstrap_nodes, loop_holder),daemon=True)
    dht_thread.start()
    
    while "loop_dht" not in loop_holder:
        time.sleep(0.1)
        
    issuer_node.dht_loop = loop_holder["loop_dht"]
    uvicorn.run(issuer_node_service, host="0.0.0.0", port=5007)
