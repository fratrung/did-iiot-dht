from AuthKademlia.kademlia.crypto.key_manager import DilithiumKeyManager, KyberKeyManager
from AuthKademlia.kademlia.auth_handler import DIDSignatureVerifierHandler
from AuthKademlia.kademlia.network import Server
from dht_handler import DHTHandler
from utils import extract_did_suffix, get_vc
import asyncio
import time
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional
import uvicorn


class AuthoritativeNode(DHTHandler):
    
    def __init__(self,dilith_keys_dir="auth_node_keys_dilithium",kyber_keys_dir="auth_node_keys_kyber"):
        super().__init__(dilith_keys_dir,kyber_keys_dir)
        
    
    def generate_authoritative_node_did_iiot(self,service_endpoint):
        did = f"did:iiot:vc-issuer"
        self.generate_did_iiot(id_service="AuthoritativeNode",service_type="vc-issuer",service_endpoint=service_endpoint,did_uri=did)
        
        
    
    def generate_vc(self,did_sub: str,modbus_operations: list = None):
        sk = self.dilith_key_manager.get_private_key("k0")
        # modifiche da fare: il key manager di AuthKademlia deve riconoscere il tipo di algoritmo dalla lunghezza della chiave privata
        algorithm = "Dilithium-2"
        #await self.start_dht_service(5000)
        #result = await self.dht_node.get(key=extract_did_suffix(did_sub))
        #if not result:
            #return None
        return get_vc(did_sub=did_sub,algorithm=algorithm,vc_issuer_sk=sk,modbus_operations=modbus_operations)
        
 
auth_node_service = FastAPI()
auth_node = AuthoritativeNode()

class VCRequest(BaseModel):
    did_sub: str
    modbus_operations: Optional[List[str]] = []

@auth_node_service.get("/get-vc")
async def generate_vc(did_sub: str, modbus_operations: Optional[List[str]] = Query(default=[])):
    #loop = asyncio.new_event_loop()
    #asyncio.set_event_loop(loop)
    if not did_sub:
        raise HTTPException(status_code=400, detail="Missing 'did_sub' parameter")

    try:
        result = auth_node.generate_vc(did_sub, modbus_operations)
        if result is None:
            raise HTTPException(status_code=404, detail="No result found")
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
                            
                            
        
async def configure_auth_node(auth_node: AuthoritativeNode):
    auth_node.generate_authoritative_node_did_iiot("127.0.0.1:5001")
    await auth_node.start_dht_service(8002)
    await auth_node.dht_node.bootstrap([("127.0.0.1",8000),("127.0.0.1",8001)])
    await auth_node.insert_did_document_in_the_DHT()
    await auth_node.dht_node.stop()
    
if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(configure_auth_node(auth_node))
    # Avvia FastAPI
    time.sleep(40)
    uvicorn.run(auth_node_service, host="127.0.0.1", port=5001)