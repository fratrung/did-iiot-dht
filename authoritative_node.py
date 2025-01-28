from dht_handler import DHTHandler
from utils import extract_did_suffix, get_vc
import asyncio
import time
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional
import socket
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
        
def send_broadcast_message():
    BROADCAST_IP = "172.29.0.255"
    PORT = 7000
    MESSAGE = b"Hello"
    MAX_ATTEMPTS = 5
    REQUIRED_RESPONSES = 3
    TIMEOUT = 3
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
    s.settimeout(TIMEOUT)
    
    peers = set()
    attempts = 0
    try:
        while attempts < MAX_ATTEMPTS:
            s.sendto(MESSAGE, (BROADCAST_IP, PORT))
            start_time = time.time()
            while time.time() - start_time < TIMEOUT:
                try:
                    response, addr = s.recvfrom(1024)
                    response_text = response.decode().strip()
                    
                    if response_text:
                        peer_info = tuple(response_text.split(":"))
                        response_tuple = (peer_info[0],int(peer_info[1]))
                        
                        if response_tuple not in peers:
                            peers.add(response_tuple)
                            
                    if len(peers) >= REQUIRED_RESPONSES:
                        return peers
                    
                except socket.timeout:
                    break
                
            attempts += 1
            time.sleep(2)
        
        return peers
    except KeyboardInterrupt:
        pass
    finally:
        s.close()
        
        
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
                            
                            
        
async def configure_auth_node(auth_node: AuthoritativeNode, peers):
    auth_node.generate_authoritative_node_did_iiot("172.29.0.2:5007")
    await auth_node.start_dht_service(5000)
    await auth_node.dht_node.bootstrap(peers)
    await auth_node.insert_did_document_in_the_DHT()
    await auth_node.dht_node.stop()
    
if __name__ == "__main__":
    peers = []
    while not peers:
        peers = send_broadcast_message()
        time.sleep(7)
        
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(configure_auth_node(auth_node,peers))
    # Avvia FastAPI
    uvicorn.run(auth_node_service, host="0.0.0.0", port=5007)

