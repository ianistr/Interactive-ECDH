# client.py
import asyncio
import json
import base64
import os
import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class E2EEClient:
    def __init__(self, client_id, api_key, identity_key, server_url="ws://localhost:8000"):
        self.client_id = client_id
        self.api_key = api_key
        
        # Ensure the URL is built correctly
        self.server_url = f"{server_url.rstrip('/')}/ws/{client_id}"
        
        # Load identity key
        if isinstance(identity_key, str):
            identity_key = identity_key.encode('ascii')
            
        self.identity_private_key = serialization.load_pem_private_key(
            identity_key.strip(), 
            password=None
        )
        self.identity_public_key = self.identity_private_key.public_key()
        
        self.peer_identity_public_key = None
        self.ws = None
        self.pending_exchanges = {}
        self.message_callback = None
        self.connected = False

    def set_peer_identity_key(self, peer_public_key_pem):
        if isinstance(peer_public_key_pem, str):
            peer_public_key_pem = peer_public_key_pem.encode('ascii')
        self.peer_identity_public_key = serialization.load_pem_public_key(peer_public_key_pem.strip())
        print(f"[{self.client_id}] Peer identity key set.")

    async def connect(self):
        try:
            print(f"[{self.client_id}] Connecting to {self.server_url}...")
            self.ws = await websockets.connect(self.server_url)
            
            auth_payload = {"type": "auth", "client_id": self.client_id, "api_key": self.api_key}
            await self.ws.send(json.dumps(auth_payload))
            
            resp = await self.ws.recv()
            if json.loads(resp).get("type") == "auth_success":
                self.connected = True
                asyncio.create_task(self._listen())
                print(f"[{self.client_id}] Authenticated successfully.")
        except Exception as e:
            print(f"[{self.client_id}] Connection error: {e}")
            raise

    # ... (Keep all other methods: _listen, _handle_message, sign_data, send_message, etc. as they were)
    def sign_data(self, data):
        return self.identity_private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def verify_signature(self, data, signature, public_key):
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except: return False

    def derive_shared_secret(self, private_key, peer_public_key):
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'e2ee-messaging').derive(shared_key)

    async def _listen(self):
        async for msg in self.ws:
            await self._handle_message(json.loads(msg))

    async def _handle_message(self, message):
        t = message.get("type")
        if t == "key_exchange_init": await self._handle_key_exchange_init(message)
        elif t == "key_exchange_response": await self._handle_key_exchange_response(message)
        elif t == "encrypted_message": await self._handle_encrypted_message(message)

    async def _handle_key_exchange_init(self, message):
        sender_id = message["sender_id"]
        ephem_pub_pem = base64.b64decode(message["ephemeral_public_key"])
        sig = base64.b64decode(message["signature"])
        if not self.verify_signature(ephem_pub_pem, sig, self.peer_identity_public_key): return
        peer_ephem_pub = serialization.load_pem_public_key(ephem_pub_pem)
        our_ephem_priv = ec.generate_private_key(ec.SECP384R1())
        our_ephem_pub_pem = our_ephem_priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        sym_key = self.derive_shared_secret(our_ephem_priv, peer_ephem_pub)
        self.pending_exchanges[message["exchange_id"]] = {'symmetric_key': sym_key}
        await self.ws.send(json.dumps({
            "type": "key_exchange_response", "sender_id": self.client_id, "recipient_id": sender_id,
            "exchange_id": message["exchange_id"],
            "ephemeral_public_key": base64.b64encode(our_ephem_pub_pem).decode(),
            "signature": base64.b64encode(self.sign_data(our_ephem_pub_pem)).decode()
        }))

    async def _handle_key_exchange_response(self, message):
        ex_id = message["exchange_id"]
        pub_pem = base64.b64decode(message["ephemeral_public_key"])
        if self.verify_signature(pub_pem, base64.b64decode(message["signature"]), self.peer_identity_public_key):
            peer_pub = serialization.load_pem_public_key(pub_pem)
            sym_key = self.derive_shared_secret(self.pending_exchanges[ex_id]["private_key"], peer_pub)
            self.pending_exchanges[ex_id]["symmetric_key"] = sym_key
            self.pending_exchanges[ex_id]["event"].set()

    async def _handle_encrypted_message(self, message):
        ex_id = message["exchange_id"]
        if ex_id in self.pending_exchanges:
            sym_key = self.pending_exchanges[ex_id]['symmetric_key']
            print(f"Symetric key for this message: {sym_key.hex()}")
            nonce = base64.b64decode(message["nonce"])
            ciphertext = base64.b64decode(message["ciphertext"])
            plaintext = AESGCM(sym_key).decrypt(nonce, ciphertext, None).decode()
            if self.message_callback: self.message_callback(message["sender_id"], plaintext)

    async def send_message(self, recipient_id, plaintext):
        ephem_priv = ec.generate_private_key(ec.SECP384R1())
        pub_pem = ephem_priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        ex_id = f"{self.client_id}-{os.urandom(4).hex()}"
        event = asyncio.Event()
        self.pending_exchanges[ex_id] = {"private_key": ephem_priv, "event": event}
        await self.ws.send(json.dumps({
            "type": "key_exchange_init", "sender_id": self.client_id, "recipient_id": recipient_id,
            "exchange_id": ex_id, "ephemeral_public_key": base64.b64encode(pub_pem).decode(),
            "signature": base64.b64encode(self.sign_data(pub_pem)).decode()
        }))
        await asyncio.wait_for(event.wait(), timeout=5.0)
        sym_key = self.pending_exchanges[ex_id]["symmetric_key"]
        print(f"Symetric key for this message: {sym_key.hex()}")
        nonce = os.urandom(12)
        ciphertext = AESGCM(sym_key).encrypt(nonce, plaintext.encode(), None)
        await self.ws.send(json.dumps({
            "type": "encrypted_message", "sender_id": self.client_id, "recipient_id": recipient_id,
            "exchange_id": ex_id, "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode()
        }))

    def set_message_callback(self, callback):
        self.message_callback = callback