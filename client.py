import asyncio
import websockets
import json
import base64
import os
from typing import Optional, Callable
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

class E2EEClient:
    def __init__(
        self,
        client_id: str,
        api_key: str,
        server_url: str = "ws://localhost:8000",
        max_message_size: int = 100 * 1024  # 100KB
    ):
        self.client_id = client_id
        self.api_key = api_key
        self.server_url = f"{server_url}/ws/{client_id}"
        self.max_message_size = max_message_size
        
        # Generate long-term identity keys
        self.identity_private_key = ec.generate_private_key(ec.SECP384R1())
        self.identity_public_key = self.identity_private_key.public_key()
        
        # WebSocket connection
        self.ws = None
        
        # Store peer's identity public key
        self.peer_identity_public_key = None
        
        # Pending key exchanges with asyncio Events
        self.pending_exchanges = {}
        
        # Message handler callback
        self.message_callback = None
        
        # Connection state
        self.connected = False
    
    def get_identity_public_key_bytes(self):
        """Export identity public key as bytes"""
        return self.identity_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def set_peer_identity_key(self, peer_public_key_pem: bytes):
        """Set peer's identity public key"""
        try:
            self.peer_identity_public_key = serialization.load_pem_public_key(peer_public_key_pem)
            print(f"[{self.client_id}] Peer identity key set")
        except Exception as e:
            print(f"[{self.client_id}] Error setting peer key: {e}")
            raise
    
    def sign_data(self, data: bytes) -> bytes:
        """Sign data with identity private key"""
        signature = self.identity_private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return signature
    
    def verify_signature(self, data: bytes, signature: bytes, public_key) -> bool:
        """Verify signature using peer's public key"""
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False
    
    def derive_shared_secret(self, private_key, peer_public_key) -> bytes:
        """Perform ECDH and derive symmetric key"""
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        print(f"shared_secret derived: {shared_key.hex()}")
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'e2ee-messaging'
        ).derive(shared_key)
        print(f"derived_key generated after HKDF: {derived_key.hex()}")
        
        return derived_key
    
    async def connect(self):
        """
        Connect to server via WebSocket with API key authentication
        """
        try:
            # Connect to WebSocket
            self.ws = await websockets.connect(
                self.server_url,
                ping_interval=20,
                ping_timeout=10,
                max_size=self.max_message_size
            )
            
            print(f"[{self.client_id}] Connected to server")
            
            # Send authentication message with API key
            auth_message = {
                "type": "auth",
                "client_id": self.client_id,
                "api_key": self.api_key
            }
            await self.ws.send(json.dumps(auth_message))
            
            # Wait for authentication response
            auth_response = await asyncio.wait_for(
                self.ws.recv(), 
                timeout=5.0
            )
            auth_data = json.loads(auth_response)
            
            if auth_data.get("type") == "auth_success":
                print(f"[{self.client_id}] ✓ Authenticated successfully")
                self.connected = True
            else:
                raise Exception(f"Authentication failed: {auth_data.get('error')}")
            
            # Start listening for messages
            asyncio.create_task(self._listen())
            
        except websockets.exceptions.InvalidStatusCode as e:
            print(f"[{self.client_id}] Connection failed: {e}")
            raise
        except asyncio.TimeoutError:
            print(f"[{self.client_id}] Authentication timeout")
            raise
        except Exception as e:
            print(f"[{self.client_id}] Connection error: {e}")
            raise
    
    async def _listen(self):
        """Listen for incoming messages"""
        try:
            async for message in self.ws:
                try:
                    data = json.loads(message)
                    await self._handle_message(data)
                except json.JSONDecodeError:
                    print(f"[{self.client_id}] Invalid JSON received")
                except Exception as e:
                    print(f"[{self.client_id}] Error handling message: {e}")
        except websockets.exceptions.ConnectionClosed:
            print(f"[{self.client_id}] Connection closed")
            self.connected = False
        except Exception as e:
            print(f"[{self.client_id}] Listen error: {e}")
            self.connected = False
    
    async def _handle_message(self, message: dict):
        """Handle incoming messages"""
        msg_type = message.get("type")
        
        if msg_type == "key_exchange_init":
            await self._handle_key_exchange_init(message)
        
        elif msg_type == "key_exchange_response":
            await self._handle_key_exchange_response(message)
        
        elif msg_type == "encrypted_message":
            await self._handle_encrypted_message(message)
        
        elif msg_type == "error":
            error_msg = message.get('error', 'Unknown error')
            print(f"[{self.client_id}] Server error: {error_msg}")
            
            # Handle errors for pending exchanges
            exchange_id = message.get('exchange_id')
            if exchange_id and exchange_id in self.pending_exchanges:
                self.pending_exchanges[exchange_id]['error'] = error_msg
                self.pending_exchanges[exchange_id]['event'].set()
    
    async def _handle_key_exchange_init(self, message: dict):
        """Handle key exchange initiation from peer"""
        try:
            sender_id = message["sender_id"]
            ephemeral_public_key_pem = base64.b64decode(message["ephemeral_public_key"])
            signature = base64.b64decode(message["signature"])
            
            if not self.peer_identity_public_key:
                print(f"[{self.client_id}] No peer identity key set!")
                return
            
            # Verify signature
            if not self.verify_signature(ephemeral_public_key_pem, signature, self.peer_identity_public_key):
                print(f"[{self.client_id}] ⚠️  Invalid signature on ephemeral key!")
                return
            
            print(f"[{self.client_id}] Received key exchange init from {sender_id}")
            
            # Load peer's ephemeral public key
            peer_ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_key_pem)
            
            # Generate our own ephemeral keys
            our_ephemeral_private_key = ec.generate_private_key(ec.SECP384R1())
            our_ephemeral_public_key = our_ephemeral_private_key.public_key()
            
            # Export and sign
            our_ephemeral_public_key_pem = our_ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            our_signature = self.sign_data(our_ephemeral_public_key_pem)
            
            # Derive shared secret
            exchange_id = message["exchange_id"]
            symmetric_key = self.derive_shared_secret(our_ephemeral_private_key, peer_ephemeral_public_key)
            
            # Store the symmetric key (as responder, we're ready immediately)
            self.pending_exchanges[exchange_id] = {
                'symmetric_key': symmetric_key,
                'sender_id': sender_id
            }
            
            # Send response
            response = {
                "type": "key_exchange_response",
                "sender_id": self.client_id,
                "recipient_id": sender_id,
                "exchange_id": exchange_id,
                "ephemeral_public_key": base64.b64encode(our_ephemeral_public_key_pem).decode(),
                "signature": base64.b64encode(our_signature).decode()
            }
            
            await self.ws.send(json.dumps(response))
            print(f"[{self.client_id}] Sent key exchange response")
            
        except Exception as e:
            print(f"[{self.client_id}] Error in key exchange init: {e}")
    
    async def _handle_key_exchange_response(self, message: dict):
        """Handle key exchange response from peer"""
        try:
            exchange_id = message["exchange_id"]
            ephemeral_public_key_pem = base64.b64decode(message["ephemeral_public_key"])
            signature = base64.b64decode(message["signature"])
            
            if exchange_id not in self.pending_exchanges:
                print(f"[{self.client_id}] Unexpected exchange_id: {exchange_id}")
                return
            
            # Verify signature
            if not self.verify_signature(ephemeral_public_key_pem, signature, self.peer_identity_public_key):
                print(f"[{self.client_id}] ⚠️  Invalid signature on ephemeral key!")
                self.pending_exchanges[exchange_id]['error'] = "Invalid signature"
                self.pending_exchanges[exchange_id]['event'].set()
                return
            
            print(f"[{self.client_id}] Received key exchange response")
            
            # Load peer's ephemeral public key
            peer_ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_key_pem)
            
            # Get our ephemeral private key
            our_ephemeral_private_key = self.pending_exchanges[exchange_id]["private_key"]
            
            # Derive shared secret
            symmetric_key = self.derive_shared_secret(our_ephemeral_private_key, peer_ephemeral_public_key)
            
            # Store and signal completion
            self.pending_exchanges[exchange_id]["symmetric_key"] = symmetric_key
            self.pending_exchanges[exchange_id]["event"].set()
            
            print(f"[{self.client_id}] ✓ Key exchange complete")
            
        except Exception as e:
            print(f"[{self.client_id}] Error in key exchange response: {e}")
            if exchange_id in self.pending_exchanges:
                self.pending_exchanges[exchange_id]['error'] = str(e)
                self.pending_exchanges[exchange_id]['event'].set()
    
    async def _handle_encrypted_message(self, message: dict):
        """Decrypt and handle encrypted message"""
        try:
            exchange_id = message["exchange_id"]
            sender_id = message["sender_id"]
            ciphertext = base64.b64decode(message["ciphertext"])
            nonce = base64.b64decode(message["nonce"])
            
            if exchange_id not in self.pending_exchanges:
                print(f"[{self.client_id}] No key for exchange_id {exchange_id}")
                return
            
            exchange_data = self.pending_exchanges[exchange_id]
            
            # Ensure we have the symmetric key
            if 'symmetric_key' not in exchange_data:
                print(f"[{self.client_id}] Exchange not complete for {exchange_id}")
                return
            
            symmetric_key = exchange_data['symmetric_key']
            
            # Decrypt
            aesgcm = AESGCM(symmetric_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            decrypted_message = plaintext.decode('utf-8')
            
            print(f"[{self.client_id}] ✓ Received message: {decrypted_message}")
            
            if self.message_callback:
                self.message_callback(sender_id, decrypted_message)
            
            # Clean up (forward secrecy)
            del self.pending_exchanges[exchange_id]
            
        except Exception as e:
            print(f"[{self.client_id}] Decryption failed: {e}")
    
    async def send_message(self, recipient_id: str, plaintext: str, timeout: float = 10.0):
        """
        Send encrypted message with perfect forward secrecy.
        
        SECURITY PROPERTIES:
        - New ephemeral keys per message
        - Authenticated with identity key signatures
        - API key authentication at connection level
        """
        if not self.connected:
            raise Exception("Not connected to server")
        
        if not self.peer_identity_public_key:
            raise Exception("Peer identity key not set")
        
        # Validate input
        if not recipient_id or len(recipient_id) > 64:
            raise ValueError("Invalid recipient_id")
        
        if len(plaintext.encode('utf-8')) > self.max_message_size:
            raise ValueError(f"Message too large (max {self.max_message_size} bytes)")
        
        try:
            # Generate ephemeral keys
            ephemeral_private_key = ec.generate_private_key(ec.SECP384R1())
            print(f"ephemeral_private_key generated: {ephemeral_private_key}")
            ephemeral_public_key = ephemeral_private_key.public_key()
            print(f"ephemeral_public_key generated: {ephemeral_public_key}")
            
            # Export and sign
            ephemeral_public_key_pem = ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            signature = self.sign_data(ephemeral_public_key_pem)
            
            # Create exchange ID
            exchange_id = f"{self.client_id}-{recipient_id}-{os.urandom(8).hex()}"
            
            # Create event for synchronization
            event = asyncio.Event()
            
            # Store state
            self.pending_exchanges[exchange_id] = {
                "private_key": ephemeral_private_key,
                "plaintext": plaintext,
                "recipient_id": recipient_id,
                "event": event,
                "error": None
            }
            
            # Send key exchange initiation
            init_message = {
                "type": "key_exchange_init",
                "sender_id": self.client_id,
                "recipient_id": recipient_id,
                "exchange_id": exchange_id,
                "ephemeral_public_key": base64.b64encode(ephemeral_public_key_pem).decode(),
                "signature": base64.b64encode(signature).decode()
            }
            
            await self.ws.send(json.dumps(init_message))
            print(f"[{self.client_id}] Initiated key exchange")
            
            # Wait for key exchange completion with timeout
            try:
                await asyncio.wait_for(event.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                print(f"[{self.client_id}] Key exchange timeout")
                del self.pending_exchanges[exchange_id]
                raise Exception("Key exchange timeout")
            
            # Check for errors
            if self.pending_exchanges[exchange_id].get('error'):
                error = self.pending_exchanges[exchange_id]['error']
                del self.pending_exchanges[exchange_id]
                raise Exception(f"Key exchange failed: {error}")
            
            # Encrypt message
            symmetric_key = self.pending_exchanges[exchange_id]["symmetric_key"]
            aesgcm = AESGCM(symmetric_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
            
            # Send encrypted message
            encrypted_message = {
                "type": "encrypted_message",
                "sender_id": self.client_id,
                "recipient_id": recipient_id,
                "exchange_id": exchange_id,
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "nonce": base64.b64encode(nonce).decode()
            }
            
            await self.ws.send(json.dumps(encrypted_message))
            print(f"[{self.client_id}] ✓ Sent encrypted message")
            
            # Clean up (forward secrecy)
            del self.pending_exchanges[exchange_id]
            
        except Exception as e:
            # Clean up on error
            if exchange_id in self.pending_exchanges:
                del self.pending_exchanges[exchange_id]
            raise
    
    def set_message_callback(self, callback: Callable[[str, str], None]):
        """Set callback for received messages"""
        self.message_callback = callback
    
    async def disconnect(self):
        """Gracefully disconnect from server"""
        if self.ws:
            await self.ws.close()
            self.connected = False
            print(f"[{self.client_id}] Disconnected")


# Example usage
async def main():
    """
    Simple example for project demonstration
    """
    
    # Load configuration from environment variables
    ALICE_API_KEY = os.getenv("API_KEY_ALICE")
    BOB_API_KEY = os.getenv("API_KEY_BOB")
    SERVER_URL = os.getenv("SERVER_URL", "ws://localhost:8000")
    
    if not ALICE_API_KEY or not BOB_API_KEY:
        print("ERROR: API keys not set in environment variables")
        print("Set API_KEY_ALICE and API_KEY_BOB")
        return
    
    # Create clients
    client1 = E2EEClient(
        "alice", 
        api_key=ALICE_API_KEY,
        server_url=SERVER_URL
    )
    client2 = E2EEClient(
        "bob", 
        api_key=BOB_API_KEY,
        server_url=SERVER_URL
    )
    
    try:
        # Connect
        print("\n=== Connecting to server ===")
        await client1.connect()
        await client2.connect()
        
        # Exchange identity keys
        print("\n=== Exchanging identity keys ===")
        client1.set_peer_identity_key(client2.get_identity_public_key_bytes())
        client2.set_peer_identity_key(client1.get_identity_public_key_bytes())
        
        # Set callbacks
        def alice_received(sender, message):
            print(f"\n📨 Alice received from {sender}: '{message}'\n")
        
        def bob_received(sender, message):
            print(f"\n📨 Bob received from {sender}: '{message}'\n")
        
        client1.set_message_callback(alice_received)
        client2.set_message_callback(bob_received)
        
        await asyncio.sleep(1)
        
        # Send messages
        print("\n=== Sending encrypted messages ===")
        await client1.send_message("bob", "Hello Bob! This is end-to-end encrypted!")
        await asyncio.sleep(2)
        
        await client2.send_message("alice", "Hi Alice! Perfect forward secrecy enabled!")
        await asyncio.sleep(2)
        
        await client1.send_message("bob", "Each message has fresh ephemeral keys!")
        await asyncio.sleep(2)
        
        await client2.send_message("alice", "The server can't read our messages!")
        await asyncio.sleep(3)
        
        # Disconnect
        print("\n=== Disconnecting ===")
        await client1.disconnect()
        await client2.disconnect()
        
    except Exception as e:
        print(f"Error: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())