from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Optional
import json
import asyncio
import os
import time
from collections import defaultdict
import uvicorn
from dotenv import load_dotenv  

load_dotenv()  # Load environment variables from .env file



app = FastAPI()



# ============================================================================
# CORS CONFIGURATION
# ============================================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development - restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# SECURITY CONFIGURATION
# ============================================================================

def load_api_keys() -> Dict[str, str]:
    """Load API keys from environment variables"""
    keys = {}
    # Format: API_KEY_ALICE=secret123,API_KEY_BOB=secret456
    for key, value in os.environ.items():
        if key.startswith("API_KEY_"):
            client_id = key.replace("API_KEY_", "").lower()
            keys[client_id] = value
    
    if not keys:
        print("[WARNING] No API keys found in environment variables!")
        print("[WARNING] Set API_KEY_<CLIENT_ID>=<secret> environment variables")
    
    return keys

VALID_API_KEYS = load_api_keys()

def verify_api_key(client_id: str, api_key: str) -> bool:
    """Verify API key for a given client"""
    expected = VALID_API_KEYS.get(client_id)
    if not expected:
        return False
    # Constant-time comparison to prevent timing attacks
    return len(api_key) == len(expected) and sum(
        a != b for a, b in zip(api_key, expected)
    ) == 0

# ============================================================================
# RATE LIMITING
# ============================================================================

class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
    
    def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed under rate limit"""
        now = time.time()
        # Clean old requests
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if now - req_time < self.window_seconds
        ]
        
        if len(self.requests[client_id]) >= self.max_requests:
            return False
        
        self.requests[client_id].append(now)
        return True

# 100 requests per minute per client
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
# WebSocket message rate limiter (1000 messages per minute)
ws_rate_limiter = RateLimiter(max_requests=1000, window_seconds=60)

# ============================================================================
# CONFIGURATION LIMITS
# ============================================================================

MAX_MESSAGE_SIZE = int(os.getenv("MAX_MESSAGE_SIZE", 1024 * 100))  # 100KB default
MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", 1000))
WS_AUTH_TIMEOUT = int(os.getenv("WS_AUTH_TIMEOUT", 5))

# ============================================================================
# IN-MEMORY STORAGE (No disk persistence)
# ============================================================================

connections: Dict[str, WebSocket] = {}
identity_keys: Dict[str, str] = {}

# ============================================================================
# AUTHENTICATED ENDPOINTS
# ============================================================================

@app.post("/register")
async def register_client(
    client_id: str,
    public_key: str,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Register a client's long-term identity public key.
    Requires valid API key authentication.
    """
    # Rate limiting
    if not rate_limiter.is_allowed(client_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    # Input validation
    if not client_id or len(client_id) > 64:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    
    if not client_id.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(status_code=400, detail="client_id must be alphanumeric")
    
    if not public_key or len(public_key) > 2048:
        raise HTTPException(status_code=400, detail="Invalid public_key")
    
    if not verify_api_key(client_id, x_api_key):
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    identity_keys[client_id] = public_key
    return {"status": "registered", "client_id": client_id}

@app.get("/public-key/{client_id}")
async def get_public_key(
    client_id: str,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """Get a client's identity public key (requires authentication)"""
    # Rate limiting
    if not rate_limiter.is_allowed(client_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    # Verify the requester has a valid API key (any valid key can query)
    if x_api_key not in VALID_API_KEYS.values():
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if client_id not in identity_keys:
        raise HTTPException(status_code=404, detail="Client not found")
    
    return {"client_id": client_id, "public_key": identity_keys[client_id]}

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """
    WebSocket connection with API key authentication.
    
    Client must send authentication message immediately after connecting:
    {"type": "auth", "client_id": "alice", "api_key": "alice_secret_key..."}
    """
    # Check connection limit
    if len(connections) >= MAX_CONNECTIONS:
        await websocket.close(code=1008, reason="Server at capacity")
        return
    
    await websocket.accept()
    
    try:
        # Wait for authentication message with timeout
        auth_message = await asyncio.wait_for(
            websocket.receive_text(), 
            timeout=WS_AUTH_TIMEOUT
        )
        
        # Validate message size
        if len(auth_message) > 4096:
            await websocket.send_text(json.dumps({
                "type": "error",
                "error": "Authentication message too large"
            }))
            await websocket.close()
            return
        
        auth_data = json.loads(auth_message)
        
        # Verify authentication
        if auth_data.get("type") != "auth":
            await websocket.send_text(json.dumps({
                "type": "error",
                "error": "First message must be authentication"
            }))
            await websocket.close()
            return
        
        provided_api_key = auth_data.get("api_key", "")
        provided_client_id = auth_data.get("client_id", "")
        
        if provided_client_id != client_id or not verify_api_key(client_id, provided_api_key):
            await websocket.send_text(json.dumps({
                "type": "error",
                "error": "Authentication failed"
            }))
            await websocket.close()
            return
        
        # Authentication successful
        connections[client_id] = websocket
        await websocket.send_text(json.dumps({
            "type": "auth_success",
            "message": "Connected and authenticated"
        }))
        
        print(f"[SERVER] Client {client_id} authenticated and connected")
        
        # Main message relay loop
        while True:
            data = await websocket.receive_text()
            
            # Message size limit
            if len(data) > MAX_MESSAGE_SIZE:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "error": "Message too large"
                }))
                continue
            
            # Rate limiting for messages
            if not ws_rate_limiter.is_allowed(client_id):
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "error": "Message rate limit exceeded"
                }))
                continue
            
            try:
                message = json.loads(data)
                recipient_id = message.get("recipient_id")
                msg_type = message.get("type")
                
                # Validate recipient_id
                if not recipient_id or not isinstance(recipient_id, str):
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "error": "Invalid recipient_id"
                    }))
                    continue
                
                print(f"[SERVER] Relaying {msg_type} from {client_id} to {recipient_id}")
                
                # IMMEDIATE RELAY - no storage
                if recipient_id in connections:
                    await connections[recipient_id].send_text(data)
                else:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "error": "Recipient not connected - message dropped",
                        "recipient_id": recipient_id
                    }))
                    print(f"[SERVER] Message dropped - {recipient_id} not connected")
            
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "error": "Invalid JSON"
                }))
            except Exception as e:
                print(f"[SERVER] Error processing message: {type(e).__name__}")
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "error": "Internal server error"
                }))
    
    except asyncio.TimeoutError:
        print(f"[SERVER] Authentication timeout for {client_id}")
        await websocket.close()
    except WebSocketDisconnect:
        print(f"[SERVER] Client {client_id} disconnected")
        if client_id in connections:
            del connections[client_id]
    except Exception as e:
        print(f"[SERVER] Error for client {client_id}: {type(e).__name__}")
        if client_id in connections:
            del connections[client_id]

@app.get("/")
async def root():
    """Server status endpoint"""
    return {
        "message": "E2EE Messaging Server - School Project",
        "connected_clients": len(connections),
        "security_features": [
            "API key authentication",
            "Rate limiting",
            "Message size limits",
            "Connection limits",
            "RAM-only message relay",
            "No disk persistence"
        ]
    }

@app.get("/health")
async def health():
    """Health check endpoint (no auth required)"""
    return {
        "status": "healthy", 
        "connected_clients": len(connections),
        "max_connections": MAX_CONNECTIONS
    }


if __name__ == "__main__":
    if not VALID_API_KEYS:
        print("[ERROR] No API keys configured!")
        print("[ERROR] Set environment variables: API_KEY_<CLIENT_ID>=<secret>")
        print("[ERROR] Example: export API_KEY_ALICE=your_secure_random_key")
        exit(1)
    
    print(f"[SERVER] Starting E2EE Messaging Server")
    print(f"[SERVER] Connected clients will be relayed messages in real-time")
    print(f"[SERVER] No persistence - messages exist only in RAM")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )