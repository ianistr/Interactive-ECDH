import asyncio
import os
from client import E2EEClient
from dotenv import load_dotenv

load_dotenv()

# Alice's own PRIVATE key for identity (keep this secret, i have exposed here for demo)
ALICE_PRIV = b'-----BEGIN PRIVATE KEY-----\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBbv7z6e0e/pTQdP4Gz\nMSs2nzgHyK6eB5Ik+HKFobE0x/BVotq+mqDm6OWQKvWsGqmhZANiAASGSpVSjAGW\nbY9+LECg41UktJzp4HDgIpvvO3zT2C/BbFXvrbS5k/pSdJzUybTD6p/8jrCfDzAl\nGF0Xcc+RPZ/3KxxSU+lccz5J0cagG1RfcQnAq8H9Uc2q2ok/Iu6SM4o=\n-----END PRIVATE KEY-----\n'

# Bob's PUBLIC key (Alice trusts this key only)
BOB_PUB = b'-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE/0/BiCqHaADYkqQBDGzX5WsVTSlTzj9r\nAtRlEpettZlsnt4RZCTKXrp2G55P3vhV8e5oiQViDwtonoVqs4QWjhjaCK1lpGwd\nf15r3KOBQCgHItoodCH/GacUQUAfF/JT\n-----END PUBLIC KEY-----\n'

async def main():
    client = E2EEClient("alice", os.getenv("API_KEY_ALICE"), ALICE_PRIV)
    client.set_peer_identity_key(BOB_PUB)
    await client.connect()
    print("\n[✓] Alice online. Type your message:")

    client.set_message_callback(lambda s, t: print(f"\n[Bob]: {t}\nAlice > ", end=""))

    while True:
        msg = await asyncio.to_thread(input, "Alice > ")
        await client.send_message("bob", msg)

if __name__ == "__main__": asyncio.run(main())