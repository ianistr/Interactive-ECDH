import asyncio
import os
from client import E2EEClient
from dotenv import load_dotenv

load_dotenv()

# Bob's own PRIVATE key (keep this secret, i have exposed here for demo)
BOB_PRIV = b'-----BEGIN PRIVATE KEY-----\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAYk3H6M99En6ECLp9i\nXzDVWObh5TbIpGs8//7dmROBXd9KTO+QqrmJmTz0UEjymlOhZANiAAT/T8GIKodo\nANiSpAEMbNflaxVNKVPOP2sC1GUSl621mWye3hFkJMpeunYbnk/e+FXx7miJBWIP\nC2iehWqzhBaOGNoIrWWkbB1/Xmvco4FAKAci2ih0If8ZpxRBQB8X8lM=\n-----END PRIVATE KEY-----\n'

# Alice's PUBLIC key (Bob trusts this key only)
ALICE_PUB = b'-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhkqVUowBlm2PfixAoONVJLSc6eBw4CKb\n7zt809gvwWxV7620uZP6UnSc1Mm0w+qf/I6wnw8wJRhdF3HPkT2f9yscUlPpXHM+\nSdHGoBtUX3EJwKvB/VHNqtqJPyLukjOK\n-----END PUBLIC KEY-----\n'

async def main():
    client = E2EEClient("bob", os.getenv("API_KEY_BOB"), BOB_PRIV)
    client.set_peer_identity_key(ALICE_PUB)
    await client.connect()
    print("\n[✓] Bob online. Type your message:")

    client.set_message_callback(lambda s, t: print(f"\n[Alice]: {t}\nBob > ", end=""))

    while True:
        msg = await asyncio.to_thread(input, "Bob > ")
        await client.send_message("alice", msg)

if __name__ == "__main__": asyncio.run(main())