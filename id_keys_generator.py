from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def get_pem_strings():
    # Alice
    a_priv = ec.generate_private_key(ec.SECP384R1())
    a_pub_bytes = a_priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    a_priv_bytes = a_priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    
    # Bob
    b_priv = ec.generate_private_key(ec.SECP384R1())
    b_pub_bytes = b_priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    b_priv_bytes = b_priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    print("--- PASTE THIS INTO ALICE.PY ---")
    print(f"ALICE_PRIV = {a_priv_bytes}")
    print(f"BOB_PUB = {b_pub_bytes}")
    print("\n--- PASTE THIS INTO BOB.PY ---")
    print(f"BOB_PRIV = {b_priv_bytes}")
    print(f"ALICE_PUB = {a_pub_bytes}")

get_pem_strings()