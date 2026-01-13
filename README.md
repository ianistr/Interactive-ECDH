# Interactive End-to-End Encrypted (E2EE) Chat

A Python-based messaging system implementing a **Three-Step Cryptographic Handshake** to ensure total privacy. This project demonstrates modern encryption standards including Elliptic Curve Diffie-Hellman (ECDH), Digital Signatures (ECDSA), and Authenticated Encryption (AES-GCM).

## 🛡️ Security Features

* **Perfect Forward Secrecy (PFS):** Every message generates a new ephemeral session key. Even if a future key is compromised, past messages remain unreadable.
* **Identity Pinning:** Alice and Bob verify each other's identity via static Public Key infrastructure, making Man-in-the-Middle (MitM) attacks mathematically impossible.
* **Military-Grade Curves:** Utilizes the **NIST P-384** curve (secp384r1), part of the NSA Suite B for Top Secret data.
* **Authenticated Encryption:** Uses **AES-32-GCM** to ensure that messages cannot be read *or* tampered with while in transit.
* **Stateless Relay:** The server acts as a "blind postman." It only relays ciphertext and never sees the decryption keys.

---

## 🏗️ The Protocol Flow

1.  **Handshake Init:** Alice generates an ephemeral EC key, signs it with her Identity Key, and sends it to Bob.
2.  **Handshake Response:** Bob verifies Alice's signature, generates his own ephemeral key, signs it, and sends it back.
3.  **Secret Derivation:** Both parties compute the shared secret locally using ECDH.
4.  **Encrypted Data:** Alice encrypts the message using the derived key and sends the "briefcase" (ciphertext + nonce).



---

## 🚀 Getting Started Locally

1.Clone the repository on your local machine
2.Create a python Virtual Environment and activate it
3.Install requirements.txt with "pip install -r requirements.txt"
4.Open a terminal, navigate to the project and run "uvicorn server:app"
5.Open 2 more terminals and run "python alice.py" and "python bob.py" in each of them
6.Open the Server Web Page and navigate to /monitor and you will see the encrypted text   --!!! Do not use in production



