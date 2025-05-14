from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import argparse
import os

class HybridCipher:
    def __init__(self, rsa_key):
        self.rsa_key = rsa_key
        self.rsa_cipher = PKCS1_OAEP.new(rsa_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        # Step 1: Generate a random AES-256 key
        aes_key = get_random_bytes(32)
        aes_iv = get_random_bytes(16)

        # Step 2: Encrypt plaintext with AES
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        ciphertext = aes_cipher.encrypt(pad(plaintext, AES.block_size))

        # Step 3: Encrypt AES key with RSA public key
        encrypted_aes_key = self.rsa_cipher.encrypt(aes_key)

        # Step 4: Output format: [len(RSA encrypted key)][RSA key][IV][AES ciphertext]
        return len(encrypted_aes_key).to_bytes(2, 'big') + encrypted_aes_key + aes_iv + ciphertext

    def decrypt(self, hybrid_data: bytes) -> bytes:
        # Step 1: Parse RSA-encrypted AES key
        rsa_key_len = int.from_bytes(hybrid_data[:2], 'big')
        encrypted_aes_key = hybrid_data[2:2 + rsa_key_len]
        aes_iv = hybrid_data[2 + rsa_key_len:2 + rsa_key_len + 16]
        ciphertext = hybrid_data[2 + rsa_key_len + 16:]

        # Step 2: Decrypt AES key
        aes_key = self.rsa_cipher.decrypt(encrypted_aes_key)

        # Step 3: Decrypt data
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        return unpad(aes_cipher.decrypt(ciphertext), AES.block_size)

    @staticmethod
    def load_rsa_key(filepath: str):
        with open(filepath, 'rb') as f:
            return RSA.import_key(f.read())

# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hybrid Encryption: RSA + AES")
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], required=True)
    parser.add_argument('--keyfile', required=True, help='Use RSA public key for encrypt, private key for decrypt')
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)

    args = parser.parse_args()

    if not os.path.exists(args.keyfile):
        print("RSA key file not found.")
        exit(1)

    rsa_key = HybridCipher.load_rsa_key(args.keyfile)
    cipher = HybridCipher(rsa_key)

    with open(args.input, 'rb') as f:
        data = f.read()

    try:
        if args.mode == 'encrypt':
            result = cipher.encrypt(data)
        else:
            result = cipher.decrypt(data)
    except Exception as e:
        print("Encryption/Decryption failed:", e)
        exit(1)

    with open(args.output, 'wb') as f:
        f.write(result)

    print(f"{args.mode.capitalize()}ion using Hybrid RSA+AES completed. Output written to {args.output}")
