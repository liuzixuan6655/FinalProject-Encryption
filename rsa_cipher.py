from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import argparse
import os

class RSACipher:
    def __init__(self, key: RSA.RsaKey):
        self.key = key
        self.is_public = key.has_private() is False

    def encrypt(self, plaintext: bytes) -> bytes:
        cipher = PKCS1_OAEP.new(self.key)
        return cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not self.key.has_private():
            raise ValueError("Private key required for decryption.")
        cipher = PKCS1_OAEP.new(self.key)
        return cipher.decrypt(ciphertext)

    def sign(self, message: bytes) -> bytes:
        if not self.key.has_private():
            raise ValueError("Private key required for signing.")
        h = SHA256.new(message)
        return pkcs1_15.new(self.key).sign(h)

    def verify(self, message: bytes, signature: bytes) -> bool:
        h = SHA256.new(message)
        try:
            pkcs1_15.new(self.key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def generate_keypair(bits=2048):
        return RSA.generate(bits)

    @staticmethod
    def save_key(key: RSA.RsaKey, filepath: str):
        with open(filepath, 'wb') as f:
            f.write(key.export_key())

    @staticmethod
    def load_key(filepath: str) -> RSA.RsaKey:
        with open(filepath, 'rb') as f:
            return RSA.import_key(f.read())

# --------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RSA CLI Encryption Tool")
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], required=True)
    parser.add_argument('--keyfile', required=True)
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)

    args = parser.parse_args()

    if not os.path.exists(args.keyfile):
        print("Key file not found.")
        exit(1)

    key = RSACipher.load_key(args.keyfile)
    cipher = RSACipher(key)

    with open(args.input, 'rb') as f:
        data = f.read()

    try:
        if args.mode == 'encrypt':
            result = cipher.encrypt(data)
        else:
            result = cipher.decrypt(data)
    except Exception as e:
        print("Error:", e)
        exit(1)

    with open(args.output, 'wb') as f:
        f.write(result)

    print(f"{args.mode.capitalize()}ion using RSA completed. Output written to {args.output}")
