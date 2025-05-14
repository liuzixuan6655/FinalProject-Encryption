from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import argparse
import os

class ChaCha20Cipher:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for ChaCha20.")
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = get_random_bytes(8)  # 64-bit nonce
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)
        return nonce + ciphertext  # Prepend nonce

    def decrypt(self, nonce_and_ciphertext: bytes) -> bytes:
        nonce = nonce_and_ciphertext[:8]
        ciphertext = nonce_and_ciphertext[8:]
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        return cipher.decrypt(ciphertext)

    @staticmethod
    def generate_key() -> bytes:
        return get_random_bytes(32)

    @staticmethod
    def save_key(key: bytes, filepath: str):
        with open(filepath, 'wb') as f:
            f.write(key)

    @staticmethod
    def load_key(filepath: str) -> bytes:
        with open(filepath, 'rb') as f:
            return f.read()

# --------------------------------------


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ChaCha20 CLI Encryption Tool")
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], required=True, help='encrypt or decrypt')
    parser.add_argument('--keyfile', required=True, help='Path to key file')
    parser.add_argument('--input', required=True, help='Path to input file')
    parser.add_argument('--output', required=True, help='Path to output file')

    args = parser.parse_args()

    if not os.path.exists(args.keyfile):
        print("Key file not found.")
        exit(1)

    key = ChaCha20Cipher.load_key(args.keyfile)

    cipher = ChaCha20Cipher(key)

    with open(args.input, 'rb') as f:
        data = f.read()

    try:
        if args.mode == 'encrypt':
            result = cipher.encrypt(data)
        else:
            result = cipher.decrypt(data)
    except Exception as e:
        print("Error during operation:", e)
        exit(1)

    with open(args.output, 'wb') as f:
        f.write(result)

    print(f"{args.mode.capitalize()}ion completed using ChaCha20. Output written to {args.output}")
