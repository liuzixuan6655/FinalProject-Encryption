from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import argparse
import os

class BlowfishCipher:
    def __init__(self, key: bytes):
        if len(key) < 4 or len(key) > 56:
            raise ValueError("Blowfish key must be between 4 and 56 bytes.")
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = get_random_bytes(8)  # Blowfish uses 64-bit (8-byte) block/IV
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
        padded_data = pad(plaintext, Blowfish.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return iv + ciphertext

    def decrypt(self, iv_and_ciphertext: bytes) -> bytes:
        iv = iv_and_ciphertext[:8]
        ciphertext = iv_and_ciphertext[8:]
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)
        return unpad(padded_data, Blowfish.block_size)

    @staticmethod
    def generate_key(length=16) -> bytes:
        if length < 4 or length > 56:
            raise ValueError("Blowfish key length must be between 4 and 56 bytes.")
        return get_random_bytes(length)

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
    parser = argparse.ArgumentParser(description="Blowfish CLI Encryption Tool")
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], required=True)
    parser.add_argument('--keyfile', required=True)
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)

    args = parser.parse_args()

    if not os.path.exists(args.keyfile):
        print("Key file not found.")
        exit(1)

    key = BlowfishCipher.load_key(args.keyfile)
    try:
        cipher = BlowfishCipher(key)
    except ValueError as e:
        print(e)
        exit(1)

    with open(args.input, 'rb') as f:
        data = f.read()

    try:
        if args.mode == 'encrypt':
            result = cipher.encrypt(data)
        else:
            result = cipher.decrypt(data)
    except Exception as e:
        print("Error during encryption/decryption:", e)
        exit(1)

    with open(args.output, 'wb') as f:
        f.write(result)

    print(f"{args.mode.capitalize()}ion completed using Blowfish. Output written to {args.output}")
