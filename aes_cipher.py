from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os
import argparse

class AESCipher:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256.")
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = get_random_bytes(16)  # CBC mode requires a 16-byte IV
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return iv + ciphertext  # Prepend IV to ciphertext for decryption

    def decrypt(self, iv_and_ciphertext: bytes) -> bytes:
        iv = iv_and_ciphertext[:16]
        ciphertext = iv_and_ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)
        return unpad(padded_data, AES.block_size)

    @staticmethod
    def generate_key() -> bytes:
        return get_random_bytes(32)  # Generate a 256-bit AES key

    @staticmethod
    def save_key(key: bytes, filepath: str):
        with open(filepath, 'wb') as f:
            f.write(key)

    @staticmethod
    def load_key(filepath: str) -> bytes:
        with open(filepath, 'rb') as f:
            return f.read()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone AES-256 CLI")
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], required=True)
    parser.add_argument('--keyfile', required=True)
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()

    key = AESCipher.load_key(args.keyfile)
    cipher = AESCipher(key)

    with open(args.input, 'rb') as f:
        data = f.read()

    if args.mode == 'encrypt':
        result = cipher.encrypt(data)
    else:
        result = cipher.decrypt(data)

    with open(args.output, 'wb') as f:
        f.write(result)

    print(f"{args.mode.capitalize()}ion complete.")
