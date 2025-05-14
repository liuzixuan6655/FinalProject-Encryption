from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
import os
import argparse

class ECCCipher:
    def __init__(self, private_key=None, public_key=None):
        self.private_key = private_key
        self.public_key = public_key

    def encrypt(self, plaintext: bytes) -> bytes:
        # Generate ephemeral key
        ephemeral_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        shared_key = ephemeral_key.exchange(ec.ECDH(), self.public_key)

        # Derive AES key from shared secret
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecc-ecdh',
            backend=default_backend()
        ).derive(shared_key)

        # AES-GCM encryption
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Serialize ephemeral public key
        ephemeral_public_bytes = ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        return ephemeral_public_bytes + iv + encryptor.tag + ciphertext

    def decrypt(self, encrypted: bytes) -> bytes:
        ephemeral_public_bytes = encrypted[:65]  # 65 bytes for SECP256R1 uncompressed point
        iv = encrypted[65:77]
        tag = encrypted[77:93]
        ciphertext = encrypted[93:]

        # Load ephemeral public key
        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_public_bytes
        )

        shared_key = self.private_key.exchange(ec.ECDH(), ephemeral_public_key)

        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecc-ecdh',
            backend=default_backend()
        ).derive(shared_key)

        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        return decryptor.update(ciphertext) + decryptor.finalize()

    @staticmethod
    def generate_key_pair():
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        return private_key, private_key.public_key()

    @staticmethod
    def save_private_key(private_key, path):
        with open(path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    @staticmethod
    def save_public_key(public_key, path):
        with open(path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    @staticmethod
    def load_private_key(path):
        with open(path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    @staticmethod
    def load_public_key(path):
        with open(path, 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())
# -----------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ECC ECIES-style Encryption Tool")
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], required=True)
    parser.add_argument('--keyfile', required=True, help='Private key for decryption / public key for encryption')
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)

    args = parser.parse_args()

    try:
        if args.mode == 'encrypt':
            pub_key = ECCCipher.load_public_key(args.keyfile)
            cipher = ECCCipher(public_key=pub_key)
        else:
            priv_key = ECCCipher.load_private_key(args.keyfile)
            cipher = ECCCipher(private_key=priv_key)

        with open(args.input, 'rb') as f:
            data = f.read()

        result = cipher.encrypt(data) if args.mode == 'encrypt' else cipher.decrypt(data)

        with open(args.output, 'wb') as f:
            f.write(result)

        print(f"{args.mode.capitalize()}ion using ECC completed. Output written to {args.output}")

    except Exception as e:
        print("Error:", e)
