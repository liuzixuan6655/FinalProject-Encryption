import time
import os
import psutil
import argparse
import statistics

from aes_cipher import AESCipher
from chacha20_cipher import ChaCha20Cipher
from blowfish_cipher import BlowfishCipher
from rsa_cipher import RSACipher
from hybrid_cipher import HybridCipher
from ecc_cipher import ECCCipher

REPEAT = 3  # Number of times each test is repeated

def measure(func, *args):
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss
    cpu_before = process.cpu_percent(interval=None)

    start = time.time()
    result = func(*args)
    elapsed = time.time() - start

    cpu_after = process.cpu_percent(interval=None)
    mem_after = process.memory_info().rss

    mem_used = (mem_after - mem_before) / 1024 / 1024  # in MB
    cpu_used = cpu_after - cpu_before

    return elapsed, mem_used, cpu_used, result

def test_algorithm(name, cipher_obj, data, mode='encrypt'):
    print(f"\nTesting {name.upper()} - {mode}")
    times = []
    mems = []
    cpus = []

    for i in range(REPEAT):
        elapsed, mem_used, cpu_used, _ = measure(
            cipher_obj.encrypt if mode == 'encrypt' else cipher_obj.decrypt,
            data
        )
        times.append(elapsed)
        mems.append(mem_used)
        cpus.append(cpu_used)

    print(f"Avg Time: {statistics.mean(times):.4f}s")
    print(f"Avg Memory: {statistics.mean(mems):.2f} MB")
    print(f"Avg CPU: {statistics.mean(cpus):.2f}%")

def load_plaintext(size='small'):
    if size == 'large':
        return os.urandom(100 * 1024 * 1024)  # 100MB random bytes
    return b"This is a short test message for encryption."

def run_tests(size='small'):
    data = load_plaintext(size)

    # AES
    key = AESCipher.generate_key()
    aes = AESCipher(key)
    encrypted = aes.encrypt(data)
    test_algorithm("AES", aes, data, mode='encrypt')
    test_algorithm("AES", aes, encrypted, mode='decrypt')

    # ChaCha20
    key = ChaCha20Cipher.generate_key()
    chacha = ChaCha20Cipher(key)
    encrypted = chacha.encrypt(data)
    test_algorithm("ChaCha20", chacha, data, mode='encrypt')
    test_algorithm("ChaCha20", chacha, encrypted, mode='decrypt')

    # Blowfish
    key = BlowfishCipher.generate_key(16)
    blow = BlowfishCipher(key)
    encrypted = blow.encrypt(data)
    test_algorithm("Blowfish", blow, data, mode='encrypt')
    test_algorithm("Blowfish", blow, encrypted, mode='decrypt')

    # RSA
    rsa_priv = RSACipher.generate_keypair()
    rsa_pub = rsa_priv.public_key()
    rsa_e = RSACipher(rsa_pub)
    rsa_d = RSACipher(rsa_priv)

    rsa_data = data if len(data) < 190 else data[:190]  # PKCS1_OAEP max limit ~190 bytes for 2048-bit key
    encrypted = rsa_e.encrypt(rsa_data)
    test_algorithm("RSA", rsa_e, rsa_data, mode='encrypt')
    test_algorithm("RSA", rsa_d, encrypted, mode='decrypt')

    # ECC
    ecc_priv, ecc_pub = ECCCipher.generate_key_pair()
    ecc_enc = ECCCipher(public_key=ecc_pub)
    ecc_dec = ECCCipher(private_key=ecc_priv)
    ecc_data = data[:512]  # ECC not suitable for large direct encryption
    encrypted = ecc_enc.encrypt(ecc_data)
    test_algorithm("ECC", ecc_enc, ecc_data, "encrypt")
    test_algorithm("ECC", ecc_dec, encrypted, "decrypt")
   
    # Hybrid
    hybrid_pub = HybridCipher(rsa_pub)
    hybrid_priv = HybridCipher(rsa_priv)
    encrypted = hybrid_pub.encrypt(data)
    test_algorithm("Hybrid", hybrid_pub, data, mode='encrypt')
    test_algorithm("Hybrid", hybrid_priv, encrypted, mode='decrypt')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encryption Algorithm Performance Tester")
    parser.add_argument('--size', choices=['small', 'large'], default='small', help='Test with short or 100MB input')
    args = parser.parse_args()

    run_tests(args.size)
