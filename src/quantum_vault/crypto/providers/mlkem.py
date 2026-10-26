"""ML-KEM-768 operations delegated to PyCA cryptography/OpenSSL."""
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey


def generate_key():
    return MLKEM768PrivateKey.generate()


def encapsulate(public_key):
    return public_key.encapsulate()  # (shared secret, encapsulation ciphertext)


def decapsulate(private_key, ciphertext):
    return private_key.decapsulate(ciphertext)
