"""Password-encrypted PKCS8 private keys; raw ML-KEM public keys."""
import hashlib
from cryptography.hazmat.primitives import serialization
from quantum_vault.crypto.providers.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey


def key_id(public_key):
    return hashlib.sha256(public_key.public_bytes_raw()).hexdigest()


def serialize_private(private_key, password):
    if not isinstance(password, bytes) or len(password) < 12:
        raise ValueError('Use a private-key password of at least 12 UTF-8 bytes.')
    return private_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password))


def load_private(data, password, expected_type=MLKEM768PrivateKey):
    if not password or not data.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'):
        raise ValueError('A password-encrypted PKCS8 private key is required.')
    key = serialization.load_pem_private_key(data, password)
    if not isinstance(key, expected_type):
        raise ValueError(f'Expected {expected_type.__name__}.')
    return key


def load_public(data):
    return MLKEM768PublicKey.from_public_bytes(data)
