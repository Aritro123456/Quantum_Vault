from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_key(shared_secret, salt, authenticated_header):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b'QuantumVault/file-key/v1\x00' + authenticated_header).derive(shared_secret)
