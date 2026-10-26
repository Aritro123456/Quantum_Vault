"""Mode-specific operations with type checks at the application boundary."""
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from quantum_vault.crypto.key_establishment.hybrid import HybridPrivateKey, HybridPublicKey
from quantum_vault.crypto.key_establishment.suites import suite_for

PRIVATE_TYPES = {'postquantum': MLKEM768PrivateKey, 'classical': X25519PrivateKey, 'hybrid': HybridPrivateKey}
PUBLIC_TYPES = {'postquantum': MLKEM768PublicKey, 'classical': X25519PublicKey, 'hybrid': HybridPublicKey}


def generate_encryption_key(mode='postquantum'):
    suite_for(mode)
    return PRIVATE_TYPES[mode].generate()


def encapsulate(public_key, mode):
    suite_for(mode)
    if not isinstance(public_key, PUBLIC_TYPES[mode]):
        raise ValueError('Public key does not match selected mode.')
    if mode == 'classical':
        ephemeral = X25519PrivateKey.generate()
        return ephemeral.exchange(public_key), ephemeral.public_key().public_bytes_raw()
    return public_key.encapsulate()


def decapsulate(private_key, ciphertext, mode):
    suite_for(mode)
    if not isinstance(private_key, PRIVATE_TYPES[mode]):
        raise ValueError('Private key does not match selected mode.')
    if mode == 'classical':
        return private_key.exchange(X25519PublicKey.from_public_bytes(ciphertext))
    return private_key.decapsulate(ciphertext)
