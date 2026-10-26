"""Context-separated ML-DSA-65 signatures using the pinned provider."""
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey
from quantum_vault.keys.manager import load_private

CONTEXT = b'QuantumVault/envelope-signature/v1'


def generate_signing_key():
    return MLDSA65PrivateKey.generate()


def load_signing_private(data, password):
    return load_private(data, password, expected_type=MLDSA65PrivateKey)


def load_signing_public(data):
    return MLDSA65PublicKey.from_public_bytes(data)


def sign(private_key, message):
    return private_key.sign(message, CONTEXT)


def verify(public_key, signature, message):
    public_key.verify(signature, message, CONTEXT)
