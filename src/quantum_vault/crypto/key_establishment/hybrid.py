"""X-Wing draft-10 integration with strict rejection of low-order X25519 inputs.

Uses provider primitives; the stricter rejection is intentional and is encoded
in the QuantumVault suite name. This is not a claim of full X-Wing conformance.
"""
from dataclasses import dataclass
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

LABEL = bytes.fromhex('5c2e2f2f5e5c')


def combine(ss_m, ss_x, ct_x, pk_x):
    if any(len(value) != 32 for value in (ss_m, ss_x, ct_x, pk_x)):
        raise ValueError('Hybrid combiner requires four 32-byte inputs.')
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + LABEL).digest()


@dataclass(frozen=True)
class HybridPublicKey:
    mlkem: MLKEM768PublicKey
    x25519: X25519PublicKey

    def public_bytes_raw(self):
        return self.mlkem.public_bytes_raw() + self.x25519.public_bytes_raw()

    @classmethod
    def from_public_bytes(cls, data):
        if len(data) != 1216:
            raise ValueError('Hybrid public key must be 1216 bytes.')
        return cls(MLKEM768PublicKey.from_public_bytes(data[:1184]), X25519PublicKey.from_public_bytes(data[1184:]))

    def encapsulate(self):
        ephemeral = X25519PrivateKey.generate()
        ct_x = ephemeral.public_key().public_bytes_raw()
        ss_x = ephemeral.exchange(self.x25519)  # Provider rejects all-zero shared secrets.
        ss_m, ct_m = self.mlkem.encapsulate()
        return combine(ss_m, ss_x, ct_x, self.x25519.public_bytes_raw()), ct_m + ct_x


@dataclass(frozen=True)
class HybridPrivateKey:
    mlkem: MLKEM768PrivateKey
    x25519: X25519PrivateKey

    @classmethod
    def from_seed(cls, seed):
        if len(seed) != 32:
            raise ValueError('X-Wing seed must be 32 bytes.')
        expanded = hashlib.shake_256(seed).digest(96)
        return cls(MLKEM768PrivateKey.from_seed_bytes(expanded[:64]), X25519PrivateKey.from_private_bytes(expanded[64:]))

    @classmethod
    def generate(cls):
        return cls.from_seed(os.urandom(32))

    def public_key(self):
        return HybridPublicKey(self.mlkem.public_key(), self.x25519.public_key())

    def decapsulate(self, ciphertext):
        if len(ciphertext) != 1120:
            raise ValueError('Hybrid encapsulation must be 1120 bytes.')
        ct_m, ct_x = ciphertext[:1088], ciphertext[1088:]
        ss_m = self.mlkem.decapsulate(ct_m)
        ss_x = self.x25519.exchange(X25519PublicKey.from_public_bytes(ct_x))
        return combine(ss_m, ss_x, ct_x, self.x25519.public_key().public_bytes_raw())
