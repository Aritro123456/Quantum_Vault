import base64
import json
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from quantum_vault.crypto.key_establishment.hybrid import HybridPrivateKey, HybridPublicKey
from quantum_vault.crypto.key_establishment.operations import generate_encryption_key, encapsulate, decapsulate
from quantum_vault.crypto.key_establishment.suites import SUITES
from quantum_vault.keys.encryption import serialize_encryption_private, load_encryption_private, load_encryption_public
from quantum_vault.keys.manager import key_id
from quantum_vault.services.files import encrypt_bytes, decrypt_bytes, DecryptionError
from quantum_vault.envelope.format import canonical


class ModeTests(unittest.TestCase):
    def test_published_xwing_vectors_keygen_and_decapsulation(self):
        fixture = Path(__file__).parents[1] / 'fixtures' / 'xwing_draft10_vectors.json'
        vectors = json.loads(fixture.read_text())['vectors']
        self.assertEqual(len(vectors), 3)
        for vector in vectors:
            key = HybridPrivateKey.from_seed(bytes.fromhex(vector['seed']))
            self.assertEqual(key.public_key().public_bytes_raw().hex(), vector['pk'])
            self.assertEqual(key.decapsulate(bytes.fromhex(vector['ct'])).hex(), vector['ss'])

    def test_shared_secret_and_file_roundtrip_all_modes(self):
        for mode in SUITES:
            with self.subTest(mode=mode):
                key = generate_encryption_key(mode)
                secret, ciphertext = encapsulate(key.public_key(), mode)
                self.assertEqual(secret, decapsulate(key, ciphertext, mode))
                for payload in (b'', bytes(range(256))):
                    encrypted = encrypt_bytes(payload, key.public_key(), mode)
                    self.assertEqual(decrypt_bytes(encrypted, key, mode), payload)
                    self.assertEqual(json.loads(encrypted)['header']['suite'], SUITES[mode])

    def test_encrypted_key_persistence_all_modes(self):
        password = b'test-password-for-modes'
        for mode in SUITES:
            with self.subTest(mode=mode):
                key = generate_encryption_key(mode)
                blob = serialize_encryption_private(key, password, mode)
                restored = load_encryption_private(blob, password, mode)
                public = load_encryption_public(key.public_key().public_bytes_raw(), mode)
                self.assertEqual(key_id(public), key_id(restored.public_key()))
                self.assertEqual(decrypt_bytes(encrypt_bytes(b'sample', public, mode), restored, mode), b'sample')
                with self.assertRaises(ValueError):
                    load_encryption_private(blob, b'wrong-password', mode)

    def test_cross_mode_keys_and_envelopes_rejected(self):
        keys = {mode: generate_encryption_key(mode) for mode in SUITES}
        for original, key in keys.items():
            envelope = encrypt_bytes(b'sample', key.public_key(), original)
            for requested in SUITES:
                if requested == original:
                    continue
                with self.subTest(original=original, requested=requested):
                    with self.assertRaises(ValueError):
                        encrypt_bytes(b'sample', key.public_key(), requested)
                    with self.assertRaises(DecryptionError):
                        decrypt_bytes(envelope, key, requested)
                    with self.assertRaises(DecryptionError):
                        decrypt_bytes(envelope, keys[requested], requested)

    def test_hybrid_both_ciphertext_components_are_required(self):
        key = generate_encryption_key('hybrid')
        original = encrypt_bytes(b'message', key.public_key(), 'hybrid')
        for offset in (0, 1088):
            value = json.loads(original)
            raw = bytearray(base64.b64decode(value['header']['kem_ciphertext']))
            raw[offset] ^= 1
            value['header']['kem_ciphertext'] = base64.b64encode(raw).decode()
            with self.assertRaises(DecryptionError):
                decrypt_bytes(canonical(value), key, 'hybrid')
        value = json.loads(original)
        value['header']['suite'] = SUITES['postquantum']
        raw = base64.b64decode(value['header']['kem_ciphertext'])[:1088]
        value['header']['kem_ciphertext'] = base64.b64encode(raw).decode()
        value['header']['recipient'] = key_id(key.mlkem.public_key())
        with self.assertRaises(DecryptionError):
            decrypt_bytes(canonical(value), key.mlkem, 'postquantum')

    def test_hybrid_wrong_component_keys_fail(self):
        first, second = generate_encryption_key('hybrid'), generate_encryption_key('hybrid')
        envelope = encrypt_bytes(b'message', first.public_key(), 'hybrid')
        for mixed in (HybridPrivateKey(first.mlkem, second.x25519), HybridPrivateKey(second.mlkem, first.x25519)):
            value = json.loads(envelope)
            value['header']['recipient'] = key_id(mixed.public_key())
            with self.assertRaises(DecryptionError):
                decrypt_bytes(canonical(value), mixed, 'hybrid')

    def test_low_order_x25519_rejection(self):
        for mode in ('classical', 'hybrid'):
            key = generate_encryption_key(mode)
            public = X25519PublicKey.from_public_bytes(bytes(32))
            if mode == 'hybrid':
                public = HybridPublicKey(key.mlkem.public_key(), public)
            with self.assertRaises(ValueError):
                encapsulate(public, mode)
            envelope = json.loads(encrypt_bytes(b'message', key.public_key(), mode))
            ct = base64.b64decode(envelope['header']['kem_ciphertext'])
            envelope['header']['kem_ciphertext'] = base64.b64encode(ct[:-32] + bytes(32)).decode()
            with self.assertRaises(DecryptionError):
                decrypt_bytes(canonical(envelope), key, mode)

    def test_hybrid_key_format_and_bounds(self):
        key = generate_encryption_key('hybrid')
        password = b'test-only-password-2026'
        blob = serialize_encryption_private(key, password, 'hybrid')
        values = [b'{}', b'[]', b'x'*16385, b'null']
        value = json.loads(blob)
        value['version'] = True
        values.append(canonical(value))
        for data in values:
            with self.assertRaises(ValueError):
                load_encryption_private(data, password, 'hybrid')
        for mode in ('classical', 'postquantum'):
            with self.assertRaises(ValueError):
                load_encryption_private(blob, password, mode)
        for size in (0, 31, 1215, 1217):
            with self.assertRaises(ValueError):
                load_encryption_public(bytes(size), 'hybrid')
