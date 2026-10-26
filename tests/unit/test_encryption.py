import base64
import json
import os
import unittest
from quantum_vault.crypto.providers.mlkem import generate_key
from quantum_vault.keys.manager import serialize_private, load_private, load_public, key_id
from quantum_vault.services.files import encrypt_bytes, decrypt_bytes, DecryptionError
from quantum_vault.envelope.format import canonical, MAX_PLAINTEXT


class EncryptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = generate_key()
        cls.password = b'test-only-password-2026'

    def test_kem_shared_secret(self):
        secret, ciphertext = self.key.public_key().encapsulate()
        self.assertEqual(len(secret), 32)
        self.assertEqual(len(ciphertext), 1088)
        self.assertEqual(self.key.decapsulate(ciphertext), secret)

    def test_round_trip_empty_unicode_binary_and_large(self):
        for payload in (b'', 'QuantumVault: \u03bb'.encode(), bytes(range(256)), os.urandom(1024*1024)):
            with self.subTest(size=len(payload)):
                self.assertEqual(decrypt_bytes(encrypt_bytes(payload, self.key.public_key()), self.key), payload)

    def test_fresh_encapsulation_and_nonce(self):
        a = json.loads(encrypt_bytes(b'message', self.key.public_key()))
        b = json.loads(encrypt_bytes(b'message', self.key.public_key()))
        for field in ('nonce', 'salt', 'kem_ciphertext'):
            self.assertNotEqual(a['header'][field], b['header'][field])
        self.assertNotEqual(a['ciphertext'], b['ciphertext'])

    def test_ciphertext_and_every_header_field_tampering(self):
        original = encrypt_bytes(b'message', self.key.public_key())
        for field in ('kem_ciphertext', 'salt', 'nonce', 'recipient', 'suite', 'version', 'magic'):
            envelope = json.loads(original)
            if field in ('kem_ciphertext', 'salt', 'nonce'):
                value = bytearray(base64.b64decode(envelope['header'][field]))
                value[0] ^= 1
                envelope['header'][field] = base64.b64encode(value).decode()
            elif field == 'recipient':
                envelope['header'][field] = '0' * 64
            elif field == 'version':
                envelope['header'][field] = 2
            else:
                envelope['header'][field] = 'modified'
            with self.subTest(field=field), self.assertRaises(DecryptionError):
                decrypt_bytes(canonical(envelope), self.key)
        envelope = json.loads(original)
        value = bytearray(base64.b64decode(envelope['ciphertext']))
        value[-1] ^= 1
        envelope['ciphertext'] = base64.b64encode(value).decode()
        with self.assertRaises(DecryptionError):
            decrypt_bytes(canonical(envelope), self.key)

    def test_wrong_key_and_recipient_rewrite(self):
        other = generate_key()
        envelope = encrypt_bytes(b'message', self.key.public_key())
        with self.assertRaises(DecryptionError):
            decrypt_bytes(envelope, other)
        value = json.loads(envelope)
        value['header']['recipient'] = key_id(other.public_key())
        with self.assertRaises(DecryptionError):
            decrypt_bytes(canonical(value), other)

    def test_malformed_truncated_and_extra_fields(self):
        valid = encrypt_bytes(b'message', self.key.public_key())
        inputs = [b'', b'{}', b'[]', b'null', b'\xff', valid[:-5], b'{"header":{},"header":{},"ciphertext":""}']
        value = json.loads(valid)
        value['extra'] = True
        inputs.append(canonical(value))
        value = json.loads(valid)
        value['header']['version'] = True
        inputs.append(canonical(value))
        value = json.loads(valid)
        value['header']['nonce'] = 'not base64'
        inputs.append(canonical(value))
        for data in inputs:
            with self.subTest(data=data[:30]), self.assertRaises(DecryptionError):
                decrypt_bytes(data, self.key)

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            encrypt_bytes(b'x' * (MAX_PLAINTEXT + 1), self.key.public_key())

    def test_encrypted_private_key_roundtrip(self):
        encrypted = serialize_private(self.key, self.password)
        self.assertTrue(encrypted.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'))
        restored = load_private(encrypted, self.password)
        self.assertEqual(key_id(restored.public_key()), key_id(self.key.public_key()))
        self.assertEqual(load_public(self.key.public_key().public_bytes_raw()).public_bytes_raw(), self.key.public_key().public_bytes_raw())
        with self.assertRaises(ValueError):
            load_private(encrypted, b'wrong-password')
        with self.assertRaises(ValueError):
            serialize_private(self.key, b'short')
        with self.assertRaises(ValueError):
            load_private(b'not-an-encrypted-key', self.password)
