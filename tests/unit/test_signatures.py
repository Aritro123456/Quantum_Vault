import base64
import json
import unittest
from cryptography.exceptions import InvalidSignature
from quantum_vault.crypto.providers.mlkem import generate_key
from quantum_vault.crypto.signatures.mldsa import generate_signing_key, load_signing_private, load_signing_public, CONTEXT
from quantum_vault.keys.manager import serialize_private, key_id, load_private
from quantum_vault.services.files import encrypt_bytes
from quantum_vault.services.signing import sign_envelope, verify_envelope, VerificationError, signed_message
from quantum_vault.envelope.format import canonical


class SignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = generate_signing_key()
        cls.envelope = encrypt_bytes(b'synthetic sample', generate_key().public_key())

    def test_sign_verify(self):
        signature = sign_envelope(self.envelope, self.key)
        verify_envelope(self.envelope, signature, self.key.public_key())
        self.assertEqual(len(base64.b64decode(json.loads(signature)['signature'])), 3309)

    def test_wrong_signer_and_rewritten_signer(self):
        other = generate_signing_key()
        signature = sign_envelope(self.envelope, self.key)
        with self.assertRaises(VerificationError):
            verify_envelope(self.envelope, signature, other.public_key())
        value = json.loads(signature)
        value['metadata']['signer'] = key_id(other.public_key())
        with self.assertRaises(VerificationError):
            verify_envelope(self.envelope, canonical(value), other.public_key())

    def test_exact_bytes_are_signed(self):
        signature = sign_envelope(self.envelope, self.key)
        with self.assertRaises(VerificationError):
            verify_envelope(self.envelope + b' ', signature, self.key.public_key())
        different = encrypt_bytes(b'synthetic sample', generate_key().public_key())
        with self.assertRaises(VerificationError):
            verify_envelope(different, signature, self.key.public_key())

    def test_signature_and_metadata_tamper(self):
        signature = sign_envelope(self.envelope, self.key)
        for field, value in [('magic', 'other'), ('version', 2), ('version', True), ('algorithm', 'other'), ('signer', '0'*64)]:
            altered = json.loads(signature)
            altered['metadata'][field] = value
            with self.subTest(field=field), self.assertRaises(VerificationError):
                verify_envelope(self.envelope, canonical(altered), self.key.public_key())
        altered = json.loads(signature)
        raw = bytearray(base64.b64decode(altered['signature']))
        raw[0] ^= 1
        altered['signature'] = base64.b64encode(raw).decode()
        with self.assertRaises(VerificationError):
            verify_envelope(self.envelope, canonical(altered), self.key.public_key())

    def test_malformed_missing_duplicate_and_extra(self):
        signature = sign_envelope(self.envelope, self.key)
        altered = json.loads(signature)
        altered['public_key'] = 'untrusted embedded key'
        values = [b'', b'{}', b'[]', b'null', b'\xff', b'x'*8193, signature[:-3], canonical(altered), b'{"metadata":{},"metadata":{},"signature":""}']
        altered = json.loads(signature)
        altered['signature'] = 'invalid!'
        values.append(canonical(altered))
        for value in values:
            with self.subTest(value=value[:20]), self.assertRaises(VerificationError):
                verify_envelope(self.envelope, value, self.key.public_key())

    def test_context_separation(self):
        value = json.loads(sign_envelope(self.envelope, self.key))
        message = signed_message(value['metadata'], self.envelope)
        signature = base64.b64decode(value['signature'])
        with self.assertRaises(InvalidSignature):
            self.key.public_key().verify(signature, message, b'other-protocol')
        self.key.public_key().verify(signature, message, CONTEXT)

    def test_signing_key_storage_and_key_purpose(self):
        password = b'test-only-password-2026'
        pem = serialize_private(self.key, password)
        restored = load_signing_private(pem, password)
        self.assertEqual(key_id(restored.public_key()), key_id(self.key.public_key()))
        self.assertEqual(key_id(load_signing_public(self.key.public_key().public_bytes_raw())), key_id(self.key.public_key()))
        with self.assertRaises(ValueError):
            load_signing_private(pem, b'wrong-password')
        with self.assertRaises(ValueError):
            load_private(pem, password)
        with self.assertRaises(ValueError):
            load_signing_private(serialize_private(generate_key(), password), password)

    def test_non_envelope_cannot_be_signed(self):
        with self.assertRaises(ValueError):
            sign_envelope(b'arbitrary plain file', self.key)
