import tempfile
import unittest
from pathlib import Path
from quantum_vault.crypto.providers.mlkem import generate_key
from quantum_vault.services.files import encrypt_file, decrypt_file, DecryptionError


class FileWorkflowTests(unittest.TestCase):
    def test_file_roundtrip_preserves_original(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, encrypted, restored = [root / n for n in ('input.bin', 'output.qv', 'restored.bin')]
            payload = bytes(range(256)) * 64
            source.write_bytes(payload)
            key = generate_key()
            encrypt_file(source, encrypted, key.public_key())
            decrypt_file(encrypted, restored, key)
            self.assertEqual(source.read_bytes(), payload)
            self.assertEqual(restored.read_bytes(), payload)

    def test_no_plaintext_output_after_failed_authentication(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, encrypted, restored = [root / n for n in ('input.txt', 'output.qv', 'restored.txt')]
            source.write_bytes(b'private message')
            encrypt_file(source, encrypted, generate_key().public_key())
            with self.assertRaises(DecryptionError):
                decrypt_file(encrypted, restored, generate_key())
            self.assertFalse(restored.exists())

    def test_refuses_overwrite_and_same_path(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, encrypted, restored = [root / n for n in ('input.txt', 'output.qv', 'restored.txt')]
            source.write_bytes(b'original')
            key = generate_key()
            with self.assertRaises(FileExistsError):
                encrypt_file(source, source, key.public_key())
            self.assertEqual(source.read_bytes(), b'original')
            encrypt_file(source, encrypted, key.public_key())
            restored.write_bytes(b'keep me')
            with self.assertRaises(FileExistsError):
                decrypt_file(encrypted, restored, key)
            self.assertEqual(restored.read_bytes(), b'keep me')
