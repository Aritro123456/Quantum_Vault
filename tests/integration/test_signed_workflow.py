import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from quantum_vault.cli import main
from quantum_vault.crypto.providers.mlkem import generate_key
from quantum_vault.crypto.signatures.mldsa import generate_signing_key
from quantum_vault.services.files import encrypt_file
from quantum_vault.services.signing import sign_file, verify_file, decrypt_verified_file, VerificationError


class SignedWorkflowTests(unittest.TestCase):
    def test_verified_decryption_and_no_output_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, encrypted, signature, output = [root/n for n in ('source', 'cipher', 'signature', 'output')]
            source.write_bytes(b'synthetic example')
            recipient, signer = generate_key(), generate_signing_key()
            encrypt_file(source, encrypted, recipient.public_key())
            sign_file(encrypted, signature, signer)
            verify_file(encrypted, signature, signer.public_key())
            with self.assertRaises(VerificationError):
                decrypt_verified_file(encrypted, output, recipient, signature, generate_signing_key().public_key())
            self.assertFalse(output.exists())
            decrypt_verified_file(encrypted, output, recipient, signature, signer.public_key())
            self.assertEqual(output.read_bytes(), source.read_bytes())
            with self.assertRaises(FileExistsError):
                decrypt_verified_file(encrypted, output, recipient, signature, signer.public_key())

    def test_unsigned_is_rejected_when_signature_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, encrypted, signature, output = [root/n for n in ('source', 'cipher', 'signature', 'output')]
            source.write_bytes(b'sample')
            recipient = generate_key()
            encrypt_file(source, encrypted, recipient.public_key())
            signature.write_bytes(b'{}')
            with self.assertRaises(VerificationError):
                decrypt_verified_file(encrypted, output, recipient, signature, generate_signing_key().public_key())
            self.assertFalse(output.exists())

    def test_cli_full_workflow_and_partial_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def run(*args):
                with patch('sys.argv', ['app.py', *map(str,args)]), patch('getpass.getpass', return_value='test-only-password-2026'), contextlib.redirect_stdout(io.StringIO()):
                    main()
            run('keygen', '--private', root/'recipient.pem', '--public', root/'recipient.pub')
            run('keygen', '--purpose', 'signing', '--private', root/'signer.pem', '--public', root/'signer.pub')
            (root/'input').write_bytes(b'CLI sample')
            run('encrypt', root/'input', root/'cipher', '--key', root/'recipient.pub')
            run('sign', root/'cipher', root/'signature', '--key', root/'signer.pem')
            run('verify', root/'cipher', root/'signature', '--key', root/'signer.pub')
            run('decrypt', root/'cipher', root/'output', '--key', root/'recipient.pem', '--signature', root/'signature', '--signer-key', root/'signer.pub')
            self.assertEqual((root/'output').read_bytes(), b'CLI sample')
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                run('decrypt', root/'cipher', root/'unused', '--key', root/'recipient.pem', '--signature', root/'signature')
            self.assertEqual(result.exception.code, 2)
            self.assertFalse((root/'unused').exists())
            value = json.loads((root/'signature').read_bytes())
            value['signature'] = 'AAAA'
            (root/'signature').write_text(json.dumps(value))
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                run('decrypt', root/'cipher', root/'unused', '--key', root/'recipient.pem', '--signature', root/'signature', '--signer-key', root/'signer.pub')
            self.assertEqual(result.exception.code, 1)
            self.assertFalse((root/'unused').exists())
