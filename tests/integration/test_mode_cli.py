import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from quantum_vault.cli import main


class ModeCliTests(unittest.TestCase):
    def test_signed_workflow_classical_and_hybrid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def run(*args):
                with patch('sys.argv', ['app.py', *map(str,args)]), patch('getpass.getpass', return_value='test-only-password-2026'), contextlib.redirect_stdout(io.StringIO()):
                    main()
            run('keygen', '--purpose', 'signing', '--private', root/'signer.pem', '--public', root/'signer.pub')
            (root/'input').write_bytes(b'multimode CLI fixture')
            for mode in ('classical', 'hybrid'):
                private, public, cipher, signature, output = [root/(mode+n) for n in ('.key','.pub','.qv','.sig','.txt')]
                run('keygen', '--mode', mode, '--private', private, '--public', public)
                run('encrypt', root/'input', cipher, '--key', public, '--mode', mode)
                run('sign', cipher, signature, '--key', root/'signer.pem')
                run('verify', cipher, signature, '--key', root/'signer.pub')
                run('decrypt', cipher, output, '--key', private, '--mode', mode, '--signature', signature, '--signer-key', root/'signer.pub')
                self.assertEqual(output.read_bytes(), (root/'input').read_bytes())
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    run('decrypt', cipher, root/'unexpected', '--key', private)
                self.assertEqual(error.exception.code, 1)
                self.assertFalse((root/'unexpected').exists())
