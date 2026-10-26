import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from quantum_vault.cli import main


class BenchmarkCliTests(unittest.TestCase):
    def test_cli_export_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'run'
            args = ['app.py','benchmark','--repetitions','1','--warmup','0','--sizes','0','--modes','postquantum','--output-dir',str(output)]
            with patch('sys.argv',args), contextlib.redirect_stdout(io.StringIO()):
                main()
            self.assertEqual(json.loads((output/'results.json').read_text())['configuration']['repetitions'], 1)
            with patch('sys.argv',args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main()
            self.assertEqual(error.exception.code, 1)
