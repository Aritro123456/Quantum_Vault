"""Run tests against the source tree with the current Python interpreter."""
import sys
import unittest
from pathlib import Path
root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / 'src'))
sys.path.insert(0, str(root))
if __name__ == '__main__':
    suite = unittest.defaultTestLoader.discover(str(root / 'tests'), top_level_dir=str(root))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
