"""Run QuantumVault from the project directory without installing the package."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from quantum_vault.cli import main

if __name__ == '__main__':
    main()
