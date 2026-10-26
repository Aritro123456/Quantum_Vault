"""Signed round trips for all modes; temporary synthetic files and protected keys."""
import json
import secrets
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from quantum_vault.crypto.key_establishment.operations import generate_encryption_key
from quantum_vault.crypto.key_establishment.suites import SUITES
from quantum_vault.keys.encryption import serialize_encryption_private, load_encryption_private
from quantum_vault.keys.manager import serialize_private
from quantum_vault.crypto.signatures.mldsa import generate_signing_key, load_signing_private
from quantum_vault.services.files import encrypt_file
from quantum_vault.services.signing import sign_file, verify_file, decrypt_verified_file


def main():
    results = []
    with tempfile.TemporaryDirectory(prefix='quantumvault-demo-') as folder:
        root = Path(folder)
        password = secrets.token_bytes(32)
        signer = load_signing_private(serialize_private(generate_signing_key(), password), password)
        source = root / 'sample.txt'
        source.write_bytes(b'QuantumVault synthetic file demonstration.\n')
        for mode in SUITES:
            key = generate_encryption_key(mode)
            protected = serialize_encryption_private(key, password, mode)
            key = load_encryption_private(protected, password, mode)
            encrypted, signature, decrypted = [root/(mode+suffix) for suffix in ('.qv','.qvsig','.txt')]
            encrypt_file(source, encrypted, key.public_key(), mode)
            sign_file(encrypted, signature, signer)
            verify_file(encrypted, signature, signer.public_key())
            decrypt_verified_file(encrypted, decrypted, key, signature, signer.public_key(), mode)
            assert source.read_bytes() == decrypted.read_bytes()
            results.append({'mode':mode, 'suite':SUITES[mode], 'round_trip':True,
                            'signature_verified':True, 'plaintext_bytes':source.stat().st_size,
                            'envelope_bytes':encrypted.stat().st_size})
    print(json.dumps({'status':'passed', 'modes':results, 'temporary_files_cleaned':True}, indent=2))


if __name__ == '__main__':
    main()
