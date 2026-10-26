"""Interactive CLI; passwords are prompted, never command-line arguments."""
import argparse
import getpass
from pathlib import Path
from quantum_vault.crypto.key_establishment.operations import generate_encryption_key
from quantum_vault.crypto.key_establishment.suites import SUITES, PUBLIC_LENGTHS
from quantum_vault.keys.encryption import serialize_encryption_private, load_encryption_private, load_encryption_public
from quantum_vault.keys.manager import key_id, serialize_private
from quantum_vault.crypto.signatures.mldsa import generate_signing_key, load_signing_private, load_signing_public
from quantum_vault.services.signing import sign_file, verify_file, decrypt_verified_file
from quantum_vault.services.files import encrypt_file, decrypt_file, write_new, read_limited


def main():
    parser = argparse.ArgumentParser(description='QuantumVault post-quantum file encryption lab')
    sub = parser.add_subparsers(dest='action', required=True)
    gen = sub.add_parser('keygen', help='Create an encrypted private key and public key')
    gen.add_argument('--private', type=Path, required=True)
    gen.add_argument('--public', type=Path, required=True)
    gen.add_argument('--mode', choices=tuple(SUITES), default='postquantum')
    gen.add_argument('--purpose', choices=('encryption', 'signing'), default='encryption')
    for action in ('encrypt', 'decrypt'):
        cmd = sub.add_parser(action)
        cmd.add_argument('input', type=Path)
        cmd.add_argument('output', type=Path)
        cmd.add_argument('--key', type=Path, required=True)
        cmd.add_argument('--mode', choices=tuple(SUITES), default='postquantum')
        if action == 'decrypt':
            cmd.add_argument('--signature', type=Path, help='Require detached signature verification')
            cmd.add_argument('--signer-key', type=Path, help='Independently trusted ML-DSA-65 public key')
    for action in ('sign', 'verify'):
        cmd = sub.add_parser(action)
        cmd.add_argument('input', type=Path, help='Encrypted envelope to sign or verify')
        cmd.add_argument('signature', type=Path, help='Detached signature output/input')
        cmd.add_argument('--key', type=Path, required=True)
    bench = sub.add_parser('benchmark', help='Measure modes and export JSON, CSV, and Markdown')
    bench.add_argument('--repetitions', type=int, default=30)
    bench.add_argument('--warmup', type=int, default=3)
    bench.add_argument('--sizes', type=int, nargs='+', default=[0, 1024, 65536, 1048576])
    bench.add_argument('--modes', choices=tuple(SUITES), nargs='+', default=list(SUITES))
    bench.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    if args.action == 'decrypt' and bool(args.signature) != bool(args.signer_key):
        parser.error('--signature and --signer-key must be supplied together')
    if args.action == 'keygen' and args.purpose == 'signing' and args.mode != 'postquantum':
        parser.error('--mode applies to encryption keys only; signing always uses ML-DSA-65')
    try:
        if args.action == 'benchmark':
            from datetime import datetime, timezone
            from quantum_vault.benchmarks.runner import run_benchmarks
            from quantum_vault.reporting.benchmarks import export_results
            output = args.output_dir or Path('benchmarks/results') / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
            if output.exists():
                raise ValueError('Benchmark output directory must not already exist.')
            results = run_benchmarks(args.repetitions, args.warmup, args.sizes, args.modes, progress=print)
            export_results(results, output)
            print(f'Benchmark report saved to {output / "report.md"}')
        elif args.action == 'keygen':
            if args.private.resolve() == args.public.resolve() or args.private.exists() or args.public.exists():
                raise ValueError('Choose two distinct, unused key paths.')
            password = getpass.getpass('New private-key password (at least 12 bytes): ').encode('utf-8')
            if password != getpass.getpass('Confirm password: ').encode('utf-8'):
                raise ValueError('Passwords do not match.')
            key = generate_encryption_key(args.mode) if args.purpose == 'encryption' else generate_signing_key()
            encrypted = (serialize_encryption_private(key, password, args.mode)
                         if args.purpose == 'encryption' else serialize_private(key, password))
            write_new(args.private, encrypted)
            try:
                write_new(args.public, key.public_key().public_bytes_raw())
            except BaseException:
                args.private.unlink()
                raise
            print(f'Key pair created. Public-key SHA-256 fingerprint: {key_id(key.public_key())}')
        elif args.action == 'encrypt':
            public_key = load_encryption_public(read_limited(args.key, PUBLIC_LENGTHS[args.mode]), args.mode)
            encrypt_file(args.input, args.output, public_key, args.mode)
            print(f'Encrypted file saved to {args.output}')
        elif args.action == 'sign':
            password = getpass.getpass('Signing-key password: ').encode('utf-8')
            key = load_signing_private(read_limited(args.key, 16384), password)
            sign_file(args.input, args.signature, key)
            print(f'Detached ML-DSA-65 signature saved to {args.signature}')
        elif args.action == 'verify':
            key = load_signing_public(read_limited(args.key, 1952))
            verify_file(args.input, args.signature, key)
            print(f'Signature verified against trusted signer: {key_id(key)}')
        else:
            password = getpass.getpass('Private-key password: ').encode('utf-8')
            private_key = load_encryption_private(read_limited(args.key, 16384), password, args.mode)
            if args.signature:
                signer = load_signing_public(read_limited(args.signer_key, 1952))
                decrypt_verified_file(args.input, args.output, private_key, args.signature, signer, args.mode)
            else:
                decrypt_file(args.input, args.output, private_key, args.mode)
            print(f'Authenticated plaintext saved to {args.output}')
    except (ValueError, TypeError, OSError) as exc:
        parser.exit(1, f'Error: {exc}\n')
