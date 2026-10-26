"""Bounded local microbenchmarks; exports timings and sizes, never key material."""
import hashlib
import math
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from quantum_vault.crypto.key_establishment.operations import generate_encryption_key, encapsulate, decapsulate
from quantum_vault.crypto.key_establishment.suites import SUITES
from quantum_vault.crypto.signatures.mldsa import generate_signing_key, sign, verify
from quantum_vault.keys.encryption import serialize_encryption_private
from quantum_vault.keys.manager import serialize_private
from quantum_vault.services.files import encrypt_bytes, decrypt_bytes
from quantum_vault.services.signing import sign_envelope, verify_envelope
from quantum_vault.crypto.aead.cipher import encrypt as aes_encrypt, decrypt as aes_decrypt

DEFAULT_SIZES = (0, 1024, 65536, 1048576)


def summarize(samples):
    if not samples or any(type(n) is not int or n < 0 for n in samples):
        raise ValueError('Expected nonempty nonnegative integer nanosecond samples.')
    ordered = sorted(samples)
    return {'median_ms': statistics.median(samples) / 1e6,
            'p95_ms': ordered[math.ceil(len(ordered) * .95) - 1] / 1e6,
            'min_ms': ordered[0] / 1e6, 'max_ms': ordered[-1] / 1e6,
            'stdev_ms': statistics.pstdev(samples) / 1e6}


def measure(operation, repetitions, warmup, validate=None):
    samples = []
    for i in range(warmup + repetitions):
        start = time.perf_counter_ns()
        result = operation()
        elapsed = time.perf_counter_ns() - start
        if validate is not None:
            validate(result)  # Correctness check excluded from the timed interval.
        if i >= warmup:
            samples.append(elapsed)
    return {'samples_ns': samples, **summarize(samples)}


def require_equal(actual, expected):
    if actual != expected:
        raise RuntimeError('Benchmark correctness check failed.')


def source_digest():
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for path in sorted(root.rglob('*.py')):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b'\x00')
        digest.update(path.read_bytes())
    return digest.hexdigest()


def run_benchmarks(repetitions=30, warmup=3, sizes=DEFAULT_SIZES, modes=tuple(SUITES), progress=None):
    if type(repetitions) is not int or not 1 <= repetitions <= 500:
        raise ValueError('Repetitions must be between 1 and 500.')
    if type(warmup) is not int or not 0 <= warmup <= 100:
        raise ValueError('Warmup must be between 0 and 100.')
    sizes, modes = tuple(sizes), tuple(modes)
    if not sizes or len(sizes) > 8 or len(set(sizes)) != len(sizes) or any(type(n) is not int or not 0 <= n <= 1048576 for n in sizes):
        raise ValueError('Choose 1-8 distinct payload sizes from 0 to 1048576 bytes.')
    if not modes or len(set(modes)) != len(modes) or any(m not in SUITES for m in modes):
        raise ValueError('Choose distinct supported modes.')
    # Bound aggregate payload work for accidental expensive configurations.
    if sum(sizes) * len(modes) * (repetitions + warmup) > 1024 * 1024 * 1024:
        raise ValueError('Benchmark payload workload exceeds the 1 GiB configuration limit.')
    records, sizes_output = [], []
    started = time.perf_counter()

    def record(mode, operation, fn, payload=None, validate=None):
        records.append({'mode': mode, 'operation': operation, 'payload_bytes': payload,
                        'repetitions': repetitions, 'warmup': warmup,
                        **measure(fn, repetitions, warmup, validate)})

    record('ML-DSA-65', 'signing_key_generation', generate_signing_key)
    signer = generate_signing_key()
    signer_public = signer.public_key()
    message = b'QuantumVault isolated signing benchmark' * 2
    record('ML-DSA-65', 'sign_message', lambda: sign(signer, message), len(message),
           lambda signature: verify(signer_public, signature, message))
    signature = sign(signer, message)
    record('ML-DSA-65', 'verify_message', lambda: verify(signer_public, signature, message), len(message))
    password = os.urandom(32)  # Only used for serialization size; never exported.
    signer_sizes = {'algorithm': 'ML-DSA-65', 'public_key_bytes': len(signer_public.public_bytes_raw()),
                    'private_seed_bytes': len(signer.private_bytes_raw()),
                    'protected_private_file_bytes': len(serialize_private(signer, password)),
                    'signature_bytes': len(signature)}
    for mode in modes:
        if progress:
            progress(f'Measuring {mode}...')
        record(mode, 'recipient_key_generation', lambda: generate_encryption_key(mode))
        key = generate_encryption_key(mode)
        public = key.public_key()
        record(mode, 'encapsulation', lambda: encapsulate(public, mode), validate=lambda result: require_equal(decapsulate(key, result[1], mode), result[0]))
        secret, kem = encapsulate(public, mode)
        record(mode, 'decapsulation', lambda: decapsulate(key, kem, mode), validate=lambda result: require_equal(result, secret))
        raw_private_size = (len(key.mlkem.private_bytes_raw()) + len(key.x25519.private_bytes_raw())
                            if mode == 'hybrid' else len(key.private_bytes_raw()))
        key_sizes = {'mode': mode, 'suite': SUITES[mode],
                     'public_key_bytes': len(public.public_bytes_raw()),
                     'stored_private_component_seed_bytes': raw_private_size,
                     'protected_private_file_bytes': len(serialize_encryption_private(key, password, mode)),
                     'encapsulation_bytes': len(kem)}
        for size in sizes:
            # Fixed synthetic contents. Payload construction is outside all timers.
            payload = (bytes(range(256)) * ((size + 255) // 256))[:size]
            record(mode, 'encrypt_envelope', lambda: encrypt_bytes(payload, public, mode), size,
                   lambda envelope: require_equal(decrypt_bytes(envelope, key, mode), payload))
            envelope = encrypt_bytes(payload, public, mode)
            record(mode, 'decrypt_envelope', lambda: decrypt_bytes(envelope, key, mode), size,
                   lambda result: require_equal(result, payload))
            record(mode, 'sign_envelope', lambda: sign_envelope(envelope, signer), size,
                   lambda sig: verify_envelope(envelope, sig, signer_public))
            detached = sign_envelope(envelope, signer)
            record(mode, 'verify_envelope', lambda: verify_envelope(envelope, detached, signer_public), size)
            sizes_output.append({**key_sizes, 'payload_bytes': size, 'envelope_bytes': len(envelope),
                                 'envelope_overhead_bytes': len(envelope) - size,
                                 'detached_signature_file_bytes': len(detached),
                                 'signed_total_bytes': len(envelope) + len(detached)})
    # Isolate bulk cipher costs from KEM, HKDF, JSON/base64, and signatures.
    aes_key = os.urandom(32)
    for size in sizes:
        payload = b'x' * size
        def bulk_encrypt():
            nonce = os.urandom(12)  # Fresh nonce for every timed encryption.
            return nonce, aes_encrypt(aes_key, nonce, payload, b'benchmark')
        record('AES-256-GCM', 'bulk_encrypt_with_nonce_generation', bulk_encrypt, size,
               lambda pair: require_equal(aes_decrypt(aes_key, pair[0], pair[1], b'benchmark'), payload))
        nonce, ciphertext = bulk_encrypt()
        record('AES-256-GCM', 'bulk_decrypt', lambda: aes_decrypt(aes_key, nonce, ciphertext, b'benchmark'), size,
               lambda result: require_equal(result, payload))
    return {'schema_version': 1,
            'created_at_utc': datetime.now(timezone.utc).isoformat(),
            'environment': {'python': platform.python_version(), 'implementation': platform.python_implementation(),
                'os': platform.platform(), 'architecture': platform.machine(), 'cpu': platform.processor() or 'unavailable',
                'logical_cpu_count': os.cpu_count(), 'cryptography': cryptography.__version__,
                'openssl': backend.openssl_version_text(), 'source_sha256': source_digest()},
            'configuration': {'repetitions': repetitions, 'warmup': warmup, 'sizes': list(sizes), 'modes': list(modes),
                'clock': 'time.perf_counter_ns', 'p95_method': 'nearest rank',
                'correctness_validation': 'after every measured and warmup operation where output can be checked',
                'scope': 'Sequential in-memory operations; no disk I/O, password KDF timing, network, or process startup.',
                'order': 'Fixed mode/payload order; shared keys and decapsulation ciphertext reused per case; fresh encapsulation/nonce on encryption.',
                'limitations': 'Single local run; noisy machine-dependent timings; modes do not have equivalent security claims; signing always ML-DSA-65.'},
            'duration_seconds': time.perf_counter() - started,
            'signer_sizes': signer_sizes, 'timings': records, 'sizes': sizes_output}
