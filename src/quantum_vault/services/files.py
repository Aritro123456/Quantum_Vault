"""Unsigned recipient encryption with authenticated envelope metadata."""
import os
from pathlib import Path
from cryptography.exceptions import InvalidTag
from quantum_vault.crypto.key_establishment.operations import encapsulate, decapsulate
from quantum_vault.crypto.key_establishment.suites import suite_for
from quantum_vault.crypto.kdf.derive import derive_key
from quantum_vault.crypto.aead import cipher
from quantum_vault.envelope.format import MAX_PLAINTEXT, MAX_ENVELOPE, canonical, encode, parse
from quantum_vault.keys.manager import key_id


class DecryptionError(ValueError):
    pass


def encrypt_bytes(plaintext, public_key, mode='postquantum'):
    if len(plaintext) > MAX_PLAINTEXT:
        raise ValueError('Plaintext exceeds the 16 MiB limit.')
    suite = suite_for(mode)
    secret, kem = encapsulate(public_key, mode)
    salt, nonce = os.urandom(32), os.urandom(12)
    header = {'magic': 'QuantumVault', 'version': 1, 'suite': suite,
              'recipient': key_id(public_key), 'kem_ciphertext': encode(kem),
              'salt': encode(salt), 'nonce': encode(nonce)}
    aad = canonical(header)
    key = derive_key(secret, salt, aad)
    ciphertext = cipher.encrypt(key, nonce, plaintext, aad)
    return canonical({'header': header, 'ciphertext': encode(ciphertext)})


def decrypt_bytes(envelope, private_key, mode='postquantum'):
    try:
        header, kem, salt, nonce, ciphertext = parse(envelope)
        if header['suite'] != suite_for(mode):
            raise ValueError('Envelope does not match required mode.')
        if header['recipient'] != key_id(private_key.public_key()):
            raise ValueError('Recipient mismatch.')
        aad = canonical(header)
        key = derive_key(decapsulate(private_key, kem, mode), salt, aad)
        return cipher.decrypt(key, nonce, ciphertext, aad)
    except (ValueError, InvalidTag) as exc:
        raise DecryptionError('Decryption failed: invalid envelope, wrong key, or modified data.') from exc


def read_limited(path, limit):
    with Path(path).open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f'Input exceeds {limit} bytes.')
    return data


def write_new(path, data):
    # Exclusive creation prevents accidental overwrite of inputs or existing keys.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            descriptor = None
            handle.write(data)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        Path(path).unlink(missing_ok=True)
        raise


def encrypt_file(source, destination, public_key, mode='postquantum'):
    write_new(destination, encrypt_bytes(read_limited(source, MAX_PLAINTEXT), public_key, mode))


def decrypt_file(source, destination, private_key, mode='postquantum'):
    # Authentication completes before the output file is created.
    plaintext = decrypt_bytes(read_limited(source, MAX_ENVELOPE), private_key, mode)
    write_new(destination, plaintext)
