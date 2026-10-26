"""Detached signatures bind exact encrypted-envelope bytes and signer metadata."""
import json
from cryptography.exceptions import InvalidSignature
from quantum_vault.crypto.signatures.mldsa import sign, verify
from quantum_vault.envelope.format import canonical, encode, decode, unique_object, parse, MAX_ENVELOPE
from quantum_vault.keys.manager import key_id
from quantum_vault.services.files import read_limited, write_new, decrypt_bytes

MAX_SIGNATURE_FILE = 8192
DOMAIN = b'QuantumVault/signed-envelope/v1\x00'


class VerificationError(ValueError):
    pass


def signed_message(metadata, envelope):
    header = canonical(metadata)
    return DOMAIN + len(header).to_bytes(4, 'big') + header + envelope


def sign_envelope(envelope, private_key):
    parse(envelope)  # Only valid QuantumVault encrypted envelopes can be signed.
    metadata = {'magic': 'QuantumVaultSignature', 'version': 1,
                'algorithm': 'ML-DSA-65', 'signer': key_id(private_key.public_key())}
    signature = sign(private_key, signed_message(metadata, envelope))
    return canonical({'metadata': metadata, 'signature': encode(signature)})


def verify_envelope(envelope, signature_file, trusted_public_key):
    try:
        if len(signature_file) > MAX_SIGNATURE_FILE:
            raise ValueError('Signature file too large.')
        value = json.loads(signature_file.decode('utf-8'), object_pairs_hook=unique_object)
        if not isinstance(value, dict) or set(value) != {'metadata', 'signature'}:
            raise ValueError('Invalid signature file fields.')
        metadata = value['metadata']
        if not isinstance(metadata, dict) or set(metadata) != {'magic', 'version', 'algorithm', 'signer'}:
            raise ValueError('Invalid signature metadata.')
        if (metadata['magic'] != 'QuantumVaultSignature' or type(metadata['version']) is not int
                or metadata['version'] != 1 or metadata['algorithm'] != 'ML-DSA-65'):
            raise ValueError('Unsupported signature version or algorithm.')
        if metadata['signer'] != key_id(trusted_public_key):
            raise ValueError('Unexpected signer.')
        signature = decode(value['signature'], 3309)
        parse(envelope)
        verify(trusted_public_key, signature, signed_message(metadata, envelope))
    except (ValueError, InvalidSignature, UnicodeError, RecursionError) as exc:
        raise VerificationError('Signature verification failed: wrong signer, modified data, or invalid format.') from exc


def sign_file(source, destination, private_key):
    write_new(destination, sign_envelope(read_limited(source, MAX_ENVELOPE), private_key))


def verify_file(source, signature_path, trusted_public_key):
    verify_envelope(read_limited(source, MAX_ENVELOPE),
                    read_limited(signature_path, MAX_SIGNATURE_FILE), trusted_public_key)


def decrypt_verified_file(source, destination, recipient_private_key, signature_path, trusted_signer, mode='postquantum'):
    # Read once: the exact bytes verified are the ones decrypted, preventing a file-swap gap.
    envelope = read_limited(source, MAX_ENVELOPE)
    signature = read_limited(signature_path, MAX_SIGNATURE_FILE)
    verify_envelope(envelope, signature, trusted_signer)
    plaintext = decrypt_bytes(envelope, recipient_private_key, mode)
    write_new(destination, plaintext)
