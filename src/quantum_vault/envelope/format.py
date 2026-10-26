"""Strict, bounded, canonical JSON envelope for the QuantumVault lab protocol."""
import base64
import binascii
import json
import re

from quantum_vault.crypto.key_establishment.suites import PQ_SUITE, KEM_LENGTHS

SUITE = PQ_SUITE
MAX_PLAINTEXT = 16 * 1024 * 1024
MAX_ENVELOPE = 23 * 1024 * 1024
HEADER_FIELDS = {'magic', 'version', 'suite', 'recipient', 'kem_ciphertext', 'salt', 'nonce'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def encode(data):
    return base64.b64encode(data).decode('ascii')


def decode(value, length=None):
    if not isinstance(value, str):
        raise ValueError('Expected base64 string.')
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError('Invalid base64.') from exc
    if encode(result) != value or (length is not None and len(result) != length):
        raise ValueError('Noncanonical base64 or incorrect field length.')
    return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field.')
        result[key] = value
    return result


def parse(data):
    if len(data) > MAX_ENVELOPE:
        raise ValueError('Envelope exceeds the 23 MiB input limit.')
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError('Invalid envelope JSON.') from exc
    if not isinstance(value, dict) or set(value) != {'header', 'ciphertext'}:
        raise ValueError('Unexpected envelope fields.')
    header = value['header']
    if not isinstance(header, dict) or set(header) != HEADER_FIELDS:
        raise ValueError('Unexpected header fields.')
    if header['magic'] != 'QuantumVault' or type(header['version']) is not int or header['version'] != 1 or not isinstance(header['suite'], str) or header['suite'] not in KEM_LENGTHS:
        raise ValueError('Unsupported envelope version or suite.')
    if not isinstance(header['recipient'], str) or not re.fullmatch('[0-9a-f]{64}', header['recipient']):
        raise ValueError('Invalid recipient ID.')
    kem = decode(header['kem_ciphertext'], KEM_LENGTHS[header['suite']])
    salt = decode(header['salt'], 32)
    nonce = decode(header['nonce'], 12)
    ciphertext = decode(value['ciphertext'])
    if not 16 <= len(ciphertext) <= MAX_PLAINTEXT + 16:
        raise ValueError('Invalid ciphertext size.')
    return header, kem, salt, nonce, ciphertext
