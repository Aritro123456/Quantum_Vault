"""Encryption-key persistence with explicit mode and protected hybrid components."""
import json
from quantum_vault.crypto.key_establishment.operations import PRIVATE_TYPES, PUBLIC_TYPES
from quantum_vault.crypto.key_establishment.hybrid import HybridPrivateKey
from quantum_vault.crypto.key_establishment.suites import suite_for
from quantum_vault.keys.manager import serialize_private, load_private
from quantum_vault.envelope.format import canonical, unique_object


def serialize_encryption_private(key, password, mode='postquantum'):
    suite_for(mode)
    if not isinstance(key, PRIVATE_TYPES[mode]):
        raise ValueError('Key does not match selected mode.')
    if mode != 'hybrid':
        return serialize_private(key, password)
    # Expanded components are separately encrypted PKCS8, never plaintext seeds.
    return canonical({'magic': 'QuantumVaultHybridPrivateKey', 'version': 1,
        'suite': suite_for(mode),
        'mlkem_pem': serialize_private(key.mlkem, password).decode('ascii'),
        'x25519_pem': serialize_private(key.x25519, password).decode('ascii')})


def load_encryption_private(data, password, mode='postquantum'):
    suite_for(mode)
    if len(data) > 16384:
        raise ValueError('Private-key file exceeds limit.')
    if mode != 'hybrid':
        return load_private(data, password, expected_type=PRIVATE_TYPES[mode])
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object)
        if not isinstance(value, dict) or set(value) != {'magic', 'version', 'suite', 'mlkem_pem', 'x25519_pem'}:
            raise ValueError('Invalid hybrid key fields.')
        if value['magic'] != 'QuantumVaultHybridPrivateKey' or type(value['version']) is not int or value['version'] != 1 or value['suite'] != suite_for(mode):
            raise ValueError('Unsupported hybrid key format.')
        if not isinstance(value['mlkem_pem'], str) or not isinstance(value['x25519_pem'], str):
            raise ValueError('Expected encrypted PEM strings.')
        return HybridPrivateKey(load_private(value['mlkem_pem'].encode('ascii'), password),
            load_private(value['x25519_pem'].encode('ascii'), password, expected_type=PRIVATE_TYPES['classical']))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError('Invalid hybrid key or incorrect password.') from exc


def load_encryption_public(data, mode='postquantum'):
    suite_for(mode)
    return PUBLIC_TYPES[mode].from_public_bytes(data)
