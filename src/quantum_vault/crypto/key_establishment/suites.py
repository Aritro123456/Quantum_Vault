"""Explicit mode registry; no automatic fallback or negotiation."""
PQ_SUITE = 'ML-KEM-768/HKDF-SHA256/AES-256-GCM'
CLASSICAL_SUITE = 'X25519/HKDF-SHA256/AES-256-GCM'
HYBRID_SUITE = 'XWING-D10-STRICT/HKDF-SHA256/AES-256-GCM'
SUITES = {'postquantum': PQ_SUITE, 'classical': CLASSICAL_SUITE, 'hybrid': HYBRID_SUITE}
KEM_LENGTHS = {PQ_SUITE: 1088, CLASSICAL_SUITE: 32, HYBRID_SUITE: 1120}
PUBLIC_LENGTHS = {'postquantum': 1184, 'classical': 32, 'hybrid': 1216}


def suite_for(mode):
    try:
        return SUITES[mode]
    except (KeyError, TypeError) as exc:
        raise ValueError('Unsupported encryption mode.') from exc
