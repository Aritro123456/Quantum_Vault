# Encryption modes

| CLI mode | Key establishment | Public key bytes | Encapsulation bytes |
| --- | --- | --- | --- |
| postquantum (default) | ML-KEM-768 | 1184 | 1088 |
| classical | Ephemeral-static X25519 | 32 | 32 |
| hybrid | X-Wing draft-10 based strict variant | 1216 | 1120 |

All modes feed the established secret into the existing metadata-bound HKDF and AES-256-GCM workflow. Signatures remain ML-DSA-65 across modes: classical refers to key establishment, not the signature system. This is not a comparison at equal claimed security strengths.

The hybrid integration uses the key expansion and SHA3-256 combiner from draft-connolly-cfrg-xwing-kem-10. Primitive operations remain in PyCA/OpenSSL. Our provider rejects low-order X25519 inputs; this stricter behavior differs from the draft. The application therefore identifies it as XWING-D10-STRICT, not a fully conformant or finalized standard implementation. The pinned draft is work in progress, not an RFC; revision 10 expired on 2026-09-03. We pin that revision for reproducible experiments, not as a claim of current final standardization.

Public hybrid keys concatenate ML-KEM and X25519 components. Persisted hybrid private keys are application-specific JSON bundles of two independently password-encrypted PKCS8 components with an explicit suite/version. They are not compact draft-format seeds, nor standard standalone PKCS8 hybrid keys. Use .json or .key filenames rather than implying a single PEM key. No raw private seed is persisted.

Modes require separate keys. Key generation, encryption, and decryption accept --mode; default remains postquantum for earlier files. Decryption checks the selected suite and key type before proceeding, with no retry or fallback. Suite metadata remains authenticated. Old postquantum v1 envelopes and detached signatures remain supported.

The classical mode is a research baseline and is not quantum-resistant. All modes still require authenticated public-key distribution. Signed modes require an independently trusted signer. No mode provides forward secrecy for static recipient keys.

Verification: 31 tests pass, including three published draft vectors for deterministic hybrid key generation/public keys and decapsulation/shared secrets, fresh randomized round trips, component tampering, wrong component keys, invalid public keys, low-order rejection, cross-mode rejection, persistence, and signed CLI workflows. Deterministic encapsulation vectors and independent full interoperability testing are not implemented.

References:
- https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.html
- https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/x25519/

The downloaded draft snapshot and extracted public test vectors are stored under tests/fixtures. These are test keys only.
