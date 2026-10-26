# Detached signature v1 and trust policy

ML-DSA-65 is provided by the pinned PyCA cryptography library. Signature size: 3309 bytes; raw public key: 1952 bytes. Private signing keys use password-encrypted PKCS8 and are purpose-checked on load.

The detached JSON file has exactly metadata and signature fields. Metadata has exactly magic="QuantumVaultSignature", integer version=1, algorithm="ML-DSA-65", and signer=SHA-256 hex fingerprint of raw signing public key. signature is canonical standard base64. Input is limited to 8192 bytes; duplicate/extra fields, invalid lengths, unsupported algorithms/versions, and invalid base64 are rejected.

Signed bytes: b"QuantumVault/signed-envelope/v1\x00" || 4-byte big-endian canonical-metadata length || canonical metadata || exact encrypted-envelope file bytes. Metadata canonicalization matches the envelope canonical JSON rules. ML-DSA context is b"QuantumVault/envelope-signature/v1". This is a pure ML-DSA signature, not an ad hoc prehash mode.

Signing accepts only structurally valid QuantumVault envelopes. Signers must authorize content separately: signing ciphertext alone does not establish that the signer inspected its plaintext. Verification requires an independently obtained, authenticated public key. The fingerprint in the signature is checked against that key; it never supplies trust itself. Key trust stores, certificates, expiry, revocation, and replay protection are not implemented.

Signature-required decryption reads the envelope once, verifies its exact bytes, then decrypts those same bytes. No plaintext output file is created until both signature and AEAD checks succeed. There is no downgrade to unsigned decryption when verification fails. The separate unsigned mode remains explicitly accessible without signature flags.

Reference: https://cryptography.io/en/stable/hazmat/primitives/asymmetric/mldsa/
