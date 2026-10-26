# Cryptographic design: milestone 1

Original suite: ML-KEM-768 / HKDF-SHA-256 / AES-256-GCM using cryptography==50.0.2. The upstream ML-KEM provider and encrypted PKCS8 serialization were smoke-tested locally. Cryptographic operations are delegated to the provider.

For every envelope: fresh ML-KEM encapsulation, 32-byte random salt, and 12-byte random nonce. HKDF derives a 32-byte file key from the encapsulated secret with info equal to b"QuantumVault/file-key/v1\x00" followed by canonical header bytes. The same header bytes are AEAD associated data. The header binds the suite, version, recipient fingerprint, encapsulation ciphertext, salt, and nonce. AES-GCM outputs ciphertext with its 16-byte tag.

Private keys are persisted only as password-encrypted PKCS8 via BestAvailableEncryption. Public keys are raw ML-KEM bytes and identified by SHA-256 fingerprint. Sender must authenticate the public key separately. No key trust store is implemented. Python cannot guarantee key erasure; memory compromise is outside this milestone. On Windows, containing-directory ACLs govern access; POSIX 0600 mode is not a Windows ACL policy.

The base encryption envelope is unsigned; optional ML-DSA-65 detached signatures are specified in signature_format.md. This is an application-specific experimental format, not a standardized file encryption protocol. Anyone holding the public key can create a valid envelope; AEAD integrity does not prove sender identity. Static recipient keys do not provide forward secrecy. No FIPS validation or independent audit is claimed.

ML-DSA-65 signatures are implemented with explicit trusted-signer verification. Classical and hybrid modes are implemented; see encryption_modes.md for suite policy and strict-variant limitations. Hybrid composition is pinned to the documented draft construction; signature coverage and verification policy are documented separately. Do not use arbitrary algorithm concatenation or an either-signature-accepted fallback for a both-required policy.

Provider references:
- https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/mlkem/
- https://cryptography.io/en/50.0.2/hazmat/primitives/aead/
- https://cryptography.io/en/50.0.2/hazmat/primitives/key-derivation-functions/
- https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/serialization/

Standards:
- https://csrc.nist.gov/pubs/fips/203/final
- https://csrc.nist.gov/pubs/fips/204/final
