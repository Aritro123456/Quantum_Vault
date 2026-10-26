# QuantumVault envelope v1

Experimental base JSON encryption format with optional detached signatures. Top-level fields must be exactly header and ciphertext. Unknown/duplicate fields and unsupported versions/suites fail closed.

Header fields:
- magic: "QuantumVault"
- version: integer 1 (boolean is rejected)
- suite: one of ML-KEM-768/HKDF-SHA256/AES-256-GCM, X25519/HKDF-SHA256/AES-256-GCM, or XWING-D10-STRICT/HKDF-SHA256/AES-256-GCM
- recipient: lowercase 64-character SHA-256 hex fingerprint of raw recipient public key
- kem_ciphertext: canonical standard base64 of 1088 (postquantum), 32 (classical), or 1120 (hybrid) bytes
- salt: canonical standard base64 of 32 bytes
- nonce: canonical standard base64 of 12 bytes

ciphertext is canonical standard base64 of AES-GCM ciphertext plus its 16-byte authentication tag. No original filename, private key, or raw shared secret is embedded.

Header canonicalization: json.dumps with sort_keys=True, separators=(',', ':'), ensure_ascii=True, encoded as ASCII. Those bytes are bound through both HKDF info and AES-GCM associated data. Formatting of the outer JSON is not authenticated; semantic header contents and ciphertext are.

Maximum plaintext: 16 MiB. Maximum input envelope: 23 MiB. File reads enforce bounds before parsing. Ciphertext must decode to between 16 bytes and 16 MiB + 16 bytes. Parser rejects invalid base64, wrong field sizes, invalid recipient IDs, duplicate keys, truncated JSON, and unknown fields. No streaming support. Optional sender signatures are specified in signature_format.md. Decryption must match the caller-selected mode; accepted suite names do not enable fallback.
