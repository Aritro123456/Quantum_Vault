# Architecture

Working path: app.py -> CLI -> key manager / file services -> bounded envelope parser -> provider adapters -> PyCA cryptography/OpenSSL.

Encryption reads bounded input, encapsulates to the recipient public key, derives a file key with a context-bound KDF, encrypts with authenticated header metadata, and creates a new envelope file exclusively.

Decryption validates the envelope, checks recipient identity, derives the key, authenticates ciphertext and metadata, and only then creates a new plaintext output. Existing files cannot be overwritten. Partial newly created outputs are removed after write failures.

Key generation protects the private key with a prompted password before writing. Keys and outputs belong in ignored runtime storage. The caller authenticates the recipient public-key fingerprint independently.

Signing path: encrypted envelope -> context-separated ML-DSA-65 signature -> detached signature file. Verification uses a caller-trusted key. Signed decryption verifies and decrypts the same bytes before output.

Mode selection uses an explicit suite registry and key type checks. Classical mode uses ephemeral-static X25519; hybrid combines ML-KEM and X25519 through the pinned draft combiner, with a distinct strict suite identifier.

Benchmark CLI calls provider/application operations in memory and exports public measurements through reporting/benchmarks.py.

Web path: Next.js client -> same-origin /api rewrite -> Django with CSRF validation -> existing crypto engine -> streamed-in-memory response/download. Benchmark history reads stored public measurements. Uploaded keys and plaintext are not persisted.

Planned: richer migration assessment workflows. See dashboard.md for local startup.
