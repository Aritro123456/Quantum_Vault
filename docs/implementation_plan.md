# Implementation roadmap

Completed milestone 1:
- Pinned cryptography provider and transitive dependencies in requirements.txt.
- ML-KEM-768 agreement and encrypted PKCS8 smoke tests.
- Post-quantum recipient key generation and password-protected private-key loading.
- Versioned bounded envelope, context-bound KDF, authenticated encryption/decryption.
- CLI, synthetic demo, and 11 passing unit/integration tests.

Completed milestone 2:
- ML-DSA-65 signing keys, detached signatures, trusted-key verification, and signature-required decryption.
- 22 passing tests including full CLI workflows, wrong signers, metadata/ciphertext/signature changes, and downgrade rejection.

Completed milestone 3:
- Classical X25519 baseline and X-Wing draft-10 based strict hybrid mode.
- Three published hybrid keygen/decapsulation vectors and 31 passing tests.
- Explicit mode policy, encrypted key persistence, and signed CLI workflows across modes.

Completed milestone 4:
- Reproducible bounded benchmarks with raw samples, environment metadata, timing distributions, and storage sizes.
- JSON, CSV, and Markdown comparison exports; 35 passing tests.

Completed milestone 5:
- Next.js/TypeScript frontend and Django backend replace the planned Streamlit interface.
- Overview, file operations, protected key downloads, benchmark charts/history, and report downloads.
- Five Django API tests added.

Browser verification completed for overview data, benchmark execution/chart updates, and protected key downloads. Setup is documented in dashboard.md.

Next:
1. Produce migration assessments from measured results and refine the threat model.

Full deterministic encapsulation vectors, cross-provider tests, and independent security review remain outstanding. No accuracy, performance, certification, or production-hardening claims are established.
