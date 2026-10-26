# Initial threat model

Goal: protect file confidentiality and integrity during storage and exchange; provide sender authentication when a configured signing mode is used.

Consider attackers who read or modify envelopes, substitute public keys, alter algorithm metadata, replay signed files, or retain ciphertext for future cryptanalysis. Public-key trust and freshness/replay requirements need explicit design.

Assumptions and limits: endpoint compromise and stolen unlocked private keys defeat file protection; Python memory erasure is limited; no forward-secrecy, production-hardening, side-channel-resistance, or certification claims are established.

Implemented controls include metadata-bound AEAD, password-encrypted private keys, and optional ML-DSA-65 signatures checked against caller-trusted public keys. Signature-required mode rejects unsigned or invalidly signed input. Replay, revocation, public-key distribution, and trust-store management remain unimplemented. A signature proves possession of the signing key, not that its owner reviewed the plaintext. Classical and hybrid modes enforce caller-selected suites with no fallback. The hybrid strict variant rejects low-order X25519 inputs; the classical baseline is not quantum-resistant. Refine this model alongside future features.
