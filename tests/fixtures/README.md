# Public conformance fixtures

xwing-draft-10.txt is the official draft snapshot downloaded from https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.txt . Its Appendix C supplies the three public test vectors in xwing_draft10_vectors.json. These seeds are test material only. No executable reference code from the draft is run.

Snapshot SHA-256: 530900ac0519e28eb1ff50bf80ecdb7648add22e500db72b465bab4fb6b6a5ec

Tests verify key generation and decapsulation, not deterministic encapsulation or all edge cases of the draft. Our strict low-order rejection is an intentional difference.
