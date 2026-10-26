# Verification

Run `.\.venv\Scripts\python.exe run_tests.py`. Current suite has 35 passing tests covering KEM agreement, file round trips, randomized encapsulations, every authenticated header field and ciphertext tampering, wrong recipient keys, malformed envelopes, file limits, encrypted-key persistence, and overwrite/output safety.

Three published draft vectors validate hybrid key generation and decapsulation. Full deterministic encapsulation vectors and cross-provider interoperability remain future work. Signature tests cover wrong keys, tampering, exact-byte binding, context separation, encrypted-key purpose checks, fail-closed decryption, and the full CLI workflow.

Benchmark tests validate known timing statistics, warmup exclusion, invalid configuration rejection, result/export consistency, output-directory protection, and the benchmark CLI.
