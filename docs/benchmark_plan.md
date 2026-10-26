# Benchmark methodology

The benchmark CLI is implemented in quantum_vault/benchmarks/runner.py with JSON, CSV, and Markdown exports from reporting/benchmarks.py. No extra runtime packages are needed.

## Defaults and reproducibility

30 measured repetitions per case after 3 warmups; sequential fixed mode/payload order; sizes 0, 1 KiB, 64 KiB, and 1 MiB. Synthetic payload creation and test validation are outside the timed regions. Cryptographic randomness remains fresh, so reproducibility means repeatable configuration and raw evidence, not identical keys or durations.

Each result records Python/OS/CPU architecture, provider and linked OpenSSL versions, logical CPU count, UTC timestamp, source-tree SHA-256, configuration, elapsed run duration, and every sample in nanoseconds. No hostnames, user paths, passwords, private/public key values, shared secrets, or file contents are exported. CPU descriptions may be generic on Windows.

Clock: time.perf_counter_ns. Report median, nearest-rank p95, min/max, and population standard deviation. With very few samples, p95 can equal the maximum. Samples represent one operation each; timer/call overhead is not subtracted. Fixed ordering, scheduling, thermal state, caching and machine load can bias comparisons; repeat runs before generalizing.

## Timed operations

- Recipient key generation per mode; ML-DSA signing-key generation separately.
- Encapsulation and decapsulation separately. Recipient keys and decapsulation ciphertexts are reused per case; encapsulation uses fresh randomness.
- Fixed-message ML-DSA signing/verification separately using the application signature context.
- Complete in-memory encrypt/decrypt envelope workflows: KEM, HKDF, AES-GCM, JSON/base64, validation and fingerprint work as applicable.
- Detached envelope signing/verification including parsing and metadata serialization.
- Isolated AES-GCM encryption (including fresh nonce generation) and decryption.

Verification and round-trip correctness checks are performed after every timed operation where output can be checked. Key generation is measured without serialization/password encryption. Disk I/O, password KDFs, network, process startup and UI are excluded. No end-to-end disk throughput or whole signed-session latency is claimed.

## Size measurements

Public-key bytes, actual stored private seed-component sizes, password-encrypted private-file sizes, encapsulation bytes, raw signature bytes, detached signature JSON sizes, encrypted envelope bytes, overhead bytes, and signed envelope-plus-signature totals. Hybrid private-component size counts two stored seeds rather than a compact draft seed or expanded key. Serialization sizes do not measure password-encryption time. Base64/JSON overhead grows with payload size.

## Bounds and interpretation

CLI accepts 1-500 repetitions, 0-100 warmups, up to eight unique sizes within 0-1 MiB, and unique supported modes. Aggregate configured payload workload is bounded; this is a configuration guard, not a total-byte-processing limit across every operation.

The modes do not imply identical security strengths. Classical key establishment is X25519; hybrid is the documented experimental strict variant. Every mode uses ML-DSA-65 for signing, so this is not a classical-vs-post-quantum signature comparison. Performance cannot establish security, cryptographic conformance, or migration readiness.
