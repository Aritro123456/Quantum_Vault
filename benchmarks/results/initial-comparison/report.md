# QuantumVault measured benchmark report

Run: 2026-10-26T21:16:33.148560+00:00

Python 3.12.1; Windows-11-10.0.26300-SP0; AMD64
CPU: Intel64 Family 6 Model 183 Stepping 1, GenuineIntel (20 logical processors)
cryptography 50.0.2; OpenSSL 4.0.3 29 Sep 2026
Source SHA-256: a5a7b69c6480aa615287ece8fc860395c9c9b4a1574f3db0e10b3ce41deaabde

30 samples per case after 3 warmups. Times are milliseconds; p95 uses nearest rank. Raw nanosecond samples are in results.json.

Sequential in-memory operations; no disk I/O, password KDF timing, network, or process startup.
Fixed mode/payload order; shared keys and decapsulation ciphertext reused per case; fresh encapsulation/nonce on encryption.
Single local run; noisy machine-dependent timings; modes do not have equivalent security claims; signing always ML-DSA-65.

## Key establishment

| Mode | Operation | Median ms | p95 ms | Min ms | Max ms |
| --- | --- | ---: | ---: | ---: | ---: |
| ML-DSA-65 | signing_key_generation | 0.125200 | 0.206400 | 0.118800 | 0.227500 |
| postquantum | recipient_key_generation | 0.109800 | 0.121100 | 0.109100 | 0.121400 |
| postquantum | encapsulation | 0.028200 | 0.032200 | 0.027900 | 0.042900 |
| postquantum | decapsulation | 0.042350 | 0.046900 | 0.042000 | 0.051400 |
| classical | recipient_key_generation | 0.024950 | 0.036300 | 0.023700 | 0.037200 |
| classical | encapsulation | 0.052800 | 0.085300 | 0.049900 | 0.093600 |
| classical | decapsulation | 0.026100 | 0.027000 | 0.024900 | 0.027100 |
| hybrid | recipient_key_generation | 0.829150 | 0.990300 | 0.265500 | 1.014800 |
| hybrid | encapsulation | 0.540700 | 0.710400 | 0.534000 | 0.715500 |
| hybrid | decapsulation | 0.505700 | 0.662600 | 0.500800 | 0.684000 |

## Payload operations

| Mode | Operation | Payload bytes | Median ms | p95 ms |
| --- | --- | ---: | ---: | ---: |
| ML-DSA-65 | sign_message | 78 | 0.390200 | 1.752000 |
| ML-DSA-65 | verify_message | 78 | 0.109700 | 0.111800 |
| postquantum | encrypt_envelope | 0 | 0.053350 | 0.067000 |
| postquantum | decrypt_envelope | 0 | 0.084650 | 0.107000 |
| postquantum | sign_envelope | 0 | 0.525300 | 1.336300 |
| postquantum | verify_envelope | 0 | 0.150950 | 0.180600 |
| postquantum | encrypt_envelope | 1024 | 0.063150 | 0.163600 |
| postquantum | decrypt_envelope | 1024 | 0.097100 | 0.178700 |
| postquantum | sign_envelope | 1024 | 0.562800 | 1.290300 |
| postquantum | verify_envelope | 1024 | 0.159600 | 0.242300 |
| postquantum | encrypt_envelope | 65536 | 0.359450 | 0.475100 |
| postquantum | decrypt_envelope | 65536 | 0.380450 | 0.424000 |
| postquantum | sign_envelope | 65536 | 0.946950 | 1.805100 |
| postquantum | verify_envelope | 65536 | 0.599450 | 0.730000 |
| postquantum | encrypt_envelope | 1048576 | 6.840050 | 7.738000 |
| postquantum | decrypt_envelope | 1048576 | 8.003200 | 8.587200 |
| postquantum | sign_envelope | 1048576 | 10.502600 | 11.477300 |
| postquantum | verify_envelope | 1048576 | 10.750850 | 12.707100 |
| classical | encrypt_envelope | 0 | 0.071150 | 0.135800 |
| classical | decrypt_envelope | 0 | 0.051750 | 0.069700 |
| classical | sign_envelope | 0 | 0.443950 | 2.260100 |
| classical | verify_envelope | 0 | 0.165850 | 0.340100 |
| classical | encrypt_envelope | 1024 | 0.079150 | 0.257500 |
| classical | decrypt_envelope | 1024 | 0.056250 | 0.092700 |
| classical | sign_envelope | 1024 | 0.843250 | 2.422200 |
| classical | verify_envelope | 1024 | 0.183150 | 0.395300 |
| classical | encrypt_envelope | 65536 | 0.380950 | 0.612400 |
| classical | decrypt_envelope | 65536 | 0.391950 | 0.668700 |
| classical | sign_envelope | 65536 | 0.871200 | 1.433100 |
| classical | verify_envelope | 65536 | 0.606400 | 0.753500 |
| classical | encrypt_envelope | 1048576 | 6.870300 | 8.099300 |
| classical | decrypt_envelope | 1048576 | 38.244750 | 49.438400 |
| classical | sign_envelope | 1048576 | 61.226250 | 102.258500 |
| classical | verify_envelope | 1048576 | 52.656300 | 59.409900 |
| hybrid | encrypt_envelope | 0 | 0.764700 | 0.878800 |
| hybrid | decrypt_envelope | 0 | 0.882350 | 1.017600 |
| hybrid | sign_envelope | 0 | 3.510450 | 9.320500 |
| hybrid | verify_envelope | 0 | 1.034250 | 1.260800 |
| hybrid | encrypt_envelope | 1024 | 0.818950 | 1.396100 |
| hybrid | decrypt_envelope | 1024 | 0.971050 | 1.407600 |
| hybrid | sign_envelope | 1024 | 3.539450 | 9.438400 |
| hybrid | verify_envelope | 1024 | 1.116900 | 1.616900 |
| hybrid | encrypt_envelope | 65536 | 2.322650 | 2.829700 |
| hybrid | decrypt_envelope | 65536 | 2.841450 | 3.168900 |
| hybrid | sign_envelope | 65536 | 5.973850 | 12.326700 |
| hybrid | verify_envelope | 65536 | 3.856400 | 4.341400 |
| hybrid | encrypt_envelope | 1048576 | 21.800500 | 32.002000 |
| hybrid | decrypt_envelope | 1048576 | 40.821500 | 42.041100 |
| hybrid | sign_envelope | 1048576 | 56.202650 | 63.776500 |
| hybrid | verify_envelope | 1048576 | 52.229000 | 67.137000 |
| AES-256-GCM | bulk_encrypt_with_nonce_generation | 0 | 0.015500 | 0.019500 |
| AES-256-GCM | bulk_decrypt | 0 | 0.012900 | 0.013200 |
| AES-256-GCM | bulk_encrypt_with_nonce_generation | 1024 | 0.016700 | 0.107400 |
| AES-256-GCM | bulk_decrypt | 1024 | 0.014200 | 0.024900 |
| AES-256-GCM | bulk_encrypt_with_nonce_generation | 65536 | 0.065450 | 0.094500 |
| AES-256-GCM | bulk_decrypt | 65536 | 0.063300 | 0.091800 |
| AES-256-GCM | bulk_encrypt_with_nonce_generation | 1048576 | 1.947300 | 2.511600 |
| AES-256-GCM | bulk_decrypt | 1048576 | 1.855000 | 2.391600 |

## Storage sizes

| Mode | Payload | Public key | Private seed components | Protected private file | Encapsulation | Envelope | Overhead | Detached signature file | Signed total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| postquantum | 0 | 1184 | 64 | 343 | 1088 | 1764 | 1764 | 4585 | 6349 |
| postquantum | 1024 | 1184 | 64 | 343 | 1088 | 3128 | 2104 | 4585 | 7713 |
| postquantum | 65536 | 1184 | 64 | 343 | 1088 | 89144 | 23608 | 4585 | 93729 |
| postquantum | 1048576 | 1184 | 64 | 343 | 1088 | 1399864 | 351288 | 4585 | 1404449 |
| classical | 0 | 32 | 32 | 302 | 32 | 352 | 352 | 4585 | 4937 |
| classical | 1024 | 32 | 32 | 302 | 32 | 1716 | 692 | 4585 | 6301 |
| classical | 65536 | 32 | 32 | 302 | 32 | 87732 | 22196 | 4585 | 92317 |
| classical | 1048576 | 32 | 32 | 302 | 32 | 1398452 | 349876 | 4585 | 1403037 |
| hybrid | 0 | 1216 | 96 | 792 | 1120 | 1814 | 1814 | 4585 | 6399 |
| hybrid | 1024 | 1216 | 96 | 792 | 1120 | 3178 | 2154 | 4585 | 7763 |
| hybrid | 65536 | 1216 | 96 | 792 | 1120 | 89194 | 23658 | 4585 | 93779 |
| hybrid | 1048576 | 1216 | 96 | 792 | 1120 | 1399914 | 351338 | 4585 | 1404499 |

ML-DSA-65 public key: 1952 bytes; signature: 3309 bytes; private seed: 32 bytes; protected private file: 302 bytes.

Private component sizes describe the actual stored seed representation, not expanded mathematical key sizes. Protected-file sizes include serialization and password-encryption overhead; password protection time is not measured.

## Interpretation and limits

- Envelope overhead includes base64/JSON expansion and cryptographic metadata, not just KEM bytes.
- Encrypt/decrypt envelope timings include KEM, HKDF, AES-GCM and serialization/parsing. Bulk cipher rows isolate AES-GCM.
- Envelope signing/verification includes envelope validation, serialization and ML-DSA operations. Payload bytes refer to the original plaintext size.
- Fixed-message signing rows measure context-separated ML-DSA separately; all three encryption modes use that same signature algorithm.
- Hybrid is the experimental XWING-D10-STRICT variant documented in docs/encryption_modes.md. These timings do not measure security strength.
- No deployment recommendation follows from speed alone. Validate trust distribution, key lifecycle, file limits and compatibility for the intended use.

Run-specific observation: substantial variation occurred across the fixed-order cases, including operations sharing the same ML-DSA algorithm. Treat this as a recorded local run, not evidence of a reliable mode speed ranking.
