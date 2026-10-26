"""Human-readable comparison and CSV summaries from measured benchmark records."""
import csv
import io
import json
from quantum_vault.services.files import write_new


def summary_csv(result):
    buffer = io.StringIO(newline='')
    fields = ['mode', 'operation', 'payload_bytes', 'repetitions', 'warmup',
              'median_ms', 'p95_ms', 'min_ms', 'max_ms', 'stdev_ms']
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    writer.writerows(result['timings'])
    return buffer.getvalue()


def markdown_report(result):
    env, config = result['environment'], result['configuration']
    lines = ['# QuantumVault measured benchmark report', '',
        f"Run: {result['created_at_utc']}", '',
        f"Python {env['python']}; {env['os']}; {env['architecture']}",
        f"CPU: {env['cpu']} ({env['logical_cpu_count']} logical processors)",
        f"cryptography {env['cryptography']}; {env['openssl']}",
        f"Source SHA-256: {env['source_sha256']}", '',
        f"{config['repetitions']} samples per case after {config['warmup']} warmups. "
        'Times are milliseconds; p95 uses nearest rank. Raw nanosecond samples are in results.json.', '',
        config['scope'], config['order'], config['limitations'], '',
        '## Key establishment', '',
        '| Mode | Operation | Median ms | p95 ms | Min ms | Max ms |',
        '| --- | --- | ---: | ---: | ---: | ---: |']
    for row in result['timings']:
        if row['payload_bytes'] is None:
            lines.append(f"| {row['mode']} | {row['operation']} | {row['median_ms']:.6f} | {row['p95_ms']:.6f} | {row['min_ms']:.6f} | {row['max_ms']:.6f} |")
    lines += ['', '## Payload operations', '',
              '| Mode | Operation | Payload bytes | Median ms | p95 ms |',
              '| --- | --- | ---: | ---: | ---: |']
    for row in result['timings']:
        if row['payload_bytes'] is not None:
            lines.append(f"| {row['mode']} | {row['operation']} | {row['payload_bytes']} | {row['median_ms']:.6f} | {row['p95_ms']:.6f} |")
    lines += ['', '## Storage sizes', '',
        '| Mode | Payload | Public key | Private seed components | Protected private file | Encapsulation | Envelope | Overhead | Detached signature file | Signed total |',
        '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for row in result['sizes']:
        lines.append('| ' + ' | '.join(str(row[k]) for k in ('mode','payload_bytes','public_key_bytes',
            'stored_private_component_seed_bytes','protected_private_file_bytes','encapsulation_bytes',
            'envelope_bytes','envelope_overhead_bytes','detached_signature_file_bytes','signed_total_bytes')) + ' |')
    signer = result['signer_sizes']
    lines += ['', f"ML-DSA-65 public key: {signer['public_key_bytes']} bytes; signature: {signer['signature_bytes']} bytes; "
        f"private seed: {signer['private_seed_bytes']} bytes; protected private file: {signer['protected_private_file_bytes']} bytes.", '',
        'Private component sizes describe the actual stored seed representation, not expanded mathematical key sizes. '
        'Protected-file sizes include serialization and password-encryption overhead; password protection time is not measured.', '',
        '## Interpretation and limits', '',
        '- Envelope overhead includes base64/JSON expansion and cryptographic metadata, not just KEM bytes.',
        '- Encrypt/decrypt envelope timings include KEM, HKDF, AES-GCM and serialization/parsing. Bulk cipher rows isolate AES-GCM.',
        '- Envelope signing/verification includes envelope validation, serialization and ML-DSA operations. Payload bytes refer to the original plaintext size.',
        '- Fixed-message signing rows measure context-separated ML-DSA separately; all three encryption modes use that same signature algorithm.',
        '- Hybrid is the experimental XWING-D10-STRICT variant documented in docs/encryption_modes.md. These timings do not measure security strength.',
        '- No deployment recommendation follows from speed alone. Validate trust distribution, key lifecycle, file limits and compatibility for the intended use.', '']
    return '\n'.join(lines)


def export_results(result, output_dir):
    # A fresh run directory avoids overwriting prior measurements.
    output_dir.mkdir(parents=True, exist_ok=False)
    files = {'results.json': json.dumps(result, indent=2) + '\n',
             'summary.csv': summary_csv(result), 'report.md': markdown_report(result)}
    for name, content in files.items():
        write_new(output_dir / name, content.encode('utf-8'))
    return output_dir
