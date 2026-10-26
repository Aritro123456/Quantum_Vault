import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from quantum_vault.benchmarks.runner import summarize, measure, run_benchmarks
from quantum_vault.reporting.benchmarks import export_results


class BenchmarkTests(unittest.TestCase):
    def test_statistics_and_warmup_exclusion(self):
        stats = summarize([1000000, 2000000, 3000000, 4000000, 100000000])
        self.assertEqual(stats['median_ms'], 3)
        self.assertEqual(stats['p95_ms'], 100)
        calls, validations = [], []
        with patch('quantum_vault.benchmarks.runner.time.perf_counter_ns', side_effect=[0,999,1000,1010,2000,2020]):
            result = measure(lambda: calls.append(1), 2, 1, lambda value: validations.append(value))
        self.assertEqual(result['samples_ns'], [10,20])
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(validations), 3)

    def test_invalid_config_fails_before_crypto(self):
        for config in ({'repetitions':0}, {'repetitions':True}, {'warmup':-1}, {'sizes':[]}, {'sizes':[1,1]}, {'sizes':[1048577]}, {'modes':['invalid']}, {'modes':['hybrid','hybrid']}, {'repetitions':500, 'sizes':[1048576]}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                run_benchmarks(**config)
        for samples in ([], [-1], [True]):
            with self.assertRaises(ValueError):
                summarize(samples)

    def test_small_benchmark_exports_consistent_public_results(self):
        result = run_benchmarks(repetitions=2, warmup=0, sizes=[0,64], modes=['classical','hybrid'])
        self.assertEqual(result['schema_version'], 1)
        self.assertEqual(len(result['sizes']), 4)
        for row in result['timings']:
            self.assertEqual(len(row['samples_ns']), 2)
            self.assertEqual(row['median_ms'], summarize(row['samples_ns'])['median_ms'])
        for row in result['sizes']:
            self.assertEqual(row['signed_total_bytes'], row['envelope_bytes'] + row['detached_signature_file_bytes'])
            self.assertEqual(row['envelope_overhead_bytes'], row['envelope_bytes'] - row['payload_bytes'])
        self.assertEqual(result['signer_sizes']['signature_bytes'], 3309)
        serialized = json.dumps(result)
        self.assertNotIn('BEGIN ENCRYPTED PRIVATE KEY', serialized)
        self.assertNotIn('shared_secret', serialized)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'run'
            export_results(result, output)
            self.assertEqual(json.loads((output/'results.json').read_text()), result)
            rows = list(csv.DictReader(io.StringIO((output/'summary.csv').read_text())))
            self.assertEqual(len(rows), len(result['timings']))
            self.assertIn('Single local run', (output/'report.md').read_text())
            with self.assertRaises(FileExistsError):
                export_results(result, output)
