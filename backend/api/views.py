"""Stateless local file operations. Uploaded keys and plaintext are not saved."""
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.http import require_GET, require_http_methods, require_POST
from quantum_vault.crypto.key_establishment.operations import generate_encryption_key
from quantum_vault.crypto.key_establishment.suites import SUITES, PUBLIC_LENGTHS
from quantum_vault.crypto.signatures.mldsa import generate_signing_key, load_signing_private, load_signing_public
from quantum_vault.keys.encryption import serialize_encryption_private, load_encryption_private, load_encryption_public
from quantum_vault.keys.manager import key_id, serialize_private
from quantum_vault.envelope.format import MAX_ENVELOPE, MAX_PLAINTEXT
from quantum_vault.services.files import encrypt_bytes, decrypt_bytes
from quantum_vault.services.signing import sign_envelope, verify_envelope, MAX_SIGNATURE_FILE
from quantum_vault.benchmarks.runner import run_benchmarks
from quantum_vault.reporting.benchmarks import export_results


def csrf_failure(request, reason=''):
    return JsonResponse({'error': 'Request verification failed. Refresh the page and try again.'}, status=403)


def guarded(fn):
    @wraps(fn)
    def wrapped(request, *args, **kwargs):
        try:
            return fn(request, *args, **kwargs)
        except (ValueError, TypeError, UnicodeError) as exc:
            return JsonResponse({'error': str(exc)}, status=400)
        except (OSError, RuntimeError):
            return JsonResponse({'error': 'Operation unavailable. Check the local backend terminal.'}, status=503)
    return wrapped


def mode_from(request):
    mode = request.POST.get('mode', 'postquantum')
    if mode not in SUITES:
        raise ValueError('Choose a supported encryption mode.')
    return mode


def upload(request, name, limit):
    item = request.FILES.get(name)
    if item is None:
        raise ValueError(f'Missing {name.replace("_", " ")} file.')
    if item.size > limit:
        raise ValueError(f'{name.replace("_", " ").capitalize()} exceeds the allowed size.')
    return item.read()


def download(data, filename, content_type='application/octet-stream'):
    response = HttpResponse(data, content_type=content_type)
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


def result_root():
    return settings.PROJECT_ROOT / 'benchmarks' / 'results'


def runs():
    root = result_root()
    if not root.exists():
        return []
    result = []
    for folder in root.iterdir():
        if folder.is_dir() and re.fullmatch(r'[A-Za-z0-9_-]+', folder.name) and (folder/'results.json').is_file():
            try:
                data = json.loads((folder/'results.json').read_text(encoding='utf-8'))
                result.append({'id': folder.name, 'created_at_utc': data['created_at_utc'],
                    'cases': len(data['timings']), 'samples': sum(len(t['samples_ns']) for t in data['timings']),
                    'repetitions': data['configuration']['repetitions']})
            except (ValueError, KeyError, TypeError, OSError):
                continue
    return sorted(result, key=lambda run: run['created_at_utc'], reverse=True)


def load_run(run_id):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', run_id):
        raise ValueError('Invalid run identifier.')
    path = result_root() / run_id / 'results.json'
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


@require_GET
def session(request):
    return JsonResponse({'csrfToken': get_token(request), 'service': 'QuantumVault Django API'})


@require_GET
@guarded
def overview(request):
    history = runs()
    latest = load_run(history[0]['id']) if history else None
    return JsonResponse({'modes': [{'id': mode, 'suite': suite} for mode, suite in SUITES.items()],
        'max_plaintext_bytes': MAX_PLAINTEXT, 'signature_algorithm': 'ML-DSA-65',
        'runs': history, 'latest': latest, 'local_only': True})


@require_POST
@guarded
def keys(request):
    mode = mode_from(request)
    purpose = request.POST.get('purpose', 'encryption')
    if purpose not in ('encryption', 'signing'):
        raise ValueError('Choose encryption or signing keys.')
    password = request.POST.get('password', '').encode('utf-8')
    key = generate_signing_key() if purpose == 'signing' else generate_encryption_key(mode)
    protected = serialize_private(key, password) if purpose == 'signing' else serialize_encryption_private(key, password, mode)
    fingerprint = key_id(key.public_key())
    extension = 'json' if purpose == 'encryption' and mode == 'hybrid' else 'pem'
    label = 'signer' if purpose == 'signing' else mode
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f'{label}-private.{extension}', protected)
        archive.writestr(f'{label}.pub', key.public_key().public_bytes_raw())
        archive.writestr('fingerprint.txt', f'Purpose: {purpose}\nMode: {mode if purpose == "encryption" else "ML-DSA-65"}\nSHA-256: {fingerprint}\nVerify this fingerprint with your recipient through a trusted channel.\n')
    response = download(buffer.getvalue(), f'quantumvault-{label}-keys.zip', 'application/zip')
    response['X-Key-Fingerprint'] = fingerprint
    return response


@require_POST
@guarded
def crypto(request, action):
    mode = mode_from(request)
    if action not in ('encrypt', 'decrypt', 'sign', 'verify'):
        return JsonResponse({'error': 'Unknown operation.'}, status=404)
    data = upload(request, 'file', MAX_PLAINTEXT if action == 'encrypt' else MAX_ENVELOPE)
    password = request.POST.get('password', '').encode('utf-8')
    if action == 'encrypt':
        public = load_encryption_public(upload(request, 'key', PUBLIC_LENGTHS[mode]), mode)
        return download(encrypt_bytes(data, public, mode), 'encrypted.qv')
    if action == 'decrypt':
        if request.POST.get('require_signature', 'true') not in ('true', 'false'):
            raise ValueError('Invalid signature requirement.')
        if request.POST.get('require_signature', 'true') == 'true':
            signature = upload(request, 'signature', MAX_SIGNATURE_FILE)
            signer = load_signing_public(upload(request, 'signer_key', 1952))
            verify_envelope(data, signature, signer)
        private = load_encryption_private(upload(request, 'key', 16384), password, mode)
        return download(decrypt_bytes(data, private, mode), 'decrypted.bin')
    if action == 'sign':
        private = load_signing_private(upload(request, 'key', 16384), password)
        return download(sign_envelope(data, private), 'envelope.qvsig')
    signature = upload(request, 'signature', MAX_SIGNATURE_FILE)
    public = load_signing_public(upload(request, 'key', 1952))
    verify_envelope(data, signature, public)
    return JsonResponse({'verified': True, 'fingerprint': key_id(public), 'message': 'Signature verified against the supplied trusted signer.'})


@require_http_methods(['GET', 'POST'])
@guarded
def benchmarks(request):
    if request.method == 'GET':
        return JsonResponse({'runs': runs()})
    repetitions = int(request.POST.get('repetitions', 5))
    if not 1 <= repetitions <= 10:
        raise ValueError('Dashboard benchmarks support 1-10 repetitions.')
    result = run_benchmarks(repetitions=repetitions, warmup=1, sizes=[1024, 65536])
    run_id = datetime.now(timezone.utc).strftime('dashboard-%Y%m%dT%H%M%S%fZ')
    export_results(result, result_root()/run_id)
    return JsonResponse({'id': run_id, 'result': result}, status=201)


@require_GET
@guarded
def benchmark_detail(request, run_id):
    data = load_run(run_id)
    if data is None:
        return JsonResponse({'error': 'Benchmark run not found.'}, status=404)
    return JsonResponse(data)


@require_GET
@guarded
def benchmark_report(request, run_id):
    if load_run(run_id) is None:
        return JsonResponse({'error': 'Benchmark run not found.'}, status=404)
    return download((result_root()/run_id/'report.md').read_bytes(), 'quantumvault-benchmark.md', 'text/markdown')
