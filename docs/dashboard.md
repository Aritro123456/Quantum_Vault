# Next.js + Django dashboard

The dashboard uses Next.js App Router, React, TypeScript, and CSS in frontend/. Django in backend/ imports the existing src/quantum_vault engine. The CLI remains available. Streamlit is not used.

## Start locally (two PowerShell terminals)

From quantum-vault:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv\Scripts\python.exe backend/manage.py runserver 127.0.0.1:8001 --noreload
```

In the second terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open http://127.0.0.1:3000 . Next.js rewrites /api requests to Django on 127.0.0.1:8001. No database or migration is required for this stateless local version. The two servers must both be running. No external service credentials are required.

## Capabilities

- Overview uses the latest actual benchmark results and engine capability limits.
- File workspace encrypts/decrypts, creates detached signatures, and verifies signatures.
- Signature-required decryption is the dashboard default; unsigned mode is explicit.
- Key generation downloads a ZIP with encrypted private key, raw public key, and fingerprint.
- Benchmark view selects existing runs, compares operations, downloads reports, and runs small local comparisons.
- Session activity records only completed operation labels in browser memory; no persistent file history.

## API contract

GET /api/session returns a CSRF token and cookie. All POST requests require X-CSRFToken and use multipart FormData. Next.js proxies same-origin requests; no permissive CORS policy or CSRF exemptions are used.

- GET /api/overview: modes, size limit, benchmark history, latest measurements.
- POST /api/keys: purpose (encryption/signing), mode, password; returns ZIP.
- POST /api/crypto/encrypt: file, key (public), mode; returns .qv.
- POST /api/crypto/decrypt: file, key (private), password, mode, require_signature (true by default); when true, signature and signer_key are required; returns plaintext only after validation.
- POST /api/crypto/sign: file (encrypted envelope), key (signer private), password; returns detached signature.
- POST /api/crypto/verify: file, key (trusted signer public), signature; returns verification status/fingerprint.
- GET /api/benchmarks: persisted public measurement history.
- POST /api/benchmarks: repetitions (1-10, default 5); runs 1 KiB/64 KiB comparisons and persists public results.
- GET /api/benchmarks/<run_id>: measured data.
- GET /api/benchmarks/<run_id>/report: Markdown report download.

Uploads are processed in memory; private keys, passwords, and plaintext are never written to application storage. Cryptography runs server-side, so those values do pass through the local Django process. Responses use no-store headers. Downloaded files are stored by the browser according to its download settings. Benchmark artifacts contain public measurements only.

This is a loopback-only personal research app without login or multi-user isolation. Do not expose these development servers publicly. Use the existing CLI for the 16 MiB maximum file workflow; dashboard encryption uses the same limit. Public deployment would need authenticated access, HTTPS, resource isolation/limits, and production server configuration.

## Verification commands

```powershell
.\.venv\Scripts\python.exe run_tests.py
.\.venv\Scripts\python.exe backend/manage.py test api
.\.venv\Scripts\python.exe backend/manage.py check
cd frontend
npm run typecheck
npm run build
```

Five Django API tests cover CSRF, untrusted origins, file round trips in all modes, encrypted key downloads, signed workflows, invalid input/limits, benchmark persistence, and report download. The core engine has 35 tests.

## Browser verification

Verified the rendered overview loads real measurements through the Next.js rewrite. Running a comparison returned HTTP 201 from Django, saved a new run, and updated the chart to 200 measured samples. Browser key generation downloaded an encrypted key ZIP and displayed the returned fingerprint. Both servers bind to 127.0.0.1. The frontend production build and 35 core plus 5 API tests pass.
