import io
import json
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch
from django.test import SimpleTestCase, Client, override_settings
from django.core.files.uploadedfile import SimpleUploadedFile
from quantum_vault.crypto.key_establishment.operations import generate_encryption_key
from quantum_vault.crypto.signatures.mldsa import generate_signing_key
from quantum_vault.keys.encryption import serialize_encryption_private
from quantum_vault.keys.manager import serialize_private
from quantum_vault.services.files import encrypt_bytes
from quantum_vault.services.signing import sign_envelope


def file(name, data):
    return SimpleUploadedFile(name, data, content_type='application/octet-stream')


class ApiTests(SimpleTestCase):
    def test_overview_and_csrf(self):
        client=Client(enforce_csrf_checks=True)
        self.assertEqual(client.post('/api/keys',{}).status_code,403)
        session=client.get('/api/session')
        self.assertIn('csrfToken',session.json())
        self.assertEqual(client.get('/api/overview').status_code,200)
        response=client.get('/api/overview')
        self.assertEqual(response['Cache-Control'],'no-store, private')
        token=session.json()['csrfToken']
        denied=client.post('/api/keys', {'password':'test-password-2026'}, HTTP_X_CSRFTOKEN=token,HTTP_ORIGIN='https://untrusted.example')
        self.assertEqual(denied.status_code,403)
        allowed=client.post('/api/keys', {'password':'test-password-2026'}, HTTP_X_CSRFTOKEN=token,HTTP_ORIGIN='http://127.0.0.1:3000')
        self.assertEqual(allowed.status_code,200)

    def test_key_download_and_encryption_all_modes(self):
        for mode in ('classical','postquantum','hybrid'):
            response=self.client.post('/api/keys',{'mode':mode,'password':'test-password-2026'})
            self.assertEqual(response.status_code,200,response.content[:100])
            with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                public=archive.read(mode+'.pub')
                private=archive.read(mode+'-private.'+('json' if mode=='hybrid' else 'pem'))
            encrypted=self.client.post('/api/crypto/encrypt',{'mode':mode,'file':file('sample.txt',b'API fixture'), 'key':file('key.pub',public)})
            self.assertEqual(encrypted.status_code,200)
            decrypted=self.client.post('/api/crypto/decrypt',{'mode':mode,'file':file('envelope.qv',encrypted.content),'key':file('private.key',private),'password':'test-password-2026','require_signature':'false'})
            self.assertEqual(decrypted.status_code,200,decrypted.content[:100])
            self.assertEqual(decrypted.content,b'API fixture')

    def test_signed_api_workflow(self):
        recipient=generate_encryption_key('hybrid')
        signer=generate_signing_key()
        envelope=encrypt_bytes(b'signed API fixture',recipient.public_key(),'hybrid')
        signature=self.client.post('/api/crypto/sign',{'mode':'hybrid','file':file('envelope',envelope),'key':file('signer.pem',serialize_private(signer,b'test-password-2026')),'password':'test-password-2026'})
        self.assertEqual(signature.status_code,200)
        verified=self.client.post('/api/crypto/verify',{'file':file('envelope',envelope),'key':file('signer.pub',signer.public_key().public_bytes_raw()),'signature':file('signature',signature.content)})
        self.assertTrue(verified.json()['verified'])
        def decrypt(sig):
            return self.client.post('/api/crypto/decrypt',{'mode':'hybrid','file':file('envelope',envelope),'key':file('recipient',serialize_encryption_private(recipient,b'test-password-2026','hybrid')),'password':'test-password-2026','signature':file('signature',sig),'signer_key':file('signer.pub',signer.public_key().public_bytes_raw())})
        self.assertEqual(decrypt(signature.content).content,b'signed API fixture')
        rejected=decrypt(b'{}')
        self.assertEqual(rejected.status_code,400)
        self.assertNotIn(b'signed API fixture',rejected.content)

    def test_invalid_inputs_and_wrong_mode(self):
        self.assertEqual(self.client.post('/api/keys',{'password':'short'}).status_code,400)
        self.assertEqual(self.client.post('/api/keys',{'password':'test-password-2026','mode':'unknown'}).status_code,400)
        self.assertEqual(self.client.post('/api/crypto/encrypt',{}).status_code,400)
        self.assertEqual(self.client.post('/api/crypto/unknown',{}).status_code,404)
        recipient=generate_encryption_key()
        encrypted=encrypt_bytes(b'sample',recipient.public_key())
        response=self.client.post('/api/crypto/decrypt',{'file':file('envelope',encrypted),'key':file('recipient',serialize_private(recipient,b'test-password-2026')),'password':'test-password-2026'})
        self.assertEqual(response.status_code,400) # Signature required by default.
        oversized=self.client.post('/api/crypto/encrypt',{'file':file('big',b'x'*(16*1024*1024+1))})
        self.assertEqual(oversized.status_code,400)

    def test_benchmark_history_and_report(self):
        with tempfile.TemporaryDirectory() as directory, override_settings(PROJECT_ROOT=Path(directory)):
            created=self.client.post('/api/benchmarks',{'repetitions':'1'})
            self.assertEqual(created.status_code,201,created.content[:100])
            run_id=created.json()['id']
            self.assertEqual(len(self.client.get('/api/benchmarks').json()['runs']),1)
            self.assertEqual(self.client.get('/api/benchmarks/'+run_id).status_code,200)
            self.assertEqual(self.client.get('/api/benchmarks/'+run_id+'/report').status_code,200)
            self.assertEqual(self.client.get('/api/benchmarks/missing').status_code,404)
            self.assertEqual(self.client.post('/api/benchmarks',{'repetitions':100}).status_code,400)
