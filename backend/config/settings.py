"""Local dashboard settings. Bind servers to loopback; no key persistence."""
import os
import secrets
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BASE_DIR.parent
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY') or secrets.token_urlsafe(48)
DEBUG = False
ALLOWED_HOSTS = ['127.0.0.1', 'localhost', 'testserver']
ROOT_URLCONF = 'config.urls'
INSTALLED_APPS = []
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'api.middleware.NoStoreMiddleware',
]
CSRF_TRUSTED_ORIGINS = ['http://127.0.0.1:3000', 'http://localhost:3000']
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_FAILURE_VIEW = 'api.views.csrf_failure'
FILE_UPLOAD_HANDLERS = ['django.core.files.uploadhandler.MemoryFileUploadHandler']
FILE_UPLOAD_MAX_MEMORY_SIZE = 34 * 1024 * 1024
DATA_UPLOAD_MAX_MEMORY_SIZE = 34 * 1024 * 1024
DATA_UPLOAD_MAX_NUMBER_FILES = 5
SECURE_CONTENT_TYPE_NOSNIFF = True
DEFAULT_CHARSET = 'utf-8'
USE_TZ = True
