# dropvault/settings.py
from pathlib import Path
import os
import dj_database_url
import logging

logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).resolve().parent.parent

# ═══════════════════════════════════════════════════════════
# 🔧 ENVIRONMENT DETECTION (NO DOTENV NEEDED)
# ═══════════════════════════════════════════════════════════
IS_RAILWAY = os.environ.get('RAILWAY_ENVIRONMENT') is not None

print(f"✅ Starting DropVault settings...")
print(f"IS_RAILWAY: {IS_RAILWAY}")

# ═══════════════════════════════════════════════════════════
# 🔐 SECURITY SETTINGS
# ═══════════════════════════════════════════════════════════
SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-dev-key-change-this-in-production')
DEBUG = os.environ.get('DEBUG', 'True').lower() in ('true', '1', 't')

# ALLOWED_HOSTS
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1,.railway.app').split(',')
ALLOWED_HOSTS = [h.strip() for h in ALLOWED_HOSTS if h.strip()]

print(f"DEBUG: {DEBUG}")
print(f"ALLOWED_HOSTS: {ALLOWED_HOSTS}")

# Railway HTTPS Configuration
if IS_RAILWAY:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    USE_X_FORWARDED_HOST = True
    USE_X_FORWARDED_PORT = True

# ═══════════════════════════════════════════════════════════
# 📧 EMAIL CONFIGURATION
# ═══════════════════════════════════════════════════════════
EMAIL_BACKEND = os.environ.get('EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', '587'))
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'True').lower() == 'true'
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'noreply@dropvault.app')

# ═══════════════════════════════════════════════════════════
# 🗄️ DATABASE CONFIGURATION (Works for both Docker & Local)
# ═══════════════════════════════════════════════════════════
# Auto-detect if running in Docker or locally
import socket

def is_running_in_docker():
    """Check if we're running inside a Docker container"""
    # Method 1: Check for .dockerenv file
    if os.path.exists('/.dockerenv'):
        return True
    
    # Method 2: Check hostname (Docker containers have unique hostnames)
    try:
        hostname = socket.gethostname()
        if len(hostname) == 12 and all(c in '0123456789abcdef' for c in hostname):
            return True
    except:
        pass
    
    # Method 3: Check for Docker-specific environment variable
    if os.environ.get('DOCKER_CONTAINER'):
        return True
    
    return False

# Determine if we're in Docker
IN_DOCKER = is_running_in_docker()
print(f"🐳 Running in Docker: {IN_DOCKER}")

# Use DATABASE_URL if provided (Railway, Heroku, etc.)
DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL:
    DATABASES = {
        'default': dj_database_url.config(
            default=DATABASE_URL,
            conn_max_age=600,
            conn_health_checks=True,
        )
    }
    print("✅ Using DATABASE_URL from environment")
else:
    # Determine the correct host based on environment
    if IN_DOCKER:
        DB_HOST = 'db'  # Docker service name
        print("🐳 Using Docker database host: db")
    else:
        DB_HOST = 'localhost'  # Local PostgreSQL
        print("💻 Using local database host: localhost")
    
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.environ.get('DB_NAME', 'dropvault'),
            'USER': os.environ.get('DB_USER', 'postgres'),
            'PASSWORD': os.environ.get('DB_PASSWORD', 'postgres123'),
            'HOST': DB_HOST,
            'PORT': os.environ.get('DB_PORT', '5432'),
        }
    }
    
# ═══════════════════════════════════════════════════════════
# 📦 INSTALLED APPS
# ═══════════════════════════════════════════════════════════
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    'django.contrib.sites',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'rest_framework',
    'rest_framework.authtoken',
    'django_ratelimit',
    'django_otp',
    'django_otp.plugins.otp_totp',
    'django_otp.plugins.otp_static',
    'corsheaders',
    'accounts',
    'files',
]

# ═══════════════════════════════════════════════════════════
# 🔐 DJANGO-ALLAUTH SETTINGS
# ═══════════════════════════════════════════════════════════
SITE_ID = 1

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

# Updated settings for django-allauth 65+
ACCOUNT_LOGIN_METHODS = {'email'}
ACCOUNT_SIGNUP_FIELDS = ['email*', 'password1*', 'password2*']
ACCOUNT_EMAIL_VERIFICATION = 'optional'
ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION = True
ACCOUNT_LOGOUT_ON_GET = False

# Rate limits
ACCOUNT_RATE_LIMITS = {
    'login_failed': '5/5m',
}

LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/'
ACCOUNT_LOGOUT_REDIRECT_URL = '/'

# ═══════════════════════════════════════════════════════════
# 🌐 SITE URL CONFIGURATION
# ═══════════════════════════════════════════════════════════
SITE_URL = os.environ.get('SITE_URL', 'http://localhost:8000')

if IS_RAILWAY:
    railway_url = os.environ.get('RAILWAY_STATIC_URL') or os.environ.get('RAILWAY_PUBLIC_DOMAIN')
    if railway_url:
        SITE_URL = railway_url if railway_url.startswith('http') else f'https://{railway_url}'

print(f"SITE_URL: {SITE_URL}")

# ═══════════════════════════════════════════════════════════
# 🔒 PASSWORD VALIDATION
# ═══════════════════════════════════════════════════════════
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
]

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 8}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# ═══════════════════════════════════════════════════════════
# 🌐 MIDDLEWARE
# ═══════════════════════════════════════════════════════════
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'accounts.middleware.SessionCleanupMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django_otp.middleware.OTPMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'accounts.middleware.EmailVerificationMiddleware',
]

# ═══════════════════════════════════════════════════════════
# 🍪 SESSION CONFIGURATION
# ═══════════════════════════════════════════════════════════
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = 'dropvault_sessionid'
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = False  # Set True in production with HTTPS

# ═══════════════════════════════════════════════════════════
# 🔧 REQUEST SIZE CONFIGURATION
# ═══════════════════════════════════════════════════════════
# Fix for "Request Line is too large" error
DATA_UPLOAD_MAX_NUMBER_FIELDS = 10000
DATA_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 52428800  # 50MB

# Increase allowed header size for Gunicorn
SECURE_PROXY_SSL_HEADER = None
USE_X_FORWARDED_HOST = False

# ═══════════════════════════════════════════════════════════
# 🌍 CORS CONFIGURATION
# ═══════════════════════════════════════════════════════════
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

CORS_ALLOW_CREDENTIALS = True

# ═══════════════════════════════════════════════════════════
# 🗂️ STATIC & MEDIA FILES
# ═══════════════════════════════════════════════════════════
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# ═══════════════════════════════════════════════════════════
# 🔐 SECURITY SETTINGS
# ═══════════════════════════════════════════════════════════
if IS_RAILWAY:
    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
else:
    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 86400
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# ═══════════════════════════════════════════════════════════
# 🚀 UPLOAD LIMITS
# ═══════════════════════════════════════════════════════════
DATA_UPLOAD_MAX_MEMORY_SIZE = 5242880
FILE_UPLOAD_MAX_MEMORY_SIZE = 50 * 1024 * 1024

# ═══════════════════════════════════════════════════════════
# 🔴 CACHE (Use local memory, no Redis needed)
# ═══════════════════════════════════════════════════════════
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'django_cache_table',
    }
}

# Ratelimit settings
RATELIMIT_USE_CACHE = 'default'
SILENCED_SYSTEM_CHECKS = ['django_ratelimit.E003', 'django_ratelimit.W001']

# ═══════════════════════════════════════════════════════════
# 🔌 REST FRAMEWORK
# ═══════════════════════════════════════════════════════════
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated'
    ],
}

# ═══════════════════════════════════════════════════════════
# 📝 LOGGING
# ═══════════════════════════════════════════════════════════
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
}

# ═══════════════════════════════════════════════════════════
# 🌐 TEMPLATES
# ═══════════════════════════════════════════════════════════
ROOT_URLCONF = 'dropvault.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'dropvault.wsgi.application'

# ═══════════════════════════════════════════════════════════
# 🌍 INTERNATIONALIZATION
# ═══════════════════════════════════════════════════════════
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

print("✅ Settings loaded successfully!")