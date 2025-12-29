# dropvault/settings.py
from pathlib import Path
import os
import dj_database_url
import logging

logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).resolve().parent.parent

# ═══════════════════════════════════════════════════════════
# 🔧 LOAD .ENV FILE (CRITICAL - MUST BE FIRST!)
# ═══════════════════════════════════════════════════════════
from dotenv import load_dotenv

env_path = BASE_DIR / '.env'
load_dotenv(dotenv_path=env_path)

if env_path.exists():
    print(f"✅ .env file found at: {env_path}")
else:
    print(f"⚠️  .env file NOT found at: {env_path}")

# ═══════════════════════════════════════════════════════════
# 🔧 ENVIRONMENT DETECTION
# ═══════════════════════════════════════════════════════════
IS_RAILWAY = os.environ.get('RAILWAY_ENVIRONMENT') is not None
IS_RENDER = os.environ.get('RENDER') is not None

print(f"✅ Starting DropVault settings...")
print(f"IS_RAILWAY: {IS_RAILWAY}")
print(f"IS_RENDER: {IS_RENDER}")

# ═══════════════════════════════════════════════════════════
# 🔐 SECURITY SETTINGS
# ═══════════════════════════════════════════════════════════
SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-dev-key-change-this-in-production')
DEBUG = os.environ.get('DEBUG', 'True').lower() in ('true', '1', 't')

ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1,.railway.app,.onrender.com').split(',')
ALLOWED_HOSTS = [h.strip() for h in ALLOWED_HOSTS if h.strip()]

print(f"DEBUG: {DEBUG}")
print(f"ALLOWED_HOSTS: {ALLOWED_HOSTS}")

# HTTPS Configuration for deployed environments
if IS_RAILWAY or IS_RENDER:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    USE_X_FORWARDED_HOST = True
    USE_X_FORWARDED_PORT = True

# ═══════════════════════════════════════════════════════════
# 🌐 SITE URL CONFIGURATION (FIXED FOR RENDER!)
# ═══════════════════════════════════════════════════════════
RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME', '')

# Determine SITE_URL based on environment
if IS_RENDER and RENDER_EXTERNAL_HOSTNAME:
    SITE_URL = f'https://{RENDER_EXTERNAL_HOSTNAME}'
    print(f"✅ Using Render URL: {SITE_URL}")
elif IS_RAILWAY:
    railway_url = os.environ.get('RAILWAY_STATIC_URL') or os.environ.get('RAILWAY_PUBLIC_DOMAIN')
    if railway_url:
        SITE_URL = railway_url if railway_url.startswith('http') else f'https://{railway_url}'
    else:
        SITE_URL = os.environ.get('SITE_URL', 'http://localhost:8000')
else:
    SITE_URL = os.environ.get('SITE_URL', 'http://localhost:8000')

print(f"✅ SITE_URL: {SITE_URL}")

# ═══════════════════════════════════════════════════════════
# 📧 EMAIL CONFIGURATION (FIXED FOR RENDER!)
# ═══════════════════════════════════════════════════════════
# Resend API - RECOMMENDED for Render (SMTP is blocked on free tier)
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '').strip()

# SMTP settings (for local development only)
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '').strip()
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '').strip()

# From email - use Resend's default if using Resend
if RESEND_API_KEY:
    DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'DropVault <onboarding@resend.dev>')
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'  # Resend uses API, not Django backend
    print(f"✅ Email: Using Resend API")
    print(f"   RESEND_API_KEY: {RESEND_API_KEY[:10]}..." if RESEND_API_KEY else "   RESEND_API_KEY: Not set")
elif EMAIL_HOST_USER and EMAIL_HOST_PASSWORD and not IS_RENDER:
    # Only use SMTP for local development (blocked on Render)
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', f'DropVault <{EMAIL_HOST_USER}>')
    print(f"✅ Email: Using SMTP (local dev)")
else:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
    DEFAULT_FROM_EMAIL = 'DropVault <noreply@dropvault.com>'
    print("⚠️ Email: Console only (no email service configured)")
    if IS_RENDER:
        print("   💡 TIP: Set RESEND_API_KEY in Render environment variables")

print(f"   DEFAULT_FROM_EMAIL: {DEFAULT_FROM_EMAIL}")


# ═══════════════════════════════════════════════════════════
# 🗄️ DATABASE CONFIGURATION
# ═══════════════════════════════════════════════════════════
import socket

def is_running_in_docker():
    if os.path.exists('/.dockerenv'):
        return True
    try:
        hostname = socket.gethostname()
        if len(hostname) == 12 and all(c in '0123456789abcdef' for c in hostname):
            return True
    except:
        pass
    if os.environ.get('DOCKER_CONTAINER'):
        return True
    return False

IN_DOCKER = is_running_in_docker()
print(f"🐳 Running in Docker: {IN_DOCKER}")
print(f"🌐 Running on Render: {IS_RENDER}")

DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()

if DATABASE_URL and DATABASE_URL.startswith('postgres'):
    print(f"✅ Using DATABASE_URL from environment")
    DATABASES = {
        'default': dj_database_url.config(
            default=DATABASE_URL,
            conn_max_age=600,
            conn_health_checks=True,
        )
    }
elif IS_RENDER:
    print("⚠️ On Render but DATABASE_URL not set - using SQLite temporarily")
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
else:
    if IN_DOCKER:
        DB_HOST = 'db'
        print("🐳 Using Docker database host: db")
    else:
        DB_HOST = 'localhost'
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

ACCOUNT_LOGIN_METHODS = {'email'}
ACCOUNT_SIGNUP_FIELDS = ['email*', 'password1*', 'password2*']
ACCOUNT_EMAIL_VERIFICATION = 'optional'  # Changed to optional - we handle manually
ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION = True
ACCOUNT_LOGOUT_ON_GET = False

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
# 🍪 SESSION & COOKIE CONFIGURATION
# ═══════════════════════════════════════════════════════════
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = 'dropvault_sessionid'
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_HTTPONLY = True

# ✅ CRITICAL - SameSite must be None for cross-origin
SESSION_COOKIE_SAMESITE = 'None'  # Changed from 'Lax'
SESSION_COOKIE_SECURE = True  # Required when SameSite=None

# CSRF settings
CSRF_COOKIE_SAMESITE = 'None'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = False  # Must be False so JS can read it
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "https://dropvault-2.onrender.com",
    "https://dropvault-frontend-1.onrender.com",
    "https://*.onrender.com",
]

if IS_RENDER or IS_RAILWAY:
    SESSION_COOKIE_SECURE = True
else:
    SESSION_COOKIE_SECURE = False

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
# 🌐 ALLOWED_HOSTS (FIXED - Remove https://)
# ═══════════════════════════════════════════════════════════
ALLOWED_HOSTS = [
    'localhost',
    '127.0.0.1',
    'dropvault-2.onrender.com',  # ✅ FIXED - No https://
    '.onrender.com',  # Allow all Render subdomains
]


# ═══════════════════════════════════════════════════════════
# 🌍 CORS CONFIGURATION - FIXED
# ═══════════════════════════════════════════════════════════
CORS_ALLOWED_ORIGINS = [
    # Local development
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    # Production - Render Frontend (ADD ALL YOUR FRONTEND URLS)
    "https://dropvaultnew-frontend.onrender.com",
    "https://dropvault-frontend-1.onrender.com",
]

# Also allow Render subdomains via regex
CORS_ALLOWED_ORIGIN_REGEXES = [
    r"^https://.*\.onrender\.com$",
]

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
    'cookie',
]

CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

CORS_EXPOSE_HEADERS = [
    'Content-Type',
    'X-CSRFToken',
    'Set-Cookie',
]

# Allow cookies to be sent cross-origin
SESSION_COOKIE_SAMESITE = 'None'
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'None'
CSRF_COOKIE_SECURE = True

# ═══════════════════════════════════════════════════════════
# 🔒 CSRF TRUSTED ORIGINS (FIXED)
# ═══════════════════════════════════════════════════════════
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "https://dropvault-2.onrender.com",  # ✅ Your backend
    "https://dropvault-frontend-1.onrender.com",  # ✅ Your frontend
    "https://*.onrender.com",
]

# Add Render URL if available
RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
if RENDER_EXTERNAL_HOSTNAME:
    CSRF_TRUSTED_ORIGINS.append(f"https://{RENDER_EXTERNAL_HOSTNAME}")
    

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
# 🔴 CACHE (Use local memory - works without database table)
# ═══════════════════════════════════════════════════════════
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'dropvault-cache',
    }
}

# Ratelimit settings - use the cache
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

# Add to your settings.py

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'files': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'accounts': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}


##re_AcNkX8Pb_NopVYHbMdU85sJnX1BxmwyQE