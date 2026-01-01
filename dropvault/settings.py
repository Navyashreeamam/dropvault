# dropvault/settings.py
from pathlib import Path
import os
import dj_database_url
import logging

logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).resolve().parent.parent

# ═══════════════════════════════════════════════════════════
# 🔧 LOAD .ENV FILE
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

ALLOWED_HOSTS = [
    'localhost',
    '127.0.0.1',
    'dropvault-2.onrender.com',
    '.onrender.com',
]

print(f"DEBUG: {DEBUG}")
print(f"ALLOWED_HOSTS: {ALLOWED_HOSTS}")

# HTTPS Configuration for deployed environments
if IS_RAILWAY or IS_RENDER:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    USE_X_FORWARDED_HOST = True
    USE_X_FORWARDED_PORT = True

# ═══════════════════════════════════════════════════════════
# 🌐 SITE URL CONFIGURATION
# ═══════════════════════════════════════════════════════════
RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME', '')

if IS_RENDER and RENDER_EXTERNAL_HOSTNAME:
    SITE_URL = f'https://{RENDER_EXTERNAL_HOSTNAME}'
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
# 📧 EMAIL CONFIGURATION
# ═══════════════════════════════════════════════════════════
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '').strip()
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '').strip()
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '').strip()

if RESEND_API_KEY:
    DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'DropVault <onboarding@resend.dev>')
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
    print(f"✅ Email: Using Resend API")
elif EMAIL_HOST_USER and EMAIL_HOST_PASSWORD and not IS_RENDER:
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', f'DropVault <{EMAIL_HOST_USER}>')
    print(f"✅ Email: Using SMTP (local dev)")
else:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
    DEFAULT_FROM_EMAIL = 'DropVault <noreply@dropvault.com>'
    print("⚠️ Email: Console only")

# ═══════════════════════════════════════════════════════════
# 🗄️ DATABASE CONFIGURATION
# ═══════════════════════════════════════════════════════════
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
else:
    print("⚠️ Using SQLite database")
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }


# ═══════════════════════════════════════════════════════════
# ☁️ CLOUDINARY CONFIGURATION (check BEFORE installed apps)
# ═══════════════════════════════════════════════════════════
CLOUDINARY_CLOUD_NAME = os.environ.get('CLOUDINARY_CLOUD_NAME', '')
CLOUDINARY_API_KEY = os.environ.get('CLOUDINARY_API_KEY', '')
CLOUDINARY_API_SECRET = os.environ.get('CLOUDINARY_API_SECRET', '')
CLOUDINARY_CONFIGURED = all([CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET])

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

    # Third party
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

    # Local apps
    'accounts',
    'files',
]

# ═══════════════════════════════════════════════════════════
# ☁️ CLOUDINARY SETUP (conditional)
# ═══════════════════════════════════════════════════════════
if CLOUDINARY_CONFIGURED:
    # Add cloudinary apps to INSTALLED_APPS
    INSTALLED_APPS.insert(0, 'cloudinary_storage')
    INSTALLED_APPS.append('cloudinary')
    
    CLOUDINARY_STORAGE = {
        'CLOUD_NAME': CLOUDINARY_CLOUD_NAME,
        'API_KEY': CLOUDINARY_API_KEY,
        'API_SECRET': CLOUDINARY_API_SECRET,
    }
    DEFAULT_FILE_STORAGE = 'cloudinary_storage.storage.MediaCloudinaryStorage'
    print("✅ Cloudinary configured for file storage")
else:
    CLOUDINARY_STORAGE = {}
    DEFAULT_FILE_STORAGE = 'django.core.files.storage.FileSystemStorage'
    print("⚠️ Cloudinary NOT configured - using local storage")
    print("   Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET")
    

# ═══════════════════════════════════════════════════════════
# 🔐 DJANGO-ALLAUTH SETTINGS
# ══════════════════════
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

ACCOUNT_EMAIL_VERIFICATION = 'optional'
ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION = True
ACCOUNT_LOGOUT_ON_GET = False

LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/'
ACCOUNT_LOGOUT_REDIRECT_URL = '/'

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
    #'accounts.middleware.SessionCleanupMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django_otp.middleware.OTPMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    #'accounts.middleware.EmailVerificationMiddleware',
]

# ═══════════════════════════════════════════════════════════
# 🍪 SESSION & COOKIE CONFIGURATION - FIXED!
# ═══════════════════════════════════════════════════════════
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = 'dropvault_sessionid'
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_SAVE_EVERY_REQUEST = True

# ✅ CRITICAL: These must be set ONCE and correctly for cross-origin
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'None'  # Required for cross-origin
SESSION_COOKIE_SECURE = True      # Required when SameSite=None

# CSRF settings
CSRF_COOKIE_SAMESITE = 'None'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = False  # Must be False so JS can read it

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "http://localhost:5173",
    "https://dropvault-2.onrender.com",
    "https://dropvault-frontend-1.onrender.com",
    "https://*.onrender.com",
]

# ═══════════════════════════════════════════════════════════
# 🌍 CORS CONFIGURATION
# ═══════════════════════════════════════════════════════════

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "https://dropvault-frontend-1.onrender.com",
    "https://dropvaultnew-frontend.onrender.com",
]

# Allow all onrender.com subdomains
CORS_ALLOWED_ORIGIN_REGEXES = [
    r"^https://.*\.onrender\.com$",
]

# Allow credentials (cookies, auth headers)
CORS_ALLOW_CREDENTIALS = True

# ✅ CRITICAL - Include ALL custom headers
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
    'x-session-id',  # ✅ ADD THIS
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

# Preflight cache - browser won't repeat OPTIONS for 24 hours
CORS_PREFLIGHT_MAX_AGE = 86400


# ═══════════════════════════════════════════════════════════
# 🗂️ STATIC & MEDIA FILES
# ═══════════════════════════════════════════════════════════
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files configuration
if CLOUDINARY_STORAGE.get('CLOUD_NAME'):
    # Using Cloudinary - no local MEDIA_ROOT needed
    MEDIA_URL = '/media/'
else:
    # Using local storage (development)
    MEDIA_URL = '/media/'
    MEDIA_ROOT = BASE_DIR / 'media'

# ═══════════════════════════════════════════════════════════
# 🔐 SECURITY SETTINGS
# ═══════════════════════════════════════════════════════════
SECURE_SSL_REDIRECT = False
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# ═══════════════════════════════════════════════════════════
# 🚀 UPLOAD LIMITS
# ═══════════════════════════════════════════════════════════
DATA_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 52428800  # 50MB
DATA_UPLOAD_MAX_NUMBER_FIELDS = 10000

# ═══════════════════════════════════════════════════════════
# 🔴 CACHE
# ═══════════════════════════════════════════════════════════
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'dropvault-cache',
    }
}

RATELIMIT_USE_CACHE = 'default'
SILENCED_SYSTEM_CHECKS = ['django_ratelimit.E003', 'django_ratelimit.W001']

# ═══════════════════════════════════════════════════════════
# 🔌 REST FRAMEWORK
# ═══════════════════════════════════════════════════════════
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
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
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
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