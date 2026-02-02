# dropvault/settings.py
from pathlib import Path
import os
import dj_database_url
import logging

logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).resolve().parent.parent

# ============================================================================
# LOAD .ENV FILE
# ============================================================================
from dotenv import load_dotenv

env_path = BASE_DIR / '.env'
load_dotenv(dotenv_path=env_path)

if env_path.exists():
    print(f"✅ .env file found at: {env_path}")
else:
    print(f"⚠️  .env file NOT found at: {env_path}")

# ============================================================================
# ENVIRONMENT DETECTION
# ============================================================================
IS_RAILWAY = os.environ.get('RAILWAY_ENVIRONMENT') is not None
IS_RENDER = os.environ.get('RENDER') is not None
IS_PRODUCTION = IS_RAILWAY or IS_RENDER

# ============================================================================
# SECURITY SETTINGS
# ============================================================================
SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-dev-key-change-this-in-production')
DEBUG = os.environ.get('DEBUG', 'False') == 'True'

ALLOWED_HOSTS = [
    'localhost',
    '127.0.0.1',
    'dropvault-2.onrender.com',
    '.onrender.com',
]

# ============================================================================
# ✅ MULTIPLE FRONTEND URLS SUPPORT
# ============================================================================

FRONTEND_URL = os.environ.get('FRONTEND_URL', 'https://dropvault-frontend.onrender.com').strip().strip("'\"")

ALLOWED_FRONTEND_URLS = [
    'https://dropvault-frontend.onrender.com',
    'https://dropvaultnew-frontend.onrender.com',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5173',
    'http://127.0.0.1:5173',
]

if FRONTEND_URL and FRONTEND_URL not in ALLOWED_FRONTEND_URLS:
    ALLOWED_FRONTEND_URLS.append(FRONTEND_URL)

print(f"✅ Primary FRONTEND_URL: {FRONTEND_URL}")
print(f"✅ All allowed frontends: {ALLOWED_FRONTEND_URLS}")

SITE_URL = os.environ.get('SITE_URL', 'https://dropvault-2.onrender.com')

if IS_RAILWAY or IS_RENDER:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    USE_X_FORWARDED_HOST = True
    USE_X_FORWARDED_PORT = True

# ============================================================================
# SITE URL CONFIGURATION
# ============================================================================
RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME', '')

SITE_URL = os.environ.get('SITE_URL', 'https://dropvault-2.onrender.com').strip().strip("'\"")

if IS_RENDER and RENDER_EXTERNAL_HOSTNAME:
    SITE_URL = f'https://{RENDER_EXTERNAL_HOSTNAME}'
elif IS_RAILWAY:
    railway_url = os.environ.get('RAILWAY_STATIC_URL') or os.environ.get('RAILWAY_PUBLIC_DOMAIN')
    if railway_url:
        SITE_URL = railway_url if railway_url.startswith('http') else f'https://{railway_url}'
else:
    if not SITE_URL.startswith('http'):
        SITE_URL = f'https://{SITE_URL}'

print(f"✅ SITE_URL: {SITE_URL}")

# ============================================================================
# EMAIL CONFIGURATION
# ============================================================================
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'True').lower() in ('true', '1', 'yes')
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', EMAIL_HOST_USER)

if EMAIL_HOST_USER:
    print(f"📧 Email configured: {EMAIL_HOST_USER}")
else:
    print("⚠️ Email NOT configured - EMAIL_HOST_USER is missing!")

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================
DATABASE_URL = os.environ.get('DATABASE_URL', '')

if DATABASE_URL:
    DATABASES = {
        'default': dj_database_url.config(
            default=DATABASE_URL,
            conn_max_age=600,
            conn_health_checks=True,
        )
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db_local.sqlite3',
        }
    }

# ============================================================================
# CLOUDINARY CONFIGURATION
# ============================================================================
CLOUDINARY_CLOUD_NAME = os.environ.get('CLOUDINARY_CLOUD_NAME', '').strip()
CLOUDINARY_API_KEY = os.environ.get('CLOUDINARY_API_KEY', '').strip()
CLOUDINARY_API_SECRET = os.environ.get('CLOUDINARY_API_SECRET', '').strip()
CLOUDINARY_CONFIGURED = all([CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET])

if CLOUDINARY_CONFIGURED:
    # Configure Cloudinary
    import cloudinary
    import cloudinary.uploader
    import cloudinary.api
    
    cloudinary.config(
        cloud_name=CLOUDINARY_CLOUD_NAME,
        api_key=CLOUDINARY_API_KEY,
        api_secret=CLOUDINARY_API_SECRET,
        secure=True
    )
    print("✅ Cloudinary configured for file storage")
else:
    print("⚠️ Cloudinary NOT configured - using local storage")

# ============================================================================
# INSTALLED APPS
# ============================================================================
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    'django.contrib.sites',

    # Third-party apps
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

# ✅ Add Cloudinary ONLY if configured
if CLOUDINARY_CONFIGURED:
    if 'cloudinary' not in INSTALLED_APPS:
        INSTALLED_APPS.append('cloudinary')

# ============================================================================
# STORAGE CONFIGURATION (Django 4.2+ way)
# ============================================================================
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage",
    },
}

WHITENOISE_MANIFEST_STRICT = False
WHITENOISE_AUTOREFRESH = True

# ============================================================================
# ALLAUTH SETTINGS
# ============================================================================
SITE_ID = 1
ACCOUNT_EMAIL_VERIFICATION = 'optional'
ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION = True
ACCOUNT_LOGOUT_ON_GET = False

LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/'
ACCOUNT_LOGOUT_REDIRECT_URL = '/'

# ============================================================================
# PASSWORD VALIDATION
# ============================================================================
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

# ============================================================================
# MIDDLEWARE
# ============================================================================
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'accounts.middleware.TokenAuthenticationMiddleware',
    'accounts.middleware.PasswordResetRequiredMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django_otp.middleware.OTPMiddleware',
    'allauth.account.middleware.AccountMiddleware',
]

ROOT_URLCONF = 'dropvault.urls'

# ============================================================================
# SESSION & COOKIE CONFIGURATION
# ============================================================================
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = 'dropvault_sessionid'
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'None'
SESSION_COOKIE_SECURE = True


# ============================================================================
# CORS CONFIGURATION
# ============================================================================
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "https://dropvault-frontend.onrender.com",
    "https://dropvaultnew-frontend.onrender.com",
]

# Remove duplicates and empty strings
CORS_ALLOWED_ORIGINS = list(set([url for url in CORS_ALLOWED_ORIGINS if url and url.startswith('http')]))

print(f"✅ CORS_ALLOWED_ORIGINS: {CORS_ALLOWED_ORIGINS}")

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
    'x-session-id',
    'cache-control',
    'pragma',
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
    'Authorization',
]

CORS_PREFLIGHT_MAX_AGE = 86400

# ============================================================================
# CSRF SETTINGS
# ============================================================================
CSRF_COOKIE_SAMESITE = 'None'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = False  # Must be False so JS can read it

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "http://localhost:5173",
    "https://dropvaultnew-frontend.onrender.com",
    "https://dropvault-frontend.onrender.com",
    "https://*.onrender.com",
]

# ============================================================================
# STATIC FILES
# ============================================================================
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / "staticfiles"

# Only include static directory if it exists
STATICFILES_DIRS = []
if (BASE_DIR / 'static').exists():
    STATICFILES_DIRS.append(BASE_DIR / 'static')

# ============================================================================
# MEDIA FILES
# ============================================================================
MEDIA_URL = '/media/'
if not CLOUDINARY_CONFIGURED:
    MEDIA_ROOT = BASE_DIR / 'media'

# ============================================================================
# UPLOAD LIMITS
# ============================================================================

DATA_UPLOAD_MAX_MEMORY_SIZE = 524288000   # 500MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 524288000   # 500MB
DATA_UPLOAD_MAX_NUMBER_FIELDS = 10000

SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True

CONN_MAX_AGE = 600  # 10 minutes

FILE_UPLOAD_HANDLERS = [
    'django.core.files.uploadhandler.TemporaryFileUploadHandler',
]

FILE_UPLOAD_TEMP_DIR = '/tmp'

STREAMING_CHUNK_SIZE = 8192

CONN_MAX_AGE = 600

# ============================================================================
# SECURITY SETTINGS
# ============================================================================
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

if IS_PRODUCTION and not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
else:
    SECURE_SSL_REDIRECT = False

# ============================================================================
# CACHE
# ============================================================================
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'dropvault-cache',
    }
}

RATELIMIT_USE_CACHE = 'default'
SILENCED_SYSTEM_CHECKS = ['django_ratelimit.E003', 'django_ratelimit.W001']

# ============================================================================
# REST FRAMEWORK
# ============================================================================
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated'
    ],
}

# ============================================================================
# LOGGING
# ============================================================================
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

# ============================================================================
# TEMPLATES
# ============================================================================
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

# ============================================================================
# INTERNATIONALIZATION
# ============================================================================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# ============================================================================
# OTHER SETTINGS
# ============================================================================
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
# AUTH_USER_MODEL = 'accounts.User'

print("✅ Settings loaded successfully!")