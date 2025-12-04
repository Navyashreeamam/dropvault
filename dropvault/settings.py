from pathlib import Path
from decouple import config, UndefinedValueError
import os
import dj_database_url
from django.core.management.utils import get_random_secret_key
import logging
import dj_database_url

logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).resolve().parent.parent


# ═══════════════════════════════════════════════════════════
# 🔧 LOAD .ENV FILE (DEVELOPMENT ONLY)
# ═══════════════════════════════════════════════════════════
IS_RAILWAY = os.environ.get('RAILWAY_ENVIRONMENT') is not None

if not IS_RAILWAY:
    try:
        from dotenv import load_dotenv
        env_path = BASE_DIR / '.env'
        if env_path.exists():
            load_dotenv(env_path)
            print("✅ .env loaded")
    except ImportError:
        print("⚠️  python-dotenv not installed")


print("✅ Environment setup complete")
print(f"DATABASE_URL present: {'DATABASE_URL' in os.environ}")


# ═══════════════════════════════════════════════════════════
# 🔧 ENVIRONMENT DETECTION
# ═══════════════════════════════════════════════════════════
IS_RAILWAY = os.environ.get('RAILWAY_ENVIRONMENT') is not None
IS_PRODUCTION = not config('DEBUG', default=False, cast=bool)

# ✅ Railway HTTPS Proxy Configuration (prevents redirect loops)
if IS_RAILWAY:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    USE_X_FORWARDED_HOST = True
    USE_X_FORWARDED_PORT = True

# Load .env only in local development
ENV_PATH = BASE_DIR / '.env'
if ENV_PATH.exists() and not IS_RAILWAY:
    from decouple import AutoConfig
    config = AutoConfig(search_path=BASE_DIR)
    print("✓ Loaded .env file")
elif IS_RAILWAY:
    print("✓ Running on Railway - using environment variables")
else:
    print("⚠️  No .env file found - using defaults")

# ═══════════════════════════════════════════════════════════
# 🔐 SECURITY SETTINGS
# ═══════════════════════════════════════════════════════════
SECRET_KEY = config(
    'SECRET_KEY',
    default='django-insecure-temp-key-for-build-replace-in-production-settings'
)

DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 't')

# ALLOWED_HOSTS
ALLOWED_HOSTS_STR = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1')
ALLOWED_HOSTS = [host.strip() for host in ALLOWED_HOSTS_STR.split(',') if host.strip()]

# Add Railway's domain if present
if 'RAILWAY_STATIC_URL' in os.environ:
    railway_domain = os.environ['RAILWAY_STATIC_URL'].replace('https://', '').replace('http://', '')
    if railway_domain not in ALLOWED_HOSTS:
        ALLOWED_HOSTS.append(railway_domain)

# Ensure we have allowed hosts
if not ALLOWED_HOSTS or ALLOWED_HOSTS == ['']:
    ALLOWED_HOSTS = ['*']  # Temporary - update in Railway vars

print(f"DEBUG: {DEBUG}")
print(f"ALLOWED_HOSTS: {ALLOWED_HOSTS}")
print(f"IS_RAILWAY: {IS_RAILWAY}")

# ═══════════════════════════════════════════════════════════
# 📧 EMAIL CONFIGURATION
# ═══════════════════════════════════════════════════════════
if IS_RAILWAY or ENV_PATH.exists():
    try:
        EMAIL_BACKEND = config('EMAIL_BACKEND', default='django.core.mail.backends.smtp.EmailBackend')
        EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
        EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
        EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
        EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
        EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
        DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='navyashreeamam@gmail.com')
        
        if EMAIL_HOST_USER:
            print(f"✓ Email configured: {EMAIL_HOST_USER}")
        else:
            print("⚠️  EMAIL_HOST_USER not set - using console backend")
            EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
            
    except Exception as e:
        print(f"⚠️  Email config incomplete: {e}")
        EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
        DEFAULT_FROM_EMAIL = 'navyashreeamam@gmail.com'
else:
    # Local development fallback
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
    DEFAULT_FROM_EMAIL = 'navyashreeamam@gmail.com'
    print("⚠️  Using console email backend (development mode)")

EMAIL_DEBUG = DEBUG

# ═══════════════════════════════════════════════════════════
# 🗄️ DATABASE CONFIGURATION
# ═══════════════════════════════════════════════════════════
DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL:
    # Railway provides DATABASE_URL
    DATABASES = {
        'default': dj_database_url.config(
            default=DATABASE_URL,
            conn_max_age=600,
            conn_health_checks=True,
        )
    }
    print("✓ Using DATABASE_URL from Railway")
else:
    # Local development
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': config('DB_NAME', default='dropvault_db'),
            'USER': config('DB_USER', default='navya'),
            'PASSWORD': config('DB_PASSWORD', default=''),
            'HOST': config('DB_HOST', default='localhost'),
            'PORT': config('DB_PORT', default='5432'),
        }
    }
    print("✓ Using local PostgreSQL database")

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

    # Third-party
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    #'allauth.socialaccount.providers.google',
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
# 🔐 AUTHENTICATION
# ═══════════════════════════════════════════════════════════
SITE_ID = 1

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',  # Default Django auth
    'allauth.account.auth_backends.AuthenticationBackend',  # Allauth (for social)
]

# Django-allauth settings
ACCOUNT_AUTHENTICATION_METHOD = 'email'
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_EMAIL_VERIFICATION = 'optional'  # Don't block login
ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION = True
ACCOUNT_LOGOUT_ON_GET = False
ACCOUNT_LOGIN_ATTEMPTS_LIMIT = 5
ACCOUNT_LOGIN_ATTEMPTS_TIMEOUT = 300

# Social Auth (Google)
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'APP': {
            'client_id': config('GOOGLE_CLIENT_ID', default=''),
            'secret': config('GOOGLE_SECRET', default=''),
        },
        'SCOPE': ['profile', 'email'],
        'AUTH_PARAMS': {'access_type': 'online'},
    }
}

# Redirect URLs (NO DUPLICATES!)
LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/'

# Dynamic SITE_URL
SITE_URL = config('SITE_URL', default='http://localhost:8000')
if IS_RAILWAY:
    railway_url = os.environ.get('RAILWAY_STATIC_URL') or os.environ.get('RAILWAY_PUBLIC_DOMAIN')
    if railway_url:
        SITE_URL = railway_url if railway_url.startswith('http') else f'https://{railway_url}'

print(f"SITE_URL: {SITE_URL}")


# ═══════════════════════════════════════════════════════════
# 🔒 PASSWORD HASHING
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
    "django.middleware.security.SecurityMiddleware",
    'whitenoise.middleware.WhiteNoiseMiddleware',
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    'django_otp.middleware.OTPMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'accounts.middleware.EmailVerificationMiddleware',
]

# ═══════════════════════════════════════════════════════════
# 🌍 CORS CONFIGURATION
# ═══════════════════════════════════════════════════════════
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# Add production frontend URL
FRONTEND_URL = config('FRONTEND_URL', default='')
if FRONTEND_URL and FRONTEND_URL not in CORS_ALLOWED_ORIGINS:
    CORS_ALLOWED_ORIGINS.append(FRONTEND_URL)

# Add Railway domain
if IS_RAILWAY and SITE_URL not in CORS_ALLOWED_ORIGINS:
    CORS_ALLOWED_ORIGINS.append(SITE_URL)

CORS_ALLOW_CREDENTIALS = True

print(f"CORS_ALLOWED_ORIGINS: {CORS_ALLOWED_ORIGINS}")

# ═══════════════════════════════════════════════════════════
# 🗂️ STATIC & MEDIA FILES
# ═══════════════════════════════════════════════════════════
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# ═══════════════════════════════════════════════════════════
# 🔐 SECURITY SETTINGS
# ═══════════════════════════════════════════════════════════
if IS_RAILWAY:
    # ✅ Railway handles HTTPS at proxy level - DON'T redirect
    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 0  # Disable HSTS initially, enable after testing
    SECURE_HSTS_INCLUDE_SUBDOMAINS = False
    SECURE_HSTS_PRELOAD = False
elif IS_PRODUCTION:
    # Other production environments (with direct HTTPS)
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
else:
    # Local development
    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SECURE_HSTS_SECONDS = 0

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

print(f"SECURE_SSL_REDIRECT: {SECURE_SSL_REDIRECT if IS_RAILWAY else 'N/A'}")

# ═══════════════════════════════════════════════════════════
# 🚀 UPLOAD LIMITS
# ═══════════════════════════════════════════════════════════
DATA_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 50 * 1024 * 1024  # 50MB

# ═══════════════════════════════════════════════════════════
# 🔴 REDIS CACHE
# ═══════════════════════════════════════════════════════════
REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/1")

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": REDIS_URL,
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        },
    }
}

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
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.UserRateThrottle',
        'rest_framework.throttling.AnonRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'user': '1000/day',
        'anon': '100/day',
    },
}

# ═══════════════════════════════════════════════════════════
# 💳 STRIPE
# ═══════════════════════════════════════════════════════════
STRIPE_SECRET_KEY = config('STRIPE_SECRET_KEY', default='sk_test_dummy')
STRIPE_PUBLISHABLE_KEY = config('STRIPE_PUBLISHABLE_KEY', default='pk_test_dummy')

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
        'django.request': {
            'handlers': ['console'],
            'level': 'ERROR',
            'propagate': False,
        },
    },
}

# ═══════════════════════════════════════════════════════════
# 🌐 TEMPLATES
# ═══════════════════════════════════════════════════════════
ROOT_URLCONF = "dropvault.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / 'templates'],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "dropvault.wsgi.application"

# ═══════════════════════════════════════════════════════════
# 🌍 INTERNATIONALIZATION
# ═══════════════════════════════════════════════════════════
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ═══════════════════════════════════════════════════════════
# 🔑 DEFAULT SETTINGS
# ═══════════════════════════════════════════════════════════
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# ═══════════════════════════════════════════════════════════
# 🌐 AUTO-SETUP DJANGO SITES ON STARTUP
# ═══════════════════════════════════════════════════════════
if IS_RAILWAY:
    try:
        # Only run during runtime, not during collectstatic
        import sys
        if 'collectstatic' not in sys.argv and 'migrate' not in sys.argv:
            from django.contrib.sites.models import Site
            try:
                site = Site.objects.get(pk=SITE_ID)
                if site.domain != 'dropvault-web-production.up.railway.app':
                    site.domain = 'dropvault-web-production.up.railway.app'
                    site.name = 'DropVault'
                    site.save()
                    print("✓ Updated Site configuration")
            except Site.DoesNotExist:
                Site.objects.create(
                    pk=SITE_ID,
                    domain='dropvault-web-production.up.railway.app',
                    name='DropVault'
                )
                print("✓ Created Site configuration")
            except Exception as e:
                print(f"⚠ Site setup skipped: {e}")
    except Exception as e:
        print(f"⚠ Could not auto-setup site: {e}")


# ═══════════════════════════════════════════════════════════
# 📧 DJANGO-ALLAUTH SETTINGS
# ═══════════════════════════════════════════════════════════
ACCOUNT_AUTHENTICATION_METHOD = 'email'
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_EMAIL_VERIFICATION = 'optional'  # Change to 'mandatory' if you want strict verification
ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION = True
ACCOUNT_LOGOUT_ON_GET = False
ACCOUNT_LOGIN_ATTEMPTS_LIMIT = 5
ACCOUNT_LOGIN_ATTEMPTS_TIMEOUT = 300

# Redirect URLs
LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/'
ACCOUNT_LOGOUT_REDIRECT_URL = '/'
ACCOUNT_SIGNUP_REDIRECT_URL = '/dashboard/'