#!/bin/bash
set -e

echo "🚀 Starting DropVault Docker Container..."

# Run migrations
echo "📦 Running migrations..."
python manage.py migrate --noinput

# Setup Django Site
echo "🌐 Setting up site..."
python manage.py shell <<EOF
from django.contrib.sites.models import Site
from django.conf import settings
Site.objects.get_or_create(pk=settings.SITE_ID, defaults={'domain': 'dropvault-web-production.up.railway.app', 'name': 'DropVault'})
EOF

# Collect static files
echo "🗂️ Collecting static files..."
python manage.py collectstatic --noinput --clear

# Start Gunicorn
echo "✅ Starting Gunicorn..."
exec gunicorn dropvault.wsgi:application \
    --bind 0.0.0.0:${PORT:-8000} \
    --workers ${GUNICORN_WORKERS:-2} \
    --timeout ${GUNICORN_TIMEOUT:-120} \
    --access-logfile - \
    --error-logfile - \
    --log-level info