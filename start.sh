#!/bin/bash

set -e

echo "========================================="
echo "🚀 Starting DropVault Deployment"
echo "========================================="

# 1. Run migrations
echo "📦 Running migrations..."
python manage.py migrate --noinput

# 2. Setup Django Sites framework
echo "🌐 Setting up sites..."
python manage.py shell <<EOF
from django.contrib.sites.models import Site
from django.conf import settings

domain = 'dropvault-web-production.up.railway.app'
site, created = Site.objects.get_or_create(
    pk=getattr(settings, 'SITE_ID', 1),
    defaults={'domain': domain, 'name': 'DropVault'}
)
if not created:
    site.domain = domain
    site.save()
print(f"✓ Site configured: {domain}")
EOF

# 3. Collect static files
echo "🗂️ Collecting static files..."
python manage.py collectstatic --noinput --clear

# 4. Start server
echo "========================================="
echo "✅ Setup complete! Starting Gunicorn..."
echo "========================================="

exec gunicorn dropvault.wsgi:application \
    --bind 0.0.0.0:$PORT \
    --workers 2 \
    --threads 4 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    --log-level info