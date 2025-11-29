#!/bin/bash
set -e

echo "🚀 Starting DropVault..."

# Run migrations
python manage.py migrate --noinput

# Setup Django Site
python manage.py shell <<EOF
from django.contrib.sites.models import Site
Site.objects.get_or_create(pk=1, defaults={'domain': 'dropvault-web-production.up.railway.app', 'name': 'DropVault'})
EOF

# Collect static files
python manage.py collectstatic --noinput --clear

# Start Gunicorn
exec gunicorn dropvault.wsgi:application \
    --bind 0.0.0.0:$PORT \
    --workers 2 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile -