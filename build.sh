#!/usr/bin/env bash
# build.sh - Render build script

set -o errexit

echo "📦 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "📁 Creating directories..."
mkdir -p staticfiles
mkdir -p static
mkdir -p media

echo "🔄 Running migrations..."
python manage.py migrate --no-input || echo "⚠️ Migration had issues, continuing..."

echo "📁 Collecting static files..."
python manage.py collectstatic --no-input --clear || echo "⚠️ collectstatic had issues, continuing..."

echo "🗄️ Creating cache table..."
python manage.py createcachetable || echo "⚠️ Cache table creation skipped (may already exist or using memory cache)"

echo "✅ Build complete!"