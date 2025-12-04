# Dockerfile
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=dropvault.settings

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    postgresql-client \
    build-essential \
    libpq-dev \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create necessary directories
RUN mkdir -p /app/media /app/staticfiles

# Collect static files
RUN python manage.py collectstatic --noinput --clear 2>/dev/null || true

# Expose port
EXPOSE 8000

# Startup script
RUN echo '#!/bin/bash\n\
set -e\n\
echo "🚀 Starting DropVault..."\n\
echo "📦 Running migrations..."\n\
python manage.py migrate --noinput\n\
echo "🧹 Collecting static files..."\n\
python manage.py collectstatic --noinput --clear || true\n\
echo "✅ Starting Gunicorn on port ${PORT:-8000}..."\n\
exec gunicorn dropvault.wsgi:application \\\n\
    --bind 0.0.0.0:${PORT:-8000} \\\n\
    --workers 2 \\\n\
    --threads 4 \\\n\
    --timeout 120 \\\n\
    --access-logfile - \\\n\
    --error-logfile - \\\n\
    --log-level info\n\
' > /app/start.sh && chmod +x /app/start.sh

CMD ["/bin/bash", "/app/start.sh"]