# Dockerfile
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV IN_DOCKER=true

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput --clear 2>/dev/null || true

# Create startup script
RUN echo '#!/bin/bash\n\
echo "🚀 Starting DropVault..."\n\
echo "📦 Running migrations..."\n\
python manage.py migrate --noinput\n\
echo "📁 Collecting static files..."\n\
python manage.py collectstatic --noinput\n\
echo "🌐 Starting Gunicorn with logging..."\n\
exec gunicorn dropvault.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 2 \
    --access-logfile - \
    --error-logfile - \
    --capture-output \
    --enable-stdio-inheritance \
    --log-level info\n\
' > /app/start.sh && chmod +x /app/start.sh

# Expose port
EXPOSE 8000

# Run startup script

CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py createcachetable --verbosity 0 || true && python manage.py collectstatic --noinput && gunicorn dropvault.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 2 --timeout 120"]