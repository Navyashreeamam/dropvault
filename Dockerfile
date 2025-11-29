FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
       postgresql-client \
       build-essential \
       libpq-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install requirements
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

EXPOSE 8000

# THIS IS THE KEY - Start gunicorn directly
CMD ["sh", "-c", "\
    python manage.py migrate && \
    python manage.py collectstatic --noinput && \
    gunicorn dropvault.wsgi:application \
        --bind 0.0.0.0:$PORT \
        --workers 2 \
        --timeout 120 \
        --access-logfile - \
        --error-logfile - \
        --log-level info \
"]