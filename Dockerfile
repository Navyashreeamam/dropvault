# Dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# ✅ CRITICAL: Set ALL needed env vars *only for collectstatic*, inline
RUN SECRET_KEY=build-dummy \
    DEBUG=False \
    ALLOWED_HOSTS=localhost \
    DB_NAME=dropvault_db \
    DB_USER=navya \
    DB_PASSWORD=dummy \
    DB_HOST=localhost \
    python manage.py collectstatic --noinput

EXPOSE 8000

CMD ["gunicorn", "dropvault.wsgi:application", "--bind", "0.0.0.0:8000"]