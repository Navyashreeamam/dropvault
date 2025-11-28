#!/bin/sh
set -e
PORT=${PORT:-8000}

echo "▶ Starting Gunicorn on port $PORT..."
exec gunicorn dropvault.wsgi:application --bind "0.0.0.0:$PORT" --workers 2