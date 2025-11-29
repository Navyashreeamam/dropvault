web: gunicorn dropvault.wsgi:application
web: python manage.py migrate && python manage.py setup_site && python manage.py collectstatic --noinput && gunicorn dropvault.wsgi:application --bind 0.0.0.0:$PORT --workers 2
