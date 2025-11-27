# vercel.py
import os
import sys
import json
from urllib.parse import urlparse, parse_qs

# Add project root to Python path
sys.path.insert(0, os.path.dirname(__file__))

# Set Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dropvault.settings')

# Initialize Django
import django
django.setup()

from django.core.wsgi import get_wsgi_application
from django.http import HttpResponse

# Get WSGI app
application = get_wsgi_application()

async def handler(request):
    """
    Vercel Edge-compatible handler (async function, receives Request)
    Converts Request → WSGI environ → Django app → Response
    """
    # Parse URL
    url = urlparse(str(request.url))
    path = url.path or "/"
    query_string = url.query

    # Read body
    try:
        body = await request.body()
    except:
        body = b""

    # Build minimal WSGI environ
    environ = {
        "REQUEST_METHOD": request.method,
        "PATH_INFO": path,
        "QUERY_STRING": query_string,
        "CONTENT_TYPE": request.headers.get("content-type", ""),
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": body,
        "wsgi.errors": sys.stderr,
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "https",
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
        "SERVER_NAME": "vercel",
        "SERVER_PORT": "443",
    }

    # Add HTTP_ headers
    for key, value in request.headers.items():
        environ[f"HTTP_{key.upper().replace('-', '_')}"] = value

    # Capture response via side effect
    response_data = {}

    def start_response(status, headers, exc_info=None):
        response_data["status"] = status
        response_data["headers"] = headers

    # Call Django app
    result = application(environ, start_response)
    body_bytes = b"".join(result)

    # Parse status
    status_code = int(response_data["status"].split()[0])
    headers = dict(response_data["headers"])

    # Handle binary (file download) vs text
    content_type = headers.get("Content-Type", "").lower()
    is_binary = any(
        t in content_type
        for t in ["application/octet-stream", "image/", "video/", "audio/", "pdf"]
    )

    if is_binary:
        # Return raw bytes (Vercel auto-base64-encodes in Edge runtime)
        return HttpResponse(
            body_bytes,
            status=status_code,
            headers=headers,
            content_type=content_type,
        )
    else:
        # Assume UTF-8 text (JSON/HTML)
        try:
            body_str = body_bytes.decode("utf-8")
        except UnicodeDecodeError:
            body_str = body_bytes.hex()
        return HttpResponse(
            body_str,
            status=status_code,
            headers=headers,
            content_type=content_type or "application/json",
        )