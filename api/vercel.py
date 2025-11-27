# api/vercel.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))  # root
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dropvault.settings')
import django; django.setup()
from django.core.wsgi import get_wsgi_application
app = get_wsgi_application()

def handler(event, context):
    from django.core.handlers.wsgi import WSGIRequest
    import base64, urllib.parse, json
    method = event.get('httpMethod', 'GET')
    path = event.get('path', '/')
    qs = urllib.parse.urlencode(event.get('queryStringParameters') or {}, doseq=True)
    body = base64.b64decode(event['body']) if event.get('isBase64Encoded') else (event.get('body') or '').encode()
    headers = {k.upper().replace('-', '_'): v for k, v in (event.get('headers') or {}).items()}
    environ = {
        'REQUEST_METHOD': method, 'PATH_INFO': path, 'QUERY_STRING': qs,
        'CONTENT_TYPE': headers.get('CONTENT_TYPE', ''), 'CONTENT_LENGTH': str(len(body)),
        'wsgi.input': body, 'wsgi.errors': sys.stderr, 'wsgi.version': (1, 0),
        'wsgi.url_scheme': 'https', 'wsgi.multithread': False, 'wsgi.multiprocess': False,
        'SERVER_NAME': 'vercel', 'SERVER_PORT': '443',
        **{f'HTTP_{k}': v for k, v in headers.items() if k != 'CONTENT_TYPE'}
    }
    response_data = {}
    def start_response(status, headers, exc_info=None):
        response_data.update(status=status, headers=headers)
    result = app(environ, start_response)
    body_out = b''.join(result)
    status_code = int(response_data['status'].split()[0])
    headers_out = dict(response_data['headers'])
    is_binary = 'octet-stream' in headers_out.get('Content-Type', '').lower()
    return {
        'statusCode': status_code,
        'headers': headers_out,
        'body': base64.b64encode(body_out).decode() if is_binary else body_out.decode('utf-8', errors='replace'),
        'isBase64Encoded': is_binary
    }