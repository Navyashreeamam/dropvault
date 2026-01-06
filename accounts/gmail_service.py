# accounts/gmail_service.py
import os
import pickle
from django.conf import settings
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.send']
USE_GMAIL = os.getenv('USE_GMAIL', 'false').lower() == 'true'

if USE_GMAIL:
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
    except ImportError:
        raise ImportError(
            "Gmail integration enabled (USE_GMAIL=true), but Google packages missing. "
            "Run: pip install google-auth google-auth-oauthlib google-api-python-client"
        )
    
def get_gmail_service(user_email):
    """Get authorized Gmail service for a specific user (server-to-server).
       For production, use service account or per-user OAuth."""
    
    creds = None
    token_path = os.path.join(settings.BASE_DIR, 'token.pickle')
    
    if os.path.exists(token_path):
        with open(token_path, 'rb') as token:
            creds = pickle.load(token)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                os.path.join(settings.BASE_DIR, 'credentials.json'), SCOPES
            )
            creds = flow.run_local_server(port=0)
        with open(token_path, 'wb') as token:
            pickle.dump(creds, token)

    return build('gmail', 'v1', credentials=creds)