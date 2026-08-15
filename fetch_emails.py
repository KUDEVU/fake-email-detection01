import os
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# Allow scope variations and avoid openid mismatch
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/gmail.readonly'
]

def get_gmail_service(target_email=None):
    """Handles Google OAuth 2.0 authentication dynamically per account."""
    creds = None
    clean_name = target_email.replace('@', '_').replace('.', '_') if target_email else "default"
    token_file = f"token_{clean_name}.json"

    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
        
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
            
        with open(token_file, 'w') as token:
            token.write(creds.to_json())
            
    service = build('gmail', 'v1', credentials=creds)
    
    try:
        user_profile = service.users().getProfile(userId='me').execute()
        active_email = user_profile.get('emailAddress', target_email or 'Active Account')
    except Exception:
        active_email = target_email or "Active Account"

    return service, active_email