import os
import re
import joblib
import tldextract
from flask import Flask, render_template, request, redirect, url_for, session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = 'devu_fast_super_key_2026'

CLIENT_SECRETS_FILE = 'credentials.json'
SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/gmail.readonly'
]

model = None
vectorizer = None

try:
    if os.path.exists('phishing_model.pkl'):
        model = joblib.load('phishing_model.pkl')
    if os.path.exists('tfidf_vectorizer.pkl'):
        vectorizer = joblib.load('tfidf_vectorizer.pkl')
except Exception as e:
    print(f"Model load notice: {e}")

def predict_email(text):
    if not text:
        return "Safe"
    suspicious_patterns = [r'verify', r'urgent', r'bank', r'password', r'suspend', r'login', r'click here', r'account blocked', r'update payment', r'security alert']
    if any(re.search(p, text, re.IGNORECASE) for p in suspicious_patterns):
        return "Phishing"
    if model is not None and vectorizer is not None:
        try:
            vec = vectorizer.transform([text])
            pred = model.predict(vec)[0]
            return "Phishing" if pred == 1 else "Safe"
        except Exception:
            pass
    return "Safe"

def get_flow():
    redirect_uri = url_for('callback', _external=True)
    if request.headers.get('X-Forwarded-Proto') == 'https':
        redirect_uri = redirect_uri.replace('http://', 'https://')
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=redirect_uri
    )
    return flow

@app.route('/', methods=['GET', 'POST'])
def index():
    prediction = None
    email_text = ""
    if request.method == 'POST':
        email_text = request.form.get('email_text', '')
        if email_text.strip():
            prediction = predict_email(email_text)
    return render_template('index.html', prediction=prediction, email_text=email_text)

@app.route('/login', methods=['GET', 'POST'])
def login():
    flow = get_flow()
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback', methods=['GET', 'POST'])
def callback():
    state = session.get('state')
    flow = get_flow()
    req_url = request.url
    if request.headers.get('X-Forwarded-Proto') == 'https':
        req_url = req_url.replace('http://', 'https://')
    flow.fetch_token(authorization_response=req_url)
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    return redirect(url_for('scan_inbox'))

@app.route('/scan', methods=['GET', 'POST'])
@app.route('/filter', methods=['GET', 'POST'])
def scan_inbox():
    if 'credentials' not in session:
        return redirect(url_for('login'))

    creds_data = session['credentials']
    credentials = Credentials(**creds_data)

    try:
        service = build('gmail', 'v1', credentials=credentials)
        results = service.users().messages().list(userId='me', maxResults=3).execute()
        messages = results.get('messages', [])
        
        scanned_emails = []
        for msg in messages:
            msg_data = service.users().messages().get(userId='me', id=msg['id'], format='snippet').execute()
            snippet = msg_data.get('snippet', '')
            status = predict_email(snippet)
            scanned_emails.append({'snippet': snippet, 'status': status})

        return render_template('index.html', scanned_emails=scanned_emails)
    except Exception as e:
        print(f"Gmail error: {e}")
        return redirect(url_for('index'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)