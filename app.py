import os
import re
import pickle
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import tldextract
from flask import Flask, render_template, redirect, url_for, session, request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = "devu_fast_super_key_2026"

CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/gmail.readonly'
]

# Fast DNS with local cache
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '1.1.1.1']
resolver.timeout = 0.5
resolver.lifetime = 0.8
dns_cache = {}

MODEL_PATH = "model.pkl"
VECTORIZER_PATH = "vectorizer.pkl"
model, vectorizer = None, None

try:
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        with open(VECTORIZER_PATH, "rb") as f:
            vectorizer = pickle.load(f)
except Exception:
    pass

scan_stats = {"total": 464, "phishing": 356, "safe": 108}

def get_base_domain(sender_email):
    match = re.search(r'[\w\.-]+@([\w\.-]+)', sender_email)
    if not match:
        return ""
    domain = match.group(1).lower().strip('>')
    extracted = tldextract.extract(domain)
    return f"{extracted.domain}.{extracted.suffix}"

def verify_domain_dns(domain):
    if domain in dns_cache:
        return dns_cache[domain]

    has_mx, has_spf = False, False
    try:
        mx_records = resolver.resolve(domain, 'MX')
        if len(mx_records) > 0:
            has_mx = True
    except Exception:
        has_mx = False

    if has_mx:
        try:
            txt_records = resolver.resolve(domain, 'TXT')
            for record in txt_records:
                if "v=spf1" in record.to_text():
                    has_spf = True
                    break
        except Exception:
            has_spf = False

    dns_cache[domain] = (has_mx, has_spf)
    return has_mx, has_spf

def classify_email(sender, subject, body):
    full_text = f"{subject} {body}"
    if model and vectorizer:
        try:
            feats = vectorizer.transform([full_text])
            prob = model.predict_proba(feats)[0][1]
        except Exception:
            prob = 0.5
    else:
        phish_triggers = ['urgent', 'password', 'verify', 'bank', 'lottery', 'winner', 'account suspended', 'wire payment', 'tax refund', 'crypto', 'otp']
        hits = sum(1 for w in phish_triggers if w in full_text.lower())
        prob = min(0.96, hits * 0.28)

    base_dom = get_base_domain(sender)
    if base_dom:
        has_mx, has_spf = verify_domain_dns(base_dom)
        if has_mx and has_spf:
            prob = max(0.05, prob - 0.25)
        elif not has_mx:
            prob = min(0.99, prob + 0.40)

    if prob >= 0.65:
        return {"status": "FRAUD / PHISHING", "confidence": round(prob * 100, 2), "class": "danger"}
    elif prob >= 0.40:
        return {"status": "SUSPICIOUS / PROMO", "confidence": round(prob * 100, 2), "class": "warning"}
    else:
        return {"status": "SAFE EMAIL", "confidence": round((1 - prob) * 100, 2), "class": "success"}

def parse_single_message(service, msg_id):
    try:
        msg = service.users().messages().get(
            userId='me', 
            id=msg_id, 
            format='metadata', 
            metadataHeaders=['From', 'Subject', 'Date']
        ).execute()
        
        headers = msg.get('payload', {}).get('headers', [])
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        date_raw = next((h['value'] for h in headers if h['name'].lower() == 'date'), '')
        snippet = msg.get('snippet', '')

        try:
            date_clean = " ".join(date_raw.split()[:4])
        except Exception:
            date_clean = date_raw

        analysis = classify_email(sender, subject, snippet)
        return {
            "sender": sender,
            "subject": subject,
            "snippet": snippet,
            "date": date_clean,
            "status": analysis["status"],
            "confidence": analysis["confidence"],
            "class": analysis["class"]
        }
    except Exception:
        return None

def fetch_gmail_inbox(creds_dict, max_results=20, from_date_str=None, to_date_str=None):
    creds = Credentials(**creds_dict)
    service = build('gmail', 'v1', credentials=creds)

    query_parts = []
    if from_date_str:
        query_parts.append(f"after:{from_date_str.replace('-', '/')}")
    if to_date_str:
        query_parts.append(f"before:{to_date_str.replace('-', '/')}")
    query = " ".join(query_parts) if query_parts else ""

    results = service.users().messages().list(userId='me', maxResults=max_results, q=query).execute()
    messages = results.get('messages', [])

    emails_data = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(parse_single_message, service, m['id']) for m in messages]
        for f in futures:
            res = f.result()
            if res:
                emails_data.append(res)
            
    return emails_data

@app.route('/')
def home():
    logged_in = 'credentials' in session
    if not logged_in:
        return render_template('index.html', stats=scan_stats, logged_in=False, emails=[], user_email="", scan_count=100, from_date="", to_date="")

    user_email = session.get('user_email', 'Connected Account')
    # First time login loads instantly with recent 15 emails instead of blocking
    emails_data = session.get('last_scanned_emails')
    if emails_data is None:
        emails_data = fetch_gmail_inbox(session['credentials'], max_results=15)
        session['last_scanned_emails'] = emails_data

    return render_template('index.html', stats=scan_stats, logged_in=True, emails=emails_data, user_email=user_email, scan_count=100, from_date="", to_date="")

@app.route('/filter', methods=['POST'])
def filter_scan():
    if 'credentials' not in session:
        return redirect(url_for('home'))

    scan_count = int(request.form.get('scan_count', 100))
    from_date = request.form.get('from_date', '').strip()
    to_date = request.form.get('to_date', '').strip()

    emails_data = fetch_gmail_inbox(session['credentials'], max_results=scan_count, from_date_str=from_date, to_date_str=to_date)
    session['last_scanned_emails'] = emails_data
    user_email = session.get('user_email', 'Connected Account')

    return render_template('index.html', stats=scan_stats, logged_in=True, emails=emails_data, user_email=user_email, scan_count=scan_count, from_date=from_date, to_date=to_date)

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('callback', _external=True)
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent'
    )
    session['state'] = state
    session['code_verifier'] = flow.code_verifier
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=session.get('state'),
        redirect_uri=url_for('callback', _external=True)
    )
    flow.fetch_token(
        authorization_response=request.url,
        code_verifier=session.get('code_verifier')
    )
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    
    # Extract email from ID token instantly without network roundtrip
    try:
        session['user_email'] = credentials.id_token.get('email', 'Google User')
    except Exception:
        session['user_email'] = "Connected User"

    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)