import os
import re
from flask import Flask, redirect, url_for, session, render_template_string, request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "devu_secret_key_fixed_9988")

SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'openid',
    'https://www.googleapis.com/auth/userinfo.email'
]

REDIRECT_URI = "https://fake-email-detection01.onrender.com/oauth2callback"

def get_client_config():
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
    return {
        "web": {
            "client_id": client_id,
            "project_id": "fake-email-detection",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": client_secret,
            "redirect_uris": [REDIRECT_URI]
        }
    }

DEVU_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DEVU - Email Threat Detection</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background-color: #f1f5f9; padding: 24px 16px; color: #0f172a; }
        .container { max-width: 960px; margin: 0 auto; }
        .navbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
        .logo-box { display: flex; align-items: center; gap: 8px; font-weight: 800; font-size: 24px; color: #2563eb; }
        .shield-icon { width: 28px; height: 28px; fill: #2563eb; }
        .disconnect-btn { display: flex; align-items: center; gap: 6px; padding: 8px 18px; border: 1.5px solid #ef4444; color: #ef4444; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 14px; background: white; }
        .disconnect-btn:hover { background: #fee2e2; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); text-align: center; }
        .stat-title { font-size: 13px; font-weight: 600; color: #64748b; text-transform: uppercase; margin-bottom: 6px; }
        .stat-number { font-size: 28px; font-weight: 800; }
        .stat-total { color: #2563eb; }
        .stat-safe { color: #16a34a; }
        .stat-threat { color: #dc2626; }

        .filter-bar { background: white; padding: 14px 20px; border-radius: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 1px 3px rgba(0,0,0,0.05); flex-wrap: wrap; gap: 10px; }
        .filter-form { display: flex; align-items: center; gap: 10px; }
        .filter-select { padding: 8px 12px; border-radius: 6px; border: 1px solid #cbd5e1; font-size: 13.5px; outline: none; }
        .filter-submit { background: #2563eb; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; }

        .email-card { background: white; border-radius: 12px; padding: 20px; margin-bottom: 16px; box-shadow: 0 2px 6px rgba(0,0,0,0.04); border-left: 6px solid #16a34a; }
        .email-card.threat { border-left-color: #dc2626; }
        .card-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .badges-left { display: flex; align-items: center; gap: 10px; font-size: 13px; color: #64748b; }
        .badge-safe { background: #dcfce7; color: #15803d; padding: 4px 8px; border-radius: 6px; font-weight: 700; font-size: 11px; }
        .badge-threat { background: #fee2e2; color: #dc2626; padding: 4px 8px; border-radius: 6px; font-weight: 700; font-size: 11px; }
        .threat-badge { background: #f8fafc; border: 1px solid #e2e8f0; color: #334155; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }
        .email-subject { font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 6px; }
        .email-sender { display: flex; align-items: center; gap: 6px; font-size: 14px; color: #475569; margin-bottom: 10px; }
        .email-body { font-size: 13.5px; color: #64748b; line-height: 1.5; word-break: break-word; }

        .login-card { background: white; padding: 48px; border-radius: 16px; text-align: center; box-shadow: 0 4px 12px rgba(0,0,0,0.05); margin-top: 40px; }
        .login-btn { background: #2563eb; color: white; border: none; padding: 12px 28px; border-radius: 8px; font-weight: 600; font-size: 15px; cursor: pointer; text-decoration: none; display: inline-block; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="navbar">
            <div class="logo-box">
                <svg class="shield-icon" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
                DEVU
            </div>
            {% if session.get('credentials') %}
            <a href="/logout" class="disconnect-btn">Disconnect</a>
            {% endif %}
        </div>

        {% if not session.get('credentials') %}
        <div class="login-card">
            <h2>Welcome to DEVU</h2>
            <p style="color:#64748b; margin-top:10px;">Full-scale automated email scan with real-time spam & threat confidence analytics.</p>
            <a href="/login" class="login-btn">Login with Google</a>
        </div>
        {% else %}
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-title">Emails Scanned</div>
                <div class="stat-number stat-total">{{ emails|length }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Safe Emails</div>
                <div class="stat-number stat-safe">{{ safe_count }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Threats / Spam Detected</div>
                <div class="stat-number stat-threat">{{ threat_count }}</div>
            </div>
        </div>

        <div class="filter-bar">
            <div style="font-size:14px; font-weight:600; color:#334155;">Showing {{ emails|length }} scanned emails</div>
            <form method="GET" action="/" class="filter-form">
                <select name="filter" class="filter-select">
                    <option value="all" {% if current_filter == 'all' %}selected{% endif %}>Recent 100 Emails</option>
                    <option value="7d" {% if current_filter == '7d' %}selected{% endif %}>Last 7 Days</option>
                    <option value="30d" {% if current_filter == '30d' %}selected{% endif %}>Last 30 Days</option>
                    <option value="today" {% if current_filter == 'today' %}selected{% endif %}>Today Only</option>
                </select>
                <button type="submit" class="filter-submit">Apply Filter</button>
            </form>
        </div>

        {% for email in emails %}
        <div class="email-card {% if email.is_threat %}threat{% endif %}">
            <div class="card-top">
                <div class="badges-left">
                    {% if email.is_threat %}
                    <span class="badge-threat">⚠ SUSPICIOUS / SPAM</span>
                    {% else %}
                    <span class="badge-safe">✓ SAFE EMAIL</span>
                    {% endif %}
                    <span>🗓 {{ email.date }}</span>
                </div>
                <span class="threat-badge">{{ email.confidence }}% Threat Confidence</span>
            </div>
            <div class="email-subject">{{ email.subject }}</div>
            <div class="email-sender">From: {{ email.sender }}</div>
            <div class="email-body">{{ email.body }}</div>
        </div>
        {% endfor %}
        {% endif %}
    </div>
</body>
</html>
"""

def detect_threat(subject, snippet, sender):
    suspicious_patterns = [
        r"exposed", r"security alert", r"password reset", r"unauthorized", 
        r"verify your account", r"suspended", r"leak", r"compromised", r"action required", r"urgent"
    ]
    combined_text = f"{subject} {snippet} {sender}".lower()
    for pattern in suspicious_patterns:
        if re.search(pattern, combined_text):
            return True, 95.0
    return False, 5.0

@app.route("/")
def index():
    if "credentials" not in session:
        return render_template_string(DEVU_TEMPLATE, emails=[], safe_count=0, threat_count=0, current_filter="all")

    creds = Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    filter_type = request.args.get("filter", "all")
    query = ""
    if filter_type == "7d":
        query = "newer_than:7d"
    elif filter_type == "30d":
        query = "newer_than:30d"
    elif filter_type == "today":
        query = "newer_than:1d"

    emails_data = []
    safe_count = 0
    threat_count = 0

    req = service.users().messages().list(userId="me", q=query, maxResults=50)

    while req is not None and len(emails_data) < 100:
        response = req.execute()
        messages = response.get("messages", [])
        if not messages:
            break

        for msg in messages:
            try:
                msg_detail = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
                headers = msg_detail.get("payload", {}).get("headers", [])
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown Sender")
                date = next((h["value"] for h in headers if h["name"] == "Date"), "")
                snippet = msg_detail.get("snippet", "")

                is_threat, confidence = detect_threat(subject, snippet, sender)
                if is_threat:
                    threat_count += 1
                else:
                    safe_count += 1

                emails_data.append({
                    "id": msg["id"],
                    "subject": subject,
                    "sender": sender,
                    "date": date,
                    "body": snippet,
                    "is_threat": is_threat,
                    "confidence": confidence
                })
            except Exception:
                continue

            if len(emails_data) >= 100:
                break

        if len(emails_data) < 100:
            req = service.users().messages().list_next(previous_request=req, previous_response=response)
        else:
            break

    return render_template_string(
        DEVU_TEMPLATE,
        emails=emails_data,
        safe_count=safe_count,
        threat_count=threat_count,
        current_filter=filter_type
    )

@app.route("/login")
def login():
    flow = Flow.from_client_config(
        get_client_config(),
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    session["state"] = state
    # Save code_verifier explicitly to fix "Missing code verifier"
    if hasattr(flow, "code_verifier") and flow.code_verifier:
        session["code_verifier"] = flow.code_verifier
    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    flow = Flow.from_client_config(
        get_client_config(),
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI
    )
    
    # Restore code_verifier
    if "code_verifier" in session:
        flow.code_verifier = session["code_verifier"]

    callback_url = request.url.replace("http://", "https://", 1)

    flow.fetch_token(authorization_response=callback_url)
    creds = flow.credentials
    session["credentials"] = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)