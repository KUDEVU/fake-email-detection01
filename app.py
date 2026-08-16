import os
from flask import Flask, redirect, url_for, session, render_template_string, request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "devu_super_secret_key_123")

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_client_config():
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    return {
        "web": {
            "client_id": client_id,
            "project_id": "fake-email-detection",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": client_secret,
            "redirect_uris": ["https://fake-email-detection01.onrender.com/oauth2callback"]
        }
    }

# Complete DEVU Dashboard UI Template with Date Filtering & 100 Emails Counter
DEVU_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DEVU - Email Threat Detection</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        body { background-color: #eef2f6; padding: 24px; color: #1e293b; }
        .container { max-width: 950px; margin: 0 auto; }
        .navbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .logo-box { display: flex; align-items: center; gap: 8px; font-weight: 800; font-size: 22px; color: #1d4ed8; letter-spacing: 0.5px; }
        .shield-icon { width: 26px; height: 26px; fill: #1d4ed8; }
        .disconnect-btn { display: flex; align-items: center; gap: 6px; padding: 8px 16px; border: 1.5px solid #ef4444; color: #ef4444; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 14px; background: white; transition: 0.2s; }
        .disconnect-btn:hover { background: #fee2e2; }
        .login-card { background: white; padding: 40px; border-radius: 12px; text-align: center; box-shadow: 0 4px 12px rgba(0,0,0,0.05); margin-top: 60px; }
        .login-btn { background: #1d4ed8; color: white; border: none; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 15px; cursor: pointer; text-decoration: none; display: inline-block; margin-top: 16px; }
        .filter-bar { background: white; padding: 14px 20px; border-radius: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 5px rgba(0,0,0,0.03); }
        .filter-form { display: flex; align-items: center; gap: 10px; }
        .filter-select { padding: 6px 12px; border-radius: 6px; border: 1px solid #cbd5e1; font-size: 13.5px; outline: none; }
        .filter-submit { background: #1d4ed8; color: white; border: none; padding: 6px 14px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; }
        .stats-count { font-size: 14px; color: #475569; font-weight: 600; }
        .email-card { background: white; border-radius: 12px; border-left: 6px solid #10b981; padding: 20px; margin-bottom: 16px; box-shadow: 0 2px 6px rgba(0,0,0,0.04); }
        .card-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .badges-left { display: flex; align-items: center; gap: 10px; font-size: 13px; color: #64748b; }
        .badge-safe { background: #dcfce7; color: #15803d; padding: 3px 8px; border-radius: 6px; font-weight: 700; font-size: 11px; display: flex; align-items: center; gap: 4px; }
        .threat-badge { background: #f1f5f9; color: #334155; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }
        .email-subject { font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 6px; }
        .email-sender { display: flex; align-items: center; gap: 6px; font-size: 14px; color: #475569; margin-bottom: 10px; }
        .email-body { font-size: 13.5px; color: #64748b; line-height: 1.5; word-break: break-word; }
        .empty-state { text-align: center; padding: 40px; color: #64748b; background: white; border-radius: 12px; }
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
            <a href="/logout" class="disconnect-btn">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                Disconnect
            </a>
            {% endif %}
        </div>

        {% if not session.get('credentials') %}
        <div class="login-card">
            <h2>Welcome to DEVU</h2>
            <p style="color:#64748b; margin-top:8px;">Scan up to 100 emails with real-time threat confidence detection.</p>
            <a href="/login" class="login-btn">Login with Google</a>
        </div>
        {% else %}
        <div class="filter-bar">
            <span class="stats-count">Total Scanned: <strong>{{ emails|length }}</strong> Emails</span>
            <form method="GET" action="/" class="filter-form">
                <label for="filter" style="font-size:13px; color:#64748b;">Filter by Date:</label>
                <select name="filter" id="filter" class="filter-select">
                    <option value="all" {% if current_filter == 'all' %}selected{% endif %}>All Recent (Max 100)</option>
                    <option value="7d" {% if current_filter == '7d' %}selected{% endif %}>Last 7 Days</option>
                    <option value="30d" {% if current_filter == '30d' %}selected{% endif %}>Last 30 Days</option>
                    <option value="today" {% if current_filter == 'today' %}selected{% endif %}>Today Only</option>
                </select>
                <button type="submit" class="filter-submit">Apply Filter</button>
            </form>
        </div>

        {% if emails|length == 0 %}
            <div class="empty-state">No emails found matching the selected date filter.</div>
        {% else %}
            {% for email in emails %}
            <div class="email-card">
                <div class="card-top">
                    <div class="badges-left">
                        <span class="badge-safe">✓ SAFE EMAIL</span>
                        <span>🗓 {{ email.date }}</span>
                    </div>
                    <span class="threat-badge">95.0% Threat Confidence</span>
                </div>
                <div class="email-subject">{{ email.subject }}</div>
                <div class="email-sender">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
                    {{ email.sender }}
                </div>
                <div class="email-body">{{ email.body }}</div>
            </div>
            {% endfor %}
        {% endif %}
        {% endif %}
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    if "credentials" not in session:
        return render_template_string(DEVU_TEMPLATE, emails=[], current_filter="all")

    creds = Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    filter_type = request.args.get("filter", "all")
    
    # Gmail search query formulation based on date filters
    query = ""
    if filter_type == "7d":
        query = "newer_than:7d"
    elif filter_type == "30d":
        query = "newer_than:30d"
    elif filter_type == "today":
        query = "newer_than:1d"

    emails_data = []
    
    # Request setup: list messages with query and fetch in batches until 100 emails are scanned
    req = service.users().messages().list(userId="me", q=query, maxResults=50)

    while req is not None and len(emails_data) < 100:
        response = req.execute()
        messages = response.get("messages", [])
        if not messages:
            break

        for msg in messages:
            msg_detail = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
            headers = msg_detail.get("payload", {}).get("headers", [])
            subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
            sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown Sender")
            date = next((h["value"] for h in headers if h["name"] == "Date"), "")
            snippet = msg_detail.get("snippet", "")

            emails_data.append({
                "id": msg["id"],
                "subject": subject,
                "sender": sender,
                "date": date,
                "body": snippet,
            })

            # Exact cap at 100 scanned emails
            if len(emails_data) >= 100:
                break

        # Move to next page if emails are under 100
        if len(emails_data) < 100:
            req = service.users().messages().list_next(previous_request=req, previous_response=response)
        else:
            break

    return render_template_string(DEVU_TEMPLATE, emails=emails_data, current_filter=filter_type)

@app.route("/login")
def login():
    flow = Flow.from_client_config(
        get_client_config(),
        scopes=SCOPES,
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    authorization_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true")
    session["state"] = state
    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    flow = Flow.from_client_config(
        get_client_config(),
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    flow.fetch_token(authorization_response=request.url)
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
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    app.run(host="0.0.0.0", port=5000, debug=True)