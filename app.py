import os
from flask import Flask, redirect, url_for, session, render_template_string, request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super_secret_devu_key_987")

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# OAuth Client Config from Environment Variables
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

@app.route("/")
def index():
    if "credentials" not in session:
        return '<a href="/login"><button style="padding:10px 20px; font-size:16px; cursor:pointer;">Login with Google</button></a>'

    creds = Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    emails_data = []
    req = service.users().messages().list(userId="me", maxResults=50)

    while req is not None:
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

        req = service.users().messages().list_next(previous_request=req, previous_response=response)
        if len(emails_data) >= 100:
            break

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>DEVU - Email Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background-color: #f4f6f8; }
            .card { background: white; padding: 20px; margin-bottom: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .header { font-weight: bold; font-size: 16px; margin-bottom: 5px; }
            .sender { color: #555; font-size: 14px; margin-bottom: 8px; }
            .date { color: #888; font-size: 12px; float: right; }
            .body { color: #333; font-size: 14px; }
        </style>
    </head>
    <body>
        <h2>Fetched Emails (Total: {{ emails|length }})</h2>
        <a href="/logout">Logout</a>
        <hr>
        {% for email in emails %}
        <div class="card">
            <span class="date">{{ email.date }}</span>
            <div class="header">{{ email.subject }}</div>
            <div class="sender">From: {{ email.sender }}</div>
            <div class="body">{{ email.body }}</div>
        </div>
        {% endfor %}
    </body>
    </html>
    """
    return render_template_string(html_template, emails=emails_data)

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