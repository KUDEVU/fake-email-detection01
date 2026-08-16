import os
from flask import Flask, redirect, url_for, session, render_template_string, request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super_secret_key_change_me")

# Gmail Readonly Scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# OAuth credentials setup from file or environment
CLIENT_SECRETS_FILE = "credentials.json"


@app.route("/")
def index():
    if "credentials" not in session:
        return '<a href="/login"><button>Login with Google</button></a>'

    # Load stored user credentials from session
    creds = Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    emails_data = []

    # Initialize request to list emails without strict result slicing
    request = service.users().messages().list(userId="me", maxResults=50)

    # Paginate through inbox messages
    while request is not None:
        response = request.execute()
        messages = response.get("messages", [])

        if not messages:
            break

        for msg in messages:
            msg_detail = service.users().messages().get(
                userId="me", id=msg["id"], format="full"
            ).execute()

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

        # Fetch next page if available, otherwise breaks the loop
        request = service.users().messages().list_next(
            previous_request=request, previous_response=response
        )

        # Safety cap: stops after 100 emails to prevent long request timeouts
        if len(emails_data) >= 100:
            break

    # Inline HTML template to display all fetched emails
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
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for("oauth2callback", _external=True),
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline", include_granted_scopes="true"
    )
    session["state"] = state
    return redirect(authorization_url)


@app.route("/oauth2callback")
def oauth2callback():
    state = session["state"]
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for("oauth2callback", _external=True),
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
    # Required for testing on local HTTP (remove in production if HTTPS is enforced)
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    app.run(host="0.0.0.0", port=5000, debug=True)