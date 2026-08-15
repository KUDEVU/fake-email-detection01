import imaplib
import email
from email.header import decode_header

# Auto-detect common IMAP host servers
IMAP_SERVERS = {
    'gmail.com': 'imap.gmail.com',
    'googlemail.com': 'imap.gmail.com',
    'outlook.com': 'outlook.office365.com',
    'hotmail.com': 'outlook.office365.com',
    'live.com': 'outlook.office365.com',
    'yahoo.com': 'imap.mail.yahoo.com',
    'icloud.com': 'imap.mail.me.com'
}

def decode_mime_words(s):
    """Decodes MIME encoded header strings."""
    if not s:
        return ""
    decoded_parts = decode_header(s)
    result = []
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            result.append(part.decode(encoding or 'utf-8', errors='ignore'))
        else:
            result.append(str(part))
    return "".join(result)

def fetch_universal_emails(user_email, app_password, limit=25, custom_host=None):
    """Fetches emails from any IMAP-compliant email provider worldwide."""
    domain = user_email.strip().split('@')[-1].lower()
    imap_host = custom_host if custom_host else IMAP_SERVERS.get(domain, f"mail.{domain}")

    # Connect to IMAP Server over SSL
    mail = imaplib.IMAP4_SSL(imap_host, 993)
    mail.login(user_email.strip(), app_password.strip())
    mail.select('INBOX')

    # Search for all emails
    status, messages = mail.search(None, 'ALL')
    if status != 'OK' or not messages[0]:
        mail.logout()
        return []

    mail_ids = messages[0].split()
    # Pick the latest 'limit' messages
    latest_mail_ids = mail_ids[-limit:]
    latest_mail_ids.reverse()

    fetched_data = []

    for m_id in latest_mail_ids:
        res, msg_data = mail.fetch(m_id, '(RFC822)')
        if res != 'OK':
            continue

        raw_email = msg_data[0][1]
        msg = email.message_from_bytes(raw_email)

        subject = decode_mime_words(msg.get("Subject", "No Subject"))
        sender = decode_mime_words(msg.get("From", "Unknown Sender"))

        # Extract text content / snippet
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition'))
                if ctype == 'text/plain' and 'attachment' not in cdispo:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text = payload.decode(errors='ignore')
                        break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body_text = payload.decode(errors='ignore')

        snippet = body_text.strip().replace('\n', ' ')[:150] if body_text else subject

        fetched_data.append({
            'sender': sender,
            'subject': subject,
            'snippet': snippet,
            'full_text': f"{subject} {snippet}"
        })

    mail.logout()
    return fetched_data