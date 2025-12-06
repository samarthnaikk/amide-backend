from flask import Flask, request, jsonify
import random
import base64
from email.mime.text import MIMEText

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

app = Flask(__name__)
SCOPES = ['https://www.googleapis.com/auth/gmail.send']


def gmail_service():
    """Authenticate and return Gmail API service."""
    creds = None
    try:
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    except:
        pass

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('client_secret.json', SCOPES)
            creds = flow.run_local_server(port=0)

        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)


def send_otp_email(to_email, otp):
    """Send OTP using Gmail API."""
    service = gmail_service()

    subject = "Your Signup OTP Code"
    body = f"Your OTP is: {otp}\n\nIt expires in 5 minutes."

    msg = MIMEText(body)
    msg['to'] = to_email
    msg['subject'] = subject

    raw_msg = base64.urlsafe_b64encode(msg.as_bytes()).decode()

    message = {
        'raw': raw_msg
    }

    service.users().messages().send(userId="me", body=message).execute()


@app.route('/signup', methods=['POST'])
def signup():
    if request.content_type != "application/json":
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    if not request.is_json:
        return jsonify({'error': 'Request body must be JSON'}), 400

    data = request.get_json()
    print(data)

    email = data.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    otp = f"{random.randint(0, 999999):06d}"

    try:
        send_otp_email(email, otp)
    except Exception as e:
        return jsonify({"error": "Failed to send email", "details": str(e)}), 500

    return jsonify({
        'status': 'ok',
        'otpSent': True,
        'email': email
    }), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
