from flask import Flask, request, jsonify
import random
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.mime.text import MIMEText
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import redis
import os
from dotenv import load_dotenv
load_dotenv()

r = redis.Redis(
    host=os.getenv("REDIS_HOST"),
    port=os.getenv("REDIS_PORT"),
    decode_responses=True,
    username=os.getenv("REDIS_USERNAME"),
    password=os.getenv("REDIS_PASSWORD")
)

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
    service = gmail_service()
    subject = "amide Signup OTP Code"

    template_file = "templates/otp_email_light.html"
    try:
        with open(template_file, "r") as f:
            html_template = f.read()
    except Exception:
        html_template = f"<html><body><h2>amide OTP</h2><p>Your OTP: <b>{otp}</b></p></body></html>"

    html_body = html_template.replace("{{ otp }}", otp)

    msg = MIMEMultipart("related")
    msg['to'] = to_email
    msg['subject'] = subject

    html_part = MIMEText(html_body, "html")
    msg.attach(html_part)

    try:
        with open("static/logo.png", "rb") as img:
            mime_img = MIMEImage(img.read())
            mime_img.add_header("Content-ID", "<logo.png>")
            msg.attach(mime_img)
    except:
        pass

    raw_msg = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    message = {'raw': raw_msg}
    service.users().messages().send(userId="me", body=message).execute()

@app.route('/signup', methods=['POST'])
def signup():
    if request.content_type != "application/json":
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    data = request.get_json()
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    key = f"otp:{email}"

    existing_otp = r.get(key)

    if existing_otp:
        ttl = r.ttl(key)
        return jsonify({
            "status": "exists",
            "otpSent": False,
            "timeLeft": ttl,
            "email": email
        }), 200

    otp = f"{random.randint(0, 999999):06d}"

    r.setex(key, 900, otp)

    try:
        send_otp_email(email, otp)
    except Exception as e:
        return jsonify({"error": "Failed to send email", "details": str(e)}), 500

    return jsonify({
        "status": "ok",
        "otpSent": True,
        "email": email
    }), 200

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    if request.content_type != "application/json":
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    data = request.get_json()

    email = data.get("email")
    otp = data.get("otp")

    if not email or not otp:
        return jsonify({"error": "Email and OTP are required"}), 400

    key = f"otp:{email}"

    stored_otp = r.get(key)

    if not stored_otp:
        return jsonify({
            "status": "not_found",
            "verified": False,
            "message": "OTP does not exist or has expired"
        }), 400

    if stored_otp != otp:
        return jsonify({
            "status": "invalid",
            "verified": False,
            "message": "Invalid OTP"
        }), 400

    r.delete(key)

    return jsonify({
        "status": "verified",
        "verified": True,
        "message": "OTP verified successfully"
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
