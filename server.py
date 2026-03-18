from flask import Flask, request, render_template, send_file, jsonify
import base64
import hashlib
import io
import os
import random
import smtplib
import string
import uuid
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, formataddr
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from pymongo import MongoClient, ASCENDING
from pymongo.errors import PyMongoError
from bson.binary import Binary

app = Flask(__name__)

MAX_FILE_SIZE = 300 * 1024 * 1024  # 300MB
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

DEFAULT_MONGO_URI = (
    "mongodb+srv://vamsigattikoppula2_db_user:file-transfer123@cluster0.ebhog9t.mongodb.net/?appName=Cluster0"
)
MONGODB_URI = os.getenv("MONGODB_URI", DEFAULT_MONGO_URI)
MONGODB_DB = os.getenv("MONGODB_DB", "wireless_file_transfer")

# SMTP configuration for email sharing
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_EMAIL = os.getenv("SMTP_EMAIL", "")   # e.g. yourapp@gmail.com
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")  # Gmail app-password

if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is required. Provide your MongoDB connection string.")

mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=10000)
db = mongo_client[MONGODB_DB]
transfers = db["transfers"]
try:
    transfers.create_index([("access_code", ASCENDING)], unique=True)
    transfers.create_index("created_at", expireAfterSeconds=60 * 60 * 24)
except PyMongoError:
    pass  # Indexes may already exist


def cleanup_expired_records():
    threshold = datetime.utcnow() - timedelta(hours=24)
    transfers.delete_many({"created_at": {"$lt": threshold}})


def generate_pin():
    return "".join(random.choices(string.digits, k=4))


def derive_key(pin: str) -> bytes:
    salt = b"unique_salt_value"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(pin.encode()))


def hash_key(pin: str) -> str:
    return hashlib.sha256(pin.encode()).hexdigest()


def get_transfer(code: str):
    return transfers.find_one({"access_code": code})


def store_transfer(
    code: str,
    key_hash: str,
    filename: str,
    size_mb: float,
    encrypted: bytes,
    downloads_remaining: int,
    content_type: str,
):
    # Create encrypted filename with .encrypted extension
    encrypted_filename = filename + ".encrypted"
    transfers.insert_one(
        {
            "access_code": code,
            "key_hash": key_hash,
            "filename": filename,  # Original filename
            "encrypted_filename": encrypted_filename,  # Filename for encrypted downloads
            "size_mb": size_mb,
            "encrypted_data": Binary(encrypted),
            "created_at": datetime.utcnow(),
            "downloads_remaining": downloads_remaining,
            "content_type": content_type,
        }
    )


def delete_transfer(code: str):
    transfers.delete_one({"access_code": code})


def generate_unique_code() -> str:
    # try a few times to avoid collisions
    for _ in range(10):
        candidate = generate_pin()
        if not get_transfer(candidate):
            return candidate
    return "".join(random.choices(string.digits, k=6))


@app.errorhandler(413)
def request_too_large(e):
    return jsonify({"error": "File exceeds 300MB limit"}), 413


@app.route("/")
def upload_form():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    file_bytes = None
    filename = None
    has_file = False
    has_text = False

    # Read file if present
    if "file" in request.files:
        f = request.files["file"]
        if f and f.filename:
            has_file = True
            data = f.read()
            if not data:
                return jsonify({"error": "Empty file"}), 400
            if len(data) > MAX_FILE_SIZE:
                return jsonify({"error": "File exceeds 300MB limit"}), 413
            file_bytes = data
            filename = f.filename

    # Read text if present
    text = request.form.get("text", "")
    if text.strip():
        has_text = True

    # Validate exclusive choice: either file or text
    if has_file and has_text:
        return jsonify({"error": "Provide either a file or text, not both"}), 400

    if not has_file and not has_text:
        return jsonify({"error": "No content provided"}), 400

    if not has_file and has_text:
        data = text.encode("utf-8")
        if len(data) > MAX_FILE_SIZE:
            return jsonify({"error": "Text exceeds 300MB limit"}), 413
        file_bytes = data
        filename = "message.txt"
        content_type = "text"
    else:
        content_type = "file"

    try:
        cleanup_expired_records()
        raw_max = request.form.get("max_downloads", "1")
        try:
            max_downloads = int(raw_max)
            if max_downloads < 1:
                max_downloads = 1
        except ValueError:
            max_downloads = 1

        access_code = generate_unique_code()

        decryption_key = generate_pin()
        derived_key = derive_key(decryption_key)
        cipher = Fernet(derived_key)
        encrypted_data = cipher.encrypt(file_bytes)
        size_mb = round(len(file_bytes) / (1024 * 1024), 2)

        store_transfer(
            code=access_code,
            key_hash=hash_key(decryption_key),
            filename=filename,
            size_mb=size_mb,
            encrypted=encrypted_data,
            downloads_remaining=max_downloads,
            content_type=content_type,
        )

        return jsonify(
            {
                "success": True,
                "file": filename,
                "size_mb": size_mb,
                "code": access_code,
                "key": decryption_key,
                "download_limit": max_downloads,
                "warning": "Files expire in 24 hours or when downloads are exhausted.",
            }
        )
    except PyMongoError as db_err:
        app.logger.exception("Database error while saving file")
        return jsonify({"error": f"Database error: {db_err}"}), 500
    except Exception as exc:
        app.logger.exception("Upload failed")
        return jsonify({"error": f"Upload failed: {exc}"}), 500


def _process_download(code: str, key: str, is_send_file: bool = True):
    """Shared logic for POST and GET download. Returns (response, None) or (None, error_msg)."""
    if not code:
        return None, "Access code is required"
    try:
        record = get_transfer(code)
        if not record:
            return None, "Invalid or expired access code"

        created_at = record.get("created_at", datetime.utcnow())
        if created_at < datetime.utcnow() - timedelta(hours=24):
            delete_transfer(code)
            return None, "File expired"

        remaining = int(record.get("downloads_remaining", 1))
        if remaining <= 0:
            delete_transfer(code)
            return None, "Download limit reached"

        encrypted_bytes = bytes(record["encrypted_data"])

        # Mode 1: Access code only - return encrypted file
        if not key:
            result = transfers.update_one(
                {"access_code": code, "downloads_remaining": {"$gt": 0}},
                {"$inc": {"downloads_remaining": -1}},
            )
            if result.matched_count == 0:
                return None, "Download limit reached"
            updated = get_transfer(code)
            if updated and int(updated.get("downloads_remaining", 0)) <= 0:
                delete_transfer(code)
            buffer = io.BytesIO(encrypted_bytes)
            buffer.seek(0)
            filename = record.get("encrypted_filename", record["filename"] + ".encrypted")
            return (send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/octet-stream"), None)

        # Mode 2: Access code + PIN - decrypt and return
        if hash_key(key) != record["key_hash"]:
            return None, "Invalid decryption PIN"
        derived_key = derive_key(key)
        cipher = Fernet(derived_key)
        try:
            decrypted_data = cipher.decrypt(encrypted_bytes)
        except Exception:
            return None, "Decryption failed. Invalid PIN."
        result = transfers.update_one(
            {"access_code": code, "downloads_remaining": {"$gt": 0}},
            {"$inc": {"downloads_remaining": -1}},
        )
        if result.matched_count == 0:
            return None, "Download limit reached"
        updated = get_transfer(code)
        if updated and int(updated.get("downloads_remaining", 0)) <= 0:
            delete_transfer(code)
        buffer = io.BytesIO(decrypted_data)
        buffer.seek(0)
        return (send_file(buffer, as_attachment=True, download_name=record["filename"], mimetype="application/octet-stream"), None)
    except PyMongoError:
        return None, "Database connection error"
    except Exception as exc:
        return None, f"Download failed: {exc}"


@app.route("/download", methods=["POST", "GET"])
def download_file():
    if request.method == "GET":
        code = request.args.get("code", "").strip()
        key = request.args.get("key", "").strip()
        if not code:
            return render_template("index.html")
        # Serve auto-submit form - POST triggers download (more reliable than direct GET response)
        return render_template("download_redirect.html", code=code, key=key)

    code = request.form.get("code", "").strip()
    key = request.form.get("key", "").strip()

    if not code:
        return render_template("index.html", error="Access code is required")

    resp, err = _process_download(code, key)
    if err:
        return render_template("index.html", error=err)
    return resp

def send_email_notification(recipient_email, download_url, filename, size_mb):
    """Send a clean, spam-filter-friendly email with the download link."""
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        raise RuntimeError("SMTP credentials not configured. Set SMTP_EMAIL and SMTP_PASSWORD env vars.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"File shared with you: {filename}"
    msg["From"] = formataddr(("Secure File Transfer", SMTP_EMAIL))
    msg["To"] = recipient_email
    msg["Reply-To"] = SMTP_EMAIL
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = f"<{uuid.uuid4()}@securefiletransfer.app>"

    # Rich plain-text version (improves spam score significantly)
    plain = f"""Hello,

A file has been shared with you through Secure File Transfer.

File details:
  Name: {filename}
  Size: {size_mb} MB

You can download the file by visiting this link:
{download_url}

This link will expire in 24 hours. Please download the file before it expires.

If you did not expect this email, you can safely ignore it.

Best regards,
Secure File Transfer
"""

    # Clean, light-themed HTML (white background, minimal styling)
    html = f"""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0; padding:0; font-family: Arial, Helvetica, sans-serif; background-color:#f4f4f7;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f7; padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="520" cellpadding="0" cellspacing="0" style="background-color:#ffffff; border-radius:8px; border:1px solid #e0e0e0;">
          <!-- Header -->
          <tr>
            <td style="padding:30px 32px 20px; text-align:center; border-bottom:1px solid #eeeeee;">
              <h1 style="margin:0; font-size:22px; color:#333333; font-weight:600;">Secure File Transfer</h1>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding:28px 32px;">
              <p style="margin:0 0 18px; font-size:15px; color:#555555; line-height:1.6;">
                Hello, a file has been shared with you. You can download it using the button below.
              </p>
              <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f8f9fa; border-radius:6px; border:1px solid #e9ecef;">
                <tr>
                  <td style="padding:16px 20px;">
                    <p style="margin:0 0 4px; font-size:14px; color:#333333;"><strong>File:</strong> {filename}</p>
                    <p style="margin:0; font-size:14px; color:#666666;"><strong>Size:</strong> {size_mb} MB</p>
                  </td>
                </tr>
              </table>
              <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:24px;">
                <tr>
                  <td align="center">
                    <a href="{download_url}" style="display:inline-block; padding:12px 36px; background-color:#4A90D9; color:#ffffff; text-decoration:none; border-radius:6px; font-weight:600; font-size:15px;">Download File</a>
                  </td>
                </tr>
              </table>
              <p style="margin:24px 0 0; font-size:13px; color:#999999; line-height:1.5;">
                This link expires in 24 hours. If you did not expect this email, you can safely ignore it.
              </p>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding:16px 32px; text-align:center; border-top:1px solid #eeeeee; background-color:#fafafa; border-radius:0 0 8px 8px;">
              <p style="margin:0; font-size:12px; color:#aaaaaa;">Sent via Secure File Transfer</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, recipient_email, msg.as_string())


@app.route("/send-email", methods=["POST"])
def send_email():
    """After a successful upload, send the download link to a recipient via email."""
    data = request.get_json(force=True)
    recipient = (data.get("recipient_email") or "").strip()
    code = (data.get("code") or "").strip()
    key = (data.get("key") or "").strip()
    filename = data.get("filename", "file")
    size_mb = data.get("size_mb", 0)

    if not recipient:
        return jsonify({"error": "Recipient email is required"}), 400
    if not code or not key:
        return jsonify({"error": "Upload code and key are required"}), 400

    download_url = request.host_url.rstrip("/") + "/download?code=" + code + "&key=" + key

    try:
        send_email_notification(recipient, download_url, filename, size_mb)
        return jsonify({"success": True, "message": f"Download link sent to {recipient}"})
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    except Exception as exc:
        app.logger.exception("Email send failed")
        return jsonify({"error": f"Failed to send email: {exc}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
