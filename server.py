from flask import Flask, request, render_template, send_file, jsonify
import base64
import hashlib
import io
import os
import random
import string
from datetime import datetime, timedelta
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
    "mongodb+srv://vamsi3126:Vsvg%40database1@cluster0.4glo7wg.mongodb.net/?appName=Cluster0"
)
MONGODB_URI = os.getenv("MONGODB_URI", DEFAULT_MONGO_URI)
MONGODB_DB = os.getenv("MONGODB_DB", "wireless_file_transfer")

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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
