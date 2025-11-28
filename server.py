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

MAX_FILE_SIZE = 150 * 1024 * 1024  # 150MB
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

DEFAULT_MONGO_URI = (
    "mongodb+srv://vamsi3126:Vsvg%40database1@cluster0.4glo7wg.mongodb.net/?appName=Cluster0"
)
MONGODB_URI = os.getenv("MONGODB_URI", DEFAULT_MONGO_URI)
MONGODB_DB = os.getenv("MONGODB_DB", "wireless_file_transfer")

if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is required. Provide your MongoDB connection string.")

mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
db = mongo_client[MONGODB_DB]
transfers = db["transfers"]
transfers.create_index([("access_code", ASCENDING)], unique=True)
# TTL index enforces 24h retention automatically
transfers.create_index("created_at", expireAfterSeconds=60 * 60 * 24)


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


def store_transfer(code: str, key_hash: str, filename: str, size_mb: float, encrypted: bytes):
    transfers.insert_one(
        {
            "access_code": code,
            "key_hash": key_hash,
            "filename": filename,
            "size_mb": size_mb,
            "encrypted_data": Binary(encrypted),
            "created_at": datetime.utcnow(),
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
    return jsonify({"error": "File exceeds 150MB limit"}), 413


@app.route("/")
def upload_form():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file selected"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    file_bytes = file.read()
    if not file_bytes:
        return jsonify({"error": "Empty file"}), 400
    if len(file_bytes) > MAX_FILE_SIZE:
        return jsonify({"error": "File exceeds 150MB limit"}), 413

    try:
        cleanup_expired_records()
        access_code = generate_unique_code()
        decryption_key = generate_pin()
        derived_key = derive_key(decryption_key)
        cipher = Fernet(derived_key)
        encrypted_data = cipher.encrypt(file_bytes)
        size_mb = round(len(file_bytes) / (1024 * 1024), 2)

        store_transfer(
            code=access_code,
            key_hash=hash_key(decryption_key),
            filename=file.filename,
            size_mb=size_mb,
            encrypted=encrypted_data,
        )

        return jsonify(
            {
                "success": True,
                "file": file.filename,
                "size_mb": size_mb,
                "code": access_code,
                "key": decryption_key,
                "warning": "Files expire in 24 hours or after one successful download.",
            }
        )
    except PyMongoError as db_err:
        app.logger.exception("Database error while saving file")
        return jsonify({"error": f"Database error: {db_err}"}), 500
    except Exception as exc:
        app.logger.exception("Upload failed")
        return jsonify({"error": f"Upload failed: {exc}"}), 500


@app.route("/download", methods=["POST"])
def download_file():
    code = request.form.get("code", "").strip()
    key = request.form.get("key", "").strip()

    if not code or not key:
        return render_template("index.html", error="Both code and key are required")

    record = get_transfer(code)
    if not record:
        return render_template("index.html", error="Invalid or expired access code")

    created_at: datetime = record.get("created_at", datetime.utcnow())
    if created_at < datetime.utcnow() - timedelta(hours=24):
        delete_transfer(code)
        return render_template("index.html", error="File expired")

    if hash_key(key) != record["key_hash"]:
        return render_template("index.html", error="Invalid decryption key")

    try:
        encrypted_bytes = bytes(record["encrypted_data"])
        derived_key = derive_key(key)
        cipher = Fernet(derived_key)
        decrypted_data = cipher.decrypt(encrypted_bytes)

        buffer = io.BytesIO(decrypted_data)
        buffer.seek(0)

        delete_transfer(code)

        return send_file(
            buffer,
            as_attachment=True,
            download_name=record["filename"],
        )
    except Exception as exc:
        app.logger.exception("Download failed")
        return render_template("index.html", error=f"Download failed: {exc}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
