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


<<<<<<< HEAD
def store_transfer(
    code: str,
    key_hash: str,
    filename: str,
    size_mb: float,
    encrypted: bytes,
    downloads_remaining: int,
    content_type: str,
):
=======
def store_transfer(code: str, key_hash: str, filename: str, size_mb: float, encrypted: bytes):
>>>>>>> ecbd216ee909525ce21fad51f9f4a6b66981aa66
    transfers.insert_one(
        {
            "access_code": code,
            "key_hash": key_hash,
            "filename": filename,
            "size_mb": size_mb,
            "encrypted_data": Binary(encrypted),
            "created_at": datetime.utcnow(),
<<<<<<< HEAD
            "downloads_remaining": downloads_remaining,
            "content_type": content_type,
=======
>>>>>>> ecbd216ee909525ce21fad51f9f4a6b66981aa66
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
<<<<<<< HEAD
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
                return jsonify({"error": "File exceeds 150MB limit"}), 413
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
            return jsonify({"error": "Text exceeds 150MB limit"}), 413
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

=======
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
>>>>>>> ecbd216ee909525ce21fad51f9f4a6b66981aa66
        decryption_key = generate_pin()
        derived_key = derive_key(decryption_key)
        cipher = Fernet(derived_key)
        encrypted_data = cipher.encrypt(file_bytes)
        size_mb = round(len(file_bytes) / (1024 * 1024), 2)

        store_transfer(
            code=access_code,
            key_hash=hash_key(decryption_key),
<<<<<<< HEAD
            filename=filename,
            size_mb=size_mb,
            encrypted=encrypted_data,
            downloads_remaining=max_downloads,
            content_type=content_type,
=======
            filename=file.filename,
            size_mb=size_mb,
            encrypted=encrypted_data,
>>>>>>> ecbd216ee909525ce21fad51f9f4a6b66981aa66
        )

        return jsonify(
            {
                "success": True,
<<<<<<< HEAD
                "file": filename,
                "size_mb": size_mb,
                "code": access_code,
                "key": decryption_key,
                "download_limit": max_downloads,
                "warning": "Files expire in 24 hours or when downloads are exhausted.",
=======
                "file": file.filename,
                "size_mb": size_mb,
                "code": access_code,
                "key": decryption_key,
                "warning": "Files expire in 24 hours or after one successful download.",
>>>>>>> ecbd216ee909525ce21fad51f9f4a6b66981aa66
            }
        )
    except PyMongoError as db_err:
        app.logger.exception("Database error while saving file")
        return jsonify({"error": f"Database error: {db_err}"}), 500
    except Exception as exc:
        app.logger.exception("Upload failed")
        return jsonify({"error": f"Upload failed: {exc}"}), 500


<<<<<<< HEAD
@app.route("/download", methods=["POST", "GET"])
def download_file():
    if request.method == "GET":
        code = request.args.get("code", "").strip()
        key = request.args.get("key", "").strip()
        if not code or not key:
            return render_template("index.html")
    else:
        code = request.form.get("code", "").strip()
        key = request.form.get("key", "").strip()

    if not code or not key:
        return render_template("index.html", error="Both code and key are required")
    try:
        record = get_transfer(code)
        if not record:
            return render_template("index.html", error="Invalid or expired access code")

        created_at: datetime = record.get("created_at", datetime.utcnow())
        if created_at < datetime.utcnow() - timedelta(hours=24):
            delete_transfer(code)
            return render_template("index.html", error="File expired")

        if hash_key(key) != record["key_hash"]:
            return render_template("index.html", error="Invalid decryption key")

        remaining = int(record.get("downloads_remaining", 1))
        if remaining <= 0:
            delete_transfer(code)
            return render_template("index.html", error="Download limit reached")

=======
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
>>>>>>> ecbd216ee909525ce21fad51f9f4a6b66981aa66
        encrypted_bytes = bytes(record["encrypted_data"])
        derived_key = derive_key(key)
        cipher = Fernet(derived_key)
        decrypted_data = cipher.decrypt(encrypted_bytes)

        buffer = io.BytesIO(decrypted_data)
        buffer.seek(0)

<<<<<<< HEAD
        new_remaining = remaining - 1
        if new_remaining <= 0:
            delete_transfer(code)
        else:
            transfers.update_one({"access_code": code}, {"$set": {"downloads_remaining": new_remaining}})

        if record.get("content_type") == "text":
            text_value = buffer.getvalue().decode("utf-8", errors="replace")
            return render_template("index.html", decrypted_text=text_value)
        else:
            return send_file(
                buffer,
                as_attachment=True,
                download_name=record["filename"],
            )
    except PyMongoError as db_err:
        app.logger.exception("Database error on download")
        return render_template("index.html", error="Database connection error")
=======
        delete_transfer(code)

        return send_file(
            buffer,
            as_attachment=True,
            download_name=record["filename"],
        )
>>>>>>> ecbd216ee909525ce21fad51f9f4a6b66981aa66
    except Exception as exc:
        app.logger.exception("Download failed")
        return render_template("index.html", error=f"Download failed: {exc}")


<<<<<<< HEAD
@app.route("/download_encrypted", methods=["POST", "GET"])
def download_encrypted():
    if request.method != "POST":
        return render_template("index.html")
    code = request.form.get("code", "").strip()
    if not code:
        return render_template("index.html", error="Access code is required")
    try:
        record = get_transfer(code)
        if not record:
            return render_template("index.html", error="Invalid or expired access code")

        created_at: datetime = record.get("created_at", datetime.utcnow())
        if created_at < datetime.utcnow() - timedelta(hours=24):
            delete_transfer(code)
            return render_template("index.html", error="File expired")

        remaining = int(record.get("downloads_remaining", 1))
        if remaining <= 0:
            delete_transfer(code)
            return render_template("index.html", error="Download limit reached")

        encrypted_bytes = bytes(record["encrypted_data"])
        buffer = io.BytesIO(encrypted_bytes)
        buffer.seek(0)

        new_remaining = remaining - 1
        if new_remaining <= 0:
            delete_transfer(code)
        else:
            transfers.update_one({"access_code": code}, {"$set": {"downloads_remaining": new_remaining}})

        if record.get("content_type") == "text":
            import base64 as _b64
            encoded = _b64.b64encode(buffer.getvalue()).decode("ascii")
            return render_template("index.html", encrypted_text=encoded)
        else:
            name = f"{record['filename']}.encrypted"
            return send_file(
                buffer,
                as_attachment=True,
                download_name=name,
            )
    except PyMongoError as db_err:
        app.logger.exception("Database error on encrypted download")
        return render_template("index.html", error="Database connection error")
    except Exception as exc:
        app.logger.exception("Encrypted download failed")
        return render_template("index.html", error=f"Download failed: {exc}")

@app.route("/db_health")
def db_health():
    try:
        mongo_client.admin.command("ping")
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

=======
>>>>>>> ecbd216ee909525ce21fad51f9f4a6b66981aa66
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
