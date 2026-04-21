"""
Secure File Transfer — Flask Application
=========================================
Supports:
  • Per-file random salt + PBKDF2-HMAC key derivation
  • Single-blob storage  for files ≤ 50 MB
  • Chunk-based storage  for files >  50 MB  (≤10 MB chunks, MongoDB-safe)
  • Multi-file uploads   (up to 3 files per request, single code + PIN)
  • ZIP response         for multi-file downloads
  • Email sharing        (file link or inline text)
"""

from flask import Flask, request, render_template, send_file, jsonify
import base64
import hashlib
import io
import logging
import os
import random
import smtplib
import string
import uuid
import zipfile
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, formataddr

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from pymongo import MongoClient, ASCENDING
from pymongo.errors import PyMongoError
from bson.binary import Binary

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App & size constants
# ---------------------------------------------------------------------------
app = Flask(__name__)

CHUNK_THRESHOLD = 50  * 1024 * 1024   # 50 MB  — use chunking above this
CHUNK_SIZE      = 10  * 1024 * 1024   # 10 MB  — max bytes per chunk
MAX_FILE_SIZE   = 300 * 1024 * 1024   # 300 MB — hard per-file limit
MAX_FILES       = 1                   # one file per upload request

# Allow one full file through Flask's body limit
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------
DEFAULT_MONGO_URI = (
    "mongodb+srv://vamsigattikoppula2_db_user:file-transfer123"
    "@cluster0.ebhog9t.mongodb.net/?appName=Cluster0"
)
MONGODB_URI = os.getenv("MONGODB_URI", DEFAULT_MONGO_URI)
MONGODB_DB  = os.getenv("MONGODB_DB", "wireless_file_transfer")

if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is required. Set it as an environment variable.")

mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=10_000)
db           = mongo_client[MONGODB_DB]
transfers    = db["transfers"]   # one doc per upload batch
chunks_col   = db["chunks"]      # one doc per encrypted chunk (large files only)

# Ensure indexes exist
try:
    transfers.create_index([("access_code", ASCENDING)], unique=True)
    transfers.create_index("created_at", expireAfterSeconds=86_400)   # 24-hour TTL
    chunks_col.create_index([("access_code", ASCENDING)])
    chunks_col.create_index([("access_code", ASCENDING), ("file_index", ASCENDING)])
    logger.info("MongoDB indexes verified.")
except PyMongoError:
    pass  # Indexes already exist — safe to ignore

# ---------------------------------------------------------------------------
# SMTP (email sharing)
# ---------------------------------------------------------------------------
SMTP_SERVER   = os.getenv("SMTP_SERVER",   "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_EMAIL    = os.getenv("SMTP_EMAIL",    "")   # sender address
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")   # Gmail app-password


# ===========================================================================
# ── Cryptography helpers ────────────────────────────────────────────────────
# ===========================================================================

def derive_key(pin: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte Fernet-compatible key from a PIN and a per-file random salt.
    Uses PBKDF2-HMAC-SHA256 with 100 000 iterations.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(pin.encode()))


def hash_pin(pin: str) -> str:
    """Return SHA-256 hex-digest of the PIN. Plaintext PIN is never stored."""
    return hashlib.sha256(pin.encode()).hexdigest()


def encrypt_index(fernet: Fernet, index: int) -> bytes:
    """Fernet-encrypt a chunk's integer index to hide storage order."""
    return fernet.encrypt(str(index).encode())


def decrypt_index(fernet: Fernet, token: bytes) -> int:
    """Decrypt an encrypted chunk index back to an integer."""
    return int(fernet.decrypt(token).decode())


# ===========================================================================
# ── Access-code / PIN generators ────────────────────────────────────────────
# ===========================================================================

def generate_pin() -> str:
    """Generate a random 4-digit numeric PIN."""
    return "".join(random.choices(string.digits, k=4))


def generate_unique_code() -> str:
    """Generate a 4-digit access code not already in use; fall back to 6 digits."""
    for _ in range(10):
        candidate = generate_pin()
        if not transfers.find_one({"access_code": candidate}):
            return candidate
    return "".join(random.choices(string.digits, k=6))


# ===========================================================================
# ── Cleanup ──────────────────────────────────────────────────────────────────
# ===========================================================================

def cleanup_expired_records():
    """
    Delete transfer records older than 24 hours and their associated chunks.
    Called on every upload as a belt-and-suspenders complement to the TTL index.
    """
    threshold = datetime.utcnow() - timedelta(hours=24)
    expired_codes = [
        r["access_code"]
        for r in transfers.find({"created_at": {"$lt": threshold}}, {"access_code": 1})
    ]
    if expired_codes:
        chunks_col.delete_many({"access_code": {"$in": expired_codes}})
        transfers.delete_many({"created_at": {"$lt": threshold}})
        logger.info("Cleaned up %d expired transfer(s).", len(expired_codes))


# ===========================================================================
# ── File upload helpers ──────────────────────────────────────────────────────
# ===========================================================================

def _stream_chunks(file_storage, chunk_size: int = CHUNK_SIZE):
    """
    Generator — yields raw byte pieces of at most `chunk_size` bytes
    from a Werkzeug FileStorage stream without loading the whole file.
    """
    while True:
        piece = file_storage.stream.read(chunk_size)
        if not piece:
            break
        yield piece


def upload_file_object(
    file_storage,
    file_index: int,
    access_code: str,
    pin: str,
) -> dict:
    """
    Process a single FileStorage object and return a file-metadata dict
    to be embedded in transfers.files[].

    Storage strategy:
      • total size ≤ 50 MB  →  encrypted single blob (storage_type = "single")
      • total size >  50 MB  →  encrypted chunks in `chunks` collection (storage_type = "chunked")

    Each file gets its own random 16-byte salt, so every file's encryption
    key is independent even when sharing the same PIN.

    Raises ValueError for empty files, oversized files, or DB errors.
    """
    filename   = file_storage.filename or f"file_{file_index}"
    salt       = os.urandom(16)               # per-file random salt
    key_bytes  = derive_key(pin, salt)
    fernet     = Fernet(key_bytes)

    # --- Stream-read the file in 10 MB chunks ---
    raw_chunks: list[bytes] = []
    total_size = 0

    for piece in _stream_chunks(file_storage):
        total_size += len(piece)
        if total_size > MAX_FILE_SIZE:
            raise ValueError(f"'{filename}' exceeds the 300 MB per-file limit.")
        raw_chunks.append(piece)

    if total_size == 0:
        raise ValueError(f"'{filename}' appears to be empty.")

    size_mb = round(total_size / (1024 * 1024), 2)
    logger.info(
        "Processing file[%d] '%s' (%.2f MB) for access_code=%s",
        file_index, filename, size_mb, access_code,
    )

    # ----------------------------------------------------------------
    # Single-blob path  (≤ 50 MB)
    # ----------------------------------------------------------------
    if total_size <= CHUNK_THRESHOLD:
        file_bytes     = b"".join(raw_chunks)
        encrypted_data = fernet.encrypt(file_bytes)
        logger.info("  → stored as single encrypted blob.")
        return {
            "file_index":     file_index,
            "filename":       filename,
            "size_mb":        size_mb,
            "content_type":   "file",
            "storage_type":   "single",
            "salt":           Binary(salt),
            "encrypted_data": Binary(encrypted_data),
            "total_chunks":   1,
        }

    # ----------------------------------------------------------------
    # Chunked path  (> 50 MB)
    # ----------------------------------------------------------------
    chunk_docs   = []
    chunk_index  = 0

    for piece in raw_chunks:
        encrypted_chunk = fernet.encrypt(piece)
        encrypted_idx   = encrypt_index(fernet, chunk_index)
        chunk_hash      = hashlib.sha256(piece).hexdigest()   # integrity tag

        chunk_docs.append({
            "access_code":           access_code,
            "file_index":            file_index,
            "chunk_order_encrypted": Binary(encrypted_idx),
            "data":                  Binary(encrypted_chunk),
            "chunk_hash":            chunk_hash,
        })
        chunk_index += 1

    chunks_col.insert_many(chunk_docs)
    logger.info("  → stored as %d chunks.", chunk_index)

    return {
        "file_index":  file_index,
        "filename":    filename,
        "size_mb":     size_mb,
        "content_type":"file",
        "storage_type":"chunked",
        "salt":        Binary(salt),
        "total_chunks": chunk_index,
        "chunk_size":   CHUNK_SIZE,
    }


# ===========================================================================
# ── File download / reconstruction helper ────────────────────────────────────
# ===========================================================================

def reconstruct_file_bytes(file_meta: dict, access_code: str, pin: str) -> bytes:
    """
    Reconstruct and return the original plaintext bytes for one file.

    Steps:
      1. Re-derive the file's encryption key using its stored salt and the PIN.
      2. For single-blob: Fernet-decrypt encrypted_data.
      3. For chunked:
           a. Fetch all chunk documents for this (access_code, file_index).
           b. Fernet-decrypt each chunk's encrypted index → sort ascending.
           c. Fernet-decrypt each chunk's data in sorted order → concatenate.

    Raises ValueError on invalid PIN or missing chunks.
    """
    filename     = file_meta.get("filename", "file")
    salt         = bytes(file_meta["salt"])
    key_bytes    = derive_key(pin, salt)
    fernet       = Fernet(key_bytes)
    storage_type = file_meta.get("storage_type", "single")

    # ── Single blob ──────────────────────────────────────────────────
    if storage_type == "single":
        try:
            return fernet.decrypt(bytes(file_meta["encrypted_data"]))
        except InvalidToken:
            raise ValueError(f"Decryption failed for '{filename}'. Check your PIN.")

    # ── Chunked ──────────────────────────────────────────────────────
    file_index = file_meta["file_index"]
    chunk_docs = list(
        chunks_col.find({"access_code": access_code, "file_index": file_index})
    )
    if not chunk_docs:
        raise ValueError(
            f"No chunks found for '{filename}' (file_index={file_index}). "
            "The transfer may have been deleted or is corrupt."
        )

    # Decrypt indices to determine correct order
    indexed: list[tuple[int, bytes]] = []
    for doc in chunk_docs:
        try:
            idx = decrypt_index(fernet, bytes(doc["chunk_order_encrypted"]))
        except InvalidToken:
            raise ValueError(f"Invalid PIN — cannot decrypt chunk index for '{filename}'.")
        indexed.append((idx, bytes(doc["data"])))

    indexed.sort(key=lambda x: x[0])
    logger.info("  Reconstructing '%s': %d chunk(s).", filename, len(indexed))

    # Decrypt and concatenate chunks in correct order
    result = bytearray()
    for idx, enc_data in indexed:
        try:
            result.extend(fernet.decrypt(enc_data))
        except InvalidToken:
            raise ValueError(f"Decryption failed for chunk {idx} of '{filename}'.")

    return bytes(result)


# ===========================================================================
# ── Download-limit helper ────────────────────────────────────────────────────
# ===========================================================================

def _decrement_or_delete(code: str) -> bool:
    """
    Atomically decrement downloads_remaining for the given access_code.
    If it reaches 0, permanently delete the transfer record and all its chunks.
    Returns False if the limit was already exhausted (matched_count == 0).
    """
    result = transfers.update_one(
        {"access_code": code, "downloads_remaining": {"$gt": 0}},
        {"$inc": {"downloads_remaining": -1}},
    )
    if result.matched_count == 0:
        return False

    updated = transfers.find_one({"access_code": code})
    if updated and int(updated.get("downloads_remaining", 0)) <= 0:
        chunks_col.delete_many({"access_code": code})
        transfers.delete_one({"access_code": code})
        logger.info("Transfer %s exhausted — deleted record and chunks.", code)

    return True


# ===========================================================================
# ── Flask error handlers ─────────────────────────────────────────────────────
# ===========================================================================

@app.errorhandler(413)
def request_too_large(e):
    return jsonify({"error": "Upload exceeds the allowed size limit (300 MB per file)."}), 413


# ===========================================================================
# ── Routes ───────────────────────────────────────────────────────────────────
# ===========================================================================

@app.route("/")
def upload_form():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# POST /upload
# ---------------------------------------------------------------------------
@app.route("/upload", methods=["POST"])
def upload_file():
    """
    Accept a single file or text snippet, encrypt it, and store in MongoDB.
    Files ≤ 50 MB are stored as a single encrypted blob.
    Files > 50 MB are split into 10 MB encrypted chunks.

    Form fields:
      file          — one file input (name="file")
      text          — plain-text content (mutually exclusive with file)
      max_downloads — integer ≥ 1 (default 1)
    """
    try:
        cleanup_expired_records()

        # Accept file under either field name for compat
        uploaded_files = request.files.getlist("file") + request.files.getlist("files")
        uploaded_files = [f for f in uploaded_files if f and f.filename]

        text      = request.form.get("text", "").strip()
        has_files = bool(uploaded_files)
        has_text  = bool(text)

        # ── Input validation ─────────────────────────────────────────
        if not has_files and not has_text:
            return jsonify({"error": "No content provided."}), 400
        if has_files and has_text:
            return jsonify({"error": "Provide either a file or text, not both."}), 400
        if has_files and len(uploaded_files) > 1:
            return jsonify({"error": "Only 1 file per upload is allowed."}), 400

        raw_max = request.form.get("max_downloads", "1")
        try:
            max_downloads = max(1, int(raw_max))
        except ValueError:
            max_downloads = 1

        # ── Generate access code + PIN ───────────────────────────────
        access_code = generate_unique_code()
        pin         = generate_pin()
        key_hash    = hash_pin(pin)

        files_meta: list[dict] = []

        # ── Process text ─────────────────────────────────────────────
        if has_text:
            text_bytes = text.encode("utf-8")
            if len(text_bytes) > MAX_FILE_SIZE:
                return jsonify({"error": "Text content exceeds the 300 MB limit."}), 413

            salt      = os.urandom(16)
            fernet    = Fernet(derive_key(pin, salt))
            encrypted = fernet.encrypt(text_bytes)

            files_meta.append({
                "file_index":     0,
                "filename":       "message.txt",
                "size_mb":        round(len(text_bytes) / (1024 * 1024), 4),
                "content_type":   "text",
                "storage_type":   "single",
                "salt":           Binary(salt),
                "encrypted_data": Binary(encrypted),
                "total_chunks":   1,
            })

        # ── Process single file ───────────────────────────────────────
        if has_files:
            try:
                meta = upload_file_object(uploaded_files[0], 0, access_code, pin)
                files_meta.append(meta)
            except ValueError as exc:
                chunks_col.delete_many({"access_code": access_code})
                return jsonify({"error": str(exc)}), 400

        # ── Persist transfer document ─────────────────────────────────
        transfers.insert_one({
            "access_code":         access_code,
            "key_hash":            key_hash,
            "files":               files_meta,
            "total_files":         1,
            "created_at":          datetime.utcnow(),
            "downloads_remaining": max_downloads,
        })
        logger.info(
            "Upload complete. code=%s  storage=%s  pin=****  max_dl=%d",
            access_code,
            files_meta[0].get("storage_type", "?") if files_meta else "text",
            max_downloads,
        )

        first = files_meta[0] if files_meta else {}
        return jsonify({
            "success":        True,
            "file":           first.get("filename", ""),
            "size_mb":        first.get("size_mb", 0),
            "storage_type":   first.get("storage_type", "single"),
            "code":           access_code,
            "key":            pin,
            "download_limit": max_downloads,
            "warning":        "Transfer expires in 24 hours or when downloads are exhausted.",
        })

    except PyMongoError as exc:
        logger.exception("Database error during upload.")
        return jsonify({"error": f"Database error: {exc}"}), 500
    except Exception as exc:
        logger.exception("Unexpected error during upload.")
        return jsonify({"error": f"Upload failed: {exc}"}), 500


# ---------------------------------------------------------------------------
# GET /download  — renders the auto-submit redirect form
# ---------------------------------------------------------------------------
@app.route("/download", methods=["GET"])
def download_redirect():
    code = request.args.get("code", "").strip()
    key  = request.args.get("key",  "").strip()
    if not code:
        return render_template("index.html")
    return render_template("download_redirect.html", code=code, key=key)


# ---------------------------------------------------------------------------
# POST /download — validates credentials, decrypts, and streams content
# ---------------------------------------------------------------------------
@app.route("/download", methods=["POST"])
def download_file():
    """
    Two modes:

    Mode A — No PIN supplied:
        Returns the raw (still-encrypted) blob(s).
        Useful for offline decryption workflows.

    Mode B — PIN supplied:
        Verifies PIN hash, decrypts content, returns:
          • text               → renders view_text.html
          • single binary file → streams file directly
          • multiple files     → streams as <code>_files.zip
    """
    code = request.form.get("code", "").strip()
    pin  = request.form.get("key",  "").strip()

    if not code:
        return render_template("index.html", error="Access code is required.")

    try:
        record = transfers.find_one({"access_code": code})
        if not record:
            return render_template("index.html", error="Invalid or expired access code.")

        # Belt-and-suspenders expiry check (TTL handles it server-side too)
        if record["created_at"] < datetime.utcnow() - timedelta(hours=24):
            chunks_col.delete_many({"access_code": code})
            transfers.delete_one({"access_code": code})
            return render_template("index.html", error="This transfer has expired.")

        if int(record.get("downloads_remaining", 0)) <= 0:
            return render_template("index.html", error="Download limit reached.")

        files_meta: list[dict] = record.get("files", [])
        if not files_meta:
            return render_template("index.html", error="No files found for this transfer.")

        # ================================================================
        # Mode A — No PIN: return the raw encrypted blob
        # ================================================================
        if not pin:
            if not _decrement_or_delete(code):
                return render_template("index.html", error="Download limit reached.")

            meta = files_meta[0]
            if meta.get("storage_type") == "single":
                enc_data = bytes(meta["encrypted_data"])
                buf = io.BytesIO(enc_data)
                buf.seek(0)
                return send_file(
                    buf,
                    as_attachment=True,
                    download_name=meta["filename"] + ".encrypted",
                    mimetype="application/octet-stream",
                )
            else:
                # Chunked — concatenate raw encrypted chunk blobs
                chunk_docs = list(chunks_col.find(
                    {"access_code": code, "file_index": meta["file_index"]}
                ))
                combined = b"".join(bytes(d["data"]) for d in chunk_docs)
                buf = io.BytesIO(combined)
                buf.seek(0)
                return send_file(
                    buf,
                    as_attachment=True,
                    download_name=meta["filename"] + ".encrypted",
                    mimetype="application/octet-stream",
                )

        # ================================================================
        # Mode B — PIN supplied: decrypt and return
        # ================================================================
        if hash_pin(pin) != record["key_hash"]:
            return render_template("index.html", error="Invalid PIN.")

        if not _decrement_or_delete(code):
            return render_template("index.html", error="Download limit reached.")

        meta = files_meta[0]

        # ── Text snippet ─────────────────────────────────────────────
        if meta.get("content_type") == "text":
            try:
                plain = reconstruct_file_bytes(meta, code, pin)
                return render_template("view_text.html", text_content=plain.decode("utf-8"))
            except ValueError as exc:
                return render_template("index.html", error=str(exc))

        # ── Binary file (single blob or chunked) ─────────────────────
        try:
            plain = reconstruct_file_bytes(meta, code, pin)
        except ValueError as exc:
            return render_template("index.html", error=str(exc))

        buf = io.BytesIO(plain)
        buf.seek(0)
        return send_file(
            buf,
            as_attachment=True,
            download_name=meta["filename"],
            mimetype="application/octet-stream",
        )

    except PyMongoError as exc:
        logger.exception("Database error during download.")
        return render_template("index.html", error=f"Database error: {exc}")
    except Exception as exc:
        logger.exception("Unexpected error during download.")
        return render_template("index.html", error=f"Download failed: {exc}")


# ===========================================================================
# ── Email helpers ────────────────────────────────────────────────────────────
# ===========================================================================

def _smtp_send(msg):
    """Send an already-composed MIMEMultipart message via SMTP STARTTLS."""
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, msg["To"], msg.as_string())


def send_email_notification(recipient_email: str, download_url: str,
                             files_info: list[dict]):
    """Send a clean, spam-filter-friendly email with the download link."""
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        raise RuntimeError(
            "SMTP credentials not configured. Set SMTP_EMAIL and SMTP_PASSWORD env vars."
        )

    # Build file list text
    if len(files_info) == 1:
        subject_name = files_info[0]["filename"]
        file_list_plain = f"  {files_info[0]['filename']} ({files_info[0]['size_mb']} MB)"
        file_list_html  = (
            f"<p style='margin:0 0 4px;font-size:14px;color:#333'>"
            f"<strong>File:</strong> {files_info[0]['filename']}</p>"
            f"<p style='margin:0;font-size:14px;color:#666'>"
            f"<strong>Size:</strong> {files_info[0]['size_mb']} MB</p>"
        )
    else:
        subject_name = f"{len(files_info)} files"
        file_list_plain = "\n".join(
            f"  {i+1}. {f['filename']} ({f['size_mb']} MB)"
            for i, f in enumerate(files_info)
        )
        file_list_html = "".join(
            f"<p style='margin:0 0 4px;font-size:14px;color:#333'>"
            f"<strong>{i+1}.</strong> {f['filename']} — {f['size_mb']} MB</p>"
            for i, f in enumerate(files_info)
        )

    msg = MIMEMultipart("alternative")
    msg["Subject"]    = f"File shared with you: {subject_name}"
    msg["From"]       = formataddr(("Secure File Transfer", SMTP_EMAIL))
    msg["To"]         = recipient_email
    msg["Reply-To"]   = SMTP_EMAIL
    msg["Date"]       = formatdate(localtime=True)
    msg["Message-ID"] = f"<{uuid.uuid4()}@securefiletransfer.app>"

    plain = f"""Hello,

A file has been shared with you through Secure File Transfer.

File details:
{file_list_plain}

You can download the file by visiting this link:
{download_url}

This link will expire in 24 hours. Please download the file before it expires.

If you did not expect this email, you can safely ignore it.

Best regards,
Secure File Transfer
"""

    html = f"""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;background-color:#f4f4f7;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f7;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="520" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:8px;border:1px solid #e0e0e0;">
          <tr>
            <td style="padding:30px 32px 20px;text-align:center;border-bottom:1px solid #eee;">
              <h1 style="margin:0;font-size:22px;color:#333;font-weight:600;">Secure File Transfer</h1>
            </td>
          </tr>
          <tr>
            <td style="padding:28px 32px;">
              <p style="margin:0 0 18px;font-size:15px;color:#555;line-height:1.6;">
                Hello, a file has been shared with you. Download it using the button below.
              </p>
              <table width="100%" cellpadding="0" cellspacing="0"
                     style="background-color:#f8f9fa;border-radius:6px;border:1px solid #e9ecef;">
                <tr><td style="padding:16px 20px;">{file_list_html}</td></tr>
              </table>
              <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:24px;">
                <tr>
                  <td align="center">
                    <a href="{download_url}"
                       style="display:inline-block;padding:12px 36px;background-color:#4A90D9;
                              color:#fff;text-decoration:none;border-radius:6px;
                              font-weight:600;font-size:15px;">Download File</a>
                  </td>
                </tr>
              </table>
              <p style="margin:24px 0 0;font-size:13px;color:#999;line-height:1.5;">
                This link expires in 24 hours. If you did not expect this email, ignore it.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding:16px 32px;text-align:center;border-top:1px solid #eee;
                       background-color:#fafafa;border-radius:0 0 8px 8px;">
              <p style="margin:0;font-size:12px;color:#aaa;">Sent via Secure File Transfer</p>
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
    msg.attach(MIMEText(html,  "html"))
    _smtp_send(msg)


def send_text_email_notification(recipient_email: str, text_content: str):
    """Send a clean email containing a shared text snippet inline."""
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        raise RuntimeError(
            "SMTP credentials not configured. Set SMTP_EMAIL and SMTP_PASSWORD env vars."
        )

    msg = MIMEMultipart("alternative")
    msg["Subject"]    = "Someone shared a secure text snippet with you"
    msg["From"]       = formataddr(("Secure File Transfer", SMTP_EMAIL))
    msg["To"]         = recipient_email
    msg["Reply-To"]   = SMTP_EMAIL
    msg["Date"]       = formatdate(localtime=True)
    msg["Message-ID"] = f"<{uuid.uuid4()}@securefiletransfer.app>"

    plain = f"""Hello,

A text snippet has been shared with you through Secure File Transfer:

---
{text_content}
---

If you did not expect this email, you can safely ignore it.

Best regards,
Secure File Transfer
"""

    html = f"""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;background-color:#f4f4f7;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f7;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="520" cellpadding="0" cellspacing="0"
               style="background-color:#ffffff;border-radius:8px;border:1px solid #e0e0e0;">
          <tr>
            <td style="padding:30px 32px 20px;text-align:center;border-bottom:1px solid #eee;">
              <h1 style="margin:0;font-size:22px;color:#333;font-weight:600;">Secure File Transfer</h1>
            </td>
          </tr>
          <tr>
            <td style="padding:28px 32px;">
              <p style="margin:0 0 18px;font-size:15px;color:#555;line-height:1.6;">
                Hello, a secure text snippet has been shared with you:
              </p>
              <table width="100%" cellpadding="0" cellspacing="0"
                     style="background-color:#f8f9fa;border-radius:6px;border:1px solid #e9ecef;">
                <tr>
                  <td style="padding:16px 20px;">
                    <pre style="margin:0;font-family:Consolas,monospace;font-size:14px;
                                color:#333;white-space:pre-wrap;word-break:break-word;">{text_content}</pre>
                  </td>
                </tr>
              </table>
              <p style="margin:24px 0 0;font-size:13px;color:#999;line-height:1.5;">
                This snippet was sent directly via email.
                If you did not expect this email, ignore it.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding:16px 32px;text-align:center;border-top:1px solid #eee;
                       background-color:#fafafa;border-radius:0 0 8px 8px;">
              <p style="margin:0;font-size:12px;color:#aaa;">Sent via Secure File Transfer</p>
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
    msg.attach(MIMEText(html,  "html"))
    _smtp_send(msg)


# ===========================================================================
# ── POST /send-email ─────────────────────────────────────────────────────────
# ===========================================================================

@app.route("/send-email", methods=["POST"])
def send_email():
    """
    Send the download link (or inline text) to a recipient after a successful upload.

    Expected JSON body:
      {
        "recipient_email": "someone@example.com",
        "code":            "3821",
        "key":             "7094",
        "text_content":    "",          ← if non-empty, send text inline
        # For single-file backward compat:
        "filename":        "report.pdf",
        "size_mb":         1.45,
        # For multi-file:
        "files": [{"filename": "a.pdf", "size_mb": 1.45}, ...]
      }
    """
    data         = request.get_json(force=True)
    recipient    = (data.get("recipient_email") or "").strip()
    code         = (data.get("code")            or "").strip()
    key          = (data.get("key")             or "").strip()
    text_content = (data.get("text_content")    or "").strip()

    if not recipient:
        return jsonify({"error": "Recipient email is required."}), 400
    if not code or not key:
        return jsonify({"error": "Upload code and key are required."}), 400

    # Build files_info list (support both single-file and multi-file callers)
    files_info: list[dict] = data.get("files") or []
    if not files_info and data.get("filename"):
        files_info = [{"filename": data["filename"], "size_mb": data.get("size_mb", 0)}]

    download_url = request.host_url.rstrip("/") + "/download?code=" + code + "&key=" + key

    try:
        if text_content:
            send_text_email_notification(recipient, text_content)
            return jsonify({"success": True, "message": f"Text snippet sent to {recipient}."})
        else:
            send_email_notification(recipient, download_url, files_info)
            return jsonify({"success": True, "message": f"Download link sent to {recipient}."})
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500
    except Exception as exc:
        logger.exception("Email send failed.")
        return jsonify({"error": f"Failed to send email: {exc}"}), 500


# ===========================================================================
# ── Entry point ──────────────────────────────────────────────────────────────
# ===========================================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000)),
        debug=False,
    )
