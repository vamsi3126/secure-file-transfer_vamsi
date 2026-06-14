# Secure File Transfer — Admin & Technical Reference

> **Audience:** Developers and system administrators responsible for deploying,
> maintaining, or extending this application.

---

## 1. Project Overview

**Secure File Transfer** is a Flask web application that lets users upload up to
**3 files** or a text snippet, encrypts them server-side with a per-file random
salt, and returns a single **Access Code + PIN** pair for the entire batch.
Recipients use that pair to download and decrypt the content. Files > 50 MB are
transparently stored in **10 MB encrypted chunks** to stay within MongoDB's
16 MB document limit. All transfers auto-expire after **24 hours** or when the
download limit is reached, whichever comes first.

---

## 2. Technology Stack

| Layer            | Library / Tool                      | Version  |
|------------------|-------------------------------------|----------|
| Web framework    | Flask                               | 2.3.2    |
| Database         | MongoDB (PyMongo with SRV support)  | 4.9.1    |
| Encryption       | cryptography (Fernet, PBKDF2-HMAC)  | 41.0.3   |
| WSGI server      | Gunicorn                            | 20.1.0   |
| Email delivery   | smtplib (stdlib, STARTTLS)          | —        |
| Runtime          | Python                              | 3.9 +    |

---

## 3. Environment Variables

| Variable        | Required | Default                        | Purpose                              |
|-----------------|----------|--------------------------------|--------------------------------------|
| `MONGODB_URI`   | ✅       | Hardcoded fallback *(dev only)*| MongoDB connection string            |
| `MONGODB_DB`    | ❌       | `wireless_file_transfer`       | MongoDB database name                |
| `SMTP_SERVER`   | ❌       | `smtp.gmail.com`               | SMTP host                            |
| `SMTP_PORT`     | ❌       | `587`                          | SMTP port (STARTTLS)                 |
| `SMTP_EMAIL`    | ✅ *     | *(empty)*                      | Sender address for email sharing     |
| `SMTP_PASSWORD` | ✅ *     | *(empty)*                      | Gmail app-password                   |
| `PORT`          | ❌       | `5000`                         | Port for the Flask dev server        |

> \* Required only when the `/send-email` route is used.  
> ⚠ **Remove** the hardcoded `DEFAULT_MONGO_URI` before any production deployment.

---

## 4. API Reference

### `GET /`
Renders the main single-page UI (`templates/index.html`).

---

### `POST /upload`
Encrypts and stores up to 3 files or a text snippet as a single batch.

**Form fields**

| Field            | Type   | Required  | Description                                        |
|------------------|--------|-----------|----------------------------------------------------|
| `file`           | File   | Either/or | One or more binary files (max 3, max 300 MB each)  |
| `text`           | String | Either/or | Plain-text content (mutually exclusive with files) |
| `max_downloads`  | Int    | No        | Download limit before auto-delete (≥ 1, default 1) |

**Success response**

```json
{
  "success": true,
  "files": [
    {"filename": "report.pdf", "size_mb": 1.45},
    {"filename": "data.csv",   "size_mb": 0.12}
  ],
  "file": "report.pdf",
  "size_mb": 1.45,
  "total_files": 2,
  "code": "3821",
  "key": "7094",
  "download_limit": 3,
  "warning": "Files expire in 24 hours or when downloads are exhausted."
}
```

> `file` and `size_mb` are backward-compat aliases pointing to the first file.

**Error codes**

| HTTP | Condition                                    |
|------|----------------------------------------------|
| 400  | No content / both file and text / > 3 files  |
| 413  | Any single file exceeds 300 MB               |
| 500  | Database or encryption failure               |

---

### `GET /download`
Accepts `?code=` and `?key=` query parameters and renders an auto-submitting
form that triggers the POST endpoint below.

---

### `POST /download`
Validates credentials, decrypts, and streams content.

| Inputs provided       | 1 file (text)    | 1 file (binary)           | Multiple files          |
|-----------------------|------------------|---------------------------|-------------------------|
| Access Code only      | —                | Streams `.encrypted` blob | ZIP of `.encrypted` blobs |
| Access Code + PIN     | Renders in browser | Streams original file   | Streams `<code>_files.zip` |

**Error codes**

| HTTP | Condition                                   |
|------|---------------------------------------------|
| 400  | Missing access code                         |
| 403  | Invalid PIN / expired / limit reached       |
| 500  | Database or decryption failure              |

---

### `POST /send-email`
Sends the download link or text snippet to a recipient via SMTP.

**JSON body**

```json
{
  "recipient_email": "someone@example.com",
  "code": "3821",
  "key": "7094",
  "text_content": "",
  "files": [
    {"filename": "report.pdf", "size_mb": 1.45},
    {"filename": "data.csv",   "size_mb": 0.12}
  ],
  "filename": "report.pdf",
  "size_mb": 1.45
}
```

> `files` (array) takes precedence over the legacy `filename`/`size_mb` scalar
> fields. Both formats are accepted for backward compatibility.  
> If `text_content` is non-empty, the text is emailed inline; otherwise a
> download link is sent.

---

## 5. MongoDB Schema

### Collection: `transfers`

One document per upload batch (single file, multi-file, or text).

| Field                 | BSON Type  | Description                                                  |
|-----------------------|------------|--------------------------------------------------------------|
| `access_code`         | String     | Unique 4-digit code (unique index)                           |
| `key_hash`            | String     | SHA-256 of the 4-digit PIN — plaintext never stored          |
| `files`               | Array      | Array of `file_meta` sub-documents (see below)               |
| `total_files`         | Int32      | Length of the `files` array                                  |
| `created_at`          | Date       | UTC creation timestamp; TTL index triggers expiry at 24 h    |
| `downloads_remaining` | Int32      | Decremented atomically; record deleted when it reaches 0     |

**`file_meta` sub-document** (one entry per file/text in `files[]`)

| Field              | BSON Type | Present when          | Description                                   |
|--------------------|-----------|-----------------------|-----------------------------------------------|
| `file_index`       | Int32     | Always                | 0-based index within the batch                |
| `filename`         | String    | Always                | Original filename or `message.txt` for text   |
| `size_mb`          | Double    | Always                | Unencrypted size in MB                        |
| `content_type`     | String    | Always                | `"file"` or `"text"`                          |
| `storage_type`     | String    | Always                | `"single"` (≤ 50 MB) or `"chunked"` (> 50 MB)|
| `salt`             | BinData   | Always                | 16-byte random KDF salt (per-file)            |
| `encrypted_data`   | BinData   | `storage_type=single` | Fernet ciphertext of entire file              |
| `total_chunks`     | Int32     | Always                | 1 when single; N when chunked                 |
| `chunk_size`       | Int32     | `storage_type=chunked`| Bytes per chunk (10 MB)                       |

**Indexes**

```
transfers.access_code  — unique
transfers.created_at   — TTL (expireAfterSeconds: 86400)
```

---

### Collection: `chunks`

One document per 10 MB encrypted chunk. Only populated for files > 50 MB.

| Field                   | BSON Type | Description                                        |
|-------------------------|-----------|----------------------------------------------------|
| `access_code`           | String    | Links chunk to its parent `transfers` document     |
| `file_index`            | Int32     | Which file within the batch this chunk belongs to  |
| `chunk_order_encrypted` | BinData   | Fernet-encrypted integer index (hides order)       |
| `data`                  | BinData   | Fernet-encrypted chunk bytes (≤ 10 MB)             |
| `chunk_hash`            | String    | SHA-256 hex digest of the plaintext chunk          |

**Indexes**

```
chunks.access_code                        — ascending
chunks.(access_code, file_index)          — ascending compound
```

> Chunks are deleted atomically when `downloads_remaining` reaches 0, or by
> `cleanup_expired_records()` called on every upload.

---

## 6. Encryption & Security

| Concern               | Detail                                                                   |
|-----------------------|--------------------------------------------------------------------------|
| Cipher                | Fernet (AES-128-CBC + HMAC-SHA256)                                       |
| Key derivation        | PBKDF2-HMAC-SHA256, 100 000 iterations                                   |
| KDF salt              | **16-byte random salt per file** — stored in `transfers.files[].salt`   |
| PIN storage           | SHA-256 hash only; plaintext PIN discarded immediately                   |
| File size enforcement | `MAX_CONTENT_LENGTH = 3 × 300 MB` + per-file inline check               |
| Chunked storage       | Files > 50 MB split into 10 MB Fernet-encrypted chunks; chunk order is   |
|                       | itself Fernet-encrypted to prevent ordering attacks                      |
| Auto-expiry           | TTL index + `cleanup_expired_records()` called on every upload           |
| Rate limiting         | ❌ Not implemented — see §8                                              |

---

## 7. Running the Application

### Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set required env vars
set MONGODB_URI=mongodb+srv://<user>:<pass>@cluster.mongodb.net/
set SMTP_EMAIL=yourapp@gmail.com
set SMTP_PASSWORD=your-app-password

# Start the dev server
python server.py
# → http://0.0.0.0:5000
```

### Production (Gunicorn + reverse proxy)

```bash
gunicorn -w 4 -b 0.0.0.0:8000 server:app
```

Place Nginx or Caddy in front and enforce HTTPS. Example Nginx snippet:

```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    client_max_body_size 950M;   # 3 × 300 MB + headroom
}
```

---

## 8. Hardening Recommendations

1. **Remove hardcoded `DEFAULT_MONGO_URI`** from `server.py`. Load exclusively
   from environment variables or a secrets manager.

2. **Rate limiting** — add Flask-Limiter to `/upload`, `/download`, and
   `/send-email` to prevent brute-force PIN attacks and abuse.

3. **HTTPS + security headers** — enforce TLS in production; add
   `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`.

4. **Stronger secrets** — consider alphanumeric or longer codes instead of
   4-digit numeric PINs (only 10 000 combinations).

5. **SMTP credentials** — store in a secrets manager; rotate the Gmail
   app-password periodically.

6. **Structured logging** — replace plain `logging` with a JSON logger and
   ship logs to a centralised store (CloudWatch, Datadog, etc.).

7. **GridFS alternative** — for very large files (hundreds of MB), consider
   MongoDB GridFS instead of the custom `chunks` collection.

---

## 9. Maintenance Checklist

| Task                        | Notes                                                         |
|-----------------------------|---------------------------------------------------------------|
| Monitor `transfers` storage | TTL + download limits keep growth bounded; audit monthly      |
| Monitor `chunks` storage    | Orphaned chunks cleaned by `cleanup_expired_records()`        |
| Inspect TTL index           | Re-create if dropped: `expireAfterSeconds: 86400`             |
| Rotate SMTP credentials     | Update `SMTP_PASSWORD` env var; no code change needed         |
| Dependency CVE scan         | `pip list --outdated` + check PyPI security advisories        |
| Blob recovery policy        | Encrypted data is unrecoverable without the PIN; document this|

---

## 10. Repository Layout

```
secure-file-transfer_vamsi-main/
├── server.py                    # Flask application (all routes & logic)
├── requirements.txt             # Pinned Python dependencies
├── runtime.txt                  # Python version declaration (Render/Heroku)
├── templates/
│   ├── index.html               # Main upload + download UI (multi-file)
│   ├── view_text.html           # Renders decrypted text in the browser
│   └── download_redirect.html   # Auto-submit form (GET → POST redirect)
├── README_ADMIN.md              # This file
└── README_USER.md               # End-user quick-start guide
```

---

*Last updated: April 2026*
