# Secure File Drop — Admin/Technical Guide

## Architecture
- Web framework: Flask (`server.py`)
- UI: Single template (`templates/index.html`) with inline CSS and JavaScript
- Database: MongoDB collection `transfers` with indices
- Crypto: `cryptography` (Fernet) + PBKDF2‑HMAC (SHA‑256) for key derivation

## Routes
- `/` GET: Render main page
- `/upload` POST: Encrypts and stores file or text, returns JSON
- `/download` POST: Validates Access Code + PIN, decrypts and returns content
- Removed unused: `/download_encrypted`, `/db_health` (cleaned for minimal surface)

## Data Model (`transfers`)
- `access_code`: string, unique index
- `key_hash`: SHA‑256 of the 4‑digit PIN
- `filename`: original filename (for files) or `message.txt` (for text)
- `size_mb`: numeric, approximate size
- `encrypted_data`: binary (Fernet ciphertext)
- `created_at`: timestamp, TTL index of 24 hours (`expireAfterSeconds = 86400`)
- `downloads_remaining`: integer, decremented on successful download
- `content_type`: `file` | `text`

## Security Design
- Encryption: Fernet symmetric encryption
- Key derivation: PBKDF2‑HMAC (SHA‑256), 100k iterations, static salt (improve by per‑record random salt)
- PIN handling: Only hash stored (`key_hash`), plaintext PIN never persisted
- Access Code + PIN required to decrypt; both must be correct
- Server rejects files over 150 MB (`MAX_FILE_SIZE` and `app.config["MAX_CONTENT_LENGTH"]`)

## Configuration
- Environment variables:
  - `MONGODB_URI`: MongoDB connection string (required)
  - `MONGODB_DB`: database name (default `wireless_file_transfer`)
- Runtime:
  - `python server.py` (development)
  - For production, use `gunicorn` behind a reverse proxy

## Operational Behavior
- TTL index cleans records automatically after 24h
- Additional cleanup is invoked on upload (`cleanup_expired_records()`)
- On each download, `downloads_remaining` is decremented and record deleted at zero

## Frontend Behavior
- Uploads via `XMLHttpRequest` with progress events
- On success, auto‑redirect to the Download section and pre‑fill Access Code + PIN
- Theme can be customized via CSS variables in `:root` (black‑neon currently)

## Error Handling
- Common errors (
  413: Payload too large,
  400: invalid inputs,
  500: DB/unknown failures
)
- User‑friendly messages rendered in the UI

## Hardening Recommendations
- Replace static KDF salt with per‑record random salt stored alongside ciphertext
- Add rate limiting to `/upload` and `/download`
- Enforce stronger PIN policy (length/entropy) or use non‑numeric secrets
- Use HTTPS in production and secure headers
- Remove any default/embedded connection strings; use secrets manager or env vars

## Maintenance
- Monitor MongoDB storage and TTL behavior
- Backup policy: encrypted blobs are non‑recoverable without PIN; ensure policy fits requirements
- Logs: Flask app logs errors on server side

## Development Notes
- Requirements: `requirements.txt`, Python 3.9+
- Styling: `templates/index.html` holds CSS variables; adjust `--primary-color`, card/input backgrounds, etc.
- Removed unused routes to reduce attack surface without impacting functionality

