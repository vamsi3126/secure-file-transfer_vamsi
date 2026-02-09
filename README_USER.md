# Secure File Drop — User Guide

## Overview
Secure File Drop lets you encrypt a file in your browser, upload it, and securely share a numeric Access Code and a 4‑digit Decryption PIN with the recipient. Files expire automatically and can be limited by download count.

## Features
- Client-side progress bar with status
- Automatic redirect to Download section after upload
- Access Code and Decryption PIN auto-filled in the Download form
- 24‑hour retention via database TTL
- Max file size: 150 MB

## Requirements
- Python 3.9+
- Pip
- MongoDB connection string (Atlas recommended)

## Setup
1. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
2. Configure environment variables (recommended):
   ```powershell
   $env:MONGODB_URI = "your-mongodb-connection-string"
   $env:MONGODB_DB  = "wireless_file_transfer"
   ```
3. Run the server:
   ```powershell
   python server.py
   ```
4. Open the app:
   - `http://127.0.0.1:5000/`

## Usage
- Upload: Choose a file and click “Encrypt & Upload File”.
- Credentials: After upload, an Access Code and Decryption PIN are shown and auto‑filled.
- Share: Send the Access Code and PIN to the recipient.
- Download: Recipient enters the Access Code and PIN, then clicks “Decrypt & Download”.

## Notes
- Files expire after 24 hours or when the allowed downloads are exhausted.
- Do not share the PIN publicly. Treat it like a password.
- For production, run behind a proper WSGI server (e.g., Gunicorn) and reverse proxy (e.g., Nginx).

## Troubleshooting
- If uploads fail, ensure your MongoDB URI is correct and accessible.
- If the page doesn’t redirect after upload, refresh and ensure JavaScript is enabled.
- Large files over 150 MB will be rejected.

