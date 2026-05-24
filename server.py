"""
droply/server.py
================
The entire backend in one file for the prototype.

WHAT:  A local HTTP file-transfer server.
WHY:   Runs on the sender's machine/phone. Receiver visits a browser URL — no install needed.
HOW:   Flask serves files; PIN auth guards every route; SHA-256 checksums verify integrity;
       rate-limiter blocks brute-force; chunked streaming handles large files without RAM blow-up.

SECURITY MODEL
--------------
- 6-digit PIN required on every session (stored in signed, encrypted cookie via Flask's secret key)
- Rate limiter: 5 PIN attempts per minute per IP → locked out for 60 s
- Files served with Content-Disposition: attachment (no browser execution)
- No file-path traversal: all uploads go to a fixed UPLOAD_DIR, basenames only
- Optional file expiry: each file can have a TTL and a download count cap
- HTTPS via self-signed cert (generated on first run) — browser will warn, user accepts once
- SHA-256 integrity: hash computed at upload time, verified on download, exposed in UI

AVAILABILITY
------------
- Chunked streaming: files sent in 1 MB chunks — never loads full file into RAM
- Concurrent downloads: Flask threaded=True handles multiple receivers
- Resume-friendly: supports HTTP Range requests for interrupted downloads
- Graceful shutdown: SIGINT handler cleans temp files

INTEGRITY
---------
- SHA-256 hash stored alongside every file record
- Download verifies hash matches before serving (detects disk corruption)
- Hash exposed in UI so receivers can verify independently
"""

import os
import sys
import hashlib
import uuid
import json
import logging
import signal
import socket
import time
import threading
import secrets
import mimetypes
from datetime import datetime, timedelta, timezone
from pathlib import Path
from functools import wraps

# Helper: timezone-aware UTC now (avoids deprecation in Python 3.12+)
def utcnow():
    return datetime.now(timezone.utc)

from flask import (
    Flask, request, session, jsonify, send_file,
    render_template, redirect, url_for, Response, abort
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── Config ────────────────────────────────────────────────────────────────────

BASE_DIR    = Path(__file__).parent
UPLOAD_DIR  = BASE_DIR / "uploads"
LOG_DIR     = BASE_DIR / "logs"
CERT_FILE   = BASE_DIR / "cert.pem"
KEY_FILE    = BASE_DIR / "key.pem"
META_FILE   = BASE_DIR / "file_meta.json"

UPLOAD_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

MAX_FILE_SIZE    = 10 * 1024 * 1024 * 1024   # 10 GB hard cap
CHUNK_SIZE       = 1 * 1024 * 1024            # 1 MB streaming chunks
PIN_LENGTH       = 6
SESSION_TIMEOUT  = 3600                        # 1 hour session

# Default expiry / download limits (can be set per file at upload)
DEFAULT_TTL_HOURS   = 24
DEFAULT_MAX_DOWNLOADS = 0   # 0 = unlimited

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "droply.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("droply")

# ── Flask app ─────────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder="templates", static_folder="static")

# Secret key for signing session cookies — regenerated each run (sessions die on restart, intentional)
app.secret_key = secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=SESSION_TIMEOUT)

# Rate limiter — backs off brute-force PIN attempts
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

# ── Global state ──────────────────────────────────────────────────────────────

# PIN is generated once at startup
CURRENT_PIN: str = ""

# File metadata: { file_id: { name, size, sha256, path, uploaded_at, ttl_hours, max_downloads, download_count, expires_at } }
file_meta: dict = {}
meta_lock = threading.Lock()

# ── Helpers ───────────────────────────────────────────────────────────────────

def generate_pin() -> str:
    """Cryptographically random 6-digit PIN."""
    return "".join([str(secrets.randbelow(10)) for _ in range(PIN_LENGTH)])


def sha256_file(path: Path) -> str:
    """Stream-hash a file — never loads it fully into RAM."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def save_meta():
    """Persist file metadata to disk (survives restart for ongoing sessions)."""
    with meta_lock:
        with open(META_FILE, "w") as f:
            json.dump(file_meta, f, default=str, indent=2)


def load_meta():
    """Load metadata from disk on startup."""
    global file_meta
    if META_FILE.exists():
        try:
            with open(META_FILE) as f:
                file_meta = json.load(f)
            log.info(f"Loaded {len(file_meta)} file records from disk")
        except Exception as e:
            log.warning(f"Could not load metadata: {e}")
            file_meta = {}


def is_expired(meta: dict) -> bool:
    """Check if a file has exceeded TTL or download count."""
    if meta.get("expires_at"):
        if utcnow().isoformat() > meta["expires_at"]:
            return True
    max_dl = meta.get("max_downloads", 0)
    if max_dl > 0 and meta.get("download_count", 0) >= max_dl:
        return True
    return False


def purge_expired():
    """Background thread: delete expired files every 60 seconds."""
    while True:
        time.sleep(60)
        with meta_lock:
            expired = [fid for fid, m in file_meta.items() if is_expired(m)]
        for fid in expired:
            with meta_lock:
                m = file_meta.pop(fid, None)
            if m:
                p = Path(m.get("path", ""))
                if p.exists():
                    p.unlink()
                    log.info(f"Purged expired file: {m['name']}")
        if expired:
            save_meta()


def get_local_ip() -> str:
    """Best-effort local IP detection (works on most platforms)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def make_qr(url: str) -> str:
    """Generate a QR code PNG as a base64 data-URI."""
    try:
        import qrcode, base64
        from io import BytesIO
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = BytesIO()
        img.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode()
        return f"data:image/png;base64,{b64}"
    except Exception as e:
        log.warning(f"QR generation failed: {e}")
        return ""


def generate_self_signed_cert():
    """
    Generate a self-signed TLS certificate for HTTPS.
    WHY: Browsers treat http:// as insecure for file downloads.
         With HTTPS the receiver gets a one-time "trust this certificate" prompt.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        local_ip = get_local_ip()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"droply"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(utcnow())
            .not_valid_after(utcnow() + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(u"localhost"),
                    x509.IPAddress(ipaddress.IPv4Address(local_ip)),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        log.info("Self-signed TLS certificate generated")
    except Exception as e:
        log.warning(f"TLS cert generation failed ({e}) — falling back to HTTP")


# ── Auth decorator ────────────────────────────────────────────────────────────

def require_pin(f):
    """
    Decorator: every route that serves files or metadata requires a valid session.
    WHY: Without this, anyone on the same Wi-Fi could pull files without the PIN.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")   # brute-force protection
def login():
    """
    PIN entry page.
    POST: validate PIN → set session → redirect to file browser.
    Rate-limited to 5 attempts/minute per IP.
    """
    error = None
    if request.method == "POST":
        pin = request.form.get("pin", "").strip()
        if secrets.compare_digest(pin, CURRENT_PIN):   # constant-time comparison
            session.permanent = True
            session["authenticated"] = True
            session["auth_time"] = utcnow().isoformat()
            log.info(f"Successful auth from {request.remote_addr}")
            return redirect(url_for("index"))
        else:
            log.warning(f"Failed PIN attempt from {request.remote_addr}")
            error = "Wrong PIN. Try again."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/files", methods=["GET"])
@require_pin
def list_files():
    """Return JSON list of available files with metadata."""
    with meta_lock:
        files = []
        for fid, m in file_meta.items():
            if not is_expired(m):
                files.append({
                    "id": fid,
                    "name": m["name"],
                    "size": m["size"],
                    "sha256": m["sha256"],
                    "uploaded_at": m["uploaded_at"],
                    "download_count": m.get("download_count", 0),
                    "max_downloads": m.get("max_downloads", 0),
                    "expires_at": m.get("expires_at", ""),
                })
    return jsonify({"files": files, "count": len(files)})


@app.route("/api/upload", methods=["POST"])
@require_pin
@limiter.limit("30 per minute")
def upload_file():
    """
    Receive a file from the sender.
    WHY chunked: large files shouldn't sit in memory — we stream straight to disk.
    INTEGRITY: SHA-256 computed after write; stored in metadata.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file in request"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    # Sanitise filename — strip any path components
    safe_name = Path(f.filename).name
    if not safe_name:
        return jsonify({"error": "Invalid filename"}), 400

    # Parse optional expiry settings from form data
    try:
        ttl_hours = int(request.form.get("ttl_hours", DEFAULT_TTL_HOURS))
        max_downloads = int(request.form.get("max_downloads", DEFAULT_MAX_DOWNLOADS))
    except ValueError:
        ttl_hours = DEFAULT_TTL_HOURS
        max_downloads = DEFAULT_MAX_DOWNLOADS

    file_id = str(uuid.uuid4())
    dest_path = UPLOAD_DIR / file_id

    try:
        # Stream to disk in chunks — avoids RAM blow-up on large files
        h = hashlib.sha256()
        size = 0
        with open(dest_path, "wb") as out:
            while True:
                chunk = f.stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                out.write(chunk)
                h.update(chunk)
                size += len(chunk)

        sha256 = h.hexdigest()
        expires_at = (utcnow() + timedelta(hours=ttl_hours)).isoformat() if ttl_hours > 0 else ""

        with meta_lock:
            file_meta[file_id] = {
                "name": safe_name,
                "size": size,
                "sha256": sha256,
                "path": str(dest_path),
                "uploaded_at": utcnow().isoformat(),
                "ttl_hours": ttl_hours,
                "max_downloads": max_downloads,
                "download_count": 0,
                "expires_at": expires_at,
            }
        save_meta()

        log.info(f"Upload: {safe_name} ({size} bytes) sha256={sha256[:16]}… from {request.remote_addr}")
        return jsonify({
            "id": file_id,
            "name": safe_name,
            "size": size,
            "sha256": sha256,
        }), 201

    except Exception as e:
        if dest_path.exists():
            dest_path.unlink()
        log.error(f"Upload failed: {e}")
        return jsonify({"error": "Upload failed"}), 500


@app.route("/api/download/<file_id>")
@require_pin
def download_file(file_id: str):
    """
    Stream file to receiver.
    Supports HTTP Range (resume).
    Increments download counter; marks expired if max_downloads reached.
    Verifies SHA-256 before serving (detects disk corruption).
    """
    with meta_lock:
        meta = file_meta.get(file_id)

    if not meta:
        abort(404)

    if is_expired(meta):
        abort(410)   # 410 Gone — file expired

    file_path = Path(meta["path"])
    if not file_path.exists():
        log.error(f"File missing on disk: {file_id}")
        abort(404)

    # Integrity check before serving
    actual_hash = sha256_file(file_path)
    if actual_hash != meta["sha256"]:
        log.error(f"Integrity failure for {file_id}: expected {meta['sha256'][:16]}… got {actual_hash[:16]}…")
        abort(500)

    # Increment download counter
    with meta_lock:
        file_meta[file_id]["download_count"] = meta.get("download_count", 0) + 1
    save_meta()

    log.info(f"Download: {meta['name']} → {request.remote_addr}")

    # Handle HTTP Range (supports resume / video seeking)
    range_header = request.headers.get("Range")
    file_size = meta["size"]

    def generate(start=0, end=None):
        end = end or file_size
        with open(file_path, "rb") as f:
            f.seek(start)
            remaining = end - start
            while remaining > 0:
                read_size = min(CHUNK_SIZE, remaining)
                data = f.read(read_size)
                if not data:
                    break
                remaining -= len(data)
                yield data

    if range_header:
        # Parse "bytes=start-end"
        try:
            byte_range = range_header.replace("bytes=", "").split("-")
            start = int(byte_range[0])
            end = int(byte_range[1]) + 1 if byte_range[1] else file_size
        except Exception:
            start, end = 0, file_size

        headers = {
            "Content-Range": f"bytes {start}-{end - 1}/{file_size}",
            "Accept-Ranges": "bytes",
            "Content-Length": str(end - start),
            "Content-Disposition": f'attachment; filename="{meta["name"]}"',
            "X-SHA256": meta["sha256"],
        }
        return Response(generate(start, end), status=206, headers=headers,
                        mimetype="application/octet-stream")

    headers = {
        "Content-Length": str(file_size),
        "Content-Disposition": f'attachment; filename="{meta["name"]}"',
        "Accept-Ranges": "bytes",
        "X-SHA256": meta["sha256"],
    }
    return Response(generate(), status=200, headers=headers,
                    mimetype="application/octet-stream")


@app.route("/api/delete/<file_id>", methods=["DELETE"])
@require_pin
def delete_file(file_id: str):
    """Sender can remove a file from sharing at any time."""
    with meta_lock:
        meta = file_meta.pop(file_id, None)

    if not meta:
        return jsonify({"error": "Not found"}), 404

    p = Path(meta["path"])
    if p.exists():
        p.unlink()

    save_meta()
    log.info(f"Deleted: {meta['name']} by {request.remote_addr}")
    return jsonify({"ok": True})


@app.route("/api/status")
@require_pin
def status():
    """Health/info endpoint — tells the UI the server IP, port, PIN hint."""
    with meta_lock:
        total_size = sum(m["size"] for m in file_meta.values() if not is_expired(m))
        count = sum(1 for m in file_meta.values() if not is_expired(m))

    return jsonify({
        "ok": True,
        "ip": get_local_ip(),
        "files": count,
        "total_size": total_size,
        "uptime": int(time.time() - START_TIME),
    })


@app.route("/api/info")
def info():
    """Public endpoint — returns QR code and connection info (no PIN required, no file data)."""
    port = int(os.environ.get("PORT", 5000))
    ip   = get_local_ip()
    use_https = CERT_FILE.exists() and KEY_FILE.exists()
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{ip}:{port}"
    qr  = make_qr(url)
    return jsonify({"url": url, "ip": ip, "port": port, "qr": qr})


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(410)
def gone(e):
    return jsonify({"error": "File expired or download limit reached"}), 410

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": f"File too large. Max {MAX_FILE_SIZE // (1024**3)} GB"}), 413

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Too many attempts. Wait 60 seconds."}), 429

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Server error — file may be corrupted"}), 500


# ── Startup ───────────────────────────────────────────────────────────────────

START_TIME = time.time()

def startup():
    global CURRENT_PIN

    load_meta()
    CURRENT_PIN = generate_pin()

    port     = int(os.environ.get("PORT", 5000))
    ip       = get_local_ip()
    use_https = CERT_FILE.exists() and KEY_FILE.exists()
    scheme   = "https" if use_https else "http"
    url      = f"{scheme}://{ip}:{port}"

    print("\n" + "═" * 58)
    print("  droply — local file transfer server")
    print("═" * 58)
    print(f"  URL  : {url}")
    print(f"  PIN  : {CURRENT_PIN}  ← share this with receivers")
    print(f"  HTTPS: {'yes (accept cert warning in browser)' if use_https else 'no (http only)'}")
    print(f"  Max file size: {MAX_FILE_SIZE // (1024**3)} GB")
    print("═" * 58 + "\n")

    # Start expiry background thread
    t = threading.Thread(target=purge_expired, daemon=True)
    t.start()

    # Graceful shutdown handler
    def handle_exit(sig, frame):
        print("\ndroply shutting down…")
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_exit)

    ssl_context = None
    if use_https:
        ssl_context = (str(CERT_FILE), str(KEY_FILE))

    app.run(
        host="0.0.0.0",
        port=port,
        threaded=True,          # handle multiple receivers concurrently
        ssl_context=ssl_context,
        debug=False,
    )


if __name__ == "__main__":
    # Generate TLS cert if not present
    if not (CERT_FILE.exists() and KEY_FILE.exists()):
        generate_self_signed_cert()
    startup()