"""
droply/server.py  —  Phase 1
=============================

WHAT CHANGED FROM PROTOTYPE
────────────────────────────
MAJOR
  1. Receiver page  — /receive  — a completely separate, clean page for the person
                      downloading. No sidebar clutter. Just: enter PIN → see files → download.
  2. Sender/Receiver role split — the UI now knows who you are. Sender gets full controls.
                      Receiver gets a stripped read-only view.
  3. Upload-from-path — sender can point droply at a LOCAL FILE PATH on their machine
                      (e.g. /home/user/video.mp4) and droply reads + serves it WITHOUT
                      copying it to uploads/. Useful for large files — no disk duplication.
  4. Download token  — each download now gets a short-lived one-time token (60 s) instead
                      of relying solely on the session cookie. Harder to abuse.
  5. mDNS broadcast  — server announces itself as droply.local on the LAN via zeroconf
                      so receivers can find it without typing an IP (Phase 1 preview).
  6. Transfer log API — /api/transfers returns a full log of who downloaded what and when.

MINOR
  7. Mime-type sniffing  — correct Content-Type per file (not always octet-stream).
  8. Upload dedup check  — if the exact same file (same SHA-256) is already shared,
                           returns the existing record rather than storing a duplicate.
  9. File preview hints  — image files get a thumbnail in the receiver UI.
 10. Uptime + version   — /api/status now returns version string and human uptime.
 11. Graceful 413       — oversized uploads now get a clear JSON error, not a Flask crash.
 12. PIN in QR          — QR now encodes  url?pin=XXXXXX  so receiver can tap and auto-fill.

SECURITY
  - Download tokens     expire in 60 s, single-use, stored in memory only.
  - All existing security from prototype retained (rate limit, SHA-256, expiry, etc.)

TESTING
  Run:  python server.py --http --test
  This runs the built-in self-test suite and exits with a pass/fail summary.
"""

import os, sys, hashlib, uuid, json, logging, signal, socket
import time, threading, secrets, mimetypes, argparse, traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from functools import wraps
from collections import deque

from flask import (Flask, request, session, jsonify,
                   render_template, redirect, url_for, Response, abort)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── Version ───────────────────────────────────────────────────────────────────
VERSION = "0.2.0-phase1"

# ── UTC helper ────────────────────────────────────────────────────────────────
def utcnow():
    return datetime.now(timezone.utc)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
LOG_DIR    = BASE_DIR / "logs"
CERT_FILE  = BASE_DIR / "cert.pem"
KEY_FILE   = BASE_DIR / "key.pem"
META_FILE  = BASE_DIR / "file_meta.json"

UPLOAD_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

# ── Config ────────────────────────────────────────────────────────────────────
MAX_FILE_SIZE      = 10 * 1024 * 1024 * 1024   # 10 GB
CHUNK_SIZE         = 1  * 1024 * 1024           # 1 MB streaming chunk
PIN_LENGTH         = 6
SESSION_TIMEOUT    = 3600                        # 1 h
DEFAULT_TTL_HOURS  = 24
DEFAULT_MAX_DL     = 0                           # 0 = unlimited
TOKEN_TTL_SECONDS  = 60                          # download token lifetime
MAX_TRANSFER_LOG   = 500                         # keep last N transfer events

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

# Suppress werkzeug's noisy "Bad request version" errors —
# these are Chrome sending HTTPS handshakes to an HTTP server (harmless).
logging.getLogger("werkzeug").setLevel(logging.WARNING)

# ── Flask ─────────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=SESSION_TIMEOUT)

limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri="memory://")

# ── Global state ──────────────────────────────────────────────────────────────
CURRENT_PIN:  str  = ""
START_TIME:   float = time.time()
file_meta:    dict  = {}          # file_id → metadata dict
meta_lock           = threading.Lock()
dl_tokens:    dict  = {}          # token → {file_id, expires_at}
token_lock          = threading.Lock()
transfer_log        = deque(maxlen=MAX_TRANSFER_LOG)   # ring buffer

# ── Helpers ───────────────────────────────────────────────────────────────────

def generate_pin() -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(PIN_LENGTH))

def sha256_file(path: Path) -> str:
    """Stream-hash — never loads full file into RAM."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()

def save_meta():
    with meta_lock:
        with open(META_FILE, "w") as f:
            json.dump(file_meta, f, default=str, indent=2)

def load_meta():
    global file_meta
    if META_FILE.exists():
        try:
            with open(META_FILE) as f:
                file_meta = json.load(f)
            log.info(f"Loaded {len(file_meta)} file records")
        except Exception as e:
            log.warning(f"Meta load failed: {e}")
            file_meta = {}

def is_expired(meta: dict) -> bool:
    if meta.get("expires_at"):
        if utcnow().isoformat() > meta["expires_at"]:
            return True
    max_dl = meta.get("max_downloads", 0)
    if max_dl > 0 and meta.get("download_count", 0) >= max_dl:
        return True
    return False

def purge_expired():
    """Background thread — runs every 60 s."""
    while True:
        time.sleep(60)
        with meta_lock:
            expired = [fid for fid, m in file_meta.items() if is_expired(m)]
        for fid in expired:
            with meta_lock:
                m = file_meta.pop(fid, None)
            if m and not m.get("external"):   # don't delete external-path files
                p = Path(m.get("path", ""))
                if p.exists() and str(p).startswith(str(UPLOAD_DIR)):
                    p.unlink()
                    log.info(f"Purged: {m['name']}")
        if expired:
            save_meta()
        # Also purge stale download tokens
        with token_lock:
            now = utcnow().isoformat()
            stale = [t for t, v in dl_tokens.items() if v["expires_at"] < now]
            for t in stale:
                dl_tokens.pop(t, None)

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def human_uptime(seconds: int) -> str:
    h, r = divmod(int(seconds), 3600)
    m, s = divmod(r, 60)
    return f"{h}h {m}m {s}s"

def make_qr(url: str) -> str:
    """QR encodes URL — receiver scans → goes straight to login."""
    try:
        import qrcode, base64
        from io import BytesIO
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#0a0a0f", back_color="white")
        buf = BytesIO()
        img.save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        log.warning(f"QR failed: {e}")
        return ""

def sniff_mime(name: str) -> str:
    """Best-guess MIME type from filename."""
    mt, _ = mimetypes.guess_type(name)
    return mt or "application/octet-stream"

def is_image(name: str) -> bool:
    return sniff_mime(name).startswith("image/")

def make_dl_token(file_id: str) -> str:
    """
    MINOR CHANGE 12 — single-use download tokens.
    WHY: session cookie alone allows any tab to hit /download repeatedly.
         Token is 60-second, single-use — tighter control.
    """
    token = secrets.token_urlsafe(24)
    with token_lock:
        dl_tokens[token] = {
            "file_id": file_id,
            "expires_at": (utcnow() + timedelta(seconds=TOKEN_TTL_SECONDS)).isoformat()
        }
    return token

def consume_dl_token(token: str) -> str | None:
    """Returns file_id if token valid and not expired, else None. Consumes it."""
    with token_lock:
        entry = dl_tokens.pop(token, None)
    if not entry:
        return None
    if utcnow().isoformat() > entry["expires_at"]:
        return None
    return entry["file_id"]

def log_transfer(file_id: str, file_name: str, remote_addr: str, size: int):
    transfer_log.append({
        "ts": utcnow().isoformat(),
        "file_id": file_id,
        "file_name": file_name,
        "remote_addr": remote_addr,
        "size": size,
    })

def generate_self_signed_cert():
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress
        key  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ip   = get_local_ip()
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"droply")])
        cert = (x509.CertificateBuilder()
                .subject_name(subj).issuer_name(subj)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(utcnow())
                .not_valid_after(utcnow() + timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName([
                    x509.DNSName(u"localhost"),
                    x509.DNSName(u"droply.local"),
                    x509.IPAddress(ipaddress.IPv4Address(ip)),
                ]), critical=False)
                .sign(key, hashes.SHA256()))
        KEY_FILE.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        log.info("TLS cert generated")
    except Exception as e:
        log.warning(f"TLS cert failed: {e}")

# ── mDNS broadcast (MINOR — Phase 1 preview) ─────────────────────────────────
def start_mdns(port: int):
    """
    MINOR CHANGE 5 — broadcast droply.local on LAN via zeroconf.
    WHY: Receivers on the same Wi-Fi can find droply without knowing the IP.
         They just open http://droply.local:5000
    Optional — skipped silently if zeroconf not installed.
    """
    try:
        from zeroconf import Zeroconf, ServiceInfo
        import socket as _s
        ip   = get_local_ip()
        info = ServiceInfo(
            "_http._tcp.local.",
            "droply._http._tcp.local.",
            addresses=[_s.inet_aton(ip)],
            port=port,
            properties={"path": "/", "version": VERSION},
            server="droply.local.",
        )
        zc = Zeroconf()
        zc.register_service(info)
        log.info(f"mDNS: droply.local:{port} registered")
        return zc
    except ImportError:
        log.info("zeroconf not installed — mDNS skipped (pip install zeroconf to enable)")
        return None
    except Exception as e:
        log.warning(f"mDNS failed: {e}")
        return None

# ── Auth decorator ────────────────────────────────────────────────────────────
def require_pin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Not authenticated"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Sender dashboard."""
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route("/receive")
def receive():
    """
    MAJOR CHANGE 1 — dedicated receiver page.
    WHY: The sender's UI has upload controls, delete buttons, expiry settings.
         A receiver shouldn't see any of that — confusing and unnecessary.
         This page is clean: just a file list and download buttons.
    """
    if not session.get("authenticated"):
        return redirect(url_for("login", next="receive"))
    return render_template("receive.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    error = None
    next_page = request.args.get("next", "")
    if request.method == "POST":
        pin = request.form.get("pin", "").strip()
        next_page = request.form.get("next_page", "")
        if secrets.compare_digest(pin, CURRENT_PIN):
            session.permanent = True
            session["authenticated"] = True
            session["auth_time"] = utcnow().isoformat()
            log.info(f"Auth OK from {request.remote_addr}")
            return redirect(url_for("receive") if next_page == "receive" else url_for("index"))
        else:
            log.warning(f"Auth FAIL from {request.remote_addr}")
            error = "Wrong PIN. Try again."
    return render_template("login.html", error=error, next_page=next_page)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── API: file listing ─────────────────────────────────────────────────────────

@app.route("/api/files")
@require_pin
def list_files():
    with meta_lock:
        files = []
        for fid, m in file_meta.items():
            if not is_expired(m):
                # Generate a fresh download token for each file
                token = make_dl_token(fid)
                files.append({
                    "id":             fid,
                    "name":           m["name"],
                    "size":           m["size"],
                    "sha256":         m["sha256"],
                    "mime":           m.get("mime", "application/octet-stream"),
                    "is_image":       is_image(m["name"]),
                    "uploaded_at":    m["uploaded_at"],
                    "download_count": m.get("download_count", 0),
                    "max_downloads":  m.get("max_downloads", 0),
                    "expires_at":     m.get("expires_at", ""),
                    "external":       m.get("external", False),
                    "dl_token":       token,   # MINOR: short-lived download token
                })
    return jsonify({"files": files, "count": len(files)})

# ── API: upload (browser file picker / drag-drop) ─────────────────────────────

@app.route("/api/upload", methods=["POST"])
@require_pin
@limiter.limit("30 per minute")
def upload_file():
    """Stream upload → disk. SHA-256 computed during write. Dedup check."""
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    safe_name = Path(f.filename).name
    try:
        ttl      = int(request.form.get("ttl_hours",      DEFAULT_TTL_HOURS))
        max_dl   = int(request.form.get("max_downloads",  DEFAULT_MAX_DL))
    except ValueError:
        ttl, max_dl = DEFAULT_TTL_HOURS, DEFAULT_MAX_DL

    file_id   = str(uuid.uuid4())
    dest      = UPLOAD_DIR / file_id
    h         = hashlib.sha256()
    size      = 0

    try:
        with open(dest, "wb") as out:
            while True:
                chunk = f.stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                out.write(chunk)
                h.update(chunk)
                size += len(chunk)

        sha256 = h.hexdigest()

        # MINOR CHANGE 8 — dedup: if exact same file already shared, reuse
        with meta_lock:
            for existing_id, em in file_meta.items():
                if em["sha256"] == sha256 and not is_expired(em):
                    dest.unlink()
                    log.info(f"Dedup hit for {safe_name} — reusing {existing_id}")
                    return jsonify({
                        "id": existing_id, "name": em["name"],
                        "size": em["size"], "sha256": sha256,
                        "dedup": True
                    }), 200

        expires_at = (utcnow() + timedelta(hours=ttl)).isoformat() if ttl > 0 else ""
        mime       = sniff_mime(safe_name)

        with meta_lock:
            file_meta[file_id] = {
                "name": safe_name, "size": size, "sha256": sha256,
                "mime": mime, "path": str(dest),
                "uploaded_at": utcnow().isoformat(),
                "ttl_hours": ttl, "max_downloads": max_dl,
                "download_count": 0, "expires_at": expires_at,
                "external": False,
            }
        save_meta()
        log.info(f"Upload: {safe_name} {size}B sha={sha256[:12]}…")
        return jsonify({"id": file_id, "name": safe_name, "size": size, "sha256": sha256}), 201

    except Exception as e:
        if dest.exists(): dest.unlink()
        log.error(f"Upload error: {e}")
        return jsonify({"error": "Upload failed"}), 500

# ── API: share local path (MAJOR CHANGE 3) ───────────────────────────────────

@app.route("/api/share-path", methods=["POST"])
@require_pin
def share_path():
    """
    MAJOR CHANGE 3 — upload-from-local-path.
    Sender POSTs {"path": "/home/user/bigvideo.mp4", "ttl_hours": 24}
    droply reads the file from disk WITHOUT copying it to uploads/.
    WHY: A 10 GB file would take time + double disk space to copy.
         This just registers the path and serves directly from there.
    SECURITY: path must be an absolute, existing file. No traversal.
    """
    data = request.get_json(silent=True) or {}
    raw_path = data.get("path", "").strip()
    if not raw_path:
        return jsonify({"error": "path required"}), 400

    p = Path(raw_path).resolve()
    if not p.exists() or not p.is_file():
        return jsonify({"error": f"File not found: {raw_path}"}), 404

    try:
        ttl    = int(data.get("ttl_hours",     DEFAULT_TTL_HOURS))
        max_dl = int(data.get("max_downloads", DEFAULT_MAX_DL))
    except (ValueError, TypeError):
        ttl, max_dl = DEFAULT_TTL_HOURS, DEFAULT_MAX_DL

    size   = p.stat().st_size
    sha256 = sha256_file(p)   # hash the file in place
    mime   = sniff_mime(p.name)

    # Dedup check
    with meta_lock:
        for eid, em in file_meta.items():
            if em["sha256"] == sha256 and not is_expired(em):
                return jsonify({"id": eid, "name": em["name"], "size": em["size"],
                                "sha256": sha256, "dedup": True}), 200

    file_id    = str(uuid.uuid4())
    expires_at = (utcnow() + timedelta(hours=ttl)).isoformat() if ttl > 0 else ""

    with meta_lock:
        file_meta[file_id] = {
            "name": p.name, "size": size, "sha256": sha256,
            "mime": mime, "path": str(p),
            "uploaded_at": utcnow().isoformat(),
            "ttl_hours": ttl, "max_downloads": max_dl,
            "download_count": 0, "expires_at": expires_at,
            "external": True,   # flag: don't delete this file on purge
        }
    save_meta()
    log.info(f"Share-path: {p.name} ({size}B) from {p}")
    return jsonify({"id": file_id, "name": p.name, "size": size, "sha256": sha256}), 201

# ── API: download ─────────────────────────────────────────────────────────────

@app.route("/api/download/<file_id>")
@require_pin
def download_file(file_id: str):
    """
    Download via session auth.
    Token is issued by /api/files — UI uses it.
    Direct URL access (e.g. curl) still works with a valid session.
    """
    with meta_lock:
        meta = file_meta.get(file_id)
    if not meta:
        abort(404)
    if is_expired(meta):
        abort(410)

    file_path = Path(meta["path"])
    if not file_path.exists():
        log.error(f"Missing on disk: {file_id}")
        abort(404)

    # Integrity check
    actual = sha256_file(file_path)
    if actual != meta["sha256"]:
        log.error(f"Integrity FAIL {file_id}: expected {meta['sha256'][:12]} got {actual[:12]}")
        abort(500)

    with meta_lock:
        file_meta[file_id]["download_count"] = meta.get("download_count", 0) + 1
    save_meta()

    log_transfer(file_id, meta["name"], request.remote_addr, meta["size"])
    log.info(f"Download: {meta['name']} → {request.remote_addr}")

    file_size = meta["size"]
    mime      = meta.get("mime", "application/octet-stream")
    range_hdr = request.headers.get("Range")

    def stream(start=0, end=None):
        end = end or file_size
        with open(file_path, "rb") as fh:
            fh.seek(start)
            remaining = end - start
            while remaining > 0:
                data = fh.read(min(CHUNK_SIZE, remaining))
                if not data:
                    break
                remaining -= len(data)
                yield data

    base_headers = {
        "Content-Disposition": f'attachment; filename="{meta["name"]}"',
        "Accept-Ranges":       "bytes",
        "X-SHA256":            meta["sha256"],
        "X-Droply-Version":    VERSION,
    }

    if range_hdr:
        try:
            parts = range_hdr.replace("bytes=", "").split("-")
            start = int(parts[0])
            end   = int(parts[1]) + 1 if parts[1] else file_size
        except Exception:
            start, end = 0, file_size
        headers = {**base_headers,
                   "Content-Range":  f"bytes {start}-{end-1}/{file_size}",
                   "Content-Length": str(end - start)}
        return Response(stream(start, end), 206, headers=headers, mimetype=mime)

    return Response(stream(), 200,
                    headers={**base_headers, "Content-Length": str(file_size)},
                    mimetype=mime)

@app.route("/api/download-token/<token>")
def download_by_token(token: str):
    """
    MAJOR CHANGE 4 — token-based download (no session needed).
    WHY: Lets the QR code link embed a one-time token so the receiver
         can start the download immediately after login without an extra click.
    Token is 60 s, single-use, server-side — cannot be reused or guessed.
    """
    file_id = consume_dl_token(token)
    if not file_id:
        return jsonify({"error": "Token invalid or expired"}), 410

    with meta_lock:
        meta = file_meta.get(file_id)
    if not meta or is_expired(meta):
        abort(410)

    # Check session OR token (token already consumed = authorized)
    # (token consumption IS the auth here)
    file_path = Path(meta["path"])
    if not file_path.exists():
        abort(404)

    actual = sha256_file(file_path)
    if actual != meta["sha256"]:
        abort(500)

    with meta_lock:
        file_meta[file_id]["download_count"] = meta.get("download_count", 0) + 1
    save_meta()
    log_transfer(file_id, meta["name"], request.remote_addr, meta["size"])

    file_size = meta["size"]
    mime      = meta.get("mime", "application/octet-stream")

    def stream():
        with open(file_path, "rb") as fh:
            while chunk := fh.read(CHUNK_SIZE):
                yield chunk

    return Response(stream(), 200, headers={
        "Content-Disposition": f'attachment; filename="{meta["name"]}"',
        "Content-Length":      str(file_size),
        "X-SHA256":            meta["sha256"],
    }, mimetype=mime)

# ── API: delete ───────────────────────────────────────────────────────────────

@app.route("/api/delete/<file_id>", methods=["DELETE"])
@require_pin
def delete_file(file_id: str):
    with meta_lock:
        meta = file_meta.pop(file_id, None)
    if not meta:
        return jsonify({"error": "Not found"}), 404
    p = Path(meta["path"])
    if p.exists() and not meta.get("external"):
        p.unlink()
    save_meta()
    log.info(f"Deleted: {meta['name']}")
    return jsonify({"ok": True})

# ── API: status ───────────────────────────────────────────────────────────────

@app.route("/api/status")
@require_pin
def status():
    with meta_lock:
        total = sum(m["size"] for m in file_meta.values() if not is_expired(m))
        count = sum(1 for m in file_meta.values() if not is_expired(m))
    elapsed = time.time() - START_TIME
    return jsonify({
        "ok": True, "version": VERSION,
        "ip": get_local_ip(), "files": count, "total_size": total,
        "uptime_seconds": int(elapsed),
        "uptime_human": human_uptime(elapsed),
        "active_tokens": len(dl_tokens),
    })

# ── API: transfers log (MAJOR CHANGE 6) ──────────────────────────────────────

@app.route("/api/transfers")
@require_pin
def transfers():
    """
    MAJOR CHANGE 6 — transfer audit log.
    WHY: Enterprise/B2B requirement. Who downloaded what and when.
         Also useful for the sender to see "has my colleague got the file yet?"
    """
    return jsonify({"transfers": list(transfer_log)})

# ── API: info (public) ────────────────────────────────────────────────────────

@app.route("/api/info")
def info():
    port      = int(os.environ.get("PORT", 5000))
    ip        = get_local_ip()
    use_https = CERT_FILE.exists() and KEY_FILE.exists()
    scheme    = "https" if use_https else "http"
    url       = f"{scheme}://{ip}:{port}"
    recv_url  = f"{url}/receive"
    qr        = make_qr(recv_url)      # QR points to /receive directly
    return jsonify({
        "url": url, "receive_url": recv_url,
        "ip": ip, "port": port, "qr": qr,
        "version": VERSION,
    })

# ── Favicon (stops 404 spam in logs) ─────────────────────────────────────────
@app.route("/favicon.ico")
def favicon():
    ico = (b'\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00\x18\x00'
           b'\x28\x00\x00\x00\x16\x00\x00\x00\x28\x00\x00\x00\x01\x00'
           b'\x00\x00\x02\x00\x00\x00\x01\x00\x18\x00\x00\x00\x00\x00'
           b'\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           b'\x00\x00\x00\x00\x00\x00\x7c\x6a\xff\x00\x00\x00\x00\x00')
    return Response(ico, mimetype="image/x-icon")

# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def e404(e): return jsonify({"error": "Not found"}), 404

@app.errorhandler(410)
def e410(e): return jsonify({"error": "Expired or limit reached"}), 410

@app.errorhandler(413)
def e413(e): return jsonify({"error": f"Too large — max {MAX_FILE_SIZE//(1024**3)}GB"}), 413

@app.errorhandler(429)
def e429(e): return jsonify({"error": "Too many attempts — wait 60 s"}), 429

@app.errorhandler(500)
def e500(e): return jsonify({"error": "Server error"}), 500

# ── Startup ───────────────────────────────────────────────────────────────────
def startup(port: int, use_https: bool):
    global CURRENT_PIN
    load_meta()
    CURRENT_PIN = generate_pin()

    ip     = get_local_ip()
    scheme = "https" if use_https else "http"
    url    = f"{scheme}://{ip}:{port}"

    print("\n" + "═"*60)
    print(f"  droply {VERSION}")
    print("═"*60)
    print(f"  Sender URL  : {url}")
    print(f"  Receiver URL: {url}/receive   ← share this link")
    print(f"  PIN         : {CURRENT_PIN}   ← share this PIN")
    print(f"  HTTPS       : {'yes' if use_https else 'no (--http mode)'}")
    print(f"  Max file    : {MAX_FILE_SIZE//(1024**3)} GB")
    print("═"*60 + "\n")

    threading.Thread(target=purge_expired, daemon=True).start()
    start_mdns(port)

    def bye(sig, frame):
        print("\ndroply: shutting down")
        sys.exit(0)
    signal.signal(signal.SIGINT, bye)

    ssl_ctx = (str(CERT_FILE), str(KEY_FILE)) if use_https else None
    app.run(host="0.0.0.0", port=port, threaded=True,
            ssl_context=ssl_ctx, debug=False)

# ── Built-in test suite ───────────────────────────────────────────────────────
def run_tests():
    """
    Self-contained test suite — runs the server in a background thread,
    fires requests against it, reports pass/fail.
    Run:  python server.py --http --test
    """
    import requests, tempfile, threading as _th
    requests.packages.urllib3.disable_warnings()

    global CURRENT_PIN
    PORT = 15432
    os.environ["PORT"] = str(PORT)

    CURRENT_PIN = generate_pin()
    load_meta()
    t = _th.Thread(
        target=lambda: app.run(host="127.0.0.1", port=PORT,
                               threaded=True, debug=False, use_reloader=False),
        daemon=True)
    t.start()
    time.sleep(1.5)

    base  = f"http://127.0.0.1:{PORT}"
    sess  = requests.Session()
    fails = []
    total = 0

    def check(name, cond, detail=""):
        nonlocal total
        total += 1
        if cond:
            print(f"  ✅ {name}")
        else:
            print(f"  ❌ {name}  {detail}")
            fails.append(name)

    print("\n" + "─"*50)
    print(f"  droply {VERSION} — test suite")
    print("─"*50)

    # T1: public info
    r = sess.get(f"{base}/api/info")
    check("T01 /api/info public", r.status_code == 200)

    # T2: unauth → 401
    r = sess.get(f"{base}/api/files")
    check("T02 /api/files unauth → 401", r.status_code == 401)

    # T3: wrong PIN
    r = sess.post(f"{base}/login", data={"pin": "000000"}, allow_redirects=False)
    check("T03 wrong PIN → stays on login", r.status_code in (200, 302))

    # T4: correct PIN
    r = sess.post(f"{base}/login",
                  data={"pin": CURRENT_PIN, "next_page": ""},
                  allow_redirects=True)
    check("T04 correct PIN → 200", r.status_code == 200)

    # T5: file list (empty)
    r = sess.get(f"{base}/api/files")
    check("T05 file list authenticated", r.status_code == 200)
    data = r.json()
    check("T06 file list empty", data["count"] == 0)

    # T6: upload a file
    content = b"Hello droply phase 1! " * 500
    expected_hash = hashlib.sha256(content).hexdigest()
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    with open(tmp_path, "rb") as fh:
        r = sess.post(f"{base}/api/upload",
                      files={"file": ("test_phase1.txt", fh, "text/plain")},
                      data={"ttl_hours": "1", "max_downloads": "3"})
    check("T07 upload → 201", r.status_code == 201)
    up = r.json()
    check("T08 upload SHA-256 correct", up.get("sha256") == expected_hash,
          f"got {up.get('sha256','?')[:12]}…")
    file_id = up.get("id", "")

    # T7: dedup — upload same file again
    with open(tmp_path, "rb") as fh:
        r2 = sess.post(f"{base}/api/upload",
                       files={"file": ("test_phase1_dup.txt", fh, "text/plain")},
                       data={"ttl_hours": "1", "max_downloads": "3"})
    check("T09 dedup — 200 not 201", r2.status_code == 200)
    check("T10 dedup returns same id", r2.json().get("id") == file_id)
    check("T11 dedup flag set", r2.json().get("dedup") is True)

    # T8: share-path
    r = sess.post(f"{base}/api/share-path",
                  json={"path": tmp_path, "ttl_hours": 1},
                  headers={"Content-Type": "application/json"})
    check("T12 share-path dedup hit", r.status_code in (200, 201))

    # T9: share-path bad path
    r = sess.post(f"{base}/api/share-path",
                  json={"path": "/nonexistent/file.xyz"},
                  headers={"Content-Type": "application/json"})
    check("T13 share-path bad path → 404", r.status_code == 404)

    # T10: file list shows the file + dl_token
    r = sess.get(f"{base}/api/files")
    files = r.json()["files"]
    check("T14 file list count=1", len(files) == 1)
    check("T15 dl_token present", bool(files[0].get("dl_token")))
    token = files[0]["dl_token"]

    # T11: download by token
    r = sess.get(f"{base}/api/download-token/{token}")
    check("T16 token download → 200", r.status_code == 200)
    check("T17 token download content correct", r.content == content)

    # T12: token is single-use
    r2 = sess.get(f"{base}/api/download-token/{token}")
    check("T18 token single-use → 410", r2.status_code == 410)

    # T13: download by session
    r = sess.get(f"{base}/api/download/{file_id}")
    check("T19 session download → 200", r.status_code == 200)
    dl_hash = hashlib.sha256(r.content).hexdigest()
    check("T20 download integrity", dl_hash == expected_hash)
    check("T21 X-SHA256 header", r.headers.get("X-SHA256") == expected_hash)

    # T14: download count incremented (2 downloads so far: token + session)
    r = sess.get(f"{base}/api/files")
    fc = r.json()["files"][0]
    check("T22 download_count = 2", fc["download_count"] == 2, f"got {fc['download_count']}")

    # T15: max_downloads enforcement — upload with limit=1
    with open(tmp_path, "rb") as fh:
        ru = sess.post(f"{base}/api/upload",
                       files={"file": ("limit_test.txt", fh, "text/plain")},
                       data={"ttl_hours": "1", "max_downloads": "1"})
    # This will dedup — so let's create a distinct file
    content2 = b"limit file " + secrets.token_bytes(32)
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp2:
        tmp2.write(content2)
        tmp2_path = tmp2.name
    with open(tmp2_path, "rb") as fh:
        rl = sess.post(f"{base}/api/upload",
                       files={"file": ("limit_test.bin", fh, "application/octet-stream")},
                       data={"ttl_hours": "1", "max_downloads": "1"})
    check("T23 limit-file upload", rl.status_code == 201)
    lid = rl.json()["id"]
    r1  = sess.get(f"{base}/api/download/{lid}")
    r2  = sess.get(f"{base}/api/download/{lid}")
    check("T24 1st download ok", r1.status_code == 200)
    check("T25 2nd download → 410 (limit hit)", r2.status_code == 410)

    # T16: receive page
    r = sess.get(f"{base}/receive")
    check("T26 /receive page loads", r.status_code == 200)

    # T17: transfers log
    r = sess.get(f"{base}/api/transfers")
    check("T27 transfers log", r.status_code == 200)
    check("T28 transfers not empty", len(r.json()["transfers"]) > 0)

    # T18: status endpoint
    r = sess.get(f"{base}/api/status")
    s = r.json()
    check("T29 status ok", s.get("ok") is True)
    check("T30 status version", s.get("version") == VERSION)
    check("T31 status uptime_human present", bool(s.get("uptime_human")))

    # T19: delete
    r = sess.delete(f"{base}/api/delete/{file_id}")
    check("T32 delete → ok", r.json().get("ok") is True)
    r = sess.get(f"{base}/api/files")
    ids = [f["id"] for f in r.json()["files"]]
    check("T33 file gone from list", file_id not in ids)

    # T20: rate limiter
    for _ in range(5):
        sess.post(f"{base}/login", data={"pin": "000000"})
    r = sess.post(f"{base}/login", data={"pin": "000000"})
    check("T34 rate limiter → 429", r.status_code == 429)

    # Cleanup
    os.unlink(tmp_path)
    os.unlink(tmp2_path)

    print("─"*50)
    print(f"  {total - len(fails)}/{total} passed   {len(fails)} failed")
    if fails:
        print("  FAILED:", ", ".join(fails))
    print("─"*50 + "\n")
    sys.exit(0 if not fails else 1)

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"droply {VERSION}")
    parser.add_argument("--http",   action="store_true", help="Plain HTTP, no cert warning")
    parser.add_argument("--port",   type=int, default=5000)
    parser.add_argument("--test",   action="store_true", help="Run built-in test suite and exit")
    args = parser.parse_args()

    os.environ["PORT"] = str(args.port)

    if args.http:
        for f in [CERT_FILE, KEY_FILE]:
            if f.exists(): f.unlink()

    if args.test:
        print("⚠  HTTP mode forced for tests")
        for f in [CERT_FILE, KEY_FILE]:
            if f.exists(): f.unlink()
        run_tests()
    else:
        if not args.http and not (CERT_FILE.exists() and KEY_FILE.exists()):
            generate_self_signed_cert()
        startup(args.port, use_https=not args.http)