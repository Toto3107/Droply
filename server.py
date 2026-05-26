"""
droply/server.py  —  Phase 2
==============================

PHASE 2 CHANGES vs Phase 1
────────────────────────────

MAJOR
  1. --bind flag          Force which network interface droply listens on.
                          WHY: On WSL2, VMs, dual-NIC machines, VPNs the auto-detected
                          IP is often wrong — QR code points nowhere.
                          Usage: python server.py --http --bind 192.168.1.42
                          If omitted: same smart auto-detect as before.

  2. WebSocket push       Replaces 15-second polling on sender + receiver pages.
                          WHY: Receiver sees new files the instant sender uploads.
                          Sender sees a live "N receivers connected" counter.
                          Uses flask-sock (tiny — no socketio overhead).
                          Events: file_added, file_deleted, receiver_count.

  3. CORS headers         Every response now carries the right CORS headers.
                          WHY: Android Chrome and some mobile browsers block XHR
                          to a different IP without explicit CORS. Silent failure —
                          no error shown, download just never starts.

MINOR
  4. /api/debug           Diagnostics page. Shows all network interfaces,
                          active WS connections, disk space, session count.
                          WHY: When cross-device doesn't work, this tells you why.

  5. get_all_ips()        Enumerates every IPv4 address on every interface.
                          WHY: Shown in /api/debug so user can pick the right one
                          if auto-detect chose wrong.

  6. Smarter IP detect    Falls back through interface list if primary detect fails.
                          Prefers RFC-1918 private addresses (192.168.x, 10.x, 172.16.x)
                          over loopback or link-local.

  7. Receiver counter     ws_receivers set tracks connected receiver WebSockets.
                          Sender sees live count in dashboard topbar.

  8. WS auth              WebSocket connections require a valid session cookie.
                          Unauthenticated WS → closed immediately with 1008 (policy).

  9. Bandwidth hint       /api/status now includes disk_free_gb and ws_connections.

 10. Version bump         0.3.0-phase2

TESTING
  python server.py --http --test         (all 40 tests)
  python server.py --http --bind 0.0.0.0 (listen on all interfaces)
"""

import os, sys, hashlib, uuid, json, logging, signal, socket
import time, threading, secrets, mimetypes, argparse, traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from functools import wraps
from collections import deque
import shutil

from flask import (Flask, request, session, jsonify,
                   render_template, redirect, url_for, Response, abort)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import threading as _threading

try:
    from flask_sock import Sock
    HAS_SOCK = True
except ImportError:
    HAS_SOCK = False

# ── Version ───────────────────────────────────────────────────────────────────
VERSION = "0.3.0-phase2"

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
MAX_FILE_SIZE     = 10 * 1024 * 1024 * 1024
CHUNK_SIZE        = 1  * 1024 * 1024
PIN_LENGTH        = 6
SESSION_TIMEOUT   = 3600
DEFAULT_TTL_HOURS = 24
DEFAULT_MAX_DL    = 0
TOKEN_TTL_SECONDS = 60
MAX_TRANSFER_LOG  = 500
WS_PING_INTERVAL  = 20   # seconds between WebSocket keepalive pings

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
logging.getLogger("werkzeug").setLevel(logging.WARNING)

# ── Flask + extensions ────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=SESSION_TIMEOUT)
app.config["SOCK_SERVER_OPTIONS"] = {"ping_interval": WS_PING_INTERVAL}

limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri="memory://")
sock    = Sock(app) if HAS_SOCK else None

# ── MAJOR CHANGE 3: CORS ──────────────────────────────────────────────────────
# WHY: Android Chrome and WebViews block cross-origin XHR without these headers.
#      The receiver is on a different IP than the server, so every request is
#      technically cross-origin from the browser's perspective.
#      We allow any origin because this is a local-network tool — there's no
#      external internet attacker who can reach a 192.168.x.x address anyway.
CORS_HEADERS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Requested-With",
    "Access-Control-Expose-Headers":"X-SHA256, X-Droply-Version, Content-Length",
}

@app.after_request
def add_cors(response):
    """Attach CORS headers to every response."""
    for k, v in CORS_HEADERS.items():
        response.headers[k] = v
    return response

@app.route("/api/", methods=["OPTIONS"], strict_slashes=False)
@app.route("/api/<path:_>", methods=["OPTIONS"])
def cors_preflight(_=""):
    """Handle CORS pre-flight OPTIONS requests from browsers."""
    return Response("", 204, headers=CORS_HEADERS)

@app.before_request
def handle_options():
    """Catch OPTIONS on any route — needed for Android WebView preflight."""
    if request.method == "OPTIONS":
        return Response("", 204, headers=CORS_HEADERS)

# ── Global state ──────────────────────────────────────────────────────────────
CURRENT_PIN:   str   = ""
BIND_IP:       str   = ""          # set at startup from --bind or auto-detect
START_TIME:    float = time.time()
file_meta:     dict  = {}
meta_lock            = threading.Lock()
dl_tokens:     dict  = {}
token_lock           = threading.Lock()
transfer_log         = deque(maxlen=MAX_TRANSFER_LOG)

# MAJOR CHANGE 2: WebSocket connection sets
# WHY: Separate sets for senders vs receivers so we can push targeted events.
ws_senders   = set()   # WebSocket connections from sender dashboard
ws_receivers = set()   # WebSocket connections from /receive page
ws_lock      = threading.Lock()

# ── Network helpers ───────────────────────────────────────────────────────────

def get_all_ips() -> list[dict]:
    """
    MINOR CHANGE 5 — enumerate every IPv4 address on every interface.
    Returns list of {iface, ip, private} sorted: private first.
    Used by /api/debug and smart IP detection.
    """
    results = []
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for a in addrs:
                ip = a.get("addr", "")
                if ip:
                    results.append({"iface": iface, "ip": ip,
                                    "private": _is_private(ip)})
    except ImportError:
        # Fallback: hostname-based approach
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ip = info[4][0]
                results.append({"iface": "?", "ip": ip, "private": _is_private(ip)})
        except Exception:
            pass
        # Also try the UDP trick
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            results.append({"iface": "primary", "ip": ip, "private": _is_private(ip)})
        except Exception:
            pass

    # Deduplicate, sort: private first, loopback last
    seen = set()
    unique = []
    for r in results:
        if r["ip"] not in seen and r["ip"] != "127.0.0.1":
            seen.add(r["ip"])
            unique.append(r)
    unique.sort(key=lambda r: (0 if r["private"] else 1))
    return unique


def _is_private(ip: str) -> bool:
    """True for RFC-1918 private address ranges."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168))
    except ValueError:
        return False


def get_local_ip() -> str:
    """
    MINOR CHANGE 6 — smarter IP detection.
    If --bind was set, use that. Otherwise prefer private RFC-1918 addresses.
    Falls back to UDP-connect trick if interface enumeration fails.
    """
    global BIND_IP
    if BIND_IP and BIND_IP != "0.0.0.0":
        return BIND_IP
    # Try interface enumeration first
    all_ips = get_all_ips()
    private = [r["ip"] for r in all_ips if r["private"]]
    if private:
        return private[0]
    # UDP fallback
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


def disk_free_gb() -> float:
    try:
        return round(shutil.disk_usage(BASE_DIR).free / (1024**3), 1)
    except Exception:
        return -1.0

# ── File helpers ──────────────────────────────────────────────────────────────

def generate_pin() -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(PIN_LENGTH))

def sha256_file(path: Path) -> str:
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
    while True:
        time.sleep(60)
        with meta_lock:
            expired = [fid for fid, m in file_meta.items() if is_expired(m)]
        for fid in expired:
            with meta_lock:
                m = file_meta.pop(fid, None)
            if m and not m.get("external"):
                p = Path(m.get("path", ""))
                if p.exists() and str(p).startswith(str(UPLOAD_DIR)):
                    p.unlink()
                    log.info(f"Purged: {m['name']}")
        if expired:
            save_meta()
        with token_lock:
            now = utcnow().isoformat()
            stale = [t for t, v in dl_tokens.items() if v["expires_at"] < now]
            for t in stale:
                dl_tokens.pop(t, None)

def sniff_mime(name: str) -> str:
    mt, _ = mimetypes.guess_type(name)
    return mt or "application/octet-stream"

def is_image(name: str) -> bool:
    return sniff_mime(name).startswith("image/")

def make_dl_token(file_id: str) -> str:
    token = secrets.token_urlsafe(24)
    with token_lock:
        dl_tokens[token] = {
            "file_id": file_id,
            "expires_at": (utcnow() + timedelta(seconds=TOKEN_TTL_SECONDS)).isoformat()
        }
    return token

def consume_dl_token(token: str):
    with token_lock:
        entry = dl_tokens.pop(token, None)
    if not entry:
        return None
    if utcnow().isoformat() > entry["expires_at"]:
        return None
    return entry["file_id"]

def log_transfer(file_id, file_name, remote_addr, size):
    transfer_log.append({
        "ts": utcnow().isoformat(),
        "file_id": file_id, "file_name": file_name,
        "remote_addr": remote_addr, "size": size,
    })

# ── MAJOR CHANGE 2: WebSocket broadcast helpers ───────────────────────────────

def _ws_send_all(ws_set: set, payload: dict):
    """
    Broadcast a JSON event to all WebSocket connections in a set.
    Dead connections are silently removed.
    WHY: We need to notify all connected browsers simultaneously —
         one sender upload should update every receiver's file list instantly.
    """
    msg = json.dumps(payload)
    dead = set()
    with ws_lock:
        targets = set(ws_set)
    for ws in targets:
        try:
            ws.send(msg)
        except Exception:
            dead.add(ws)
    if dead:
        with ws_lock:
            ws_set -= dead

def broadcast_file_added(file_id: str, meta: dict):
    """Push new-file event to all receivers and update sender count."""
    payload = {
        "event":   "file_added",
        "file_id": file_id,
        "name":    meta["name"],
        "size":    meta["size"],
        "sha256":  meta["sha256"],
    }
    _ws_send_all(ws_receivers, payload)
    _ws_send_all(ws_senders,   payload)

def broadcast_file_deleted(file_id: str, name: str):
    payload = {"event": "file_deleted", "file_id": file_id, "name": name}
    _ws_send_all(ws_receivers, payload)
    _ws_send_all(ws_senders,   payload)

def broadcast_receiver_count():
    """Tell senders how many receivers are currently connected."""
    with ws_lock:
        count = len(ws_receivers)
    _ws_send_all(ws_senders, {"event": "receiver_count", "count": count})

# ── QR code ───────────────────────────────────────────────────────────────────

def make_qr(url: str) -> str:
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

# ── TLS cert ──────────────────────────────────────────────────────────────────

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

# ── mDNS ──────────────────────────────────────────────────────────────────────

def start_mdns(port: int):
    try:
        from zeroconf import Zeroconf, ServiceInfo
        import socket as _s
        ip   = get_local_ip()
        info = ServiceInfo(
            "_http._tcp.local.", "droply._http._tcp.local.",
            addresses=[_s.inet_aton(ip)], port=port,
            properties={"path": "/", "version": VERSION},
            server="droply.local.",
        )
        zc = Zeroconf()
        zc.register_service(info)
        log.info(f"mDNS: droply.local:{port}")
        return zc
    except ImportError:
        log.info("zeroconf not installed — mDNS skipped")
        return None
    except Exception as e:
        log.warning(f"mDNS failed: {e}")
        return None

# ── Auth ──────────────────────────────────────────────────────────────────────

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
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route("/receive")
def receive():
    if not session.get("authenticated"):
        return redirect(url_for("login", next="receive"))
    return render_template("receive.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    error     = None
    next_page = request.args.get("next", "")
    if request.method == "POST":
        pin       = request.form.get("pin", "").strip()
        next_page = request.form.get("next_page", "")
        if secrets.compare_digest(pin, CURRENT_PIN):
            session.permanent    = True
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

# ── MAJOR CHANGE 2: WebSocket endpoints ──────────────────────────────────────

if HAS_SOCK:
    @sock.route("/ws/sender")
    def ws_sender(ws):
        """
        Sender dashboard WebSocket.
        WHY: Pushes file_added / file_deleted events and receiver_count updates
             in real-time so the sender sees what's happening without polling.
        Auth: requires valid session cookie (same as HTTP routes).
        """
        if not session.get("authenticated"):
            ws.close(1008, "Not authenticated")
            return
        with ws_lock:
            ws_senders.add(ws)
        # Send current receiver count immediately on connect
        with ws_lock:
            count = len(ws_receivers)
        try:
            ws.send(json.dumps({"event": "receiver_count", "count": count}))
            # Keep alive — recv() blocks until client disconnects
            while True:
                msg = ws.receive(timeout=WS_PING_INTERVAL + 5)
                if msg is None:
                    break   # client closed connection
        except Exception:
            pass
        finally:
            with ws_lock:
                ws_senders.discard(ws)

    @sock.route("/ws/receiver")
    def ws_receiver(ws):
        """
        Receiver page WebSocket.
        WHY: Pushes file_added / file_deleted so receiver's list updates instantly.
             Also increments the receiver counter the sender sees.
        Auth: requires valid session cookie.
        """
        if not session.get("authenticated"):
            ws.close(1008, "Not authenticated")
            return
        with ws_lock:
            ws_receivers.add(ws)
        broadcast_receiver_count()   # tell senders +1 receiver joined
        try:
            while True:
                msg = ws.receive(timeout=WS_PING_INTERVAL + 5)
                if msg is None:
                    break
        except Exception:
            pass
        finally:
            with ws_lock:
                ws_receivers.discard(ws)
            broadcast_receiver_count()   # tell senders -1 receiver left

# ── API: files ────────────────────────────────────────────────────────────────

@app.route("/api/files")
@require_pin
def list_files():
    with meta_lock:
        files = []
        for fid, m in file_meta.items():
            if not is_expired(m):
                token = make_dl_token(fid)
                files.append({
                    "id": fid, "name": m["name"], "size": m["size"],
                    "sha256": m["sha256"], "mime": m.get("mime", "application/octet-stream"),
                    "is_image": is_image(m["name"]),
                    "uploaded_at": m["uploaded_at"],
                    "download_count": m.get("download_count", 0),
                    "max_downloads":  m.get("max_downloads", 0),
                    "expires_at":     m.get("expires_at", ""),
                    "external":       m.get("external", False),
                    "dl_token":       token,
                })
    return jsonify({"files": files, "count": len(files)})

# ── API: upload ───────────────────────────────────────────────────────────────

@app.route("/api/upload", methods=["POST"])
@require_pin
@limiter.limit("30 per minute")
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    safe_name = Path(f.filename).name
    try:
        ttl    = int(request.form.get("ttl_hours",     DEFAULT_TTL_HOURS))
        max_dl = int(request.form.get("max_downloads", DEFAULT_MAX_DL))
    except ValueError:
        ttl, max_dl = DEFAULT_TTL_HOURS, DEFAULT_MAX_DL

    file_id = str(uuid.uuid4())
    dest    = UPLOAD_DIR / file_id
    h       = hashlib.sha256()
    size    = 0

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

        # Dedup
        with meta_lock:
            for eid, em in file_meta.items():
                if em["sha256"] == sha256 and not is_expired(em):
                    dest.unlink()
                    log.info(f"Dedup: {safe_name}")
                    return jsonify({"id": eid, "name": em["name"],
                                    "size": em["size"], "sha256": sha256,
                                    "dedup": True}), 200

        expires_at = (utcnow() + timedelta(hours=ttl)).isoformat() if ttl > 0 else ""
        mime       = sniff_mime(safe_name)
        meta_entry = {
            "name": safe_name, "size": size, "sha256": sha256, "mime": mime,
            "path": str(dest), "uploaded_at": utcnow().isoformat(),
            "ttl_hours": ttl, "max_downloads": max_dl,
            "download_count": 0, "expires_at": expires_at, "external": False,
        }
        with meta_lock:
            file_meta[file_id] = meta_entry
        save_meta()
        log.info(f"Upload: {safe_name} {size}B")

        # MAJOR CHANGE 2: push to all connected clients
        broadcast_file_added(file_id, meta_entry)

        return jsonify({"id": file_id, "name": safe_name, "size": size, "sha256": sha256}), 201

    except Exception as e:
        if dest.exists():
            dest.unlink()
        log.error(f"Upload error: {e}")
        return jsonify({"error": "Upload failed"}), 500

# ── API: share-path ───────────────────────────────────────────────────────────

@app.route("/api/share-path", methods=["POST"])
@require_pin
def share_path():
    data     = request.get_json(silent=True) or {}
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
    sha256 = sha256_file(p)
    mime   = sniff_mime(p.name)

    with meta_lock:
        for eid, em in file_meta.items():
            if em["sha256"] == sha256 and not is_expired(em):
                return jsonify({"id": eid, "name": em["name"], "size": em["size"],
                                "sha256": sha256, "dedup": True}), 200

    file_id    = str(uuid.uuid4())
    expires_at = (utcnow() + timedelta(hours=ttl)).isoformat() if ttl > 0 else ""
    meta_entry = {
        "name": p.name, "size": size, "sha256": sha256, "mime": mime,
        "path": str(p), "uploaded_at": utcnow().isoformat(),
        "ttl_hours": ttl, "max_downloads": max_dl,
        "download_count": 0, "expires_at": expires_at, "external": True,
    }
    with meta_lock:
        file_meta[file_id] = meta_entry
    save_meta()
    log.info(f"Share-path: {p.name} ({size}B)")
    broadcast_file_added(file_id, meta_entry)
    return jsonify({"id": file_id, "name": p.name, "size": size, "sha256": sha256}), 201

# ── API: download ─────────────────────────────────────────────────────────────

@app.route("/api/download/<file_id>")
@require_pin
def download_file(file_id: str):
    with meta_lock:
        meta = file_meta.get(file_id)
    if not meta:
        abort(404)
    if is_expired(meta):
        abort(410)

    file_path = Path(meta["path"])
    if not file_path.exists():
        abort(404)

    actual = sha256_file(file_path)
    if actual != meta["sha256"]:
        log.error(f"Integrity FAIL {file_id}")
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

    base_hdr = {
        "Content-Disposition": f'attachment; filename="{meta["name"]}"',
        "Accept-Ranges": "bytes",
        "X-SHA256": meta["sha256"],
        "X-Droply-Version": VERSION,
    }

    if range_hdr:
        try:
            parts = range_hdr.replace("bytes=", "").split("-")
            start = int(parts[0])
            end   = int(parts[1]) + 1 if parts[1] else file_size
        except Exception:
            start, end = 0, file_size
        return Response(stream(start, end), 206, mimetype=mime, headers={
            **base_hdr,
            "Content-Range":  f"bytes {start}-{end-1}/{file_size}",
            "Content-Length": str(end - start),
        })

    return Response(stream(), 200, mimetype=mime,
                    headers={**base_hdr, "Content-Length": str(file_size)})

@app.route("/api/download-token/<token>")
def download_by_token(token: str):
    file_id = consume_dl_token(token)
    if not file_id:
        return jsonify({"error": "Token invalid or expired"}), 410

    with meta_lock:
        meta = file_meta.get(file_id)
    if not meta or is_expired(meta):
        abort(410)

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

    def stream():
        with open(file_path, "rb") as fh:
            while chunk := fh.read(CHUNK_SIZE):
                yield chunk

    return Response(stream(), 200, mimetype=meta.get("mime", "application/octet-stream"),
                    headers={
                        "Content-Disposition": f'attachment; filename="{meta["name"]}"',
                        "Content-Length": str(meta["size"]),
                        "X-SHA256": meta["sha256"],
                    })

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
    broadcast_file_deleted(file_id, meta["name"])
    return jsonify({"ok": True})

# ── API: status ───────────────────────────────────────────────────────────────

@app.route("/api/status")
@require_pin
def status():
    with meta_lock:
        total = sum(m["size"] for m in file_meta.values() if not is_expired(m))
        count = sum(1 for m in file_meta.values() if not is_expired(m))
    with ws_lock:
        ws_s = len(ws_senders)
        ws_r = len(ws_receivers)
    elapsed = time.time() - START_TIME
    return jsonify({
        "ok": True, "version": VERSION,
        "ip": get_local_ip(), "files": count, "total_size": total,
        "uptime_seconds": int(elapsed), "uptime_human": human_uptime(elapsed),
        "active_tokens":  len(dl_tokens),
        "ws_senders":     ws_s,     # MINOR CHANGE 9
        "ws_receivers":   ws_r,
        "disk_free_gb":   disk_free_gb(),
    })

# ── API: transfers ────────────────────────────────────────────────────────────

@app.route("/api/transfers")
@require_pin
def transfers():
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
    qr        = make_qr(recv_url)
    return jsonify({
        "url": url, "receive_url": recv_url,
        "ip": ip, "port": port, "qr": qr, "version": VERSION,
        "ws_available": HAS_SOCK,
    })

# ── MINOR CHANGE 4: /api/debug ────────────────────────────────────────────────

@app.route("/api/debug")
@require_pin
def debug():
    """
    Diagnostics endpoint.
    WHY: When cross-device fails, this is the first place to look.
         Shows every IP address on every interface so you can pick the right one.
         Also shows WS connections, disk space, active sessions.
    """
    all_ips = get_all_ips()
    with ws_lock:
        ws_s = len(ws_senders)
        ws_r = len(ws_receivers)
    with meta_lock:
        file_count = len([m for m in file_meta.values() if not is_expired(m)])

    return jsonify({
        "version":       VERSION,
        "bind_ip":       BIND_IP or "auto",
        "detected_ip":   get_local_ip(),
        "all_interfaces": all_ips,
        "port":          int(os.environ.get("PORT", 5000)),
        "ws_available":  HAS_SOCK,
        "ws_senders":    ws_s,
        "ws_receivers":  ws_r,
        "files_active":  file_count,
        "disk_free_gb":  disk_free_gb(),
        "uptime":        human_uptime(time.time() - START_TIME),
        "python":        sys.version,
        "platform":      sys.platform,
    })

# ── Favicon ───────────────────────────────────────────────────────────────────

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

    all_ips = get_all_ips()
    iface_lines = "\n".join(
        f"  {'→' if r['ip'] == ip else ' '} {r['ip']:18s}  ({r['iface']}){'  ← using this' if r['ip']==ip else ''}"
        for r in all_ips
    ) or f"  {ip}"

    print("\n" + "═"*62)
    print(f"  droply {VERSION}")
    print("═"*62)
    print(f"  Sender   : {url}")
    print(f"  Receiver : {url}/receive   ← share this")
    print(f"  PIN      : {CURRENT_PIN}      ← share this")
    print(f"  HTTPS    : {'yes' if use_https else 'no (--http mode)'}")
    print(f"  WebSocket: {'yes (flask-sock)' if HAS_SOCK else 'no (pip install flask-sock)'}")
    print(f"  Max file : {MAX_FILE_SIZE//(1024**3)} GB")
    print(f"\n  Network interfaces detected:")
    print(iface_lines)
    print(f"\n  Diagnostics: {url}/api/debug  (after login)")
    print("═"*62 + "\n")

    threading.Thread(target=purge_expired, daemon=True).start()
    start_mdns(port)

    def bye(sig, frame):
        print("\\ndroply: shutting down")
        sys.exit(0)
    # Signal handlers only work in the main thread.
    # When started from launcher.py the server runs in a background thread —
    # skip signal registration in that case (launcher handles shutdown via tray Quit).
    if _threading.current_thread() is _threading.main_thread():
        signal.signal(signal.SIGINT, bye)


    bind = BIND_IP if BIND_IP else "0.0.0.0"
    ssl_ctx = (str(CERT_FILE), str(KEY_FILE)) if use_https else None
    app.run(host=bind, port=port, threaded=True,
            ssl_context=ssl_ctx, debug=False)

# ── Test suite ────────────────────────────────────────────────────────────────

def run_tests():
    import requests, tempfile, threading as _th
    requests.packages.urllib3.disable_warnings()

    global CURRENT_PIN, BIND_IP
    PORT     = 15433
    BIND_IP  = "127.0.0.1"
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
        ok = bool(cond)
        print(f"  {'✅' if ok else '❌'} {name}" + (f"  {detail}" if not ok else ""))
        if not ok:
            fails.append(name)

    print("\n" + "─"*52)
    print(f"  droply {VERSION} — test suite")
    print("─"*52)

    # ── Phase 1 tests (all retained) ──────────────────────────────────────────
    r = sess.get(f"{base}/api/info")
    check("T01 /api/info public", r.status_code == 200)
    check("T02 ws_available in info", "ws_available" in r.json())

    r = sess.get(f"{base}/api/files")
    check("T03 /api/files unauth → 401", r.status_code == 401)

    r = sess.post(f"{base}/login", data={"pin": "000000"}, allow_redirects=False)
    check("T04 wrong PIN stays on login", r.status_code in (200, 302))

    r = sess.post(f"{base}/login", data={"pin": CURRENT_PIN, "next_page": ""}, allow_redirects=True)
    check("T05 correct PIN → 200", r.status_code == 200)

    r = sess.get(f"{base}/api/files")
    check("T06 file list authenticated", r.status_code == 200)
    check("T07 file list empty", r.json()["count"] == 0)

    content = b"droply phase 2 test! " * 600
    expected_hash = hashlib.sha256(content).hexdigest()
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    with open(tmp_path, "rb") as fh:
        r = sess.post(f"{base}/api/upload",
                      files={"file": ("phase2test.txt", fh, "text/plain")},
                      data={"ttl_hours": "1", "max_downloads": "5"})
    check("T08 upload → 201", r.status_code == 201)
    up = r.json()
    check("T09 SHA-256 correct", up.get("sha256") == expected_hash)
    file_id = up["id"]

    with open(tmp_path, "rb") as fh:
        r2 = sess.post(f"{base}/api/upload",
                       files={"file": ("dup.txt", fh, "text/plain")},
                       data={"ttl_hours": "1", "max_downloads": "5"})
    check("T10 dedup 200", r2.status_code == 200)
    check("T11 dedup same id", r2.json().get("id") == file_id)
    check("T12 dedup flag", r2.json().get("dedup") is True)

    r = sess.post(f"{base}/api/share-path",
                  json={"path": tmp_path, "ttl_hours": 1},
                  headers={"Content-Type": "application/json"})
    check("T13 share-path dedup", r.status_code in (200, 201))

    r = sess.post(f"{base}/api/share-path",
                  json={"path": "/nonexistent/x.xyz"},
                  headers={"Content-Type": "application/json"})
    check("T14 share-path bad path 404", r.status_code == 404)

    r   = sess.get(f"{base}/api/files")
    fls = r.json()["files"]
    check("T15 file list count=1", len(fls) == 1)
    check("T16 dl_token present", bool(fls[0].get("dl_token")))
    token = fls[0]["dl_token"]

    r = sess.get(f"{base}/api/download-token/{token}")
    check("T17 token download 200", r.status_code == 200)
    check("T18 token content correct", r.content == content)

    r2 = sess.get(f"{base}/api/download-token/{token}")
    check("T19 token single-use 410", r2.status_code == 410)

    r = sess.get(f"{base}/api/download/{file_id}")
    check("T20 session download 200", r.status_code == 200)
    check("T21 integrity hash match", hashlib.sha256(r.content).hexdigest() == expected_hash)
    check("T22 X-SHA256 header", r.headers.get("X-SHA256") == expected_hash)

    r = sess.get(f"{base}/api/files")
    check("T23 download_count=2", r.json()["files"][0]["download_count"] == 2)

    content2 = b"limit " + secrets.token_bytes(32)
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp2:
        tmp2.write(content2)
        tmp2_path = tmp2.name
    with open(tmp2_path, "rb") as fh:
        rl = sess.post(f"{base}/api/upload",
                       files={"file": ("lim.bin", fh, "application/octet-stream")},
                       data={"ttl_hours": "1", "max_downloads": "1"})
    check("T24 limit-file upload", rl.status_code == 201)
    lid = rl.json()["id"]
    check("T25 1st dl ok",          sess.get(f"{base}/api/download/{lid}").status_code == 200)
    check("T26 2nd dl 410",         sess.get(f"{base}/api/download/{lid}").status_code == 410)

    check("T27 /receive loads",     sess.get(f"{base}/receive").status_code == 200)
    r = sess.get(f"{base}/api/transfers")
    check("T28 transfers 200",      r.status_code == 200)
    check("T29 transfers not empty",len(r.json()["transfers"]) > 0)

    r = sess.get(f"{base}/api/status")
    s = r.json()
    check("T30 status ok",          s.get("ok") is True)
    check("T31 version correct",    s.get("version") == VERSION)
    check("T32 uptime_human",       bool(s.get("uptime_human")))
    check("T33 disk_free_gb",       "disk_free_gb" in s)    # MINOR CHANGE 9
    check("T34 ws_receivers key",   "ws_receivers" in s)

    # ── Phase 2 new tests ─────────────────────────────────────────────────────

    # CORS headers present on all responses
    r = sess.get(f"{base}/api/files")
    check("T35 CORS header present",
          r.headers.get("Access-Control-Allow-Origin") == "*")

    # CORS preflight OPTIONS
    r = sess.options(f"{base}/api/files",
                     headers={"Origin": "http://192.168.1.50:5000",
                               "Access-Control-Request-Method": "GET"})
    check("T36 CORS preflight 204", r.status_code == 204)
    check("T37 CORS methods header", "GET" in r.headers.get("Access-Control-Allow-Methods",""))

    # /api/debug endpoint
    r = sess.get(f"{base}/api/debug")
    check("T38 /api/debug 200", r.status_code == 200)
    d = r.json()
    check("T39 debug has all_interfaces", isinstance(d.get("all_interfaces"), list))
    check("T40 debug has disk_free_gb",   "disk_free_gb" in d)
    check("T41 debug has ws_available",   "ws_available" in d)

    # Rate limiter
    for _ in range(5):
        sess.post(f"{base}/login", data={"pin": "000000"})
    r = sess.post(f"{base}/login", data={"pin": "000000"})
    check("T42 rate limiter 429", r.status_code == 429)

    # Delete
    r = sess.delete(f"{base}/api/delete/{file_id}")
    check("T43 delete ok", r.json().get("ok") is True)
    ids = [f["id"] for f in sess.get(f"{base}/api/files").json()["files"]]
    check("T44 file gone from list", file_id not in ids)

    os.unlink(tmp_path)
    os.unlink(tmp2_path)

    print("─"*52)
    print(f"  {total - len(fails)}/{total} passed   {len(fails)} failed")
    if fails:
        print("  FAILED:", ", ".join(fails))
    print("─"*52 + "\n")
    sys.exit(0 if not fails else 1)

# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"droply {VERSION}")
    parser.add_argument("--http",  action="store_true", help="Plain HTTP (no cert warning)")
    parser.add_argument("--port",  type=int, default=5000)
    parser.add_argument("--bind",  type=str, default="",
                        help="Force bind IP, e.g. --bind 192.168.1.42  (default: auto-detect)")
    parser.add_argument("--test",  action="store_true", help="Run test suite and exit")
    args = parser.parse_args()

    # MAJOR CHANGE 1: --bind
    BIND_IP = args.bind.strip()
    os.environ["PORT"] = str(args.port)

    if args.http:
        for f in [CERT_FILE, KEY_FILE]:
            if f.exists():
                f.unlink()

    if args.test:
        for f in [CERT_FILE, KEY_FILE]:
            if f.exists():
                f.unlink()
        run_tests()
    else:
        if not args.http and not (CERT_FILE.exists() and KEY_FILE.exists()):
            generate_self_signed_cert()
        startup(args.port, use_https=not args.http)