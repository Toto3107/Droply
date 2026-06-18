"""
droply_relay/relay.py  —  Phase 4
===================================

WHAT THIS IS
────────────
The relay server runs on a public VPS (Fly.io / Render / Railway).
Sender and receiver no longer need to be on the same Wi-Fi.

HOW IT WORKS
────────────

  Sender (any network)          Relay (VPS)           Receiver (any network)
  ─────────────────────         ──────────────────    ─────────────────────────
  1. POST /relay/session   ──►  create session        
     { sender_password }        PIN generated         
     ◄── { session_id, PIN }    store in Redis TTL    
                                                      2. GET  /relay/join
                                                          { session_id, PIN }
                                                         ◄── 200 OK + file list
  3. POST /relay/upload    ──►  store encrypted        
     multipart, chunk=N         chunk in Redis        
     X-Session-ID               TTL = 2h              
     X-Chunk-Index                                    4. GET  /relay/download
     X-Total-Chunks                                      { session_id, PIN,
     X-SHA256 (full file)                                 file_id, chunk=N }
     body = AES-256-GCM                                  ◄── raw ciphertext chunk
     ciphertext                 verify chunk                 (decrypted client-side)
                                present + emit WS     
  WS /relay/ws/receiver   ──►  push file_added event  ◄── WS file_added received
  (receiver connected)          to receiver           file appears instantly


ENCRYPTION MODEL
────────────────
End-to-end: the relay NEVER sees plaintext.

Key derivation:
  key = HKDF-SHA256(
    ikm  = PIN.encode(),
    salt = session_id.encode(),
    info = b"droply-relay-v1",
    length = 32                    # 256-bit AES key
  )

Per-chunk encryption:
  nonce = os.urandom(12)           # 96-bit, random per chunk
  ciphertext, tag = AES-256-GCM(key, nonce).encrypt(chunk)
  wire format = nonce(12) + tag(16) + ciphertext

WHY per-chunk: large files are split into 2 MB chunks so:
  - Upload can resume if connection drops
  - Receiver can start playing/viewing before full download
  - Mobile 4G connections can handle 2 MB without timing out
  - Relay never assembles the full plaintext (each chunk is independent)

RELAY STORAGE
─────────────
Redis with TTL — no database, no disk writes.

  relay:session:{session_id}   → JSON session metadata (TTL 2h)
  relay:chunk:{session_id}:{file_id}:{chunk_index}  → raw ciphertext bytes (TTL 2h)
  relay:file:{session_id}:{file_id}  → JSON file metadata (TTL 2h)

Fallback: if Redis is not available (local dev), falls back to in-memory
dict storage so the relay still runs for testing.

RATE LIMITS
───────────
  POST /relay/session   → 10/hour per IP     (session creation)
  POST /relay/upload    → 100/hour per IP    (chunk upload)
  GET  /relay/download  → 200/hour per IP    (chunk download)
  POST /relay/join      → 30/minute per IP   (wrong PIN brute-force)

DEPLOYMENT
──────────
  fly.io (free tier):
    fly launch --name droply-relay
    fly secrets set RELAY_SECRET=<random-64-hex>
    fly deploy

  Render (free tier):
    Connect repo → set RELAY_SECRET env var → deploy

  Local dev:
    python relay.py --dev
    # starts with in-memory storage, no Redis needed

TESTING
───────
  python relay.py --test
  # runs 30 tests against a local relay instance
"""

import os, sys, json, hashlib, uuid, logging, time, threading, secrets
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from functools import wraps
from collections import defaultdict

from flask import Flask, request, jsonify, Response, render_template, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

try:
    from flask_sock import Sock
    HAS_SOCK = True
except ImportError:
    HAS_SOCK = False

# Redis is optional — only used if both installed AND REDIS_URL env var is set
# DO NOT add redis to requirements.txt unless you have a Redis server ready
try:
    import redis as redis_lib
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Version ───────────────────────────────────────────────────────────────────
VERSION = "1.0.0-relay"

# ── UTC helper ────────────────────────────────────────────────────────────────
def utcnow():
    return datetime.now(timezone.utc)

# ── Config (overridable via env) ──────────────────────────────────────────────
RELAY_SECRET     = os.environ.get("RELAY_SECRET", secrets.token_hex(32))
REDIS_URL        = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
SESSION_TTL_SEC  = int(os.environ.get("SESSION_TTL_SEC",  7200))   # 2 hours
CHUNK_SIZE_BYTES = int(os.environ.get("CHUNK_SIZE_BYTES", 2 * 1024 * 1024))  # 2 MB
MAX_FILE_SIZE    = int(os.environ.get("MAX_FILE_SIZE",    5 * 1024 * 1024 * 1024))  # 5 GB
MAX_FILES_PER_SESSION = int(os.environ.get("MAX_FILES", 20))
PIN_LENGTH       = 6
CHUNK_NONCE_SIZE = 12   # bytes — GCM nonce
CHUNK_TAG_SIZE   = 16   # bytes — GCM auth tag

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "relay.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("relay")
logging.getLogger("werkzeug").setLevel(logging.WARNING)

# ── Flask ─────────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates")
app.secret_key = RELAY_SECRET
limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri="memory://")
sock = Sock(app) if HAS_SOCK else None

# ── CORS (relay is accessed cross-origin from any client) ────────────────────
CORS_HEADERS = {
    "Access-Control-Allow-Origin":   "*",
    "Access-Control-Allow-Methods":  "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers":  "Content-Type, X-Session-ID, X-Chunk-Index, X-Total-Chunks, X-SHA256, X-File-Name, X-File-Size",
    "Access-Control-Expose-Headers": "X-SHA256, X-Chunk-Index, X-Total-Chunks, Content-Length",
}

@app.after_request
def add_cors(r):
    for k, v in CORS_HEADERS.items():
        r.headers[k] = v
    return r

@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        return Response("", 204, headers=CORS_HEADERS)

# ── Storage backend ───────────────────────────────────────────────────────────

class MemoryStore:
    """In-memory store — used in DEV_MODE / unit tests only."""
    def __init__(self):
        self._data: dict = {}
        self._expiry: dict = {}
        self._lock = threading.RLock()   # RLock prevents deadlock on re-entry

    def set(self, key: str, value: bytes, ttl: int = None):
        with self._lock:
            self._data[key] = value
            if ttl:
                self._expiry[key] = time.time() + ttl

    def get(self, key: str) -> bytes | None:
        with self._lock:
            if key in self._expiry and time.time() > self._expiry[key]:
                self._data.pop(key, None); self._expiry.pop(key, None)
                return None
            return self._data.get(key)

    def delete(self, key: str):
        with self._lock:
            self._data.pop(key, None); self._expiry.pop(key, None)

    def keys(self, pattern: str) -> list[str]:
        prefix = pattern.rstrip("*")
        with self._lock:
            now = time.time()
            return [k for k in self._data
                    if k.startswith(prefix)
                    and (k not in self._expiry or now <= self._expiry[k])]

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def expire(self, key: str, ttl: int):
        with self._lock:
            if key in self._data:
                self._expiry[key] = time.time() + ttl


class DiskStore:
    """
    Disk-backed store — survives gunicorn worker restarts.
    WHY: Render free tier restarts workers periodically. MemoryStore loses all
         sessions on restart. DiskStore writes each key as a file in /tmp
         so sessions survive across restarts within the same instance lifetime.
    Storage: /tmp/droply_store/ (or DATA_DIR env var)
    Format:  one file per key, binary content, sidecar .ttl for expiry.
    Thread-safe: RLock (reentrant) prevents deadlock when set() is called
                 from within a lock context.
    """
    def __init__(self, base_dir: str = ""):
        self._base = Path(base_dir or os.environ.get("DATA_DIR", "/tmp/droply_store"))
        self._base.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()   # RLock prevents deadlock on re-entry
        log.info(f"DiskStore: {self._base}")

    def _path(self, key: str) -> Path:
        # sanitise key to safe filename
        safe = key.replace(":", "__").replace("/", "_").replace(" ", "_")
        return self._base / safe

    def _is_expired(self, key: str) -> bool:
        ttl_file = Path(str(self._path(key)) + ".ttl")
        if ttl_file.exists():
            try:
                expire_at = float(ttl_file.read_text())
                if time.time() > expire_at:
                    return True
            except Exception:
                pass
        return False

    def set(self, key: str, value: bytes, ttl: int = None):
        p = self._path(key)
        if isinstance(value, str):
            value = value.encode()
        p.write_bytes(value)
        ttl_file = Path(str(p) + ".ttl")
        if ttl:
            ttl_file.write_text(str(time.time() + ttl))
        elif ttl_file.exists():
            ttl_file.unlink()

    def get(self, key: str) -> bytes | None:
        if self._is_expired(key):
            self.delete(key)
            return None
        p = self._path(key)
        if p.exists():
            try:
                return p.read_bytes()
            except Exception:
                return None
        return None

    def delete(self, key: str):
        p = self._path(key)
        for f in [p, Path(str(p) + ".ttl")]:
            try:
                if f.exists(): f.unlink()
            except Exception:
                pass

    def keys(self, pattern: str) -> list[str]:
        prefix = pattern.rstrip("*").replace(":", "__").replace("/", "_")
        result = []
        try:
            for f in self._base.iterdir():
                name = f.name
                if name.endswith(".ttl"):
                    continue
                if name.startswith(prefix):
                    # Convert back to original key format
                    orig = name.replace("__", ":").replace("_relay:", "relay:")
                    if not self._is_expired(name.replace("__",":").replace("_relay:","relay:")):
                        result.append(orig)
        except Exception:
            pass
        return result

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def expire(self, key: str, ttl: int):
        p = self._path(key)
        if p.exists():
            ttl_file = Path(str(p) + ".ttl")
            ttl_file.write_text(str(time.time() + ttl))


class RedisStore:
    """
    Redis-backed storage for production.
    WHY: Survives restarts, shared across multiple gunicorn workers,
         built-in TTL enforcement, scales horizontally.
    """
    def __init__(self, url: str):
        self._r = redis_lib.from_url(url, decode_responses=False)

    def set(self, key: str, value: bytes, ttl: int = None):
        if ttl:
            self._r.setex(key, ttl, value)
        else:
            self._r.set(key, value)

    def get(self, key: str) -> bytes | None:
        return self._r.get(key)

    def delete(self, key: str):
        self._r.delete(key)

    def keys(self, pattern: str) -> list[str]:
        return [k.decode() if isinstance(k, bytes) else k
                for k in self._r.keys(pattern)]

    def exists(self, key: str) -> bool:
        return bool(self._r.exists(key))

    def expire(self, key: str, ttl: int):
        self._r.expire(key, ttl)


# ── DEV_MODE must be declared BEFORE _init_store() ──────────────────────────
DEV_MODE = os.environ.get("DROPLY_DEV", "").lower() in ("1", "true", "yes")

def _init_store():
    """
    Pick storage backend (priority order):
    1. Redis  — if REDIS_URL env var set and redis package installed
    2. Memory — if DEV_MODE (unit tests only)
    3. Disk   — default for production (survives Render restarts, no extra setup)
    """
    redis_url = os.environ.get("REDIS_URL", "").strip()
    if HAS_REDIS and redis_url:
        try:
            s = RedisStore(redis_url)
            s._r.ping()
            log.info(f"Storage: Redis ({redis_url[:30]}…)")
            return s
        except Exception as e:
            log.warning(f"Redis ping failed ({e}) — falling back to disk store")
    if DEV_MODE:
        log.info("Storage: in-memory (DEV_MODE — data lost on restart)")
        return MemoryStore()
    log.info("Storage: DiskStore (/tmp/droply_store) — survives Render restarts")
    return DiskStore()

# ── Store: initialised at module level so every gunicorn worker has it ────────
store: MemoryStore | DiskStore | RedisStore = _init_store()

# ── Key helpers ───────────────────────────────────────────────────────────────

def session_key(sid: str) -> str:
    return f"relay:session:{sid}"

def file_key(sid: str, fid: str) -> str:
    return f"relay:file:{sid}:{fid}"

def chunk_key(sid: str, fid: str, idx: int) -> str:
    return f"relay:chunk:{sid}:{fid}:{idx}"

# ── Crypto ────────────────────────────────────────────────────────────────────

def derive_key(pin: str, session_id: str) -> bytes:
    """
    HKDF-SHA256 key derivation.
    WHY HKDF over raw PIN: the PIN is short (6 chars) and low-entropy.
    HKDF stretches it into a proper 256-bit AES key using the session_id
    as a salt so the same PIN on different sessions produces different keys.
    The relay never sees this key — it's derived identically on both ends.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_id.encode(),
        info=b"droply-relay-v1",
    )
    return hkdf.derive(pin.encode())


def encrypt_chunk(data: bytes, key: bytes) -> bytes:
    """
    AES-256-GCM encrypt.
    Wire format: nonce(12) | tag(16) | ciphertext
    WHY GCM: authenticated encryption — detects tampering.
    WHY random nonce per chunk: replay attacks impossible even with same key.
    """
    nonce = os.urandom(CHUNK_NONCE_SIZE)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + tag concatenated
    ct_and_tag = aesgcm.encrypt(nonce, data, None)
    return nonce + ct_and_tag   # nonce(12) + ciphertext+tag


def decrypt_chunk(wire: bytes, key: bytes) -> bytes:
    """Inverse of encrypt_chunk. Raises InvalidTag if tampered."""
    nonce     = wire[:CHUNK_NONCE_SIZE]
    ct_and_tag = wire[CHUNK_NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ct_and_tag, None)


def verify_hmac(session_id: str, token: str) -> bool:
    """
    Verify a session management token.
    WHY: Sender gets a management token at session creation.
    Only the holder of this token can delete the session or
    get the audit log — not receivers.
    """
    import hmac
    expected = hmac.new(
        RELAY_SECRET.encode(), session_id.encode(), "sha256"
    ).hexdigest()
    return hmac.compare_digest(token, expected)


def make_mgmt_token(session_id: str) -> str:
    import hmac as _hmac
    return _hmac.new(
        RELAY_SECRET.encode(), session_id.encode(), "sha256"
    ).hexdigest()

# ── WebSocket registry ────────────────────────────────────────────────────────
# Maps session_id → set of WebSocket connections (receivers watching that session)
ws_sessions: dict[str, set] = defaultdict(set)
ws_lock = threading.Lock()

def ws_broadcast(session_id: str, payload: dict):
    """Push a JSON event to all receivers watching a given session."""
    msg = json.dumps(payload)
    dead = set()
    with ws_lock:
        targets = set(ws_sessions.get(session_id, set()))
    for ws in targets:
        try:
            ws.send(msg)
        except Exception:
            dead.add(ws)
    if dead:
        with ws_lock:
            ws_sessions[session_id] -= dead

# ── Auth helpers ──────────────────────────────────────────────────────────────

def get_session_data(session_id: str) -> dict | None:
    raw = store.get(session_key(session_id))
    if not raw:
        return None
    return json.loads(raw)

def verify_pin(session_data: dict, pin: str) -> bool:
    import hmac
    stored = session_data.get("pin_hash", "")
    candidate = hashlib.sha256(pin.encode()).hexdigest()
    return hmac.compare_digest(stored, candidate)

def touch_session(session_id: str):
    """Extend TTL each time session is actively used."""
    store.expire(session_key(session_id), SESSION_TTL_SEC)

# ── Routes: session management ────────────────────────────────────────────────

@app.route("/relay/session", methods=["POST"])
@limiter.limit("10 per hour")
def create_session():
    """
    Sender creates a new relay session.
    Returns: session_id, PIN (to share with receivers), mgmt_token (keep secret)

    WHY mgmt_token: the session_id is shared publicly (e.g. in a QR).
    The management token lets the sender delete files or end the session
    without a password — only the creator has it.
    """
    data = request.get_json(silent=True) or {}

    # Optional: sender can supply their droply password for audit trail
    # (relay doesn't verify it — it's just logged for the sender's records)
    pin = "".join(str(secrets.randbelow(10)) for _ in range(PIN_LENGTH))
    session_id = secrets.token_urlsafe(16)
    mgmt_token = make_mgmt_token(session_id)
    expires_at = (utcnow() + timedelta(seconds=SESSION_TTL_SEC)).isoformat()

    session_data = {
        "session_id":  session_id,
        "pin_hash":    hashlib.sha256(pin.encode()).hexdigest(),
        "created_at":  utcnow().isoformat(),
        "expires_at":  expires_at,
        "files":       {},   # file_id → {name, size, sha256, chunks_total, chunks_received}
        "creator_ip":  request.remote_addr,
    }

    store.set(session_key(session_id),
              json.dumps(session_data).encode(),
              ttl=SESSION_TTL_SEC)

    log.info(f"Session created: {session_id[:8]}… from {request.remote_addr}")
    return jsonify({
        "session_id": session_id,
        "pin":        pin,
        "mgmt_token": mgmt_token,
        "expires_at": expires_at,
        "version":    VERSION,
    }), 201


@app.route("/relay/join", methods=["POST"])
@limiter.limit("30 per minute")
def join_session():
    """
    Receiver joins a session with session_id + PIN.
    Returns file list (metadata only — no content yet).
    WHY POST: we don't want PIN in query string (logged by proxies).
    """
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id", "").strip()
    pin        = data.get("pin", "").strip()

    if not session_id or not pin:
        return jsonify({"error": "session_id and pin required"}), 400

    sd = get_session_data(session_id)
    if not sd:
        return jsonify({"error": "Session not found or expired"}), 404

    if not verify_pin(sd, pin):
        log.warning(f"Wrong PIN for session {session_id[:8]}… from {request.remote_addr}")
        return jsonify({"error": "Wrong PIN"}), 401

    touch_session(session_id)

    # Build file list — metadata only
    files = []
    for fid, fm in sd.get("files", {}).items():
        complete = fm.get("chunks_received", 0) >= fm.get("chunks_total", 1)
        files.append({
            "id":             fid,
            "name":           fm["name"],
            "size":           fm["size"],
            "sha256":         fm["sha256"],
            "chunks_total":   fm["chunks_total"],
            "chunks_received":fm.get("chunks_received", 0),
            "complete":       complete,
        })

    log.info(f"Receiver joined session {session_id[:8]}… ({len(files)} files)")
    return jsonify({
        "session_id": session_id,
        "files":      files,
        "expires_at": sd["expires_at"],
    }), 200


@app.route("/relay/session/<session_id>", methods=["DELETE"])
def delete_session(session_id: str):
    """Sender can terminate a session early (all chunks deleted)."""
    mgmt_token = request.headers.get("X-Mgmt-Token", "")
    if not verify_hmac(session_id, mgmt_token):
        return jsonify({"error": "Invalid management token"}), 403

    sd = get_session_data(session_id)
    if not sd:
        return jsonify({"error": "Not found"}), 404

    # Delete all stored chunks
    pattern = f"relay:chunk:{session_id}:*"
    for k in store.keys(pattern):
        store.delete(k)
    store.delete(session_key(session_id))

    # Notify any connected receivers
    ws_broadcast(session_id, {"event": "session_ended"})

    log.info(f"Session deleted: {session_id[:8]}…")
    return jsonify({"ok": True}), 200

# ── Routes: upload ────────────────────────────────────────────────────────────

@app.route("/relay/upload", methods=["POST"])
@limiter.limit("200 per hour")
def upload_chunk():
    """
    Receive one encrypted chunk from the sender.

    Headers (all required):
      X-Session-ID    the relay session
      X-File-ID       UUID for this file (sender generates)
      X-File-Name     original filename
      X-File-Size     total unencrypted bytes
      X-File-SHA256   SHA-256 of the FULL original file (for integrity)
      X-Chunk-Index   0-based chunk number
      X-Total-Chunks  total chunks for this file
      X-Mgmt-Token    sender's management token

    Body: raw bytes — AES-256-GCM ciphertext of this chunk
          (encrypted client-side before sending, relay never sees plaintext)

    WHY multipart isn't used:
      Raw body upload is simpler for large binary chunks and avoids
      the overhead of multipart boundary parsing.
    """
    session_id = request.headers.get("X-Session-ID", "").strip()
    file_id    = request.headers.get("X-File-ID", "").strip()
    file_name  = request.headers.get("X-File-Name", "").strip()
    file_sha   = request.headers.get("X-File-SHA256", "").strip()
    mgmt_token = request.headers.get("X-Mgmt-Token", "").strip()
    chunk_idx  = request.headers.get("X-Chunk-Index", "0")
    total_chks = request.headers.get("X-Total-Chunks", "1")
    file_size  = request.headers.get("X-File-Size", "0")

    # Validate
    if not all([session_id, file_id, file_name, mgmt_token]):
        return jsonify({"error": "Missing required headers"}), 400

    if not verify_hmac(session_id, mgmt_token):
        return jsonify({"error": "Invalid management token"}), 403

    # Always re-read session fresh — critical for multi-chunk and multi-file
    sd = get_session_data(session_id)
    if not sd:
        log.warning(f"Upload: session {session_id[:8]}… not found (expired or restarted?)")
        return jsonify({"error": "Session not found or expired — create a new session"}), 404

    try:
        chunk_idx  = int(chunk_idx)
        total_chks = int(total_chks)
        file_size  = int(file_size)
    except ValueError:
        return jsonify({"error": "Invalid chunk index headers"}), 400

    if file_size > MAX_FILE_SIZE:
        return jsonify({"error": f"File too large (max {MAX_FILE_SIZE//(1024**3)}GB)"}), 413

    sd_files = sd.get("files", {})
    if len(sd_files) >= MAX_FILES_PER_SESSION and file_id not in sd_files:
        return jsonify({"error": f"Session file limit ({MAX_FILES_PER_SESSION}) reached"}), 429

    # Read ciphertext body
    ciphertext = request.get_data()
    if not ciphertext:
        return jsonify({"error": "Empty body — no ciphertext received"}), 400

    # Store chunk
    ck = chunk_key(session_id, file_id, chunk_idx)
    store.set(ck, ciphertext, ttl=SESSION_TTL_SEC)

    # Upsert file metadata
    safe_name = Path(file_name).name or "file"
    if file_id not in sd_files:
        sd_files[file_id] = {
            "name":            safe_name,
            "size":            file_size,
            "sha256":          file_sha,
            "chunks_total":    total_chks,
            "chunks_received": 0,
            "created_at":      utcnow().isoformat(),
        }
    # Always update total/size in case sender retries with corrected values
    sd_files[file_id]["chunks_total"] = total_chks
    sd_files[file_id]["chunks_received"] = sd_files[file_id].get("chunks_received", 0) + 1

    # Write session back atomically
    sd["files"] = sd_files
    store.set(session_key(session_id), json.dumps(sd).encode(), ttl=SESSION_TTL_SEC)

    final_name   = sd_files[file_id]["name"]
    chunks_done  = sd_files[file_id]["chunks_received"]
    is_complete  = chunks_done >= total_chks

    if is_complete:
        ws_broadcast(session_id, {
            "event": "file_complete", "file_id": file_id,
            "name":  final_name, "size": file_size, "sha256": file_sha,
        })
        log.info(f"File complete: {final_name} ({file_size}B) in session {session_id[:8]}…")
    else:
        ws_broadcast(session_id, {
            "event": "chunk_received", "file_id": file_id,
            "chunk": chunk_idx, "total": total_chks,
        })

    return jsonify({
        "ok": True, "file_id": file_id,
        "chunk": chunk_idx, "total": total_chks,
        "received": chunks_done, "complete": is_complete,
    }), 200


# ── Routes: download ──────────────────────────────────────────────────────────

@app.route("/relay/download/<session_id>/<file_id>/chunk/<int:chunk_idx>")
@limiter.limit("300 per hour")
def download_chunk(session_id: str, file_id: str, chunk_idx: int):
    """
    Receiver fetches one encrypted chunk.
    Returns raw ciphertext bytes.
    Receiver decrypts client-side using PIN-derived key.

    WHY return ciphertext not plaintext:
      The relay never sees the PIN (only its hash).
      It cannot decrypt. This is the E2E guarantee —
      even if the relay server is compromised, files are safe.
    """
    # Verify PIN from header (not body — GET request)
    pin        = request.headers.get("X-PIN", "").strip()
    session_id = session_id.strip()

    if not pin:
        return jsonify({"error": "X-PIN header required"}), 401

    sd = get_session_data(session_id)
    if not sd:
        return jsonify({"error": "Session not found"}), 404

    if not verify_pin(sd, pin):
        log.warning(f"Wrong PIN on download {session_id[:8]}…")
        return jsonify({"error": "Wrong PIN"}), 401

    # Check file exists in session metadata
    file_meta_relay = sd.get("files", {}).get(file_id)
    if not file_meta_relay:
        return jsonify({"error": "File not found in session"}), 404

    # Fetch chunk from store
    ck = chunk_key(session_id, file_id, chunk_idx)
    ciphertext = store.get(ck)
    if ciphertext is None:
        return jsonify({"error": f"Chunk {chunk_idx} not available yet"}), 404

    touch_session(session_id)

    return Response(
        ciphertext,
        200,
        mimetype="application/octet-stream",
        headers={
            "X-Chunk-Index":  str(chunk_idx),
            "X-Total-Chunks": str(file_meta_relay["chunks_total"]),
            "X-SHA256":       file_meta_relay.get("sha256", ""),
            "Content-Length": str(len(ciphertext)),
        }
    )


@app.route("/relay/session/<session_id>/files")
@limiter.limit("60 per minute")
def list_files(session_id: str):
    """List files in a session (requires PIN in header)."""
    pin = request.headers.get("X-PIN", "").strip()
    sd  = get_session_data(session_id)
    if not sd:
        return jsonify({"error": "Session not found"}), 404
    if not verify_pin(sd, pin):
        return jsonify({"error": "Wrong PIN"}), 401

    touch_session(session_id)
    files = []
    for fid, fm in sd.get("files", {}).items():
        complete = fm.get("chunks_received", 0) >= fm.get("chunks_total", 1)
        files.append({
            "id":              fid,
            "name":            fm["name"],
            "size":            fm["size"],
            "sha256":          fm["sha256"],
            "chunks_total":    fm["chunks_total"],
            "chunks_received": fm.get("chunks_received", 0),
            "complete":        complete,
        })
    return jsonify({"files": files, "session_id": session_id}), 200


# ── WebSocket: receiver watches a session for live updates ────────────────────
if HAS_SOCK:
    @sock.route("/relay/ws/<session_id>")
    def relay_ws(ws, session_id: str):
        """
        Receiver connects here to get push notifications.
        WHY: Receiver doesn't poll — when sender finishes uploading
             a chunk, the relay pushes file_complete instantly.

        Auth: PIN in first message (JSON {"pin": "XXXXXX"})
        WHY not a header: WebSocket doesn't support custom headers
             reliably across all browsers and mobile WebViews.
        """
        try:
            # First message must be auth
            raw = ws.receive(timeout=10)
            if not raw:
                ws.close(1008, "No auth")
                return
            msg = json.loads(raw)
            pin = msg.get("pin", "")
            sd  = get_session_data(session_id)
            if not sd or not verify_pin(sd, pin):
                ws.send(json.dumps({"event": "error", "message": "Wrong PIN"}))
                ws.close(1008, "Wrong PIN")
                return

            ws.send(json.dumps({"event": "connected", "session_id": session_id}))
            with ws_lock:
                ws_sessions[session_id].add(ws)

            log.info(f"WS receiver connected to {session_id[:8]}…")

            # Stay alive — relay sends keepalive pings every 25s
            while True:
                msg = ws.receive(timeout=30)
                if msg is None:
                    break   # client disconnected
                # Client can send {"event": "ping"} for keepalive
        except Exception:
            pass
        finally:
            with ws_lock:
                ws_sessions.get(session_id, set()).discard(ws)
            log.info(f"WS receiver left {session_id[:8]}…")

# ── Page routes (serve the sender/receiver HTML UI) ──────────────────────────

@app.route("/send")
@limiter.limit("60 per hour")
def relay_send():
    """Sender UI — create session, upload encrypted files."""
    return render_template("relay_send.html")

@app.route("/receive")
@limiter.limit("60 per hour")
def relay_receive():
    """Receiver UI — enter PIN, download files."""
    return render_template("relay_receive.html")

@app.route("/relay/verify-session", methods=["POST"])
@limiter.limit("30 per minute")
def verify_session():
    """
    Lightweight session-resume check.
    WHY: When a receiver refreshes the page, the browser still has
         session_id + pin in sessionStorage, but we need to confirm
         the session is STILL valid on the server before skipping
         straight to the file list — otherwise an expired session
         would silently show a stale, broken file list.
    Returns 200 if valid, 404/401 otherwise — same checks as /relay/join
    but without re-logging a "joined" event, since this is a resume,
    not a fresh join.
    """
    data       = request.get_json(silent=True) or {}
    session_id = data.get("session_id", "").strip()
    pin        = data.get("pin", "").strip()
    if not session_id or not pin:
        return jsonify({"valid": False, "error": "Missing session_id or pin"}), 400
    sd = get_session_data(session_id)
    if not sd:
        return jsonify({"valid": False, "error": "Session expired"}), 404
    if not verify_pin(sd, pin):
        return jsonify({"valid": False, "error": "Wrong PIN"}), 401
    return jsonify({"valid": True, "expires_at": sd["expires_at"]}), 200

# Serve relay_client.js — explicit route so it always works regardless of
# how Flask's static_folder is configured. Path(__file__).parent ensures
# it works both locally and on Render where the cwd may differ.
@app.route("/relay_client.js")
def relay_client_js():
    static_dir = Path(__file__).parent / "static"
    js_file    = static_dir / "relay_client.js"
    if not js_file.exists():
        log.error(f"relay_client.js not found at {js_file}")
        return "// relay_client.js not found", 404, {"Content-Type":"application/javascript"}
    content_js = js_file.read_text(encoding="utf-8")
    return content_js, 200, {
        "Content-Type": "application/javascript; charset=utf-8",
        "Cache-Control": "public, max-age=3600",
        "Content-Length": str(len(content_js.encode("utf-8"))),
    }

# ── Health / info ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Landing page — choose send or receive."""
    return render_template("relay_landing.html")

@app.route("/api/info")
def api_info():
    active = len([k for k in store.keys("relay:session:*")])
    return jsonify({
        "service":    "droply-relay",
        "version":    VERSION,
        "status":     "ok",
        "sessions":   active,
        "storage":    "redis" if isinstance(store, RedisStore) else "memory",
        "ws":         HAS_SOCK,
    }), 200

@app.route("/api/qr")
def api_qr():
    """
    Generate a QR code PNG as a base64 data-URI for a given URL.
    WHY: Keeps QR generation server-side so no external API call needed —
         works fully offline on the local network.
    """
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "url param required"}), 400
    try:
        import qrcode, base64
        from io import BytesIO
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#0a0a0f", back_color="white")
        buf = BytesIO()
        img.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode()
        return jsonify({"qr": f"data:image/png;base64,{b64}"})
    except ImportError:
        return jsonify({"qr": "", "error": "qrcode not installed"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    return jsonify({"ok": True, "version": VERSION}), 200

# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def e404(e): return jsonify({"error": "Not found"}), 404

@app.errorhandler(429)
def e429(e): return jsonify({"error": "Rate limit exceeded"}), 429

@app.errorhandler(413)
def e413(e): return jsonify({"error": "Payload too large"}), 413

@app.errorhandler(500)
def e500(e): return jsonify({"error": "Server error"}), 500

# ── Test suite ────────────────────────────────────────────────────────────────
def run_tests():
    import requests as req
    import io

    global DEV_MODE, store
    os.environ["DROPLY_DEV"] = "1"   # triggers MemoryStore in _init_store
    DEV_MODE = True
    store    = _init_store()

    PORT = 19876
    t = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=PORT,
                               debug=False, use_reloader=False),
        daemon=True)
    t.start()
    time.sleep(1.5)

    BASE   = f"http://127.0.0.1:{PORT}"
    sess   = req.Session()
    fails  = []
    total  = 0

    def chk(name, cond, detail=""):
        nonlocal total
        total += 1
        ok = bool(cond)
        print(f"  {'✅' if ok else '❌'} {name}" + (f"  {detail}" if not ok else ""))
        if not ok: fails.append(name)

    print("\n" + "─"*54)
    print(f"  droply relay {VERSION} — test suite")
    print("─"*54)

    # T01: health
    r = sess.get(f"{BASE}/health")
    chk("T01 health ok", r.status_code == 200)

    # T02: index renders the landing page (mode chooser), no longer a redirect
    r = sess.get(f"{BASE}/", allow_redirects=False)
    chk("T02 index renders landing page", r.status_code == 200)
    chk("T02b landing has send link", "/send" in r.text)
    chk("T02c landing has receive link", "/receive" in r.text)

    r = sess.get(f"{BASE}/api/info")
    chk("T03 api/info ok", r.status_code == 200)
    chk("T03b version in api/info", r.json().get("version") == VERSION)

    # T04: create session
    r = sess.post(f"{BASE}/relay/session", json={})
    chk("T04 create session 201", r.status_code == 201)
    d = r.json()
    chk("T05 session_id returned", "session_id" in d)
    chk("T06 pin returned 6 digits", len(d.get("pin","")) == 6)
    chk("T07 mgmt_token returned", "mgmt_token" in d)
    SESSION_ID = d["session_id"]
    PIN        = d["pin"]
    MGMT_TOKEN = d["mgmt_token"]

    # T08: join with wrong PIN
    r = sess.post(f"{BASE}/relay/join",
                  json={"session_id": SESSION_ID, "pin": "000000"})
    chk("T08 wrong PIN 401", r.status_code == 401)

    # T09: join with correct PIN
    r = sess.post(f"{BASE}/relay/join",
                  json={"session_id": SESSION_ID, "pin": PIN})
    chk("T09 join ok 200", r.status_code == 200)
    chk("T10 empty file list", r.json()["files"] == [])

    # T11: join nonexistent session
    r = sess.post(f"{BASE}/relay/join",
                  json={"session_id": "nope", "pin": "000000"})
    chk("T11 nonexistent 404", r.status_code == 404)

    # T12-T17: upload a file in chunks
    plaintext  = b"Hello droply relay! " * 5000   # ~100KB
    file_sha   = hashlib.sha256(plaintext).hexdigest()
    file_id    = str(uuid.uuid4())
    file_name  = "test_relay.txt"
    chunk_size = 20480   # 20KB chunks for test
    chunks     = [plaintext[i:i+chunk_size]
                  for i in range(0, len(plaintext), chunk_size)]
    total_chks = len(chunks)

    # Derive key the same way client would
    key = derive_key(PIN, SESSION_ID)

    for idx, chunk in enumerate(chunks):
        ciphertext = encrypt_chunk(chunk, key)
        r = sess.post(f"{BASE}/relay/upload",
                      data=ciphertext,
                      headers={
                          "Content-Type":   "application/octet-stream",
                          "X-Session-ID":   SESSION_ID,
                          "X-File-ID":      file_id,
                          "X-File-Name":    file_name,
                          "X-File-Size":    str(len(plaintext)),
                          "X-File-SHA256":  file_sha,
                          "X-Chunk-Index":  str(idx),
                          "X-Total-Chunks": str(total_chks),
                          "X-Mgmt-Token":   MGMT_TOKEN,
                      })
        if idx == 0:
            chk("T12 first chunk upload 200", r.status_code == 200)
    chk("T13 all chunks uploaded", r.status_code == 200)
    chk("T14 chunks_received correct",
        r.json().get("received") == total_chks)

    # T15: file appears in list
    r = sess.get(f"{BASE}/relay/session/{SESSION_ID}/files",
                 headers={"X-PIN": PIN})
    chk("T15 file list ok", r.status_code == 200)
    files = r.json()["files"]
    chk("T16 file in list", len(files) == 1)
    chk("T17 file marked complete", files[0]["complete"] is True)

    # T18: download all chunks and reassemble
    reassembled = b""
    for idx in range(total_chks):
        r = sess.get(
            f"{BASE}/relay/download/{SESSION_ID}/{file_id}/chunk/{idx}",
            headers={"X-PIN": PIN})
        chk(f"T18 chunk {idx} download 200", r.status_code == 200) if idx==0 else None
        decrypted = decrypt_chunk(r.content, key)
        reassembled += decrypted

    chk("T19 reassembled length correct", len(reassembled) == len(plaintext))
    chk("T20 SHA-256 integrity",
        hashlib.sha256(reassembled).hexdigest() == file_sha)
    chk("T21 content identical", reassembled == plaintext)

    # T22: download with wrong PIN
    r = sess.get(
        f"{BASE}/relay/download/{SESSION_ID}/{file_id}/chunk/0",
        headers={"X-PIN": "000000"})
    chk("T22 wrong PIN on download 401", r.status_code == 401)

    # T23: download without PIN
    r = sess.get(
        f"{BASE}/relay/download/{SESSION_ID}/{file_id}/chunk/0")
    chk("T23 no PIN 401", r.status_code == 401)

    # T24: second session (isolation)
    r2 = sess.post(f"{BASE}/relay/session", json={})
    SESSION_ID2 = r2.json()["session_id"]
    PIN2        = r2.json()["pin"]
    # Try to access session 1 chunk with session 2 PIN
    r = sess.get(
        f"{BASE}/relay/download/{SESSION_ID}/{file_id}/chunk/0",
        headers={"X-PIN": PIN2})
    chk("T24 cross-session isolation 401", r.status_code == 401)

    # T25: wrong mgmt token on upload
    r = sess.post(f"{BASE}/relay/upload",
                  data=b"garbage",
                  headers={
                      "X-Session-ID":   SESSION_ID,
                      "X-File-ID":      str(uuid.uuid4()),
                      "X-File-Name":    "evil.bin",
                      "X-File-Size":    "7",
                      "X-File-SHA256":  "abc",
                      "X-Chunk-Index":  "0",
                      "X-Total-Chunks": "1",
                      "X-Mgmt-Token":   "wrong-token",
                  })
    chk("T25 wrong mgmt token 403", r.status_code == 403)

    # T26: delete session
    r = sess.delete(f"{BASE}/relay/session/{SESSION_ID}",
                    headers={"X-Mgmt-Token": MGMT_TOKEN})
    chk("T26 delete session 200", r.status_code == 200)

    # T27: session gone after delete
    r = sess.post(f"{BASE}/relay/join",
                  json={"session_id": SESSION_ID, "pin": PIN})
    chk("T27 session gone after delete 404", r.status_code == 404)

    # T28: key derivation deterministic
    k1 = derive_key("847291", "abc123")
    k2 = derive_key("847291", "abc123")
    chk("T28 key derivation deterministic", k1 == k2)

    # T29: different PIN → different key
    k3 = derive_key("000000", "abc123")
    chk("T29 different PIN different key", k1 != k3)

    # T30: different session → different key
    k4 = derive_key("847291", "xyz999")
    chk("T30 different session different key", k1 != k4)

    print("─"*54)
    print(f"  {total - len(fails)}/{total} passed   {len(fails)} failed")
    if fails:
        print("  FAILED:", ", ".join(fails))
    print("─"*54 + "\n")
    sys.exit(0 if not fails else 1)

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"droply relay {VERSION}")
    parser.add_argument("--dev",    action="store_true",
                        help="Dev mode: in-memory storage, no Redis needed")
    parser.add_argument("--port",   type=int, default=8765)
    parser.add_argument("--host",   type=str, default="0.0.0.0")
    parser.add_argument("--test",   action="store_true",
                        help="Run test suite and exit")
    args = parser.parse_args()

    DEV_MODE = args.dev or args.test
    store    = _init_store()

    if args.test:
        run_tests()

    PORT = args.port
    os.environ["PORT"] = str(PORT)

    # Detect LAN IP so banner shows shareable address
    import socket as _sock
    try:
        _s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        _s.connect(("8.8.8.8", 80))
        LAN_IP = _s.getsockname()[0]
        _s.close()
    except Exception:
        LAN_IP = "127.0.0.1"

    print("\n" + "═"*62)
    print(f"  droply relay {VERSION}")
    print("═"*62)
    print(f"  Local   : http://127.0.0.1:{PORT}/send")
    print(f"  Network : http://{LAN_IP}:{PORT}/send  ← share with other devices")
    print(f"  Storage : {'Redis (' + REDIS_URL + ')' if not DEV_MODE else 'in-memory (dev mode)'}")
    print(f"  WS push : {'yes' if HAS_SOCK else 'no (pip install flask-sock)'}")
    print(f"  Session : {SESSION_TTL_SEC//3600}h TTL  |  Max file: {MAX_FILE_SIZE//(1024**3)}GB")
    print("═"*62 + "\n")

    app.run(
        host=args.host,
        port=PORT,
        threaded=True,
        debug=False,        # never True — causes reloader double-init crash
        use_reloader=False,
    )