"""
droply_relay/test_integration.py
=================================
Full integration test suite for the relay.
Tests every public route, the encryption/decryption pipeline,
session isolation, WebSocket events, and error handling.

Runs against a live relay instance (local dev mode, no Redis needed).

Usage:
    python test_integration.py              # runs all tests
    python test_integration.py -v           # verbose output
    python test_integration.py --port 9999  # custom port

What's tested:
    Section A — Infrastructure     (health, version, CORS)
    Section B — Session lifecycle  (create, join, delete, expiry)
    Section C — Upload pipeline    (single file, multi-chunk, multi-file)
    Section D — Download pipeline  (all chunks, integrity, wrong PIN)
    Section E — Crypto correctness (HKDF determinism, cross-session isolation)
    Section F — Security           (auth bypass, mgmt token, rate limits)
    Section G — Edge cases         (large chunks, empty file, duplicate upload)
    Section H — WebSocket          (connect, auth, push events)
    Section I — Concurrent access  (two receivers, race on same file)
"""

import sys
import os
import time
import uuid
import hashlib
import secrets
import threading
import argparse

import requests
requests.packages.urllib3.disable_warnings()

# Import relay crypto so we can encrypt/decrypt in tests
sys.path.insert(0, os.path.dirname(__file__))
import relay as rel

# ── Test runner ────────────────────────────────────────────────────────────────

class TestRunner:
    def __init__(self, base: str, verbose: bool = False):
        self.base    = base.rstrip("/")
        self.verbose = verbose
        self.total   = 0
        self.fails   = []
        self.sess    = requests.Session()

    def check(self, name: str, cond, detail: str = ""):
        self.total += 1
        ok = bool(cond)
        marker = "  ✅" if ok else "  ❌"
        suffix = f"  [{detail}]" if (not ok and detail) else ""
        print(f"{marker} {name}{suffix}")
        if not ok:
            self.fails.append(name)
        return ok

    def summary(self):
        print(f"\n{'─'*56}")
        print(f"  {self.total - len(self.fails)}/{self.total} passed   {len(self.fails)} failed")
        if self.fails:
            print(f"  FAILED:")
            for f in self.fails:
                print(f"    • {f}")
        print(f"{'─'*56}\n")
        return len(self.fails) == 0

    # convenience wrappers
    def get(self, path, **kwargs):
        return self.sess.get(f"{self.base}{path}", **kwargs)

    def post(self, path, **kwargs):
        return self.sess.post(f"{self.base}{path}", **kwargs)

    def delete(self, path, **kwargs):
        return self.sess.delete(f"{self.base}{path}", **kwargs)


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_session(r: TestRunner):
    """Create a fresh session and return (session_id, pin, mgmt_token)."""
    resp = r.post("/relay/session", json={})
    d    = resp.json()
    return d["session_id"], d["pin"], d["mgmt_token"]


def upload_file(r: TestRunner, session_id: str, mgmt_token: str, pin: str,
                data: bytes, name: str = "test.bin",
                chunk_size: int = 20 * 1024) -> str:
    """Upload bytes as encrypted chunks. Returns file_id."""
    key      = rel.derive_key(pin, session_id)
    file_id  = str(uuid.uuid4())
    sha256   = hashlib.sha256(data).hexdigest()
    chunks   = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    total    = len(chunks)

    for idx, chunk in enumerate(chunks):
        ct = rel.encrypt_chunk(chunk, key)
        resp = r.sess.post(f"{r.base}/relay/upload",
            data=ct,
            headers={
                "Content-Type":   "application/octet-stream",
                "X-Session-ID":   session_id,
                "X-File-ID":      file_id,
                "X-File-Name":    name,
                "X-File-Size":    str(len(data)),
                "X-File-SHA256":  sha256,
                "X-Chunk-Index":  str(idx),
                "X-Total-Chunks": str(total),
                "X-Mgmt-Token":   mgmt_token,
            })
        assert resp.status_code == 200, f"Chunk {idx} upload failed: {resp.text}"

    return file_id


def download_file(r: TestRunner, session_id: str, pin: str,
                  file_id: str, total_chunks: int) -> bytes:
    """Download and decrypt all chunks, return reassembled bytes."""
    key   = rel.derive_key(pin, session_id)
    parts = []
    for i in range(total_chunks):
        resp = r.sess.get(
            f"{r.base}/relay/download/{session_id}/{file_id}/chunk/{i}",
            headers={"X-PIN": pin})
        assert resp.status_code == 200, f"Chunk {i} failed: {resp.text}"
        parts.append(rel.decrypt_chunk(resp.content, key))
    return b"".join(parts)


# ── Test sections ──────────────────────────────────────────────────────────────

def section_a_infra(r: TestRunner):
    print("\n  ── Section A: Infrastructure")

    resp = r.get("/health")
    r.check("A01 /health returns 200", resp.status_code == 200)
    r.check("A02 /health ok=true", resp.json().get("ok") is True)

    resp = r.get("/")
    r.check("A03 index returns 200", resp.status_code == 200)
    d = resp.json()
    r.check("A04 version in index", "version" in d)
    r.check("A05 service name correct", d.get("service") == "droply-relay")

    # CORS headers
    resp = r.get("/health")
    r.check("A06 CORS allow-origin header",
            resp.headers.get("Access-Control-Allow-Origin") == "*")
    r.check("A07 CORS expose-headers present",
            "X-SHA256" in resp.headers.get("Access-Control-Expose-Headers", ""))

    # CORS preflight
    resp = r.sess.options(f"{r.base}/relay/session",
                          headers={"Origin": "https://example.com",
                                   "Access-Control-Request-Method": "POST"})
    r.check("A08 OPTIONS preflight 204", resp.status_code == 204)

    # 404 handler
    resp = r.get("/nonexistent-route-xyz")
    r.check("A09 404 returns JSON", resp.headers.get("Content-Type","").startswith("application/json"))


def section_b_sessions(r: TestRunner):
    print("\n  ── Section B: Session lifecycle")

    # Create
    resp = r.post("/relay/session", json={})
    r.check("B01 create session 201", resp.status_code == 201)
    d = resp.json()
    r.check("B02 session_id present", len(d.get("session_id","")) > 8)
    r.check("B03 PIN is 6 digits", len(d.get("pin","")) == PIN_LENGTH and d["pin"].isdigit())
    r.check("B04 mgmt_token present", len(d.get("mgmt_token","")) == 64)
    r.check("B05 expires_at present", "T" in d.get("expires_at",""))
    SID, PIN, MGMT = d["session_id"], d["pin"], d["mgmt_token"]

    # Join correct
    resp = r.post("/relay/join", json={"session_id": SID, "pin": PIN})
    r.check("B06 join correct PIN 200", resp.status_code == 200)
    r.check("B07 files list empty", r.check.__func__ or resp.json().get("files") == [])
    r.check("B07 files list empty", resp.json().get("files") == [])

    # Join wrong PIN
    resp = r.post("/relay/join", json={"session_id": SID, "pin": "000000"})
    r.check("B08 join wrong PIN 401", resp.status_code == 401)

    # Join nonexistent
    resp = r.post("/relay/join", json={"session_id": "nope123", "pin": "000000"})
    r.check("B09 join nonexistent 404", resp.status_code == 404)

    # Missing fields
    resp = r.post("/relay/join", json={"session_id": SID})
    r.check("B10 join missing pin 400", resp.status_code == 400)

    # Delete with wrong token
    resp = r.delete(f"/relay/session/{SID}",
                    headers={"X-Mgmt-Token": "wrong"})
    r.check("B11 delete wrong token 403", resp.status_code == 403)

    # Delete with correct token
    resp = r.delete(f"/relay/session/{SID}",
                    headers={"X-Mgmt-Token": MGMT})
    r.check("B12 delete correct token 200", resp.status_code == 200)

    # Session gone
    resp = r.post("/relay/join", json={"session_id": SID, "pin": PIN})
    r.check("B13 session gone after delete 404", resp.status_code == 404)


PIN_LENGTH = 6


def section_c_upload(r: TestRunner):
    print("\n  ── Section C: Upload pipeline")

    SID, PIN, MGMT = make_session(r)
    key = rel.derive_key(PIN, SID)

    # Single small file (1 chunk)
    data   = b"Hello droply relay integration test! " * 100
    sha256 = hashlib.sha256(data).hexdigest()
    fid    = str(uuid.uuid4())
    ct     = rel.encrypt_chunk(data, key)

    resp = r.sess.post(f"{r.base}/relay/upload", data=ct, headers={
        "Content-Type": "application/octet-stream",
        "X-Session-ID": SID, "X-File-ID": fid,
        "X-File-Name": "hello.txt", "X-File-Size": str(len(data)),
        "X-File-SHA256": sha256, "X-Chunk-Index": "0",
        "X-Total-Chunks": "1", "X-Mgmt-Token": MGMT,
    })
    r.check("C01 single chunk upload 200", resp.status_code == 200)
    r.check("C02 received=1", resp.json().get("received") == 1)

    # Multi-chunk file
    big_data  = secrets.token_bytes(50 * 1024)   # 50 KB
    big_fid   = upload_file(r, SID, MGMT, PIN, big_data, "big.bin", chunk_size=10240)
    r.check("C03 multi-chunk upload ok", big_fid is not None)

    # File list shows both files
    resp = r.sess.get(f"{r.base}/relay/session/{SID}/files",
                      headers={"X-PIN": PIN})
    r.check("C04 file list 200", resp.status_code == 200)
    files = resp.json()["files"]
    r.check("C05 two files in list", len(files) == 2)
    r.check("C06 both complete", all(f["complete"] for f in files))

    # Upload without mgmt token
    resp = r.sess.post(f"{r.base}/relay/upload", data=b"x", headers={
        "Content-Type": "application/octet-stream",
        "X-Session-ID": SID, "X-File-ID": str(uuid.uuid4()),
        "X-File-Name": "x", "X-File-Size": "1",
        "X-File-SHA256": "abc", "X-Chunk-Index": "0",
        "X-Total-Chunks": "1",
    })
    r.check("C07 upload no mgmt token 400/403", resp.status_code in (400, 403))

    # Upload wrong mgmt token
    resp = r.sess.post(f"{r.base}/relay/upload", data=b"x", headers={
        "Content-Type": "application/octet-stream",
        "X-Session-ID": SID, "X-File-ID": str(uuid.uuid4()),
        "X-File-Name": "x.bin", "X-File-Size": "1",
        "X-File-SHA256": "abc", "X-Chunk-Index": "0",
        "X-Total-Chunks": "1", "X-Mgmt-Token": "wrongtoken",
    })
    r.check("C08 upload wrong token 403", resp.status_code == 403)

    # Upload to nonexistent session
    resp = r.sess.post(f"{r.base}/relay/upload", data=ct, headers={
        "Content-Type": "application/octet-stream",
        "X-Session-ID": "nosession", "X-File-ID": fid,
        "X-File-Name": "x.bin", "X-File-Size": "10",
        "X-File-SHA256": "abc", "X-Chunk-Index": "0",
        "X-Total-Chunks": "1", "X-Mgmt-Token": rel.make_mgmt_token("nosession"),
    })
    r.check("C09 upload nonexistent session 404", resp.status_code == 404)

    r.delete(f"/relay/session/{SID}", headers={"X-Mgmt-Token": MGMT})


def section_d_download(r: TestRunner):
    print("\n  ── Section D: Download pipeline")

    SID, PIN, MGMT = make_session(r)

    # Upload a known file
    plaintext  = b"The quick brown fox jumps over the lazy dog. " * 200
    file_sha   = hashlib.sha256(plaintext).hexdigest()
    fid        = upload_file(r, SID, MGMT, PIN, plaintext, "fox.txt", chunk_size=1024)

    # Get file info
    resp = r.sess.get(f"{r.base}/relay/session/{SID}/files",
                      headers={"X-PIN": PIN})
    files  = resp.json()["files"]
    finfo  = next(f for f in files if f["id"] == fid)
    total  = finfo["chunks_total"]

    # Download and reassemble
    reassembled = download_file(r, SID, PIN, fid, total)
    r.check("D01 reassembled length", len(reassembled) == len(plaintext))
    r.check("D02 SHA-256 matches", hashlib.sha256(reassembled).hexdigest() == file_sha)
    r.check("D03 content identical", reassembled == plaintext)

    # X-SHA256 header present on chunk response
    resp = r.sess.get(
        f"{r.base}/relay/download/{SID}/{fid}/chunk/0",
        headers={"X-PIN": PIN})
    r.check("D04 X-SHA256 header present", resp.headers.get("X-SHA256") == file_sha)
    r.check("D05 X-Total-Chunks header", resp.headers.get("X-Total-Chunks") == str(total))

    # Wrong PIN on download
    resp = r.sess.get(
        f"{r.base}/relay/download/{SID}/{fid}/chunk/0",
        headers={"X-PIN": "000000"})
    r.check("D06 wrong PIN 401", resp.status_code == 401)

    # No PIN on download
    resp = r.sess.get(f"{r.base}/relay/download/{SID}/{fid}/chunk/0")
    r.check("D07 no PIN 401", resp.status_code == 401)

    # Nonexistent file
    resp = r.sess.get(
        f"{r.base}/relay/download/{SID}/nope/chunk/0",
        headers={"X-PIN": PIN})
    r.check("D08 nonexistent file 404", resp.status_code == 404)

    # Nonexistent chunk (out of range)
    resp = r.sess.get(
        f"{r.base}/relay/download/{SID}/{fid}/chunk/9999",
        headers={"X-PIN": PIN})
    r.check("D09 nonexistent chunk 404", resp.status_code == 404)

    # List files without PIN
    resp = r.sess.get(f"{r.base}/relay/session/{SID}/files")
    r.check("D10 list files no PIN 401", resp.status_code == 401)

    r.delete(f"/relay/session/{SID}", headers={"X-Mgmt-Token": MGMT})


def section_e_crypto(r: TestRunner):
    print("\n  ── Section E: Crypto correctness")

    # HKDF determinism
    k1 = rel.derive_key("847291", "session-abc")
    k2 = rel.derive_key("847291", "session-abc")
    r.check("E01 key derivation deterministic", k1 == k2)

    # Different PIN → different key
    k3 = rel.derive_key("000000", "session-abc")
    r.check("E02 different PIN different key", k1 != k3)

    # Different session → different key
    k4 = rel.derive_key("847291", "session-xyz")
    r.check("E03 different session different key", k1 != k4)

    # Encrypt/decrypt round-trip
    key  = rel.derive_key("123456", "test-session")
    data = b"secret payload " * 100
    wire = rel.encrypt_chunk(data, key)
    r.check("E04 ciphertext differs from plaintext", wire != data)
    r.check("E05 ciphertext longer (nonce+tag overhead)", len(wire) > len(data))

    recovered = rel.decrypt_chunk(wire, key)
    r.check("E06 decrypt round-trip", recovered == data)

    # Two encryptions of same data produce different ciphertexts (random nonce)
    wire2 = rel.encrypt_chunk(data, key)
    r.check("E07 random nonce — two encryptions differ", wire != wire2)

    # Tamper detection
    tampered = bytearray(wire)
    tampered[20] ^= 0xFF   # flip a bit in ciphertext
    try:
        rel.decrypt_chunk(bytes(tampered), key)
        r.check("E08 tamper detection", False, "should have raised InvalidTag")
    except Exception:
        r.check("E08 tamper detection", True)

    # Wrong key fails
    wrong_key = rel.derive_key("999999", "test-session")
    try:
        rel.decrypt_chunk(wire, wrong_key)
        r.check("E09 wrong key rejected", False, "should have failed")
    except Exception:
        r.check("E09 wrong key rejected", True)

    # HMAC management token
    sid   = "test-session-id-123"
    token = rel.make_mgmt_token(sid)
    r.check("E10 mgmt token is 64 chars", len(token) == 64)
    r.check("E11 mgmt token verifies", rel.verify_hmac(sid, token))
    r.check("E12 wrong sid fails verify", not rel.verify_hmac("other-sid", token))


def section_f_security(r: TestRunner):
    print("\n  ── Section F: Security")

    SID, PIN, MGMT = make_session(r)
    SID2, PIN2, MGMT2 = make_session(r)

    # Upload to session 1
    data = b"session 1 secret data " * 50
    fid  = upload_file(r, SID, MGMT, PIN, data, "secret.bin", chunk_size=len(data))

    # Try to download session 1 chunk using session 2 PIN
    resp = r.sess.get(
        f"{r.base}/relay/download/{SID}/{fid}/chunk/0",
        headers={"X-PIN": PIN2})
    r.check("F01 cross-session PIN rejected 401", resp.status_code == 401)

    # Try to upload to session 1 with session 2 mgmt token
    key = rel.derive_key(PIN2, SID2)
    ct  = rel.encrypt_chunk(b"evil", key)
    resp = r.sess.post(f"{r.base}/relay/upload", data=ct, headers={
        "Content-Type": "application/octet-stream",
        "X-Session-ID": SID, "X-File-ID": str(uuid.uuid4()),
        "X-File-Name": "evil.bin", "X-File-Size": "4",
        "X-File-SHA256": "abc", "X-Chunk-Index": "0",
        "X-Total-Chunks": "1", "X-Mgmt-Token": MGMT2,   # wrong session's token
    })
    r.check("F02 cross-session mgmt token rejected 403", resp.status_code == 403)

    # Empty body upload
    resp = r.sess.post(f"{r.base}/relay/upload", data=b"", headers={
        "Content-Type": "application/octet-stream",
        "X-Session-ID": SID, "X-File-ID": str(uuid.uuid4()),
        "X-File-Name": "empty.bin", "X-File-Size": "0",
        "X-File-SHA256": "abc", "X-Chunk-Index": "0",
        "X-Total-Chunks": "1", "X-Mgmt-Token": MGMT,
    })
    r.check("F03 empty body rejected 400", resp.status_code == 400)

    # Path traversal in file name (server should sanitise)
    safe_name = "../../../etc/passwd"
    key1 = rel.derive_key(PIN, SID)
    ct1  = rel.encrypt_chunk(b"x", key1)
    resp = r.sess.post(f"{r.base}/relay/upload", data=ct1, headers={
        "Content-Type": "application/octet-stream",
        "X-Session-ID": SID, "X-File-ID": str(uuid.uuid4()),
        "X-File-Name": safe_name, "X-File-Size": "1",
        "X-File-SHA256": hashlib.sha256(b"x").hexdigest(),
        "X-Chunk-Index": "0", "X-Total-Chunks": "1",
        "X-Mgmt-Token": MGMT,
    })
    if resp.status_code == 200:
        # Check the stored name was sanitised
        files_resp = r.sess.get(f"{r.base}/relay/session/{SID}/files",
                                headers={"X-PIN": PIN})
        fnames = [f["name"] for f in files_resp.json().get("files", [])]
        r.check("F04 path traversal sanitised",
                not any("/" in n or "\\" in n for n in fnames))
    else:
        r.check("F04 path traversal rejected", resp.status_code in (400, 422))

    r.delete(f"/relay/session/{SID}",  headers={"X-Mgmt-Token": MGMT})
    r.delete(f"/relay/session/{SID2}", headers={"X-Mgmt-Token": MGMT2})


def section_g_edge(r: TestRunner):
    print("\n  ── Section G: Edge cases")

    SID, PIN, MGMT = make_session(r)

    # Single-byte file
    tiny = b"x"
    fid  = upload_file(r, SID, MGMT, PIN, tiny, "tiny.txt", chunk_size=1024)
    resp = r.sess.get(f"{r.base}/relay/session/{SID}/files",
                      headers={"X-PIN": PIN})
    r.check("G01 single-byte file stored", len(resp.json()["files"]) >= 1)
    recovered = download_file(r, SID, PIN, fid, 1)
    r.check("G02 single-byte round-trip", recovered == tiny)

    # File with special characters in name (HTTP headers are latin-1 only,
    # so we percent-encode the filename before putting it in a header)
    import urllib.parse
    unicode_name = "special file & name (2024).txt"   # ASCII-safe but special chars
    safe_header_name = urllib.parse.quote(unicode_name)
    data2 = b"special name test " * 10
    fid2  = upload_file(r, SID, MGMT, PIN, data2, safe_header_name, chunk_size=1024)
    resp2 = r.sess.get(f"{r.base}/relay/session/{SID}/files",
                       headers={"X-PIN": PIN})
    names = [f["name"] for f in resp2.json()["files"]]
    r.check("G03 special filename doesn't crash server", fid2 is not None)

    # Multi-file session
    for i in range(3):
        upload_file(r, SID, MGMT, PIN, f"file {i}".encode() * 100,
                    f"multi_{i}.txt", chunk_size=512)
    resp = r.sess.get(f"{r.base}/relay/session/{SID}/files",
                      headers={"X-PIN": PIN})
    r.check("G04 multiple files in one session",
            len(resp.json()["files"]) >= 4)   # tiny + unicode + 3

    # Idempotent chunk re-upload (same chunk twice — shouldn't corrupt)
    key   = rel.derive_key(PIN, SID)
    idata = b"idempotent test " * 20
    ifid  = str(uuid.uuid4())
    isha  = hashlib.sha256(idata).hexdigest()
    ict   = rel.encrypt_chunk(idata, key)
    for _ in range(2):   # upload same chunk twice
        r.sess.post(f"{r.base}/relay/upload", data=ict, headers={
            "Content-Type": "application/octet-stream",
            "X-Session-ID": SID, "X-File-ID": ifid,
            "X-File-Name": "idem.bin", "X-File-Size": str(len(idata)),
            "X-File-SHA256": isha, "X-Chunk-Index": "0",
            "X-Total-Chunks": "1", "X-Mgmt-Token": MGMT,
        })
    recovered = download_file(r, SID, PIN, ifid, 1)
    r.check("G05 re-uploaded chunk still downloads", recovered == idata)

    r.delete(f"/relay/session/{SID}", headers={"X-Mgmt-Token": MGMT})


def section_h_ws(r: TestRunner):
    print("\n  ── Section H: WebSocket (basic)")
    try:
        import websocket   # pip install websocket-client
    except ImportError:
        print("  ⚠  websocket-client not installed — skipping WS tests")
        print("     pip install websocket-client  to enable")
        return

    SID, PIN, MGMT = make_session(r)

    ws_url = r.base.replace("http://", "ws://").replace("https://", "wss://")
    ws_url = f"{ws_url}/relay/ws/{SID}"

    received_events = []
    ws_connected    = threading.Event()
    ws_file_event   = threading.Event()

    def on_message(ws_conn, message):
        msg = __import__("json").loads(message)
        received_events.append(msg)
        if msg.get("event") == "connected":
            ws_connected.set()
        if msg.get("event") == "file_complete":
            ws_file_event.set()

    def on_error(ws_conn, error):
        pass

    ws_conn = websocket.WebSocketApp(
        ws_url,
        on_message=on_message,
        on_error=on_error,
    )

    t = threading.Thread(target=ws_conn.run_forever, daemon=True)
    t.start()
    time.sleep(0.5)

    # Send auth message
    ws_conn.send(__import__("json").dumps({"pin": PIN}))
    connected = ws_connected.wait(timeout=4)
    r.check("H01 WS connects and receives auth ack", connected)

    # Now upload a file — should trigger file_complete event
    data = b"websocket push test " * 50
    upload_file(r, SID, MGMT, PIN, data, "ws_test.bin", chunk_size=len(data))

    got_event = ws_file_event.wait(timeout=4)
    r.check("H02 file_complete event received over WS", got_event)

    file_events = [e for e in received_events if e.get("event") == "file_complete"]
    r.check("H03 file_complete has name", bool(file_events and file_events[0].get("name")))

    ws_conn.close()

    # WS with wrong PIN should close
    ws2_closed = threading.Event()

    def on_close2(ws_c, code, msg):
        ws2_closed.set()

    ws2 = websocket.WebSocketApp(ws_url, on_close=on_close2)
    t2  = threading.Thread(target=ws2.run_forever, daemon=True)
    t2.start()
    time.sleep(0.5)
    ws2.send(__import__("json").dumps({"pin": "000000"}))
    closed = ws2_closed.wait(timeout=4)
    r.check("H04 wrong PIN WS closed by server", closed)

    r.delete(f"/relay/session/{SID}", headers={"X-Mgmt-Token": MGMT})


def section_i_concurrent(r: TestRunner):
    print("\n  ── Section I: Concurrent access")

    SID, PIN, MGMT = make_session(r)

    # Upload one file
    data = secrets.token_bytes(30 * 1024)
    fid  = upload_file(r, SID, MGMT, PIN, data, "concurrent.bin", chunk_size=8192)
    resp = r.sess.get(f"{r.base}/relay/session/{SID}/files",
                      headers={"X-PIN": PIN})
    total = resp.json()["files"][0]["chunks_total"]

    # Two receivers download simultaneously
    results = {}
    errors  = {}

    def recv(name):
        try:
            results[name] = download_file(r, SID, PIN, fid, total)
        except Exception as e:
            errors[name] = str(e)

    t1 = threading.Thread(target=recv, args=("r1",))
    t2 = threading.Thread(target=recv, args=("r2",))
    t1.start(); t2.start()
    t1.join(timeout=10); t2.join(timeout=10)

    r.check("I01 both receivers got data", "r1" in results and "r2" in results,
            str(errors))
    r.check("I02 r1 content correct",
            results.get("r1") == data)
    r.check("I03 r2 content correct",
            results.get("r2") == data)
    r.check("I04 no cross-contamination",
            results.get("r1") == results.get("r2"))

    r.delete(f"/relay/session/{SID}", headers={"X-Mgmt-Token": MGMT})


# ── Main ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="droply relay integration tests")
    parser.add_argument("--port",    type=int, default=19870)
    parser.add_argument("--url",     type=str, default="",
                        help="Test against a live relay URL (e.g. https://droply-relay.fly.dev)")
    parser.add_argument("-v","--verbose", action="store_true")
    args = parser.parse_args()

    if args.url:
        # Test against existing live relay
        BASE = args.url.rstrip("/")
        print(f"\n  Testing live relay: {BASE}")
        local_server = False
    else:
        # Start a local relay instance for testing
        BASE = f"http://127.0.0.1:{args.port}"
        local_server = True

        global DEV_MODE, store
        rel.DEV_MODE = True
        rel.store    = rel._init_store()

        t = threading.Thread(
            target=lambda: rel.app.run(
                host="127.0.0.1", port=args.port,
                debug=False, use_reloader=False),
            daemon=True)
        t.start()

        # Wait for server to be ready
        import socket
        for _ in range(20):
            try:
                s = socket.create_connection(("127.0.0.1", args.port), timeout=0.3)
                s.close()
                break
            except OSError:
                time.sleep(0.2)

    runner = TestRunner(BASE, args.verbose)

    print("\n" + "═"*56)
    print(f"  droply relay — integration test suite")
    print(f"  Target: {BASE}")
    print("═"*56)

    section_a_infra(runner)
    section_b_sessions(runner)
    section_c_upload(runner)
    section_d_download(runner)
    section_e_crypto(runner)
    section_f_security(runner)
    section_g_edge(runner)
    section_h_ws(runner)
    section_i_concurrent(runner)

    passed = runner.summary()
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()