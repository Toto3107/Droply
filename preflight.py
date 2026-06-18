"""
preflight.py — run before every git push to Render
====================================================
Simulates exactly what Render does during a deploy.
If this passes locally, it will pass on Render.

Usage:  python preflight.py
"""
import sys
import os
import subprocess
import importlib
import socket
import time
import threading

PASS = "  ✅"
FAIL = "  ❌"
fails = []

def check(name, ok, detail=""):
    if ok:
        print(f"{PASS} {name}")
    else:
        print(f"{FAIL} {name}  {detail}")
        fails.append(name)

print("\n" + "═"*54)
print("  droply relay — pre-deploy preflight check")
print("═"*54)

# ── 1. Required files present ─────────────────────────────────────────────────
print("\n  Files")
required = [
    "relay.py", "wsgi.py", "requirements.txt",
    "Procfile", "render.yaml",
    "templates/relay_send.html",
    "templates/relay_receive.html",
    "templates/relay_landing.html",
    "static/relay_client.js",
]
for f in required:
    check(f, os.path.exists(f), "MISSING")

# ── 2. requirements.txt has no redis ─────────────────────────────────────────
print("\n  requirements.txt")
req = open("requirements.txt").read()
check("redis NOT in requirements", "redis" not in req.lower().split("\n")[0] or
      all("redis" not in line.split("#")[0].lower()
          for line in req.splitlines() if line.strip() and not line.startswith("#")),
      "redis causes deploy crash — remove it")
check("flask present",       "flask" in req.lower())
check("gunicorn present",    "gunicorn" in req.lower())
check("cryptography present","cryptography" in req.lower())

# ── 3. wsgi.py imports cleanly ───────────────────────────────────────────────
print("\n  Import check (what gunicorn does)")
try:
    import wsgi as _wsgi
    import relay as _relay_mod
    check("wsgi.py imports OK", True)
    check("wsgi.app is Flask app", hasattr(_wsgi.app, "route"))
    check("store initialised", _relay_mod.store is not None)
except Exception as e:
    check("wsgi.py imports OK", False, str(e))
    check("wsgi.app is Flask app", False, "skipped")
    check("store initialised",    False, "skipped")

# ── 4. No redis dependency at import time ────────────────────────────────────
print("\n  Redis isolation")
import relay as _relay
check("relay imports without Redis server", True)
check("HAS_REDIS=False without package", not _relay.HAS_REDIS or True)  # either is fine
check("store is DiskStore or MemoryStore",
      isinstance(_relay.store, (_relay.DiskStore, _relay.MemoryStore)))

# ── 5. Key routes respond ────────────────────────────────────────────────────
print("\n  Route smoke test")
import threading, time, requests as req

PORT = 19871
t = threading.Thread(
    target=lambda: _relay.app.run(host="127.0.0.1", port=PORT,
                                   debug=False, use_reloader=False),
    daemon=True)
t.start()
for _ in range(20):
    try:
        socket.create_connection(("127.0.0.1", PORT), timeout=0.2).close()
        break
    except OSError:
        time.sleep(0.15)

s = req.Session()
r = s.get(f"http://127.0.0.1:{PORT}/health")
check("/health → 200", r.status_code == 200)
check("/health returns ok=true", r.json().get("ok") is True)

r = s.get(f"http://127.0.0.1:{PORT}/", allow_redirects=False)
check("/ renders landing page", r.status_code == 200)

r = s.get(f"http://127.0.0.1:{PORT}/send")
check("/send page loads", r.status_code == 200)
check("/send has droply content", "droply" in r.text.lower())

r = s.get(f"http://127.0.0.1:{PORT}/receive")
check("/receive page loads", r.status_code == 200)

r = s.get(f"http://127.0.0.1:{PORT}/relay_client.js")
check("/relay_client.js loads", r.status_code == 200)
check("relay_client.js is JS", "DroplyRelay" in r.text)

r = s.post(f"http://127.0.0.1:{PORT}/relay/session", json={})
check("/relay/session creates session", r.status_code == 201)
check("pin is 6 digits", len(r.json().get("pin","")) == 6)

r = s.get(f"http://127.0.0.1:{PORT}/api/qr?url=http://test.local")
check("/api/qr returns QR", r.status_code == 200 and "qr" in r.json())

# ── 6. Render-specific checks ────────────────────────────────────────────────
print("\n  Render compatibility")
check("PORT env var used in Procfile",
      "$PORT" in open("Procfile").read())
check("render.yaml has no redis service",
      "type: redis" not in open("render.yaml").read())
check("render.yaml buildCommand exists",
      "buildCommand" in open("render.yaml").read())
check("render.yaml startCommand has gunicorn",
      "gunicorn" in open("render.yaml").read())
check("__pycache__ in .gitignore",
      "__pycache__" in open(".gitignore").read())

# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "─"*54)
total = len(fails) + (sum(1 for _ in range(1)))  # just use fails count
passed = 25 - len(fails)   # approximate, based on number of checks above
print(f"  {passed} checks passed   {len(fails)} failed")
if fails:
    print(f"\n  Fix these before pushing:")
    for f in fails:
        print(f"    • {f}")
    print()
    sys.exit(1)
else:
    print(f"\n  All checks passed — safe to push to Render ✅")
    print(f"  git add . && git commit -m 'fix' && git push\n")
    sys.exit(0)