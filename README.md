# droply — Local Wireless File Transfer
## Prototype v0.1

Transfer large files between any devices on the same network — no internet, no cloud, no account.
Receiver only needs a browser. Zero install on their side.

---

## What's in this prototype

| What | Why |
|------|-----|
| Flask HTTP server | Runs on sender's machine, serves files to browsers |
| PIN auth (rate-limited) | 6-digit PIN, max 5 attempts/min, constant-time compare |
| Self-signed HTTPS | Encrypts the transfer, browser warns once then trusts |
| Chunked upload | Large files stream to disk — never blows RAM |
| HTTP Range download | Supports resume + parallel chunk download |
| SHA-256 integrity | Hash computed at upload, verified before every download |
| File expiry / download cap | Files auto-delete by TTL or after N downloads |
| Background purge | Daemon thread cleans expired files every 60 seconds |
| QR code | Receiver scans to get the URL — no typing |
| Drag-and-drop UI | Clean browser UI, works on mobile |

---

## Quickstart

### 1. Install dependencies

```bash
cd droply
pip install -r requirements.txt
```

### 2. Run the server

```bash
python server.py
```

You'll see:

```
══════════════════════════════════════════════════════════
  droply — local file transfer server
══════════════════════════════════════════════════════════
  URL  : https://192.168.1.42:5000
  PIN  : 847291  ← share this with receivers
  HTTPS: yes (accept cert warning in browser)
  Max file size: 10 GB
══════════════════════════════════════════════════════════
```

### 3. Connect a receiver

**Option A — same machine (testing):**
Open `https://127.0.0.1:5000` in your browser.

**Option B — another device on same Wi-Fi:**
Have them open `https://192.168.x.x:5000` (the URL shown in terminal).
They'll get a cert warning → click "Advanced" → "Proceed" (self-signed cert).

**Option C — phone via hotspot:**
1. Turn on your phone's hotspot
2. Connect your laptop to the phone hotspot
3. Run `python server.py` on laptop
4. Phone scans the QR code shown in the sidebar

### 4. Enter PIN
The receiver types the 6-digit PIN shown in your terminal.
They now see all shared files and can download.

---

## Testing checklist

Run these in order to verify everything works:

### Basic tests (5 minutes)

```bash
# 1. Does the server start?
python server.py
# Expected: URL and PIN printed, no errors

# 2. Does the login page load?
# Open https://127.0.0.1:5000/login in browser
# Expected: 6-digit PIN boxes

# 3. Can you log in?
# Enter the PIN from terminal
# Expected: redirected to file browser

# 4. Can you upload a file?
# Drag any file onto the upload zone
# Expected: progress bar → toast "uploaded" → file appears in list

# 5. Can you download the file?
# Click "Download" on a file
# Expected: browser downloads the file

# 6. Is the SHA-256 shown?
# Expected: hash shown under each filename — click to copy
```

### Security tests

```bash
# 7. Does wrong PIN fail?
# Try a wrong PIN 5 times
# Expected: "Too many attempts. Wait 60 seconds."

# 8. Does unauthenticated access redirect?
# Open https://127.0.0.1:5000/api/files in a new incognito window
# Expected: redirected to /login

# 9. Does path traversal fail?
curl -k -b "session=fake" https://127.0.0.1:5000/api/download/../server.py
# Expected: 401 or 302 redirect to login

# 10. Does the rate limiter work on login?
for i in {1..6}; do
  curl -k -X POST https://127.0.0.1:5000/login -d "pin=000000"
done
# Expected: 6th attempt returns 429
```

### Integrity test

```bash
# 11. Verify file integrity manually
# After uploading a file, note its SHA-256 from the UI
# Download it, then:
shasum -a 256 downloaded_file.ext
# Expected: matches the hash shown in droply UI exactly
```

### Large file test

```bash
# 12. Generate a test large file (100 MB)
dd if=/dev/urandom of=/tmp/test_100mb.bin bs=1M count=100

# Upload it via the UI
# Expected: progress bar shows %, speed, estimated time

# 13. Verify it downloads correctly
shasum -a 256 /tmp/test_100mb.bin
# Download via browser, then compare hash
```

### Expiry test

```bash
# 14. Upload with 1-hour expiry, 2 download limit
# Set "Expires after" to "1 hour", "Download limit" to 2

# Download twice → check counter goes 0→1→2
# Third download attempt:
# Expected: 410 Gone

# 15. Check purge runs (wait 2 minutes after TTL)
# Expected: file disappears from UI, deleted from uploads/ folder
```

### Multi-device test

```bash
# 16. Connect two different browsers / devices
# Both log in with the same PIN
# Device A uploads a file
# Device B should see it within 10 seconds (auto-refresh)
# Both can download simultaneously
```

---

## File structure

```
new/
├── server.py          ← entire backend (Flask, auth, upload, download, integrity)
├── requirements.txt   ← pip dependencies
├── cert.pem           ← auto-generated TLS cert (created on first run)
├── key.pem            ← TLS private key
├── file_meta.json     ← file metadata (persists across restarts)
├── uploads/           ← uploaded files stored here (by UUID filename)
├── logs/
│   └── droply.log     ← all events logged here
└── templates/
    ├── login.html     ← PIN entry page
    └── index.html     ← main file browser UI
```

---

## What to build next (Phase 1)

- [ ] Android app (Kotlin) — wraps this server, auto-starts hotspot
- [ ] File-level passwords (different PIN per file)
- [ ] WebSocket progress (real-time push instead of polling)
- [ ] Multi-file zip-on-the-fly streaming
- [ ] mDNS/Bonjour auto-discovery (no manual URL needed)
- [ ] Dark/light theme toggle
- [ ] iOS sender support via Bonjour

---

## Known prototype limitations

| Limitation | Phase 1 fix |
|-----------|-------------|
| Manual hotspot setup | Android app auto-creates hotspot |
| Self-signed cert browser warning | Let user install cert once, or use .local mDNS |
| No mobile sender UI | Native Android/iOS app |
| Single server instance | Multi-node session support |
| PIN is same for all receivers | Per-receiver PIN or link tokens |