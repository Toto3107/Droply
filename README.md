# droply — Local Wireless File Transfer
## Prototype v0.1

# droply ⚡

> Transfer large files between any devices — no internet, no cloud, no account.
> Receiver only needs a browser.

![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square)
![Flask](https://img.shields.io/badge/flask-3.0-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-prototype-orange?style=flat-square)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)

---

## What is droply?

droply is a local wireless file transfer server. The sender runs it on their machine — the receiver opens a browser URL and pulls files directly. No internet required. No sign-up. No cloud. Files never leave your local network.
## Known prototype limitations

| Limitation | Phase 1 fix |
|-----------|-------------|
| Manual hotspot setup | Android app auto-creates hotspot |
| Self-signed cert browser warning | Let user install cert once, or use .local mDNS |
| No mobile sender UI | Native Android/iOS app |
| Single server instance | Multi-node session support |
| PIN is same for all receivers | Per-receiver PIN or link tokens |
**The core insight:** the receiver never needs to install anything. Just a browser.

```
Sender runs:   python server.py --http
Receiver opens: http://192.168.x.x:5000
Enters PIN → downloads files at full Wi-Fi speed
```

Works across Android, iOS, Windows, Mac — any device with a browser.

---

## Why build this?

Every existing solution has a catch:

| Tool | Problem |
|------|---------|
| AirDrop | Apple only |
| Nearby Share | Android + Windows only, no iOS |
| WhatsApp / Telegram | Compresses files, needs internet |
| USB cable | Requires cable, slow for large files |
| Google Drive / WeTransfer | Needs internet, uploads to cloud |
| LocalSend | Both devices must install the app |

droply's approach: **only the sender installs anything.** The receiver just opens a link.

---

## Features (prototype v0.1)

- **Zero internet** — works entirely over local Wi-Fi or phone hotspot
- **Browser-based receiver** — no install on the receiver side
- **PIN authentication** — 6-digit PIN guards every session
- **Rate limiting** — 5 attempts/min, blocks brute force
- **Chunked streaming** — large files never blow RAM
- **HTTP Range support** — downloads can resume if connection drops
- **SHA-256 integrity** — every file is verified before serving
- **File expiry** — set TTL (1h / 6h / 24h) and download count caps
- **Auto file purge** — expired files deleted automatically
- **QR code** — receiver scans to get the URL, no typing
- **Drag & drop UI** — clean browser interface, works on mobile
- **HTTPS option** — self-signed cert for encrypted transfers
- **Transfer logs** — everything logged to `logs/droply.log`

---

## Quickstart

```bash
# Clone
git clone https://github.com/Toto3107/droply.git
cd droply

# Install dependencies
pip install -r requirements.txt

# Run (HTTP mode — no browser cert warning)
python server.py --http
```

You'll see:

```
══════════════════════════════════════════════════════════
  droply — local file transfer server
══════════════════════════════════════════════════════════
  URL  : http://192.168.1.42:5000
  PIN  : [------]  ← share this with receivers
  HTTPS: no (http only)
  Max file size: 10 GB
══════════════════════════════════════════════════════════
```

Open the URL on any device on the same network. Enter the PIN. Done.

### Flags

```bash
python server.py              # HTTPS with self-signed cert
python server.py --http       # Plain HTTP, no cert warning
python server.py --port 8080  # Custom port
python server.py --http --port 8080
```

### Using across devices (hotspot)

1. Turn on your **phone's hotspot**
2. Connect your **laptop** to the hotspot
3. Run `python server.py --http` on the laptop
4. On your phone, **scan the QR code** shown in the sidebar
5. Enter PIN → pull any file

---

## Project structure

```
droply/
├── server.py            ← entire backend (Flask, auth, integrity, streaming)
├── requirements.txt
├── .gitignore
├── uploads/             ← files stored here by UUID (gitignored)
├── logs/                ← transfer logs (gitignored)
└── templates/
    ├── index.html       ← file browser UI (sender + receiver)
    └── login.html
    └──  receive.html  ← PIN entry page
```

---

## Security model

| Layer | Implementation |
|-------|---------------|
| Auth | 6-digit PIN, constant-time compare (`secrets.compare_digest`) |
| Brute force | Rate limiter: 5 attempts/min per IP → 429 |
| Path traversal | All uploads stored by UUID, filenames sanitised |
| Integrity | SHA-256 computed at upload, verified before every download |
| Encryption | Optional HTTPS via auto-generated self-signed cert |
| Session | Flask signed cookie, 1-hour timeout |
| File expiry | TTL + download count cap, background purge thread |

---

## Roadmap

### Phase 1 — Desktop app (next)
- [ ] Package as single executable (PyInstaller) — no Python needed
- [ ] System tray icon (Windows + Mac)
- [ ] WebSocket real-time progress push
- [ ] mDNS/Bonjour auto-discovery (no manual URL)
- [ ] Multi-file zip streaming

### Phase 2 — Mobile sender
- [ ] Android app (Kotlin) — auto-starts hotspot, shows QR
- [ ] iOS sender via Bonjour on existing Wi-Fi

### Phase 3 — B2B / Teams
- [ ] Named device sessions
- [ ] File-level access control
- [ ] Admin audit log export
- [ ] MDM / fleet deployment support

### Phase 4 — Hybrid relay
- [ ] Optional encrypted relay for cross-network transfers
- [ ] CLI tool (`droply send ./file.zip`)
- [ ] API for third-party integrations

---

## Contributing

This is an early prototype and contributions are very welcome — especially:

- **Bug reports** — anything that breaks on your OS / browser / network setup
- **Platform testing** — does it work on your Android? iOS? Linux?
- **Feature ideas** — what would make this actually useful for you?
- **Code** — see open issues; anything tagged `good first issue` is a clean starting point

### How to contribute

```bash
# Fork the repo, then:
git clone https://github.com/Toto3107/droply.git
cd droply
pip install -r requirements.txt

# Create a branch
git checkout -b feature/your-feature-name

# Make changes, test, then open a PR
```

Please open an issue before starting large changes — happy to discuss direction first.

---

## License

MIT — use it, fork it, build on it.

---

## Built by

www.linkedin.com/in/mayank-gehlot-28b0381ba — built this to solve a real frustration: sending large files to someone in the same room while burning mobile data. Turns out there's no clean cross-platform answer. droply is the attempt.

**If you find this useful, star the repo ⭐ — it helps more than you'd think.**
---

