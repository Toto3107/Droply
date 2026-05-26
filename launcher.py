"""
droply/launcher.py
==================
Entry point for the packaged executable (droply.exe / droply.app).

WHAT THIS FILE DOES
───────────────────
1. Starts the Flask server (server.py startup()) in a background thread.
2. Opens the receiver URL in the default browser after 1.5 s (server warm-up).
3. Shows a system tray icon (Windows/macOS/Linux via pystray + Pillow).
4. Tray menu:
     ○ "droply is running" (disabled label)
     ○ "PIN: XXXXXX"       (click → copies PIN to clipboard)
     ○ "Open sender"       (click → opens sender dashboard in browser)
     ○ "Copy receiver link"(click → copies /receive URL to clipboard)
     ○ ──────────────────
     ○ "Quit"              (click → clean shutdown)

WHY A TRAY ICON
───────────────
Without it, the user gets a terminal window that they're afraid to close.
A tray icon:
  - Hides the terminal                     (feels like a real app)
  - Surfaces the PIN without digging       (the #1 user question: "what's the PIN?")
  - Provides a clean quit path             (no Ctrl-C guesswork)
  - Opens browser automatically            (zero friction for the sender)

FALLBACK
────────
If pystray is not installed (headless server, CI), launcher falls back to
running server.py directly with the same CLI args.  This means the packaged
exe still works on a server without a display — it just won't show a tray icon.

PACKAGING NOTE
──────────────
This file is the PyInstaller entry point.
The .spec file sets:
    Analysis(scripts=['launcher.py'], ...)
server.py is imported as a module (not a script) so its __name__ != "__main__"
and its argparse / startup() block does NOT run automatically.
"""

import sys
import os
import threading
import time
import webbrowser
import socket
from pathlib import Path

# ── resolve DATA_DIR the same way server.py does ─────────────────────────────
def _frozen():
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")

DATA_DIR = Path(sys.executable).parent if _frozen() else Path(__file__).parent

# ── CLI args (subset of server.py's args) ─────────────────────────────────────
import argparse
parser = argparse.ArgumentParser(description="droply")
parser.add_argument("--http",  action="store_true", help="Plain HTTP (no cert warning)")
parser.add_argument("--port",  type=int, default=5000)
parser.add_argument("--bind",  type=str, default="")
parser.add_argument("--no-browser", action="store_true", help="Don't open browser on start")
args, _ = parser.parse_known_args()

PORT     = args.port
os.environ["PORT"] = str(PORT)

# ── import server module (does NOT run startup() yet) ────────────────────────
# WHY: We import server as a module rather than subprocess so we share memory
#      and can read CURRENT_PIN directly from server.CURRENT_PIN.
import server as _srv

# ── generate cert if needed (before server thread starts) ────────────────────
if not args.http:
    if not (_srv.CERT_FILE.exists() and _srv.KEY_FILE.exists()):
        _srv.generate_self_signed_cert()
elif args.http:
    for f in [_srv.CERT_FILE, _srv.KEY_FILE]:
        if f.exists():
            f.unlink()

# ── bind IP ───────────────────────────────────────────────────────────────────
_srv.BIND_IP = args.bind.strip()

# ── start server in background thread ────────────────────────────────────────
def _run_server():
    _srv.startup(port=PORT, use_https=not args.http)

server_thread = threading.Thread(target=_run_server, daemon=True)
server_thread.start()

# wait for server to be ready (poll the port)
def _wait_ready(timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.15)
    return False

_wait_ready()

# ── build URLs ────────────────────────────────────────────────────────────────
_ip     = _srv.get_local_ip()
_scheme = "https" if (not args.http) else "http"
SENDER_URL   = f"{_scheme}://{_ip}:{PORT}"
RECEIVER_URL = f"{_scheme}://{_ip}:{PORT}/receive"

# ── open browser ──────────────────────────────────────────────────────────────
if not args.no_browser:
    threading.Timer(0.5, lambda: webbrowser.open(SENDER_URL)).start()

# ── tray icon ─────────────────────────────────────────────────────────────────
def _run_tray():
    """
    Build and run the system tray icon.
    Uses pystray + Pillow to draw a minimal icon and menu.
    Falls back silently if pystray is unavailable.
    """
    try:
        import pystray
        from PIL import Image, ImageDraw
    except ImportError:
        # No tray — just keep the server thread alive
        print("\ndroply running. Press Ctrl-C to quit.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            sys.exit(0)
        return

    def _make_icon_image(size=64):
        """
        Draw a simple droply icon: dark background, purple 'd' lettermark.
        WHY Pillow: pystray requires a PIL Image, not a file path.
                    This keeps everything self-contained with no external assets.
        """
        img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Background circle
        draw.ellipse([2, 2, size-2, size-2], fill=(124, 106, 255, 255))
        # White 'd' approximated as a filled arc + rect
        cx, cy, r = size//2, size//2, size//4
        draw.ellipse([cx-r, cy-r, cx+r, cy+r], fill=(255, 255, 255, 230))
        draw.ellipse([cx-r+4, cy-r+4, cx+r-4, cy+r-4], fill=(124, 106, 255, 255))
        draw.rectangle([cx-r, cy-r, cx, cy+r], fill=(255, 255, 255, 230))
        return img

    def _copy_to_clipboard(text: str):
        """Cross-platform clipboard write."""
        try:
            import subprocess
            if sys.platform == "darwin":
                subprocess.run(["pbcopy"], input=text.encode(), check=True)
            elif sys.platform == "win32":
                subprocess.run(["clip"],  input=text.encode(), check=True)
            else:
                # Linux: try xclip then xsel
                try:
                    subprocess.run(["xclip", "-selection", "clipboard"],
                                   input=text.encode(), check=True)
                except FileNotFoundError:
                    subprocess.run(["xsel", "--clipboard", "--input"],
                                   input=text.encode(), check=True)
        except Exception as e:
            print(f"Clipboard failed: {e}")

    def _open_sender(icon, item):
        webbrowser.open(SENDER_URL)

    def _copy_pin(icon, item):
        pin = _srv.CURRENT_PIN
        _copy_to_clipboard(pin)
        print(f"PIN copied: {pin}")

    def _copy_receiver(icon, item):
        _copy_to_clipboard(RECEIVER_URL)
        print(f"Receiver link copied: {RECEIVER_URL}")

    def _quit(icon, item):
        icon.stop()
        sys.exit(0)

    # Rebuild menu each time to show current PIN (in case it was regenerated)
    def _build_menu():
        pin = _srv.CURRENT_PIN
        return pystray.Menu(
            pystray.MenuItem("droply is running", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(f"PIN: {pin}  (click to copy)", _copy_pin),
            pystray.MenuItem("Open sender dashboard", _open_sender, default=True),
            pystray.MenuItem("Copy receiver link", _copy_receiver),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit droply", _quit),
        )

    icon = pystray.Icon(
        name="droply",
        icon=_make_icon_image(64),
        title=f"droply  —  PIN: {_srv.CURRENT_PIN}",
        menu=_build_menu(),
    )

    print(f"\ndroply tray icon started.")
    print(f"  Sender  : {SENDER_URL}")
    print(f"  Receiver: {RECEIVER_URL}")
    print(f"  PIN     : {_srv.CURRENT_PIN}\n")

    icon.run()

# Run tray (blocking — keeps process alive)
_run_tray()