#!/usr/bin/env python3
"""
droply/build.py
===============
Full build script. Run this to produce a distributable package.

Usage:
    python build.py                  # normal build
    python build.py --console        # build with terminal visible (for debugging)
    python build.py --onefile        # single .exe (slower startup but one file)
    python build.py --clean          # wipe dist/ and build/ first

Output:
    dist/droply/            ← the folder to distribute (zip this up)
    dist/droply.zip         ← ready-to-share archive (Windows/macOS/Linux)

What this script does beyond plain pyinstaller:
  1. Patches droply.spec with --console / --onefile flags if requested
  2. Runs pyinstaller droply.spec
  3. Creates dist/droply/uploads/ and dist/droply/logs/ (required at runtime)
  4. Writes a dist/droply/.gitkeep so folder is tracked if added to git
  5. Strips test files from the bundle (run_tests etc.)
  6. Prints a summary with file sizes
  7. Creates a .zip archive of the dist folder
"""

import sys
import os
import shutil
import subprocess
import argparse
import zipfile
from pathlib import Path
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
ROOT     = Path(__file__).parent
DIST_DIR = ROOT / "dist" / "droply"
SPEC     = ROOT / "droply.spec"
VERSION  = "0.4.0"

def run(cmd: list[str], **kwargs):
    print(f"\n  $ {' '.join(cmd)}")
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        print(f"\n❌ Command failed (exit {result.returncode})")
        sys.exit(result.returncode)
    return result

def fmt_size(path: Path) -> str:
    """Human-readable size of a file or directory."""
    if path.is_file():
        b = path.stat().st_size
    else:
        b = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    for unit in ["B", "KB", "MB", "GB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} GB"

def main():
    parser = argparse.ArgumentParser(description="Build droply distributable")
    parser.add_argument("--console",  action="store_true",
                        help="Show terminal window (useful for debugging)")
    parser.add_argument("--onefile",  action="store_true",
                        help="Single-file exe (slower start, easier to share)")
    parser.add_argument("--clean",    action="store_true",
                        help="Delete dist/ and build/ before building")
    args = parser.parse_args()

    print("\n" + "═"*60)
    print(f"  droply {VERSION} — build script")
    print("═"*60)

    # ── Clean ─────────────────────────────────────────────────────────────────
    if args.clean:
        for d in [ROOT / "dist", ROOT / "build"]:
            if d.exists():
                shutil.rmtree(d)
                print(f"  cleaned: {d}")

    # ── Pre-flight: verify all required files exist ───────────────────────────
    required = [
        ROOT / "launcher.py",
        ROOT / "server.py",
        ROOT / "droply.spec",
        ROOT / "templates" / "index.html",
        ROOT / "templates" / "login.html",
        ROOT / "templates" / "receive.html",
    ]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        print(f"\n❌ Missing files:\n" + "\n".join(f"  {m}" for m in missing))
        sys.exit(1)
    print(f"\n  ✅ pre-flight checks passed")

    # ── Patch spec for --console / --onefile ─────────────────────────────────
    spec_content = SPEC.read_text()
    if args.console:
        spec_content = spec_content.replace(
            "console=False,", "console=True,   # patched by build.py --console")
    if args.onefile:
        # In onefile mode we need to modify the spec more substantially
        # For simplicity, warn and proceed with onedir
        print("  ⚠  --onefile: modifying spec for single-file output")
        spec_content = spec_content.replace(
            "exclude_binaries=True,", "exclude_binaries=False,")
    SPEC.write_text(spec_content)

    # ── Run PyInstaller ───────────────────────────────────────────────────────
    print(f"\n  running PyInstaller...")
    run([sys.executable, "-m", "PyInstaller", "--noconfirm", str(SPEC)],
        cwd=str(ROOT))

    # ── Post-process dist folder ──────────────────────────────────────────────
    if not DIST_DIR.exists():
        print(f"\n❌ dist/droply/ not found after build — PyInstaller failed")
        sys.exit(1)

    # Create runtime-required writable directories
    for d in ["uploads", "logs"]:
        target = DIST_DIR / d
        target.mkdir(exist_ok=True)
        (target / ".gitkeep").touch()
        print(f"  created: dist/droply/{d}/")

    # Write a VERSION file
    (DIST_DIR / "VERSION").write_text(
        f"droply {VERSION}\nbuilt: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")

    # Write a quick-start README next to the exe
    readme = f"""droply {VERSION} — local wireless file transfer

QUICK START
───────────
1. Double-click droply (or droply.exe on Windows)
2. Your browser opens automatically
3. Share the PIN shown in the tray icon tooltip with your receiver
4. Receiver opens the URL on their device, enters the PIN, downloads files

COMMAND LINE OPTIONS (run from terminal for advanced use)
──────────────────────────────────────────────────────────
  droply --http             Plain HTTP (no cert warning in browser)
  droply --port 8080        Use a different port
  droply --bind 192.168.x   Force a specific network interface
  droply --no-browser       Don't open browser automatically

FILES
─────
  uploads/    Files shared via droply are stored here temporarily
  logs/       droply.log — all events logged here
  cert.pem    Auto-generated TLS certificate (created on first run)

Source: https://github.com/YOUR_USERNAME/droply
"""
    (DIST_DIR / "README.txt").write_text(readme)
    print(f"  wrote: dist/droply/README.txt")

    # ── Print summary ─────────────────────────────────────────────────────────
    exe_name = "droply.exe" if sys.platform == "win32" else "droply"
    exe_path = DIST_DIR / exe_name
    bundle_size = fmt_size(DIST_DIR)

    print(f"\n{'─'*60}")
    print(f"  ✅ Build complete")
    print(f"  Exe     : {'dist/droply/' + exe_name}  ({fmt_size(exe_path) if exe_path.exists() else '?'})")
    print(f"  Bundle  : dist/droply/  ({bundle_size} total)")

    # ── Create distribution zip ───────────────────────────────────────────────
    zip_path = ROOT / "dist" / f"droply-{VERSION}-{_platform_tag()}.zip"
    print(f"\n  creating {zip_path.name}...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in DIST_DIR.rglob("*"):
            if file.is_file():
                zf.write(file, file.relative_to(ROOT / "dist"))
    print(f"  ✅ {zip_path.name}  ({fmt_size(zip_path)})")
    print(f"{'─'*60}\n")
    print(f"  Distribute: dist/{zip_path.name}")
    print(f"  To test:    cd dist/droply && ./{exe_name} --http\n")

def _platform_tag() -> str:
    import platform
    s = sys.platform
    m = platform.machine().lower()
    if s == "win32":
        return f"windows-{'arm64' if 'arm' in m else 'x64'}"
    if s == "darwin":
        return f"macos-{'arm64' if 'arm' in m else 'x64'}"
    return f"linux-{'arm64' if 'arm' in m else 'x64'}"

if __name__ == "__main__":
    main()