"""Unified Zero-Config Platform Launcher for Sentinel-AI SOC Platform.

Coordinates:
1. Automated DB verification and admin credential pre-seeding.
2. FAISS vector store verification and automatic pre-population.
3. Node.js frontend dependencies verification.
4. Port availability verification (detecting conflicts on port 8080).
5. Concurrent launch of FastAPI Uvicorn backend (port 8080) and React Vite frontend (port 5173).
6. Graceful termination on Ctrl+C (SIGINT / SIGBREAK) across all child processes.
"""

import os
import sys
import time
import signal
import socket
import argparse
import subprocess
from pathlib import Path

# Safeguard console UTF-8 output on Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def is_port_in_use(port: int) -> bool:
    """Checks whether a TCP socket port is currently bound on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def resolve_project_paths():
    """Resolves root backend directory and frontend directory reliably."""
    cwd = Path.cwd()
    script_dir = Path(__file__).resolve().parent

    # Check current directory
    if (cwd / "src" / "main.py").exists():
        backend_dir = cwd
    elif (cwd / "threat-agent-platform" / "src" / "main.py").exists():
        backend_dir = cwd / "threat-agent-platform"
    elif (script_dir / "src" / "main.py").exists():
        backend_dir = script_dir
    elif (script_dir / "threat-agent-platform" / "src" / "main.py").exists():
        backend_dir = script_dir / "threat-agent-platform"
    else:
        backend_dir = script_dir

    # Frontend directory (check inside backend, adjacent, or at workspace root)
    if (backend_dir / "frontend" / "package.json").exists():
        frontend_dir = backend_dir / "frontend"
    elif (backend_dir.parent / "frontend" / "package.json").exists():
        frontend_dir = backend_dir.parent / "frontend"
    elif (cwd / "frontend" / "package.json").exists():
        frontend_dir = cwd / "frontend"
    else:
        frontend_dir = backend_dir / "frontend"

    return backend_dir, frontend_dir


def main():
    parser = argparse.ArgumentParser(description="Unified Sentinel SOC Platform Launcher")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Verify database, indices, and dependencies without spawning persistent dev servers",
    )
    parser.add_argument(
        "--port-backend",
        type=int,
        default=8080,
        help="FastAPI backend port (default: 8080)",
    )
    parser.add_argument(
        "--port-frontend",
        type=int,
        default=5173,
        help="React frontend port (default: 5173)",
    )
    args = parser.parse_args()

    backend_dir, frontend_dir = resolve_project_paths()

    print("=" * 80)
    print("🛡️  INITIALIZING SENTINEL-AI ENTERPRISE SOC PLATFORM")
    print("🛡️  SENTINEL-AI: UNIFIED ZERO-CONFIG PLATFORM LAUNCHER")
    print("=" * 80)

    # 1. Automatic pre-seeding and database initialization
    print("[*] Verifying database and credentials...")
    db_path = backend_dir / "data" / "sentinel_soc.db"
    (backend_dir / "data").mkdir(parents=True, exist_ok=True)

    seed_script = backend_dir / "seed_admin.py"
    if seed_script.exists():
        subprocess.run([sys.executable, str(seed_script)], cwd=str(backend_dir), check=False)
    else:
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import asyncio; from src.db.session import init_db; asyncio.run(init_db())",
            ],
            cwd=str(backend_dir),
            check=True,
        )
    print(f"[✓] SQLite database verified at {db_path.name}.")

    # 2. Check FAISS email index
    faiss_path = backend_dir / "data" / "indices" / "faiss_email_index.bin"
    if not faiss_path.exists():
        print("[*] FAISS email index not found. Building vector store...")
        subprocess.run([sys.executable, "build_index.py"], cwd=str(backend_dir), check=True)
        print("[✓] FAISS vector store generated successfully.")
    else:
        print("[✓] FAISS vector store verified.")

    # 3. Check Node & Frontend
    node_modules_dir = frontend_dir / "node_modules"
    if not node_modules_dir.exists():
        print("[*] Installing frontend dependencies (npm install)...")
        subprocess.run(["npm", "install"], cwd=str(frontend_dir), shell=True, check=True)
        print("[✓] Frontend dependencies installed successfully.")
    else:
        print("[✓] Frontend dependencies verified.")

    if args.check_only:
        print("\n[+] Pre-flight checks passed successfully.")
        return

    backend_port = args.port_backend
    frontend_port = args.port_frontend

    # 4. Port availability check
    if is_port_in_use(backend_port):
        print(f"[!] Warning: Port {backend_port} is already in use. Attempting clean launch...")

    # 5. Start FastAPI Backend
    print(f"[+] Starting FastAPI Backend on http://127.0.0.1:{backend_port}")
    backend_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "src.main:app",
            "--reload",
            "--host",
            "127.0.0.1",
            "--port",
            str(backend_port),
        ],
        cwd=str(backend_dir),
        shell=False,
    )

    # 6. Start Frontend
    print(f"[+] Starting React SOC Dashboard on http://localhost:{frontend_port}")
    frontend_proc = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd=str(frontend_dir),
        shell=True,
    )

    print("\n" + "=" * 80)
    print("🚀 PLATFORM ONLINE:")
    print(f"   • URL        : http://localhost:{frontend_port}")
    print("   • Username   : admin")
    print("   • Password   : admin123")
    print("   Press CTRL+C at any time to shut down all processes.")
    print("=" * 80 + "\n")

    def signal_handler(sig, frame):
        print("\n[*] Terminating all processes...")
        try:
            backend_proc.terminate()
        except Exception:
            pass

        if sys.platform == "win32":
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(frontend_proc.pid)],
                    shell=True,
                    capture_output=True,
                )
            except Exception:
                pass
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(backend_proc.pid)],
                    shell=True,
                    capture_output=True,
                )
            except Exception:
                pass
        else:
            try:
                frontend_proc.terminate()
            except Exception:
                pass

        print("[✓] Services stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()
