"""Unified One-Click Platform Launcher for Sentinel-AI SOC Platform (Workspace Root).

Coordinates:
1. Environment and dependency verification.
2. Database initialization and verification (data/sentinel_soc.db).
3. FAISS vector store verification and automatic pre-population.
4. Concurrent launch of FastAPI Uvicorn backend (port 8000) and React Vite frontend (port 5173).
5. Graceful termination on Ctrl+C (SIGINT / SIGBREAK) across all child processes.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent / "threat-agent-platform"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

import run_system

if __name__ == "__main__":
    run_system.main()
