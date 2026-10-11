"""Unit tests for Unified One-Click Platform Launcher in run_system.py."""

import sys
import subprocess
from pathlib import Path
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import run_system


class TestRunSystemLauncher:
    """Test suite for run_system.py launcher."""

    def test_resolve_project_paths(self):
        backend_dir, frontend_dir = run_system.resolve_project_paths()

        assert backend_dir.exists()
        assert (backend_dir / "src" / "main.py").exists()
        assert frontend_dir.exists()
        assert (frontend_dir / "package.json").exists()

    def test_preflight_checks_execution(self):
        result = subprocess.run(
            [sys.executable, "run_system.py", "--check-only"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )

        assert "INITIALIZING SENTINEL-AI ENTERPRISE SOC PLATFORM" in result.stdout
        assert "SQLite database verified" in result.stdout or "initialized successfully" in result.stdout
        assert "FAISS vector store verified" in result.stdout or "generated successfully" in result.stdout
        assert "Frontend dependencies verified" in result.stdout or "installed successfully" in result.stdout
        assert "Pre-flight checks passed successfully" in result.stdout

    def test_cli_help_flag(self):
        result = subprocess.run(
            [sys.executable, "run_system.py", "--help"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )

        assert "--check-only" in result.stdout
        assert "--port-backend" in result.stdout
        assert "--port-frontend" in result.stdout
