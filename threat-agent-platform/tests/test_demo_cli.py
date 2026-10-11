"""Unit tests for Automated One-Click Scenario Injector CLI in run_demo_cli.py."""

import asyncio
from pathlib import Path
import sys
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

import run_demo_cli


class TestDemoCliRunner:
    """Test suite for run_demo_cli."""

    def test_run_scenario_attack(self, capsys):
        asyncio.run(run_demo_cli.run_scenario("attack"))
        captured = capsys.readouterr()

        assert "SENTINEL-AI: AUTONOMOUS CYBER WAR-ROOM DEMONSTRATION RUNNER" in captured.out
        assert "Staging Scenario A: Coordinated Multi-Stage Attack Chain" in captured.out
        assert "REAL-TIME WAR-ROOM AGENT INTERACTION" in captured.out
        assert "CRITICAL INCIDENT IDENTIFIED" in captured.out
        assert "iptables -A INPUT" in captured.out

    def test_run_scenario_benign(self, capsys):
        asyncio.run(run_demo_cli.run_scenario("benign"))
        captured = capsys.readouterr()

        assert "SENTINEL-AI: AUTONOMOUS CYBER WAR-ROOM DEMONSTRATION RUNNER" in captured.out
        assert "Staging Scenario B: Benign & Disjoint Routine Traffic" in captured.out
        assert "NO COORDINATED BREACH DETECTED (False Positive Prevented)" in captured.out
