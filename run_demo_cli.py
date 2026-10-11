"""Automated One-Click Scenario Injector CLI (Workspace Root Wrapper).

Allows live CLI-based examiner demonstrations without requiring manual data entry
or browser interactions. Supports staging:
- Scenario A: Coordinated Multi-Stage Attack Chain (--scenario attack)
- Scenario B: Benign & Disjoint Routine Traffic (--scenario benign)
"""

import os
import sys
from pathlib import Path

# Ensure threat-agent-platform root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent / "threat-agent-platform"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

import run_demo_cli

if __name__ == "__main__":
    import asyncio
    import argparse

    parser = argparse.ArgumentParser(description="Sentinel SOC Scenario Runner")
    parser.add_argument(
        "--scenario",
        choices=["attack", "benign"],
        default="attack",
        help="Scenario to execute (attack or benign)",
    )
    args = parser.parse_args()
    asyncio.run(run_demo_cli.run_scenario(args.scenario))
