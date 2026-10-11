"""Automated One-Click Scenario Injector CLI.

Allows live CLI-based examiner demonstrations without requiring manual data entry
or browser interactions. Supports staging:
- Scenario A: Coordinated Multi-Stage Attack Chain (--scenario attack)
- Scenario B: Benign & Disjoint Routine Traffic (--scenario benign)
"""

import os
import sys
import asyncio
import argparse
from pathlib import Path

# Safeguard console UTF-8 output on Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Enable VT100 ANSI sequences on Windows
if os.name == "nt":
    os.system("")

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

# Terminal ANSI Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"


async def run_scenario(scenario_type: str):
    """Executes the chosen scenario through the multi-agent cyber war-room swarm."""
    from src.core.swarm_graph import build_cyber_warroom_swarm

    print(f"\n{BOLD}{CYAN}" + "=" * 80)
    print("🚀 SENTINEL-AI: AUTONOMOUS CYBER WAR-ROOM DEMONSTRATION RUNNER")
    print("=" * 80 + f"{RESET}")

    swarm = build_cyber_warroom_swarm()

    if scenario_type == "attack":
        print(f"{YELLOW}[*] Staging Scenario A: Coordinated Multi-Stage Attack Chain{RESET}\n")
        state = {
            "task_id": "demo_attack_01",
            "raw_email_stream": (
                "URGENT: Corporate security patch required immediately. "
                "Visit http://192.168.1.105/auth.php or access will be revoked within 24 hours."
            ),
            "raw_log_stream": (
                "Oct 11 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 11 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 11 02:14:06 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 11 02:15:10 srv1 sudo: webapp : 3 incorrect password attempts ; TTY=pts/0"
            ),
            "target_cidr": "192.168.1.105",
            "messages": [],
            "specialist_findings": [],
            "next_speaker": "supervisor",
            "iteration_count": 0,
            "max_iterations": 8,
            "consensus_reached": False,
            "final_incident_report": None,
        }
    else:
        print(f"{GREEN}[*] Staging Scenario B: Benign & Disjoint Routine Traffic{RESET}\n")
        state = {
            "task_id": "demo_benign_01",
            "raw_email_stream": "Hi team, please find attached the meeting agenda for Monday morning sync.",
            "raw_log_stream": (
                "Oct 11 09:00:01 srv1 systemd[1]: Started Daily apt upgrade and clean activities.\n"
                "Oct 11 09:05:12 srv1 sshd[220]: Accepted publickey for admin from 10.0.0.15 port 54322"
            ),
            "target_cidr": "127.0.0.1",
            "messages": [],
            "specialist_findings": [],
            "next_speaker": "supervisor",
            "iteration_count": 0,
            "max_iterations": 8,
            "consensus_reached": False,
            "final_incident_report": None,
        }

    res = await swarm.ainvoke(state)

    print(f"\n{BOLD}--- 💬 REAL-TIME WAR-ROOM AGENT INTERACTION ---{RESET}")
    for msg in res.get("messages", []):
        sender = getattr(msg, "sender", msg.get("sender", "") if isinstance(msg, dict) else "")
        recipient = getattr(msg, "recipient", msg.get("recipient", "") if isinstance(msg, dict) else "")
        content = getattr(msg, "content", msg.get("content", "") if isinstance(msg, dict) else "")

        color = (
            YELLOW
            if sender == "LeadSupervisor"
            else (
                CYAN
                if sender == "EmailHunter"
                else (
                    GREEN
                    if sender == "LogForensics"
                    else (
                        BLUE
                        if sender == "NetworkRecon"
                        else (
                            RED
                            if sender in ["RedTeamAdversarySim", "RedTeamSim"]
                            else (
                                MAGENTA
                                if sender == "BlueTeamCommander"
                                else BOLD
                            )
                        )
                    )
                )
            )
        )
        print(f"{color}[{sender} ➔ {recipient}]{RESET} {content}")

    report = res.get("final_incident_report")
    is_active = getattr(report, "incident_active", False) if report else False
    if report and is_active:
        conf = getattr(report, "consensus_confidence", 0.0) * 100.0
        root_cause = getattr(report, "root_cause_analysis", "")
        commands = getattr(report, "containment_commands", [])

        print(f"\n{BOLD}{RED}" + "=" * 80)
        print(f"🚨 CRITICAL INCIDENT IDENTIFIED | CONFIDENCE: {conf:.1f}%")
        print("=" * 80 + f"{RESET}")
        print(f"{BOLD}Root Cause:{RESET} {root_cause}")
        print(f"\n{BOLD}Automated Containment Rules (SOAR Playbook):{RESET}")
        for cmd in commands:
            print(f"  {RED}# {cmd}{RESET}")
    else:
        print(f"\n{BOLD}{GREEN}" + "=" * 80)
        print("✅ NO COORDINATED BREACH DETECTED (False Positive Prevented)")
        print("=" * 80 + f"{RESET}")
        print("All incoming events remain isolated. No active multi-vector threat identified.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel SOC Scenario Runner")
    parser.add_argument(
        "--scenario",
        choices=["attack", "benign"],
        default="attack",
        help="Scenario to execute (attack or benign)",
    )
    args = parser.parse_args()
    asyncio.run(run_scenario(args.scenario))
