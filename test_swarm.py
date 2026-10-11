"""Autonomous Cyber War-Room Swarm Terminal Runner.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
"""

import asyncio
import uuid
import sys
from pathlib import Path

# Ensure UTF-8 console output for Windows terminal compatibility
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure threat-agent-platform root and src are in sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = WORKSPACE_ROOT / "threat-agent-platform"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.core.swarm_graph import build_cyber_warroom_swarm


async def main():
    print("=" * 80)
    print("🚨 ACTIVATING AUTONOMOUS CYBER WAR-ROOM SWARM")
    print("=" * 80)

    swarm = build_cyber_warroom_swarm()

    initial_state = {
        "task_id": str(uuid.uuid4()),
        "raw_email_stream": "URGENT: Corporate security certificate renewal. Authenticate immediately at http://192.168.1.105/cert.php",
        "raw_log_stream": """Oct 11 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22
Oct 11 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22
Oct 11 02:14:06 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22
Oct 11 02:15:10 srv1 sudo: user : 3 incorrect password attempts ; TTY=pts/0""",
        "target_cidr": "192.168.1.105",
        "messages": [],
        "specialist_findings": [],
        "next_speaker": "supervisor",
        "iteration_count": 0,
        "max_iterations": 10,
        "consensus_reached": False,
        "final_incident_report": None,
    }

    final_state = await swarm.ainvoke(initial_state)

    print("\n--- 💬 LIVE AGENT WAR-ROOM CONVERSATION ---")
    for msg in final_state["messages"]:
        prefix = f"[{msg.sender} ➔ {msg.recipient}]"
        print(f"{prefix:<35} : {msg.content}")

    report = final_state["final_incident_report"]
    if report:
        print("\n" + "=" * 80)
        print(f"🛡️  SWARM INCIDENT REPORT | SEVERITY: {report.threat_severity} | CONFIDENCE: {report.consensus_confidence*100:.1f}%")
        print("=" * 80)
        print(f"Root Cause: {report.root_cause_analysis}")
        print("\nAutomated Containment Commands:")
        for cmd in report.containment_commands:
            print(f"  # {cmd}")


if __name__ == "__main__":
    asyncio.run(main())
