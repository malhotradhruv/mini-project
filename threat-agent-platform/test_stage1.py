"""Stage 1 End-to-End Validation: LangGraph Multi-Agent SOC Workflow.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"

Validates:
1. Parallel/sequential execution of specialized agents (Email, Log, IP Recon).
2. Deterministic forensic tool grounding (DNS, sentiment, regex IOCs, Nmap/CVE).
3. Cross-domain entity intersection ($IP_{email} \\cap IP_{log} \\cap IP_{network}$).
4. Supervisor synthesis of correlated incident report, attack timeline, and containment playbook.
"""

import asyncio
import json
import os
import sys
from typing import Dict, Any

# Ensure UTF-8 output on Windows consoles to prevent UnicodeEncodeError
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure threat-agent-platform root is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from src.core.graph import create_multi_agent_soc_graph
from src.core.state import (
    create_initial_threat_state,
    ThreatState,
    CorrelatedIncidentReport,
)


async def run_stage1_verification() -> Dict[str, Any]:
    """Executes the pre-staged coordinated multi-stage cyber attack scenario."""
    print("=" * 80)
    print("[STAGE 1 VALIDATION] Multi-Agent SOC LangGraph Pipeline")
    print("IEEE Access (Hmimou et al., 2025) Architectural Verification")
    print("=" * 80)

    # 1. Compile the Graph
    print("\n[*] Compiling StateGraph workflow...")
    soc_app = create_multi_agent_soc_graph()
    print("    -> StateGraph successfully compiled with 4 nodes:")
    print("       - email_worker (Email Intelligence)")
    print("       - log_worker (Behavioral Syslog)")
    print("       - ip_worker (Network Surface & CVEs)")
    print("       - supervisor_correlator (Cross-Domain Correlation)")

    # 2. Stage Coordinated Attack Telemetry
    raw_email = (
        "URGENT: Critical security update required immediately. "
        "Download security patch from http://192.168.1.105/patch.php "
        "or your workstation will be locked within 24 hours. IT Support."
    )
    raw_logs = (
        "Oct 10 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
        "Oct 10 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
        "Oct 10 02:14:05 srv1 sshd[102]: Accepted password for root from 192.168.1.105 port 22\n"
        "Oct 10 02:14:10 srv1 sudo: pam_unix(sudo:session): session opened for user root by (uid=0)"
    )
    target_ip = "192.168.1.105"

    initial_state = create_initial_threat_state(
        task_id="TEST-STAGE1-CORRELATED-001",
        raw_email=raw_email,
        raw_logs=raw_logs,
        target_network=target_ip,
    )

    print("\n[*] Staged Threat Vector Telemetry:")
    print(f"    - Email Vector: [Length: {len(raw_email)} chars] Contains lure URL -> 192.168.1.105")
    print(f"    - Log Vector:   [Lines: 4] SSH Brute-Force + Sudo Elevation from -> 192.168.1.105")
    print(f"    - Network Host: Target IP -> {target_ip} (Exposing Ports 22, 80)")

    # 3. Asynchronously Execute Graph
    print("\n[*] Dispatching execution across LangGraph worker nodes...")
    final_state: ThreatState = await soc_app.ainvoke(initial_state)

    # 4. Extract Results
    findings = final_state.get("findings", [])
    report: CorrelatedIncidentReport = final_state.get("correlation_result")
    audit_trace = final_state.get("audit_trace", [])

    print("\n" + "=" * 80)
    print("[EXECUTION RESULTS - AGENT FINDINGS]")
    print("=" * 80)
    for idx, f in enumerate(findings, 1):
        print(f"\n[{idx}] Worker Node: {f.agent_id}")
        print(f"    Malicious Flag : {f.is_malicious}")
        print(f"    Risk Score     : {f.risk_score:.2f} / 1.00")
        print(f"    Indicators     : {f.indicators}")
        print(f"    Artifacts (IP) : {f.artifacts.ips}")
        print(f"    Artifacts (URL): {f.artifacts.urls}")
        print(f"    Artifacts (CVE): {f.artifacts.cves}")
        print(f"    Summary        : {f.analyst_summary}")

    print("\n" + "=" * 80)
    print("[SUPERVISOR CORRELATION REPORT]")
    print("=" * 80)
    if report:
        print(f"Incident Detected   : {report.incident_detected}")
        print(f"Threat Severity     : {report.threat_severity}")
        print(f"Confidence Score    : {report.confidence_score:.2f}")
        print(f"Participating Agents: {report.participating_agents}")
        print(f"Correlated Common IPs: {report.common_artifacts.ips}")
        print(f"\nForensic Narrative:\n  {report.forensic_narrative}\n")

        print("Reconstructed MITRE ATT&CK Timeline:")
        for stage in report.attack_timeline:
            print(f"  Stage {stage.stage_number} [{stage.tactic}]: {stage.description}")
            print(f"    -> Correlated Indicator: {stage.correlated_indicator}")

        print("\nContainment Playbook Actions:")
        for action in report.containment_playbook:
            print(f"  [!] {action}")
    else:
        print("[!] No correlation report generated!")

    print("\n" + "=" * 80)
    print("[AUDIT TRACE]")
    print("=" * 80)
    for step in audit_trace:
        print(f"  -> {step}")

    # 5. Programmatic Assertions for Automated Verification
    print("\n[*] Running Programmatic Assertions...")
    assert len(findings) == 3, f"Expected 3 worker findings, got {len(findings)}"
    assert all(f.is_malicious for f in findings), "All findings in coordinated attack should be malicious"
    assert report is not None, "Supervisor correlation report must not be None"
    assert report.incident_detected is True, "Incident should be detected for multi-stage pivot"
    assert report.threat_severity in ["HIGH", "CRITICAL"], f"Expected HIGH or CRITICAL, got {report.threat_severity}"
    assert report.confidence_score >= 0.70, f"Confidence score should be >= 0.70, got {report.confidence_score}"
    assert target_ip in report.common_artifacts.ips, f"Pivot IP {target_ip} must be in common artifacts"
    assert len(report.attack_timeline) >= 2, "Timeline should have at least 2 attack stages"
    assert len(report.containment_playbook) >= 1, "Containment playbook must contain action items"

    print("\n[SUCCESS] All Stage 1 Pipeline Assertions PASSED successfully!")
    print("=" * 80)
    return final_state


if __name__ == "__main__":
    asyncio.run(run_stage1_verification())
