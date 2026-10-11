"""Behavioral log analyzer agent conforming to IEEE Access (Hmimou et al., 2025).

Executes hard deterministic forensic checks before calling the LLM:
1. Log normalization & feature extraction (multiline auth.log, web access, CIC-IDS text streams).
   Extracts IPv4 addresses, target user accounts, and HH:MM:SS timestamps.
2. Rule-based anomaly scoring:
   - Brute Force: Flag if failed authentication attempts from a single IP exceed 3 occurrences.
   - Privilege Escalation: Flag unauthorized sudo attempts or failed su sequences.
   - Web Exploits: Flag HTTP 500 status codes, path traversals ('../'), or SQL syntax strings.
3. Chain-of-Thought LLM Summarization:
   Constructs a forensic sequence summary and evaluates attacker persistence.
4. Returns a strictly validated Pydantic AgentReport.
"""

from collections import defaultdict
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set
from dotenv import load_dotenv
from langchain_groq import ChatGroq

load_dotenv()

from src.models.schemas import AgentReport, ExtractedEntities
from src.core.llm_gateway import LLMGateway
from src.core.state import ThreatState, AgentFinding, ExtractedArtifacts


logger = logging.getLogger("LogAgent")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class LogAgent:
    """Specialized Behavioral Log Forensic Analyzer Agent."""

    AGENT_ID = "log_agent"

    # Regular expressions for log entity extraction
    IP_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
    TIMESTAMP_REGEX = re.compile(r"\b(\d{2}:\d{2}:\d{2})\b")
    USER_PATTERNS = [
        re.compile(r"for\s+(?:invalid\s+user\s+)?([A-Za-z0-9._-]+)", re.IGNORECASE),
        re.compile(r"user[=:\s]+([A-Za-z0-9._-]+)", re.IGNORECASE),
        re.compile(r"sudo:\s+([A-Za-z0-9._-]+)\s*:", re.IGNORECASE),
        re.compile(r"USER=([A-Za-z0-9._-]+)", re.IGNORECASE),
    ]

    # Web exploit patterns
    PATH_TRAVERSAL_REGEX = re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)", re.IGNORECASE)
    SQLI_PATTERNS = [
        re.compile(r"UNION\s+SELECT", re.IGNORECASE),
        re.compile(r"'\s*OR\s*'1'\s*=\s*'1", re.IGNORECASE),
        re.compile(r"\bOR\s+1\s*=\s*1\b", re.IGNORECASE),
        re.compile(r"DROP\s+TABLE", re.IGNORECASE),
        re.compile(r"SLEEP\s*\(", re.IGNORECASE),
        re.compile(r";\s*--", re.IGNORECASE),
        re.compile(r"INFORMATION_SCHEMA", re.IGNORECASE),
        re.compile(r"\bsqlmap\b", re.IGNORECASE),
    ]
    HTTP_500_REGEX = re.compile(r'(?:"\s+500\s+|\bHTTP/\d\.\d"?\s+500\b|\bstatus=500\b|\b500\s+\d+)', re.IGNORECASE)

    # Privilege escalation patterns
    PRIV_ESC_PATTERNS = [
        re.compile(r"NOT\s+in\s+sudoers", re.IGNORECASE),
        re.compile(r"incorrect\s+password\s+attempts", re.IGNORECASE),
        re.compile(r"FAILED\s+SU\b", re.IGNORECASE),
        re.compile(r"failed\s+su\b", re.IGNORECASE),
        re.compile(r"su(?:\[\d+\])?:\s+pam_authenticate:\s+Authentication\s+failure", re.IGNORECASE),
        re.compile(r"su:\s+authentication\s+failure", re.IGNORECASE),
        re.compile(r"COMMAND=.*(?:/bin/bash|/bin/sh|curl.*\|.*bash|wget.*\|.*bash|chmod\s+\+x)", re.IGNORECASE),
    ]

    def __init__(self, llm_gateway: Optional[LLMGateway] = None):
        """Initialize LogAgent with resilient LLMGateway."""
        self.llm_gateway = llm_gateway or LLMGateway()

    def _normalize_and_extract(self, log_text: str) -> Dict[str, Any]:
        """Normalize log stream and extract IPs, user accounts, and HH:MM:SS timestamps."""
        lines = [line.strip() for line in log_text.strip().splitlines() if line.strip()]

        all_ips: Set[str] = set()
        all_timestamps: List[str] = []
        all_users: Set[str] = set()
        parsed_lines: List[Dict[str, Any]] = []

        for line in lines:
            line_ips = self.IP_REGEX.findall(line)
            for ip in line_ips:
                all_ips.add(ip)

            ts_match = self.TIMESTAMP_REGEX.search(line)
            timestamp = ts_match.group(1) if ts_match else "00:00:00"
            if ts_match:
                all_timestamps.append(timestamp)

            line_user = None
            for upat in self.USER_PATTERNS:
                um = upat.search(line)
                if um:
                    line_user = um.group(1)
                    all_users.add(line_user)
                    break

            parsed_lines.append({
                "raw": line,
                "timestamp": timestamp,
                "ips": line_ips,
                "user": line_user,
            })

        return {
            "parsed_lines": parsed_lines,
            "ips": sorted(list(all_ips)),
            "timestamps": all_timestamps,
            "users": sorted(list(all_users)),
            "total_lines": len(lines),
        }

    def _audit_anomalies(self, parsed_lines: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute deterministic rule checks for Brute Force, Priv Esc, and Web Exploits."""
        failed_logins_per_ip: Dict[str, int] = defaultdict(int)
        flagged_lines: List[str] = []
        brute_force_flags: List[str] = []
        priv_esc_flags: List[str] = []
        web_exploit_flags: List[str] = []

        for entry in parsed_lines:
            line = entry["raw"]
            ts = entry["timestamp"]
            ips = entry["ips"]
            is_line_flagged = False

            # 1. Failed Authentication Check
            if any(term in line.lower() for term in ["failed password", "authentication failure", "failed login", "invalid user"]):
                if ips:
                    for ip in ips:
                        failed_logins_per_ip[ip] += 1
                else:
                    failed_logins_per_ip["unknown"] += 1

            # 2. Privilege Escalation Check
            for pat in self.PRIV_ESC_PATTERNS:
                if pat.search(line):
                    priv_esc_flags.append(f"Privilege Escalation Event [{ts}]: {line}")
                    is_line_flagged = True
                    break

            # 3. Web Exploit Check: Path Traversal
            if self.PATH_TRAVERSAL_REGEX.search(line):
                web_exploit_flags.append(f"Path Traversal Pattern [{ts}]: {line}")
                is_line_flagged = True

            # 4. Web Exploit Check: SQL Injection
            for sqli in self.SQLI_PATTERNS:
                if sqli.search(line):
                    web_exploit_flags.append(f"SQL Injection Syntax [{ts}]: {line}")
                    is_line_flagged = True
                    break

            # 5. Web Exploit Check: HTTP 500 Status
            if self.HTTP_500_REGEX.search(line):
                web_exploit_flags.append(f"Server Error (HTTP 500) [{ts}]: {line}")
                is_line_flagged = True

            if is_line_flagged or any(term in line.lower() for term in ["failed password", "accepted password", "sudo:", "command="]):
                flagged_lines.append(f"[{ts}] {line}")

        # Check Brute Force threshold (>= 3 occurrences per IP)
        for ip, count in failed_logins_per_ip.items():
            if count >= 3:
                brute_force_flags.append(
                    f"Brute Force Detected: IP {ip} reached threshold with {count} failed authentication attempts (>= 3)"
                )

        return {
            "failed_counts": dict(failed_logins_per_ip),
            "brute_force_flags": brute_force_flags,
            "priv_esc_flags": priv_esc_flags,
            "web_exploit_flags": web_exploit_flags,
            "flagged_lines": flagged_lines,
        }

    def analyze(self, payload: str) -> AgentReport:
        """Perform deterministic behavioral log audit followed by Chain-of-Thought LLM summarization."""
        # 1. Log Normalization & Feature Extraction
        norm = self._normalize_and_extract(payload)
        parsed_lines = norm["parsed_lines"]

        # 2. Rule-Based Anomaly Scoring
        anomalies = self._audit_anomalies(parsed_lines)
        brute_flags = anomalies["brute_force_flags"]
        priv_flags = anomalies["priv_esc_flags"]
        web_flags = anomalies["web_exploit_flags"]
        flagged_chronological = anomalies["flagged_lines"]

        technical_indicators = []
        score_accumulator = 0.0

        if brute_flags:
            score_accumulator += 0.60
            technical_indicators.extend(brute_flags)
        elif any(c >= 2 for c in anomalies["failed_counts"].values()):
            score_accumulator += 0.25
            technical_indicators.append("Multiple failed authentication attempts detected below threshold")

        if priv_flags:
            score_accumulator += 0.60
            technical_indicators.extend(priv_flags)

        if web_flags:
            score_accumulator += 0.60
            technical_indicators.extend(web_flags)

        final_risk = max(0.0, min(1.0, score_accumulator))
        is_malicious = final_risk >= 0.50

        entities = ExtractedEntities(
            ips=norm["ips"],
            domains=[],
            timestamps=norm["timestamps"],
            ports=[],
        )

        raw_evidence = {
            "total_lines": norm["total_lines"],
            "targeted_users": norm["users"],
            "failed_attempts_by_ip": anomalies["failed_counts"],
            "brute_force_events": brute_flags,
            "privilege_escalation_events": priv_flags,
            "web_exploit_events": web_flags,
            "flagged_sequence_sample": flagged_chronological[:10],
        }

        # 3. Chain-of-Thought LLM Summarization
        system_prompt = (
            "You are an expert Behavioral Log Forensics Agent conforming to IEEE Access (Hmimou et al., 2025). "
            "You are provided with verified chronological log indicators extracted deterministically. "
            "Follow Chain-of-Thought reasoning to: "
            "1. Construct a step-by-step forensic sequence summary. "
            "2. Evaluate attacker persistence (e.g. brute-force velocity, target rotation, privilege transition). "
            "Return a JSON object with a single key 'explanation' containing your analysis."
        )

        user_prompt = (
            f"Flagged Chronological Log Stream:\n"
            + "\n".join(flagged_chronological[:15]) + "\n\n"
            f"Forensic Indicators:\n"
            f"- Brute Force Flags: {brute_flags}\n"
            f"- Privilege Escalation Flags: {priv_flags}\n"
            f"- Web Exploit Flags: {web_flags}\n"
            f"- Targeted Accounts: {norm['users']}\n"
            f"- Computed Risk Score: {final_risk:.2f} (Malicious: {is_malicious})\n\n"
            f"Construct the forensic sequence summary and evaluate attacker persistence."
        )

        explanation = ""
        try:
            llm_result = self.llm_gateway.query_json(system_prompt, user_prompt)
            explanation = llm_result.get("explanation", "")
        except Exception:
            pass

        if not explanation:
            if is_malicious:
                explanation = (
                    f"Forensic sequence analysis confirmed anomalous behavioral threat (Risk: {final_risk:.2f}). "
                    f"Indicators: {'; '.join(technical_indicators)}."
                )
            else:
                explanation = (
                    f"Baseline log analysis concluded benign authentication state (Risk: {final_risk:.2f}). "
                    f"Total lines analyzed: {norm['total_lines']}."
                )

        return AgentReport(
            agent_id=self.AGENT_ID,
            is_malicious=is_malicious,
            risk_score=final_risk,
            entities=entities,
            technical_indicators=technical_indicators,
            raw_evidence=raw_evidence,
            explanation=explanation,
        )


# =============================================================================
# LANGGRAPH NODE IMPLEMENTATION
# =============================================================================
_groq_key = os.getenv("GROQ_API_KEY") or "gsk_placeholder_for_offline_eval"
llm = ChatGroq(model_name="llama-3.3-70b-versatile", temperature=0.1, groq_api_key=_groq_key)


async def log_agent_node(state: ThreatState) -> dict:
    """Specialized Behavioral Log Forensics worker node in the LangGraph workflow."""
    raw_logs = state.get("raw_logs", "")
    if not raw_logs.strip():
        return {"audit_trace": ["LogAgent: No logs provided. Skipping."]}

    lines = [line.strip() for line in raw_logs.split("\n") if line.strip()]
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    time_pattern = r'\b\d{2}:\d{2}:\d{2}\b'

    ips = list(set(re.findall(ip_pattern, raw_logs)))
    timestamps = list(set(re.findall(time_pattern, raw_logs)))
    indicators = []

    # State Machine checks
    failed_attempts = sum(1 for l in lines if "failed" in l.lower() or "invalid user" in l.lower())
    sudo_abuses = sum(1 for l in lines if "sudo" in l.lower() and ("incorrect password" in l.lower() or "session opened for user root" in l.lower() or "not in sudoers" in l.lower()))
    http_500s = sum(1 for l in lines if " 500 " in l or "internal error" in l.lower())

    if failed_attempts >= 2:
        indicators.append(f"Brute force signature: {failed_attempts} failed authentication attempts")
    if sudo_abuses > 0:
        indicators.append(f"Privilege escalation alert: {sudo_abuses} unauthorized sudo executions")
    if http_500s > 0:
        indicators.append(f"Web application exploit attempt: {http_500s} HTTP 500 anomalies")

    prompt = f"""You are a Log Forensics Agent. Output STRICT JSON with keys: is_malicious (bool), risk_score (float 0.0-1.0), explanation (str).
Logs:
{raw_logs}
Heuristics:
{indicators}
Extracted IPs: {ips}"""

    try:
        response = await llm.ainvoke([
            {"role": "system", "content": "You are a cyber forensics investigator. Respond ONLY in valid JSON."},
            {"role": "user", "content": prompt}
        ])
        data = json.loads(response.content)
    except Exception:
        data = {
            "is_malicious": len(indicators) > 0,
            "risk_score": 0.85 if indicators else 0.1,
            "explanation": "Evaluated via log state heuristics.",
        }

    risk_val = min(max(float(data.get("risk_score", 0.1)), 0.0), 1.0)
    finding = AgentFinding(
        agent_id="BehavioralLogAgent",
        is_malicious=bool(data.get("is_malicious", False)),
        risk_score=risk_val,
        artifacts=ExtractedArtifacts(ips=ips, timestamps=timestamps),
        indicators=indicators,
        raw_evidence={"total_lines": len(lines), "failed_logins": failed_attempts},
        analyst_summary=data.get("explanation", "Log forensic analysis completed.")
    )
    return {
        "findings": [finding],
        "audit_trace": [f"LogAgent completed with risk {finding.risk_score}"]
    }


__all__ = [
    "LogAgent",
    "log_agent_node",
    "llm",
]

