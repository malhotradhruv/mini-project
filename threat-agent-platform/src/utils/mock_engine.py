"""Offline Resilience, Tool Fallbacks & Mock Generators.

Provides deterministic forensic fallbacks and synthetic telemetry generators
to safeguard against network timeouts, API rate-limiting (HTTP 429), or missing
adapters during air-gapped lab simulations and presentation environments.
"""

import os
import json
from typing import Dict, Any, List, Optional


class OfflineResilienceEngine:
    """Automated deterministic fallback and mock generator engine."""

    @staticmethod
    def get_fallback_email_analysis(email_text: str) -> Dict[str, Any]:
        """Returns deterministic analysis if external LLM / Groq API is unreachable."""
        has_suspicious_url = "http" in email_text.lower() or "href" in email_text.lower()
        has_urgency = any(
            k in email_text.lower()
            for k in ["urgent", "expired", "suspended", "immediate", "action required"]
        )
        is_mal = has_suspicious_url and has_urgency
        return {
            "is_malicious": is_mal,
            "confidence": 0.89 if is_mal else 0.15,
            "dialogue_message": (
                "Offline Heuristics Engine: Detected high-pressure urgency cues paired with external IP/URI targets."
                if is_mal
                else "Email payload matches routine communication profile."
            ),
        }

    @staticmethod
    def get_fallback_log_analysis(log_text: str) -> Dict[str, Any]:
        """Returns deterministic log analysis when API connection is down."""
        lines = [l for l in log_text.split("\n") if l.strip()]
        failed_count = sum(1 for l in lines if "failed" in l.lower() or "invalid" in l.lower())
        sudo_count = sum(1 for l in lines if "sudo" in l.lower() and "incorrect" in l.lower())
        is_mal = failed_count >= 3 or sudo_count > 0
        return {
            "is_malicious": is_mal,
            "confidence": 0.92 if is_mal else 0.10,
            "dialogue_message": (
                f"Offline Log Engine: Identified authentication anomaly ({failed_count} SSH failures, {sudo_count} sudo violations)."
                if is_mal
                else "Standard background audit logs; no exploit signatures found."
            ),
        }

    @staticmethod
    def get_fallback_cve_catalog(service_name: str) -> List[Dict[str, Any]]:
        """Pre-cached local NIST NVD database for offline lab demonstrations."""
        catalog = {
            "Apache 2.4.49": [
                {
                    "cve_id": "CVE-2021-41773",
                    "cvss": 7.5,
                    "description": "Path traversal and file disclosure flaw.",
                },
                {
                    "cve_id": "CVE-2021-42013",
                    "cvss": 9.8,
                    "description": "Remote code execution flaw via mod_cgi.",
                },
            ],
            "OpenSSH 7.4": [
                {
                    "cve_id": "CVE-2018-15473",
                    "cvss": 5.3,
                    "description": "User enumeration flaw in auth2-gss.c.",
                },
                {
                    "cve_id": "CVE-2017-15906",
                    "cvss": 5.3,
                    "description": "Read-only sftp-server file creation denial.",
                },
            ],
            "vsftpd 2.3.4": [
                {
                    "cve_id": "CVE-2011-2523",
                    "cvss": 9.8,
                    "description": "Backdoor Command Execution via smiley face in username.",
                }
            ],
        }
        for banner, cves in catalog.items():
            if banner.lower() in service_name.lower():
                return cves
        return [
            {
                "cve_id": "CVE-2024-DEMO-01",
                "cvss": 7.2,
                "description": "Generic exposure advisory recorded.",
            }
        ]

    @staticmethod
    def get_fallback_supervisor_consensus(attacker_ip: str, findings: list) -> Dict[str, Any]:
        """Synthesizes structured incident consensus when cloud LLM fails."""
        return {
            "threat_severity": "CRITICAL",
            "consensus_confidence": 0.94,
            "root_cause_analysis": (
                f"Multi-vector intrusion campaign identified. Offending entity {attacker_ip} "
                f"observed across phishing lures, SSH brute force bursts, and open unpatched daemons."
            ),
            "containment_commands": [
                f"iptables -A INPUT -s {attacker_ip} -j DROP",
                f"iptables -A FORWARD -s {attacker_ip} -j DROP",
                "systemctl restart sshd",
                f"fail2ban-client set sshd banip {attacker_ip}",
            ],
        }

    @staticmethod
    def generate_mock_email(scenario: str = "phishing") -> str:
        """Generates realistic synthetic email telemetry for offline demonstrations."""
        if scenario.lower() in ["phishing", "phish", "malicious"]:
            return (
                "URGENT: Your account credentials have expired. "
                "Authenticate immediately at http://192.168.1.105/auth.php within 24 hours."
            )
        return "Hi team, please find attached the meeting agenda for Monday morning sync."

    @staticmethod
    def generate_mock_auth_log(scenario: str = "brute_force") -> str:
        """Generates realistic synthetic syslog telemetry for offline demonstrations."""
        if scenario.lower() in ["brute_force", "malicious", "attack"]:
            return (
                "Oct 11 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 11 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 11 02:14:06 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
                "Oct 11 02:15:10 srv1 sudo: webapp : 3 incorrect password attempts ; TTY=pts/0"
            )
        return "Oct 11 09:00:01 srv1 systemd[1]: Started Daily apt upgrade and clean activities."

    @staticmethod
    def generate_mock_adversary_hypothesis() -> Dict[str, Any]:
        """Generates deterministic adversary hypothesis for Red Team simulation."""
        return {
            "predicted_next_step": "Attacker will attempt lateral SSH pivot to internal subnet using stolen credentials.",
            "target_asset": "192.168.1.0/24 Subnet",
            "mitre_tactic": "Lateral Movement",
            "exploit_vector": "SSH Key Reuse / T1021.004",
            "war_room_broadcast": "Adversary Warning: Attacker possesses valid credentials and will attempt lateral movement.",
        }


__all__ = [
    "OfflineResilienceEngine",
]
