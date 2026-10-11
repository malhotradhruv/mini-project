"""Unit tests for OfflineResilienceEngine in src/utils/mock_engine.py."""

from pathlib import Path
import sys
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.utils.mock_engine import OfflineResilienceEngine


class TestOfflineResilienceEngine:
    """Test suite for OfflineResilienceEngine fallbacks and generators."""

    def test_fallback_email_analysis_phishing(self):
        email_text = (
            "URGENT: Your account credentials have expired. "
            "Please click http://192.168.1.105/login immediately to verify."
        )
        result = OfflineResilienceEngine.get_fallback_email_analysis(email_text)

        assert result["is_malicious"] is True
        assert result["confidence"] >= 0.85
        assert "urgency" in result["dialogue_message"].lower()

    def test_fallback_email_analysis_benign(self):
        email_text = "Hi team, please find attached the meeting agenda for Monday morning sync."
        result = OfflineResilienceEngine.get_fallback_email_analysis(email_text)

        assert result["is_malicious"] is False
        assert result["confidence"] <= 0.20
        assert "routine" in result["dialogue_message"].lower()

    def test_fallback_log_analysis_failed_logins(self):
        log_text = (
            "Oct 11 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
            "Oct 11 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n"
            "Oct 11 02:14:06 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22"
        )
        result = OfflineResilienceEngine.get_fallback_log_analysis(log_text)

        assert result["is_malicious"] is True
        assert result["confidence"] >= 0.90
        assert "3 SSH failures" in result["dialogue_message"]

    def test_fallback_log_analysis_sudo_abuse(self):
        log_text = "Oct 11 03:00:10 srv1 sudo: webapp : 1 incorrect password attempt ; TTY=pts/0"
        result = OfflineResilienceEngine.get_fallback_log_analysis(log_text)

        assert result["is_malicious"] is True
        assert result["confidence"] >= 0.90
        assert "sudo violations" in result["dialogue_message"]

    def test_fallback_log_analysis_benign(self):
        log_text = "Oct 11 09:00:01 srv1 systemd[1]: Started Daily apt upgrade and clean activities."
        result = OfflineResilienceEngine.get_fallback_log_analysis(log_text)

        assert result["is_malicious"] is False
        assert result["confidence"] <= 0.20
        assert "Standard background audit logs" in result["dialogue_message"]

    def test_fallback_cve_catalog_known_services(self):
        apache_cves = OfflineResilienceEngine.get_fallback_cve_catalog("Apache 2.4.49")
        assert len(apache_cves) == 2
        cve_ids = [c["cve_id"] for c in apache_cves]
        assert "CVE-2021-41773" in cve_ids
        assert "CVE-2021-42013" in cve_ids

        openssh_cves = OfflineResilienceEngine.get_fallback_cve_catalog("OpenSSH 7.4p1")
        assert len(openssh_cves) == 2
        cve_ids = [c["cve_id"] for c in openssh_cves]
        assert "CVE-2018-15473" in cve_ids
        assert "CVE-2017-15906" in cve_ids

        vsftpd_cves = OfflineResilienceEngine.get_fallback_cve_catalog("vsftpd 2.3.4")
        assert len(vsftpd_cves) == 1
        assert vsftpd_cves[0]["cve_id"] == "CVE-2011-2523"
        assert vsftpd_cves[0]["cvss"] == 9.8

    def test_fallback_cve_catalog_unknown_service(self):
        unknown_cves = OfflineResilienceEngine.get_fallback_cve_catalog("CustomDaemon 1.0")
        assert len(unknown_cves) == 1
        assert "DEMO" in unknown_cves[0]["cve_id"]
        assert unknown_cves[0]["cvss"] == 7.2

    def test_fallback_supervisor_consensus(self):
        ip = "192.168.1.105"
        consensus = OfflineResilienceEngine.get_fallback_supervisor_consensus(ip, findings=[])

        assert consensus["threat_severity"] == "CRITICAL"
        assert consensus["consensus_confidence"] == 0.94
        assert ip in consensus["root_cause_analysis"]
        assert len(consensus["containment_commands"]) >= 4
        assert any(ip in cmd for cmd in consensus["containment_commands"])
        assert any("iptables" in cmd for cmd in consensus["containment_commands"])
        assert any("fail2ban" in cmd for cmd in consensus["containment_commands"])

    def test_mock_generators(self):
        phish = OfflineResilienceEngine.generate_mock_email("phishing")
        assert "URGENT" in phish
        assert "http" in phish

        ham = OfflineResilienceEngine.generate_mock_email("benign")
        assert "agenda" in ham

        mal_log = OfflineResilienceEngine.generate_mock_auth_log("brute_force")
        assert "Failed password" in mal_log

        clean_log = OfflineResilienceEngine.generate_mock_auth_log("benign")
        assert "systemd" in clean_log

        hypo = OfflineResilienceEngine.generate_mock_adversary_hypothesis()
        assert "predicted_next_step" in hypo
        assert "mitre_tactic" in hypo
        assert hypo["mitre_tactic"] == "Lateral Movement"
