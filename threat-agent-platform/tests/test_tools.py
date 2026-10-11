"""Unit tests for deterministic forensic tools in src/utils/tools.py.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
"""

import os
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch
import pytest
import requests

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.utils.tools import (
    ThreatIntelligenceTools,
    SemanticVectorStore,
    NISTVulnerabilityEngine,
)


class TestThreatIntelligenceTools:
    """Tests for ThreatIntelligenceTools."""

    def test_extract_iocs_ips_urls_domains(self):
        sample_text = (
            "URGENT: Suspicious activity from 192.168.1.105 and 10.0.0.1. "
            "Visit https://login-verify-account.security-update.top/auth or www.malicious-portal.org/login "
            "for immediate recovery."
        )
        ips, urls, domains = ThreatIntelligenceTools.extract_iocs(sample_text)

        # Assert extracted IPs
        assert "192.168.1.105" in ips
        assert "10.0.0.1" in ips

        # Assert extracted URLs
        assert any("login-verify-account.security-update.top/auth" in u for u in urls)
        assert any("malicious-portal.org/login" in u for u in urls)

        # Assert extracted Domains
        assert "security-update.top" in domains
        assert "malicious-portal.org" in domains

    def test_extract_iocs_clean_text(self):
        clean_text = "Hello team, please see the meeting notes attached."
        ips, urls, domains = ThreatIntelligenceTools.extract_iocs(clean_text)
        assert ips == []
        assert urls == []
        assert domains == []

    def test_verify_dns_unresolvable_domain(self):
        res = ThreatIntelligenceTools.verify_dns("this-is-a-definitely-fake-domain-12345.xyz")
        assert res["resolvable"] is False
        assert len(res["flags"]) >= 1
        assert any("lacks valid DNS A-record" in f for f in res["flags"])

    def test_analyze_social_engineering(self):
        text = "Immediate action required! Your account suspended within 24 hours. Verify credentials now."
        analysis = ThreatIntelligenceTools.analyze_social_engineering(text)
        assert "immediate action" in analysis["urgency_matches"]
        assert "account suspended" in analysis["urgency_matches"]
        assert "24 hours" in analysis["urgency_matches"]
        assert "verify credentials" in analysis["urgency_matches"]
        assert isinstance(analysis["subjectivity_score"], float)
        assert isinstance(analysis["polarity_score"], float)


class TestSemanticVectorStore:
    """Tests for SemanticVectorStore."""

    def test_initialize_and_similarity_search(self):
        vstore = SemanticVectorStore()
        # Query similarity against phishing lure
        results = vstore.similarity_search("URGENT: Microsoft 365 password expired", top_k=2)
        assert isinstance(results, list)
        if len(vstore.documents) > 0:
            assert len(results) > 0
            assert "content" in results[0]
            assert "similarity" in results[0]
            assert 0.0 <= results[0]["similarity"] <= 1.0

    def test_empty_vector_store_behavior(self, tmp_path):
        empty_index_path = str(tmp_path / "empty_index.bin")
        vstore = SemanticVectorStore(index_path=empty_index_path)
        assert vstore.similarity_search("test query") == []

        # Add documents and search
        vstore.add_documents(["Phishing email template lure", "Benign meeting notice"])
        assert len(vstore.documents) == 2
        results = vstore.similarity_search("Phishing lure", top_k=1)
        assert len(results) == 1
        assert "similarity" in results[0]

        # Save and reload
        vstore.save()
        reloaded = SemanticVectorStore(index_path=empty_index_path)
        assert len(reloaded.documents) == 2


class TestNISTVulnerabilityEngine:
    """Tests for NISTVulnerabilityEngine."""

    def test_offline_benchmark_fallback_known_banners(self):
        engine = NISTVulnerabilityEngine()

        with patch("requests.get", side_effect=requests.RequestException("Offline mode")):
            # Test OpenSSH 7.4 fallback
            res_ssh = engine.query_cve_by_banner("OpenSSH 7.4")
            assert len(res_ssh) >= 2
            cve_ids_ssh = [item["cve_id"] for item in res_ssh]
            assert "CVE-2018-15473" in cve_ids_ssh

            # Test Apache 2.4.49 fallback
            res_apache = engine.query_cve_by_banner("Apache 2.4.49")
            assert len(res_apache) >= 2
            cve_ids_apache = [item["cve_id"] for item in res_apache]
            assert "CVE-2021-41773" in cve_ids_apache

    def test_offline_benchmark_fallback_unknown_banner(self):
        engine = NISTVulnerabilityEngine()
        with patch("requests.get", side_effect=requests.RequestException("Offline mode")):
            res = engine.query_cve_by_banner("Custom-Service-Daemon 1.0")
            assert len(res) == 1
            assert res[0]["cve_id"].startswith("CVE-2024-")
            assert res[0]["cvss"] == 6.8


    @patch("requests.get")
    def test_online_nvd_api_response_parsing(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-12345",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 8.8
                                    }
                                }
                            ]
                        }
                    }
                }
            ]
        }
        mock_get.return_value = mock_resp

        engine = NISTVulnerabilityEngine()
        results = engine.query_cve_by_banner("SomeService 2.0")
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2023-12345"
        assert results[0]["cvss"] == 8.8
