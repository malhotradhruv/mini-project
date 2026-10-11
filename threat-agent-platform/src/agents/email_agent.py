"""Email verification agent conforming to IEEE Access (Hmimou et al., 2025).

Executes hard deterministic forensic checks before calling the LLM:
1. Regex extraction of URLs, IPv4 addresses, and base domains via tldextract.
2. dnspython DNS resolution (A and MX records) flagging NXDOMAIN, unresolved, or blackhole responses.
3. TextBlob sentiment & urgency cue matching ('suspend', '24 hours', 'unauthorized transfer', 'verify credential').
4. FAISS vector similarity matching against known phishing threat templates (> 0.75 threshold).
5. Semantic synthesis with Groq LLaMA 3.3 (0.1 temperature) outputting a validated AgentReport.
"""

import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Union
import dns.resolver
from textblob import TextBlob
import tldextract
from dotenv import load_dotenv
from langchain_groq import ChatGroq

load_dotenv()

from src.models.schemas import AgentReport, ExtractedEntities
from src.core.llm_gateway import LLMGateway
from src.utils.vector_store import VectorStoreManager
from src.core.state import ThreatState, AgentFinding, ExtractedArtifacts
from src.utils.tools import ThreatIntelligenceTools, SemanticVectorStore


logger = logging.getLogger("EmailAgent")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class EmailAgent:
    """Specialized Email Forensic Verification Agent."""

    AGENT_ID = "email_agent"

    URGENCY_CUES = [
        "suspend",
        "24 hours",
        "unauthorized transfer",
        "verify credential",
        "immediately",
        "account suspended",
        "wire transfer",
        "wire payment",
        "within 2 hours",
        "security alert",
        "password expired",
        "action required",
        "verify account",
        "confidential",
        "do not call",
        "do not verify",
    ]

    SUSPICIOUS_TLDS = {"top", "xyz", "cc", "ru", "work", "click", "buzz", "support", "online"}

    def __init__(
        self,
        vector_store: Optional[Union[VectorStoreManager, LLMGateway]] = None,
        llm_gateway: Optional[Union[LLMGateway, VectorStoreManager]] = None,
    ):
        """Initialize EmailAgent with VectorStoreManager and LLMGateway.

        Supports both positional and keyword argument variations gracefully.
        """
        # Resolve potentially swapped positional arguments
        v_store = vector_store if isinstance(vector_store, VectorStoreManager) else None
        l_gw = llm_gateway if isinstance(llm_gateway, LLMGateway) else None

        if isinstance(vector_store, LLMGateway):
            l_gw = vector_store
        if isinstance(llm_gateway, VectorStoreManager):
            v_store = llm_gateway

        self.llm_gateway = l_gw or LLMGateway()

        if v_store:
            self.vector_store = v_store
        else:
            self.vector_store = VectorStoreManager()
            default_index = Path(__file__).resolve().parent.parent.parent / "data" / "indices" / "faiss_email_index.bin"
            if default_index.exists():
                try:
                    self.vector_store.load(default_index)
                except Exception as e:
                    logger.debug(f"Could not auto-load FAISS index: {e}")

    def _extract_artifacts(self, text: str) -> Dict[str, Any]:
        """Deterministically extract URLs, IPv4 addresses, and base domains."""
        # 1. Regex IPv4 extraction
        ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ips = list(set(re.findall(ip_pattern, text)))

        # 2. Regex URL extraction
        url_pattern = r"https?://[^\s<>\"']+"
        urls = re.findall(url_pattern, text)

        # 3. Base domain extraction via tldextract
        domains = set()
        for url in urls:
            host = url.split("://")[-1].split("/")[0].split(":")[0]
            ext = tldextract.extract(url)
            if ext.domain and ext.suffix:
                domains.add(f"{ext.domain}.{ext.suffix}")
            elif "." in host:
                parts = host.split(".")
                domains.add(".".join(parts[-2:]))

        # Also inspect sender/recipient email addresses
        email_pattern = r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,7})\b"
        for domain_match in re.findall(email_pattern, text):
            ext = tldextract.extract(domain_match)
            if ext.domain and ext.suffix:
                domains.add(f"{ext.domain}.{ext.suffix}")
            elif "." in domain_match:
                parts = domain_match.split(".")
                domains.add(".".join(parts[-2:]))

        # Timestamps
        ts_pattern = r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})?\b"
        timestamps = list(set(re.findall(ts_pattern, text)))

        return {
            "ips": ips,
            "urls": urls,
            "domains": sorted(list(domains)),
            "timestamps": timestamps,
        }

    def _check_dns(self, domains: List[str]) -> List[Dict[str, Any]]:
        """Verify each extracted domain using dnspython (A and MX records).

        Flags non-existent (NXDOMAIN), unresolved, or blackhole responses.
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.0
        resolver.lifetime = 1.0

        dns_results = []
        blackholes = {"0.0.0.0", "127.0.0.1", "127.0.0.2"}

        for domain in domains:
            record_info: Dict[str, Any] = {
                "domain": domain,
                "a_records": [],
                "mx_records": [],
                "is_anomalous": False,
                "anomaly_reason": None,
            }

            # Check A record
            try:
                answers_a = resolver.resolve(domain, "A")
                record_info["a_records"] = [str(r) for r in answers_a]
                if any(ip in blackholes for ip in record_info["a_records"]):
                    record_info["is_anomalous"] = True
                    record_info["anomaly_reason"] = f"Domain '{domain}' resolved to blackhole/sinkhole IP ({record_info['a_records']})"
            except dns.resolver.NXDOMAIN:
                record_info["is_anomalous"] = True
                record_info["anomaly_reason"] = f"Non-existent domain (NXDOMAIN) detected for '{domain}'"
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout) as exc:
                record_info["is_anomalous"] = True
                record_info["anomaly_reason"] = f"Unresolved DNS response for '{domain}' ({type(exc).__name__})"
            except Exception as exc:
                record_info["is_anomalous"] = True
                record_info["anomaly_reason"] = f"DNS resolution failure for '{domain}': {str(exc)}"

            # Check MX record
            try:
                answers_mx = resolver.resolve(domain, "MX")
                record_info["mx_records"] = [str(r.exchange).rstrip(".") for r in answers_mx]
            except Exception:
                pass

            dns_results.append(record_info)

        return dns_results

    def _analyze_urgency_and_sentiment(self, text: str) -> Dict[str, Any]:
        """Audit high-pressure urgency cues and TextBlob sentiment metrics."""
        text_lower = text.lower()
        matched_cues = [cue for cue in self.URGENCY_CUES if cue in text_lower]

        polarity = 0.0
        subjectivity = 0.0
        try:
            blob = TextBlob(text)
            polarity = round(float(blob.sentiment.polarity), 4)
            subjectivity = round(float(blob.sentiment.subjectivity), 4)
        except Exception:
            pass

        return {
            "matched_cues": matched_cues,
            "cue_count": len(matched_cues),
            "polarity": polarity,
            "subjectivity": subjectivity,
        }

    def analyze(self, payload: str) -> AgentReport:
        """Perform deterministic forensic pipeline followed by LLM semantic synthesis."""
        # 1. Extraction
        artifacts = self._extract_artifacts(payload)
        extracted_ips = artifacts["ips"]
        extracted_domains = artifacts["domains"]
        extracted_urls = artifacts["urls"]
        extracted_timestamps = artifacts["timestamps"]

        # 2. Deterministic DNS Verification
        dns_results = self._check_dns(extracted_domains)
        dns_anomalies = [r for r in dns_results if r["is_anomalous"]]

        # 3. Urgency & Sentiment Auditing
        urgency_audit = self._analyze_urgency_and_sentiment(payload)
        matched_cues = urgency_audit["matched_cues"]

        # 4. FAISS RAG Matching
        vector_matches = self.vector_store.search_similarity(payload, top_k=3)
        top_match = vector_matches[0] if vector_matches else None
        top_similarity = top_match["similarity_score"] if top_match else 0.0
        top_category = top_match["metadata"].get("category", "unknown") if top_match else "none"

        # 5. Deterministic Risk Scoring & Indicator Compilation
        technical_indicators = []
        score_accumulator = 0.0

        # DNS anomaly indicator
        for anomaly in dns_anomalies:
            score_accumulator += 0.35
            technical_indicators.append(f"DNS Forensics: {anomaly['anomaly_reason']}")

        # High-pressure urgency indicators
        if matched_cues:
            score_accumulator += min(len(matched_cues) * 0.15, 0.45)
            technical_indicators.append(
                f"Urgency Forensics: Identified high-pressure cues ({', '.join(matched_cues[:4])})"
            )

        # Suspicious TLD check
        for domain in extracted_domains:
            ext = tldextract.extract(domain)
            if ext.suffix in self.SUSPICIOUS_TLDS:
                score_accumulator += 0.25
                technical_indicators.append(f"High-Risk TLD: '.{ext.suffix}' in extracted domain '{domain}'")

        # Business Email Compromise (BEC) check
        bec_financial = ["wire transfer", "wire payment", "swift", "routing", "disbursement", "$", "dollar"]
        bec_urgency = ["today", "urgent", "immediate", "action required", "confidential", "immediately", "do not call", "do not verify", "exclusive"]
        if any(w in payload.lower() for w in bec_financial) and any(w in payload.lower() for w in bec_urgency):
            score_accumulator += 0.35
            technical_indicators.append("Business Email Compromise (BEC): High-risk wire transfer with urgency blackout")

        # Email auth header check
        if any(term in payload.lower() for term in ["dmarc=fail", "spf=fail", "dkim=fail"]):
            score_accumulator += 0.30
            technical_indicators.append("Email Authentication: SPF/DKIM/DMARC failure detected in headers")

        # Direct FAISS threat indicator rule: similarity > 0.75
        is_rag_direct_threat = (top_similarity > 0.75 and top_category == "phishing")
        if is_rag_direct_threat:
            score_accumulator += 0.45
            technical_indicators.append(
                f"FAISS RAG Threat Match: Nearest vector similarity {top_similarity:.2f} > 0.75 threshold (Category: {top_category})"
            )
        elif top_similarity >= 0.45 and top_category == "phishing":
            score_accumulator += 0.30
            technical_indicators.append(
                f"FAISS RAG Threat Match: High similarity ({top_similarity:.2f}) to known phishing signature"
            )
        elif top_similarity >= 0.70 and top_category == "legitimate":
            score_accumulator -= 0.30

        final_risk = max(0.0, min(1.0, score_accumulator))
        is_malicious = final_risk >= 0.50

        entities = ExtractedEntities(
            ips=extracted_ips,
            domains=extracted_domains,
            timestamps=extracted_timestamps,
            ports=[],
        )

        raw_evidence = {
            "urls": extracted_urls,
            "dns_audit": dns_results,
            "urgency_audit": urgency_audit,
            "faiss_nearest_match": {
                "similarity_score": top_similarity,
                "category": top_category,
                "sample_text": top_match["text"][:120] if top_match else "",
                "exceeds_threat_threshold": is_rag_direct_threat,
            },
        }

        # 6. LLM Semantic Synthesis
        system_prompt = (
            "You are an expert Email Verification Agent conforming to IEEE Access (Hmimou et al., 2025). "
            "You receive deterministic forensic findings: regex IOCs, dnspython resolution results, "
            "TextBlob urgency audits, and FAISS RAG similarity scores. "
            "Your task is strictly to provide a concise, factual, technical semantic synthesis of the threat. "
            "Return a JSON object with a single key 'explanation' containing your analysis."
        )

        user_prompt = (
            f"Forensic Evidence Summary:\n"
            f"- Extracted Base Domains: {extracted_domains}\n"
            f"- DNS Anomalies: {[a['anomaly_reason'] for a in dns_anomalies]}\n"
            f"- Urgency Cues: {matched_cues} (Subjectivity: {urgency_audit['subjectivity']})\n"
            f"- FAISS RAG Similarity: {top_similarity:.2f} (Category: {top_category}, Exceeds 0.75: {is_rag_direct_threat})\n"
            f"- Risk Score: {final_risk:.2f} (Malicious: {is_malicious})\n"
            f"- Technical Indicators: {technical_indicators}\n"
            f"- Email Payload Excerpt: {payload[:280]}\n\n"
            f"Synthesize this deterministic evidence into a structured technical justification."
        )

        explanation = ""
        try:
            llm_result = self.llm_gateway.query_json(system_prompt, user_prompt)
            explanation = llm_result.get("explanation", "")
        except Exception:
            pass

        if not explanation:
            status_desc = "Malicious phishing/social engineering campaign" if is_malicious else "Legitimate email communication"
            explanation = (
                f"{status_desc} confirmed with risk score {final_risk:.2f}. "
                f"Forensic indicators: {'; '.join(technical_indicators) or 'Baseline telemetry within normal limits.'}"
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
vector_db = SemanticVectorStore()
_groq_key = os.getenv("GROQ_API_KEY") or "gsk_placeholder_for_offline_eval"
llm = ChatGroq(model_name="llama-3.3-70b-versatile", temperature=0.1, groq_api_key=_groq_key)


async def email_agent_node(state: ThreatState) -> dict:
    """Specialized Email Security worker node in the LangGraph supervisor workflow."""
    raw_text = state.get("raw_email", "")
    if not raw_text.strip():
        return {"audit_trace": ["EmailAgent: Empty payload passed. Skipping."]}

    # 1. Deterministic Analysis
    ips, urls, domains = ThreatIntelligenceTools.extract_iocs(raw_text)
    dns_findings = []
    for domain in domains:
        res = ThreatIntelligenceTools.verify_dns(domain)
        dns_findings.extend(res["flags"])

    social_eng = ThreatIntelligenceTools.analyze_social_engineering(raw_text)
    rag_matches = vector_db.similarity_search(raw_text, top_k=1)
    top_similarity = rag_matches[0]["similarity"] if rag_matches else 0.0

    indicators = list(dns_findings)
    if social_eng["urgency_matches"]:
        indicators.append(f"Urgency keywords: {social_eng['urgency_matches']}")
    if top_similarity > 0.70:
        indicators.append(f"Vector similarity match to known phishing: {top_similarity:.2f}")

    # 2. Structured LLM Synthesis
    prompt = f"""You are a specialized Email Security Agent. 
Analyze the technical indicators and formulate a risk assessment.
Output STRICT JSON matching keys: is_malicious (bool), risk_score (float 0.0-1.0), explanation (str).

Evidence:
- Text: {raw_text}
- Extracted IPs: {ips}
- Extracted Domains: {domains}
- Deterministic Flags: {indicators}
- Vector Match Score: {top_similarity}"""

    try:
        response = await llm.ainvoke([
            {"role": "system", "content": "You are a cyber security analyst. Respond ONLY in valid JSON."},
            {"role": "user", "content": prompt}
        ])
        data = json.loads(response.content)
    except Exception:
        data = {
            "is_malicious": len(indicators) > 0,
            "risk_score": 0.8 if indicators else 0.1,
            "explanation": "Deterministic heuristic evaluation.",
        }

    risk_val = min(max(float(data.get("risk_score", 0.1)), 0.0), 1.0)
    finding = AgentFinding(
        agent_id="EmailIntelligenceAgent",
        is_malicious=bool(data.get("is_malicious", False)),
        risk_score=risk_val,
        artifacts=ExtractedArtifacts(ips=ips, domains=domains, urls=urls),
        indicators=indicators,
        raw_evidence={"social_eng": social_eng, "rag_score": top_similarity},
        analyst_summary=data.get("explanation", "Forensic analysis completed.")
    )
    return {
        "findings": [finding],
        "audit_trace": [f"EmailAgent completed with risk {finding.risk_score}"]
    }


__all__ = [
    "EmailAgent",
    "email_agent_node",
    "vector_db",
    "llm",
]

