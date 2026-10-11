"""Pre-populates FAISS vector store index with phishing templates and benign communications.

Creates and saves data/indices/faiss_email_index.bin using VectorStoreManager.
Reference: IEEE Access (Hmimou et al., 2025).
"""

import os
import sys
from pathlib import Path

# Add project root and src to Python path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.utils.vector_store import VectorStoreManager

PHISHING_TEMPLATES = [
    {
        "text": "URGENT: Your Microsoft 365 account has been suspended due to unauthorized login attempts. Click here immediately to verify your credentials: https://login-microsoft-security.verify-portal.top/auth",
        "metadata": {"category": "phishing", "type": "account_lockout", "severity": "high"}
    },
    {
        "text": "IMMEDIATE ACTION REQUIRED: Security Alert - Your Google Workspace password expired today. Renew credentials now to prevent mailbox deletion: http://accounts-google-verify.net/reset",
        "metadata": {"category": "phishing", "type": "account_lockout", "severity": "high"}
    },
    {
        "text": "CONFIDENTIAL: Wire transfer payment needed before close of business today for urgent vendor acquisition. Please process $48,500 immediately to attached routing info. Do not call CFO as he is in closed hearings.",
        "metadata": {"category": "phishing", "type": "ceo_fraud_bec", "severity": "critical"}
    },
    {
        "text": "URGENT PAYMENT: Please execute the overdue supplier wire transfer detailed below immediately to avoid shipment hold. Routing: 021000021, Account: 9840291823.",
        "metadata": {"category": "phishing", "type": "ceo_fraud_bec", "severity": "critical"}
    },
    {
        "text": "Global IT Department: Mandatory critical VPN client security patch update. All employees must download and run the executable patch before end of day: http://internal-vpn-patch.top/download/cisco_patch.exe",
        "metadata": {"category": "phishing", "type": "spoofed_it_update", "severity": "high"}
    },
    {
        "text": "IT Service Desk: Network maintenance requires immediate credentials resynchronization. Log into the corporate active directory sync tool here: http://sso-internal-corp-auth.com",
        "metadata": {"category": "phishing", "type": "spoofed_it_update", "severity": "high"}
    },
    {
        "text": "HR Notification: Discrepancy detected in your direct deposit bank account details for upcoming payroll. Verify your banking information within 24 hours to prevent delayed paycheck: http://hr-portal-payroll-benefits.org/login",
        "metadata": {"category": "phishing", "type": "credential_harvesting", "severity": "high"}
    },
    {
        "text": "Accounting notice: Invoice #INV-849202 has been shared with you via OneDrive. Please review payment breakdown: https://onedrive-secure-doc-share.ru/view/inv849202.pdf.exe",
        "metadata": {"category": "phishing", "type": "malware_delivery", "severity": "critical"}
    },
    {
        "text": "Duo Security: Two-factor authentication device reset requested from IP 185.220.101.5. If this was not requested by you, disavow and confirm your PIN code immediately: http://duo-mfa-verify.support/disavow",
        "metadata": {"category": "phishing", "type": "mfa_reset_spoof", "severity": "high"}
    },
    {
        "text": "DocuSign: Please review and electronically sign 'Executive_Severance_Agreement.pdf'. Access the document through this link: http://docusign-envelope-review.cc/sign",
        "metadata": {"category": "phishing", "type": "credential_harvesting", "severity": "high"}
    }
]

LEGITIMATE_SAMPLES = [
    {
        "text": "Hi team, here is the agenda for tomorrow's weekly engineering sprint planning at 10:00 AM EST. Please ensure all backlog tasks are estimated and updated in Jira.",
        "metadata": {"category": "legitimate", "type": "internal_team_planning", "severity": "none"}
    },
    {
        "text": "Could you please review PR #412 when you have a moment? I refactored the database connection pooling logic and updated unit tests in the repository.",
        "metadata": {"category": "legitimate", "type": "code_review", "severity": "none"}
    },
    {
        "text": "All-Hands Reminder: Company quarterly town hall will take place this Thursday at 2:00 PM in the main auditorium and broadcasted via Google Meet. Link is in calendar invite.",
        "metadata": {"category": "legitimate", "type": "company_announcement", "severity": "none"}
    },
    {
        "text": "Release v2.4.0 is now live in production. Release notes: Fixed memory leak in worker pool, optimized FAISS index loading, upgraded dependency versions.",
        "metadata": {"category": "legitimate", "type": "release_notes", "severity": "none"}
    },
    {
        "text": "Hey everyone, a few of us are heading to the cafeteria for lunch around 12:30 PM. Feel free to join if you are around!",
        "metadata": {"category": "legitimate", "type": "social_communication", "severity": "none"}
    },
    {
        "text": "Your expense report for travel to Black Hat conference has been approved by your department manager and forwarded to accounting for reimbursement.",
        "metadata": {"category": "legitimate", "type": "hr_expense_report", "severity": "none"}
    },
    {
        "text": "Monthly infrastructure billing report: AWS utilization for September decreased by 4.2% following auto-scaling group optimization.",
        "metadata": {"category": "legitimate", "type": "operational_report", "severity": "none"}
    },
    {
        "text": "The shared conference room reservation for Room 3B has been confirmed for your design sync on Friday from 1:00 PM to 2:00 PM.",
        "metadata": {"category": "legitimate", "type": "calendar_confirmation", "severity": "none"}
    }
]


def build_email_vector_index(index_path: Path = None):
    """Build and save the FAISS vector index."""
    if index_path is None:
        index_path = PROJECT_ROOT / "data" / "indices" / "faiss_email_index.bin"

    print(f"[*] Initializing VectorStoreManager (Model: all-MiniLM-L6-v2)...")
    manager = VectorStoreManager(model_name="all-MiniLM-L6-v2")

    corpus = PHISHING_TEMPLATES + LEGITIMATE_SAMPLES
    texts = [item["text"] for item in corpus]
    metadatas = [item["metadata"] for item in corpus]

    print(f"[*] Indexing {len(corpus)} email templates ({len(PHISHING_TEMPLATES)} phishing, {len(LEGITIMATE_SAMPLES)} legitimate)...")
    manager.add_texts(texts, metadatas=metadatas)

    print(f"[*] Persisting index to: {index_path}")
    manager.save(index_path)
    print(f"[+] Successfully built and saved FAISS index to {index_path}")

    # Verify lookup
    test_query = "URGENT: Your account has been suspended! Please verify your password here."
    print(f"\n[*] Running sanity check similarity search for query: '{test_query}'")
    matches = manager.search_similarity(test_query, top_k=2)
    for i, match in enumerate(matches, 1):
        print(f"  Match {i}: Similarity={match['similarity_score']} | Category={match['metadata'].get('category')} | Type={match['metadata'].get('type')}")
        print(f"  Snippet: {match['text'][:80]}...\n")

    return manager


if __name__ == "__main__":
    target = PROJECT_ROOT / "data" / "indices" / "faiss_email_index.bin"
    build_email_vector_index(target)
