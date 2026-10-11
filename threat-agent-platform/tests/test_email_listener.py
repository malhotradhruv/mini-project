"""Unit tests for Automated Live Email Ingestion Worker.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
"""

import asyncio
import email
from email.message import EmailMessage
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch
import pytest
from sqlalchemy import select

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.db.models import IngestedSource
from src.db.session import init_db, async_session
from src.ingest.email_listener import EmailIngestionDaemon


class TestEmailIngestionDaemon:
    """Tests for EmailIngestionDaemon polling and database persistence."""

    def test_header_decoding(self):
        daemon = EmailIngestionDaemon()
        assert daemon._decode_header_str("") == ""
        assert daemon._decode_header_str("Simple Subject") == "Simple Subject"

        # RFC 2047 Base64 encoded: "Payroll Alert"
        encoded = "=?utf-8?B?UGF5cm9sbCBBbGVydA==?="
        assert daemon._decode_header_str(encoded) == "Payroll Alert"

    def test_unconfigured_credentials_fallback(self):
        daemon = EmailIngestionDaemon(imap_user="", imap_password="")
        mail_data = daemon.fetch_latest_unread_email()

        assert mail_data is not None
        assert "ACTION REQUIRED" in mail_data["subject"]
        assert "paypa1-support.com" in mail_data["sender"]
        assert "192.168.1.105" in mail_data["body"]
        assert "date" in mail_data

    def test_imap_unread_fetch_mocked(self):
        daemon = EmailIngestionDaemon(
            imap_server="imap.example.com",
            imap_user="soc@example.com",
            imap_password="SecretPassword123",
        )

        # Build mock RFC822 email payload
        msg = EmailMessage()
        msg["From"] = "alert@threat-actor.top"
        msg["Subject"] = "Urgent: VPN Gateway Update"
        msg["Date"] = "Mon, 11 Oct 2026 12:00:00 +0000"
        msg.set_content("Click http://192.168.1.105/vpn to update credentials.")
        raw_bytes = msg.as_bytes()

        mock_imap = MagicMock()
        mock_imap.search.return_value = ("OK", [b"101 102"])
        mock_imap.fetch.return_value = ("OK", [(b"102 (RFC822 {123}", raw_bytes)])

        with patch("imaplib.IMAP4_SSL", return_value=mock_imap):
            fetched = daemon.fetch_latest_unread_email()

            mock_imap.login.assert_called_once_with("soc@example.com", "SecretPassword123")
            mock_imap.select.assert_called_once_with("inbox")
            mock_imap.search.assert_called_once_with(None, "UNSEEN")
            mock_imap.logout.assert_called_once()

            assert fetched is not None
            assert fetched["subject"] == "Urgent: VPN Gateway Update"
            assert "threat-actor.top" in fetched["sender"]
            assert "192.168.1.105" in fetched["body"]

    def test_run_poll_cycle_persists_to_database(self):
        daemon = EmailIngestionDaemon(imap_user="", imap_password="")

        async def _run():
            await init_db()
            payload = await daemon.run_poll_cycle()

            assert payload is not None
            assert "From: security-update@paypa1-support.com" in payload
            assert "Subject: ACTION REQUIRED" in payload
            assert "192.168.1.105" in payload

            # Verify persisted record in DB
            async with async_session() as session:
                stmt = (
                    select(IngestedSource)
                    .where(IngestedSource.source_type == "IMAP_EMAIL")
                    .order_by(IngestedSource.received_at.desc())
                )
                res = await session.execute(stmt)
                records = res.scalars().all()
                assert len(records) > 0
                latest = records[0]
                assert latest.source_type == "IMAP_EMAIL"
                assert latest.processed is True
                assert "paypa1-support.com" in latest.raw_content

        asyncio.run(_run())

    def test_daemon_lifecycle_and_callback(self):
        daemon = EmailIngestionDaemon(imap_user="", imap_password="")
        callback_received = []

        async def dummy_callback(content: str):
            callback_received.append(content)
            daemon.stop_daemon()

        async def _run():
            await init_db()
            # Start daemon and verify it calls callback on unread email
            await daemon.start_daemon(poll_interval_seconds=0.1, trigger_swarm=dummy_callback)
            assert len(callback_received) == 1
            assert "paypa1-support.com" in callback_received[0]
            assert daemon.is_running is False

        asyncio.run(_run())
