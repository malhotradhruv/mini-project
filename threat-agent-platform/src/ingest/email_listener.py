"""Automated Live Email Ingestion Worker.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"

Features:
- Polls live mailboxes via IMAP/SSL (e.g., Gmail, Outlook, Exchange).
- Decodes RFC 2047 multi-part MIME headers and text/plain payloads.
- Falls back to pre-configured forensic lab email templates when offline or unconfigured.
- Persists raw telemetry to IngestedSource in the database.
- Provides hooks for asynchronous swarm triggering.
"""

import os
import email
import imaplib
import inspect
import asyncio
import uuid
import datetime
from email.header import decode_header
from typing import Optional, Dict, Any, Callable
from dotenv import load_dotenv

from src.db.session import async_session
from src.db.models import IngestedSource

load_dotenv()


class EmailIngestionDaemon:
    """IMAP live polling daemon and mail dropzone ingestor."""

    def __init__(
        self,
        imap_server: Optional[str] = None,
        imap_user: Optional[str] = None,
        imap_password: Optional[str] = None,
    ):
        self.imap_server = imap_server or os.getenv("IMAP_SERVER", "imap.gmail.com")
        self.imap_user = imap_user if imap_user is not None else os.getenv("IMAP_USER", "")
        self.imap_password = imap_password if imap_password is not None else os.getenv("IMAP_PASSWORD", "")
        self.is_running = False

    def _decode_header_str(self, header_value: str) -> str:
        """Decodes RFC 2047 MIME encoded email headers into UTF-8 strings."""
        if not header_value:
            return ""
        try:
            decoded_parts = decode_header(header_value)
            parts = []
            for decoded, encoding in decoded_parts:
                if isinstance(decoded, bytes):
                    parts.append(decoded.decode(encoding or "utf-8", errors="ignore"))
                else:
                    parts.append(str(decoded))
            return "".join(parts)
        except Exception:
            return str(header_value)

    def fetch_latest_unread_email(self) -> Optional[Dict[str, Any]]:
        """Connects via IMAP to pull the latest unread message (or falls back to mock if unconfigured)."""
        if not self.imap_user or not self.imap_password:
            # Safe Fallback: Returns a pre-configured sample email for lab testing
            return {
                "subject": "ACTION REQUIRED: Employee Payroll Verification",
                "sender": "security-update@paypa1-support.com",
                "body": "URGENT: Your account credentials have expired. Verify immediately at http://192.168.1.105/auth.php within 24 hours.",
                "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }

        try:
            mail = imaplib.IMAP4_SSL(self.imap_server)
            mail.login(self.imap_user, self.imap_password)
            mail.select("inbox")

            status, messages = mail.search(None, "UNSEEN")
            if not messages or not messages[0]:
                mail.logout()
                return None

            email_ids = messages[0].split()
            if not email_ids:
                mail.logout()
                return None

            latest_id = email_ids[-1]
            res, msg_data = mail.fetch(latest_id, "(RFC822)")
            if not msg_data or not msg_data[0] or len(msg_data[0]) < 2:
                mail.logout()
                return None

            raw = email.message_from_bytes(msg_data[0][1])

            subject = self._decode_header_str(raw.get("Subject", ""))
            sender = self._decode_header_str(raw.get("From", ""))
            body = ""

            if raw.is_multipart():
                for part in raw.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode(errors="ignore")
                        break
            else:
                payload = raw.get_payload(decode=True)
                if payload:
                    body = payload.decode(errors="ignore")

            mail.logout()
            return {
                "subject": subject,
                "sender": sender,
                "body": body,
                "date": str(raw.get("Date", "")),
            }
        except Exception as e:
            print(f"[!] IMAP Error: {e}")
            return None

    async def run_poll_cycle(self) -> Optional[str]:
        """Polls once, saves raw payload to DB, and returns payload text if new."""
        data = self.fetch_latest_unread_email()
        if not data:
            return None

        combined_text = (
            f"From: {data['sender']}\n"
            f"Subject: {data['subject']}\n"
            f"Date: {data['date']}\n\n"
            f"{data['body']}"
        )

        async with async_session() as session:
            record = IngestedSource(
                id=str(uuid.uuid4()),
                source_type="IMAP_EMAIL",
                raw_content=combined_text,
                processed=True,
            )
            session.add(record)
            await session.commit()

        return combined_text

    async def start_daemon(
        self,
        poll_interval_seconds: int = 10,
        trigger_swarm: Optional[Callable[[str], Any]] = None,
    ):
        """Runs the continuous ingestion daemon loop."""
        self.is_running = True
        while self.is_running:
            try:
                payload = await self.run_poll_cycle()
                if payload and trigger_swarm:
                    if inspect.iscoroutinefunction(trigger_swarm):
                        await trigger_swarm(payload)
                    else:
                        trigger_swarm(payload)
            except Exception as e:
                print(f"[!] Email listener poll error: {e}")
            await asyncio.sleep(poll_interval_seconds)

    def stop_daemon(self):
        """Signals the ingestion daemon loop to stop."""
        self.is_running = False


__all__ = [
    "EmailIngestionDaemon",
]
