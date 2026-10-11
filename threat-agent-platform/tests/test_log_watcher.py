"""Unit tests for Live File Log Tailing and Syslog Watcher.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
"""

import asyncio
import os
import tempfile
from pathlib import Path
import sys
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
from src.ingest.log_watcher import LogFileWatcher


class TestLogFileWatcher:
    """Tests for LogFileWatcher tailing and persistence."""

    def test_file_initialization_and_clean_tail(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "test_auth.log")
            watcher = LogFileWatcher(log_path=log_path)

            assert os.path.exists(log_path)
            # Comments are ignored
            lines = watcher.read_new_lines()
            assert lines == []

    def test_tailing_incremental_lines(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "test_auth.log")
            watcher = LogFileWatcher(log_path=log_path)

            # Append first batch
            with open(log_path, "a", encoding="utf-8") as f:
                f.write("Oct 11 02:00:01 srv1 sshd[10]: Connection established\n")
                f.write("Oct 11 02:00:02 srv1 sshd[10]: Session opened\n")

            batch1 = watcher.read_new_lines()
            assert len(batch1) == 2
            assert "Connection established" in batch1[0]
            assert "Session opened" in batch1[1]

            # Second call without new writes returns empty
            assert watcher.read_new_lines() == []

            # Append second batch
            with open(log_path, "a", encoding="utf-8") as f:
                f.write("Oct 11 02:00:05 srv1 sshd[10]: Session closed\n")

            batch2 = watcher.read_new_lines()
            assert len(batch2) == 1
            assert "Session closed" in batch2[0]

    def test_simulate_attack_event(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "test_auth.log")
            watcher = LogFileWatcher(log_path=log_path)

            watcher.simulate_attack_event(attacker_ip="192.168.1.105")
            lines = watcher.read_new_lines()

            assert len(lines) == 4
            assert sum(1 for l in lines if "Failed password" in l) == 3
            assert sum(1 for l in lines if "incorrect password attempts" in l) == 1
            assert all("192.168.1.105" in l or "sudo" in l for l in lines)

    def test_log_truncation_or_rotation_reset(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "test_auth.log")
            watcher = LogFileWatcher(log_path=log_path)

            with open(log_path, "a", encoding="utf-8") as f:
                f.write("Line 1: A very long log line that increases file size significantly\n")

            assert len(watcher.read_new_lines()) == 1

            # Simulate log rotation (truncate file to 0 bytes)
            with open(log_path, "w", encoding="utf-8") as f:
                f.write("New line after rotation\n")

            lines = watcher.read_new_lines()
            assert len(lines) == 1
            assert lines[0] == "New line after rotation"

    def test_poll_and_save_database_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "test_auth.log")
            watcher = LogFileWatcher(log_path=log_path)

            async def _run():
                await init_db()
                watcher.simulate_attack_event(attacker_ip="10.0.0.99")
                combined = await watcher.poll_and_save()

                assert combined is not None
                assert "10.0.0.99" in combined
                assert "Failed password" in combined

                # Verify in database
                async with async_session() as session:
                    stmt = (
                        select(IngestedSource)
                        .where(IngestedSource.source_type == "SYSLOG_FILE")
                        .order_by(IngestedSource.received_at.desc())
                    )
                    res = await session.execute(stmt)
                    records = res.scalars().all()
                    assert len(records) > 0
                    latest = records[0]
                    assert latest.source_type == "SYSLOG_FILE"
                    assert "10.0.0.99" in latest.raw_content

            asyncio.run(_run())

    def test_start_watching_callback_trigger(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "test_auth.log")
            watcher = LogFileWatcher(log_path=log_path)
            received = []

            async def callback(content: str):
                received.append(content)
                watcher.stop_watching()

            async def _run():
                await init_db()
                # Append line before starting loop
                watcher.simulate_attack_event("192.168.1.105")
                await watcher.start_watching(poll_interval_seconds=0.05, callback=callback)

                assert len(received) == 1
                assert "192.168.1.105" in received[0]
                assert watcher.is_running is False

            asyncio.run(_run())
