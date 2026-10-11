"""Live File Log Tailing and Syslog Watcher.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"

Features:
- Asynchronous cursor-based file tailing for server auth logs (auth.log / syslog).
- Detects log file rotation or truncation and resets cursor automatically.
- Simulates live brute-force bursts and privilege escalation events for lab scenarios.
- Persists newly captured log telemetry to IngestedSource in the database.
- Provides non-blocking background daemon loops with callback triggers.
"""

import os
import inspect
import asyncio
import datetime
import uuid
from pathlib import Path
from typing import List, Callable, Optional, Any

from src.db.session import async_session
from src.db.models import IngestedSource


def _utc_now_iso() -> str:
    """Returns current UTC ISO-8601 timestamp."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class LogFileWatcher:
    """Continuous log file tailer and attack simulator."""

    def __init__(self, log_path: str = "data/raw/auth_logs.log"):
        self.log_path = log_path
        self.last_position = 0
        self.is_running = False

        dir_name = os.path.dirname(self.log_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)

        if not os.path.exists(self.log_path):
            with open(self.log_path, "w", encoding="utf-8") as f:
                f.write(f"# Sentinel SOC Log Stream Initialized: {_utc_now_iso()}\n")

    def read_new_lines(self) -> List[str]:
        """Tails the file from the previous cursor position."""
        if not os.path.exists(self.log_path):
            return []

        # Handle log rotation or truncation
        try:
            current_size = os.path.getsize(self.log_path)
            if current_size < self.last_position:
                self.last_position = 0
        except OSError:
            return []

        new_lines: List[str] = []
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.last_position)
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        new_lines.append(stripped)
                self.last_position = f.tell()
        except Exception as e:
            print(f"[!] Error reading log file: {e}")

        return new_lines

    def simulate_attack_event(self, attacker_ip: str = "192.168.1.105"):
        """Utility to append a live brute-force burst into the log file during presentations/tests."""
        now = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        burst = [
            f"{now} srv1 sshd[102]: Failed password for root from {attacker_ip} port 22",
            f"{now} srv1 sshd[102]: Failed password for root from {attacker_ip} port 22",
            f"{now} srv1 sshd[102]: Failed password for root from {attacker_ip} port 22",
            f"{now} srv1 sudo: user : 3 incorrect password attempts ; TTY=pts/0",
        ]
        with open(self.log_path, "a", encoding="utf-8") as f:
            for l in burst:
                f.write(l + "\n")

    async def poll_and_save(self) -> Optional[str]:
        """Tails new lines, commits to the database, and returns combined log payload."""
        new_lines = self.read_new_lines()
        if not new_lines:
            return None

        combined = "\n".join(new_lines)
        async with async_session() as session:
            record = IngestedSource(
                id=str(uuid.uuid4()),
                source_type="SYSLOG_FILE",
                raw_content=combined,
                processed=True,
            )
            session.add(record)
            await session.commit()

        return combined

    async def start_watching(
        self,
        poll_interval_seconds: float = 0.5,
        callback: Optional[Callable[[str], Any]] = None,
    ):
        """Asynchronous non-blocking loop watching for appended log records."""
        self.is_running = True
        while self.is_running:
            try:
                payload = await self.poll_and_save()
                if payload and callback:
                    if inspect.iscoroutinefunction(callback):
                        await callback(payload)
                    else:
                        callback(payload)
            except Exception as e:
                print(f"[!] Log watcher error: {e}")
            await asyncio.sleep(poll_interval_seconds)

    def stop_watching(self):
        """Signals the watching loop to terminate."""
        self.is_running = False


__all__ = [
    "LogFileWatcher",
]
