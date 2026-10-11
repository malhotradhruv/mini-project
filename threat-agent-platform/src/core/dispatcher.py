"""Task dispatcher gateway for multi-agent threat detection.

Validates payload integrity and routes tasks synchronously or asynchronously
to specialized domain agents (EmailAgent, LogAgent, IPAgent).
Reference: IEEE Access (Hmimou et al., 2025).
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional, Union

from src.models.schemas import AgentReport, ExtractedEntities, TaskInput
from src.core.llm_gateway import LLMGateway
from src.utils.vector_store import VectorStoreManager
from src.utils.nvd_client import NVDClient

logger = logging.getLogger("TaskDispatcher")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class TaskDispatcher:
    """Central Task Dispatcher Gateway validating and routing security analysis tasks."""

    def __init__(
        self,
        llm_gateway: Optional[LLMGateway] = None,
        vector_store: Optional[VectorStoreManager] = None,
        nvd_client: Optional[NVDClient] = None,
    ):
        """Initialize dispatcher and domain agent pool with shared forensic clients."""
        from src.agents.email_agent import EmailAgent
        from src.agents.log_agent import LogAgent
        from src.agents.ip_agent import IPAgent

        self.llm_gateway = llm_gateway or LLMGateway()
        self.vector_store = vector_store or VectorStoreManager()
        self.nvd_client = nvd_client or NVDClient()

        self.agents = {
            "email": EmailAgent(llm_gateway=self.llm_gateway, vector_store=self.vector_store),
            "log": LogAgent(llm_gateway=self.llm_gateway),
            "ip": IPAgent(llm_gateway=self.llm_gateway, nvd_client=self.nvd_client),
        }

    def validate_payload(self, task: TaskInput) -> None:
        """Validate payload integrity according to task type constraints.

        Raises:
            ValueError: If payload does not satisfy strict domain syntax rules.
        """
        if not task.payload or not task.payload.strip():
            raise ValueError(f"Task payload for '{task.task_type}' cannot be empty.")

        clean_payload = task.payload.strip()

        if task.task_type == "ip":
            # Verify IP address or CIDR network syntax
            is_valid = False
            try:
                ipaddress.ip_network(clean_payload, strict=False)
                is_valid = True
            except ValueError:
                try:
                    ipaddress.ip_address(clean_payload)
                    is_valid = True
                except ValueError:
                    # Fallback check for embedded IP addresses in string
                    if re.search(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", clean_payload):
                        is_valid = True

            if not is_valid:
                raise ValueError(
                    f"Invalid IP task payload: '{clean_payload}' does not match IPv4/IPv6 or CIDR syntax."
                )

        elif task.task_type == "email":
            # Verify email payload contains readable text
            if len(clean_payload) < 5:
                raise ValueError("Email task payload must contain text content (minimum 5 characters).")

        elif task.task_type == "log":
            # Verify log payload contains line-delimited records
            lines = [line.strip() for line in clean_payload.splitlines() if line.strip()]
            if not lines:
                raise ValueError("Log task payload must contain at least one valid line-delimited log entry.")

    def dispatch(self, task: TaskInput) -> AgentReport:
        """Synchronously validate and route a TaskInput to its target agent."""
        # 1. Validate payload integrity
        self.validate_payload(task)

        # 2. Lookup agent
        agent = self.agents.get(task.task_type)
        if not agent:
            raise ValueError(f"Unknown task_type: '{task.task_type}'. Valid types: {list(self.agents.keys())}")

        logger.info(f"Dispatching task of type '{task.task_type}' to {agent.AGENT_ID}")
        return agent.analyze(task.payload)

    def dispatch_single(self, task: TaskInput) -> AgentReport:
        """Synchronous dispatch alias matching API contract."""
        return self.dispatch(task)

    async def dispatch_async(self, task: TaskInput) -> AgentReport:
        """Asynchronously validate and route task via non-blocking worker thread."""
        return await asyncio.to_thread(self.dispatch, task)

    def dispatch_batch(self, tasks: List[TaskInput], max_workers: int = 4) -> List[AgentReport]:
        """Concurrently dispatch a batch of tasks across a thread pool."""
        reports: List[AgentReport] = []
        if not tasks:
            return reports

        with ThreadPoolExecutor(max_workers=min(max_workers, len(tasks))) as executor:
            futures = {executor.submit(self.dispatch, task): task for task in tasks}
            for future in as_completed(futures):
                task = futures[future]
                try:
                    report = future.result()
                    reports.append(report)
                except Exception as exc:
                    logger.error(f"Task dispatch failed for '{task.task_type}': {exc}")
                    # Return deterministic fallback error report
                    reports.append(AgentReport(
                        agent_id=f"{task.task_type}_agent",
                        is_malicious=False,
                        risk_score=0.0,
                        entities=ExtractedEntities(),
                        technical_indicators=[f"DISPATCH_ERROR: {str(exc)}"],
                        raw_evidence={"payload": task.payload, "error": str(exc)},
                        explanation=f"Dispatcher rejected or failed task of type '{task.task_type}': {str(exc)}",
                    ))

        return reports
