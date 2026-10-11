"""Resilient Groq LLM Gateway using llama-3.3-70b-versatile.

Enforces deterministic inference (temperature=0.1) and provides robust fallback
handling in the event of missing keys, rate limits, or network timeouts.
Reference: IEEE Access (Hmimou et al., 2025).
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Union
from dotenv import load_dotenv

# Search and load .env from current directory, parent directory, and project root
_ENV_PATHS = [
    Path.cwd() / ".env",
    Path(__file__).resolve().parent.parent.parent / ".env",
    Path.cwd() / "threat-agent-platform" / ".env",
]
for env_path in _ENV_PATHS:
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
        break
else:
    load_dotenv()

logger = logging.getLogger("LLMGateway")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class LLMGateway:
    """Enterprise-grade LLM Gateway wrapping Groq API for deterministic cybersecurity analysis."""

    DEFAULT_MODEL = "llama-3.3-70b-versatile"
    DEFAULT_TEMPERATURE = 0.1

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        """Initialize Groq client with environment credentials or fallback gracefully.

        Args:
            api_key: Optional explicit Groq API key (defaults to GROQ_API_KEY env var).
            model: Optional model name (defaults to llama-3.3-70b-versatile).
        """
        self.api_key = api_key or os.getenv("GROQ_API_KEY", "").strip()
        self.model = model or os.getenv("GROQ_MODEL", self.DEFAULT_MODEL).strip()
        self.client = None

        if self.api_key:
            try:
                from groq import Groq
                self.client = Groq(api_key=self.api_key)
                logger.info(f"LLMGateway initialized successfully with model: {self.model}")
            except Exception as e:
                logger.warning(f"Failed to initialize Groq client: {e}. Running in deterministic fallback mode.")
                self.client = None
        else:
            logger.warning("GROQ_API_KEY is not set. LLMGateway initialized in deterministic fallback mode.")

    @property
    def model_name(self) -> str:
        """Alias for model name attribute."""
        return self.model

    def _generate_fallback_json(self, system_prompt: str, user_prompt: str, error_reason: str) -> str:
        """Produce deterministic, structured JSON fallback payload when LLM is unavailable."""
        fallback_data: Dict[str, Any] = {
            "status": "fallback",
            "warning": f"LLM inference unavailable ({error_reason}). Deterministic fallback response returned.",
            "is_malicious": False,
            "risk_score": 0.0,
            "technical_indicators": ["DETERMINISTIC_FALLBACK_ENGAGED"],
            "explanation": (
                "Deterministic heuristic synthesis: LLM inference bypassed due to unconfigured API key or rate limit. "
                "Downstream decisions rely solely on deterministic Python tooling."
            ),
            "narrative": "Deterministic synthesis: All extracted indicators were evaluated via static security rules.",
            "remediation_steps": [
                "Configure GROQ_API_KEY in .env to enable semantic LLM reasoning.",
                "Review deterministic indicators in raw evidence."
            ],
            "incident_detected": False,
            "confidence_score": 0.0,
            "participating_agents": [],
            "correlated_entities": {"ips": [], "domains": [], "timestamps": [], "ports": []},
            "attack_timeline": []
        }
        return json.dumps(fallback_data, indent=2)

    def _generate_fallback_text(self, system_prompt: str, user_prompt: str, error_reason: str) -> str:
        """Produce deterministic plaintext fallback explanation."""
        return (
            f"[Deterministic Fallback - {error_reason}]\n"
            "Semantic summarization unavailable. Please check GROQ_API_KEY configuration or rate limits."
        )

    def query(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: str = "text",
    ) -> str:
        """Query Groq LLM with strictly bounded temperature (0.1).

        Args:
            system_prompt: Guiding persona and constraints for the model.
            user_prompt: Specific task context and evidence to analyze.
            response_format: 'json' for JSON object output, or 'text' for standard prose.

        Returns:
            str: Valid JSON string (if response_format='json') or plain text response.
                 Guaranteed to return valid JSON when response_format='json' even during API errors.
        """
        fmt_lower = response_format.lower()

        # Handle missing client or key
        if not self.client or not self.api_key:
            if fmt_lower == "json":
                return self._generate_fallback_json(system_prompt, user_prompt, "API key missing")
            return self._generate_fallback_text(system_prompt, user_prompt, "API key missing")

        try:
            kwargs: Dict[str, Any] = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": self.DEFAULT_TEMPERATURE,
            }

            if fmt_lower == "json":
                kwargs["response_format"] = {"type": "json_object"}

            response = self.client.chat.completions.create(**kwargs)
            content = response.choices[0].message.content or ""

            if fmt_lower == "json":
                # Verify that content is actually valid JSON
                try:
                    json.loads(content)
                    return content
                except json.JSONDecodeError:
                    logger.warning("LLM output was not valid JSON despite json_object mode. Sanitizing...")
                    # Attempt to extract json block if wrapped in markdown
                    cleaned = content.strip()
                    if cleaned.startswith("```json"):
                        cleaned = cleaned[7:]
                    if cleaned.startswith("```"):
                        cleaned = cleaned[3:]
                    if cleaned.endswith("```"):
                        cleaned = cleaned[:-3]
                    cleaned = cleaned.strip()
                    json.loads(cleaned)  # validate
                    return cleaned

            return content

        except Exception as exc:
            error_msg = f"{type(exc).__name__}: {str(exc)}"
            logger.warning(f"Groq API call encountered an error: {error_msg}. Engaging deterministic fallback.")
            if fmt_lower == "json":
                return self._generate_fallback_json(system_prompt, user_prompt, error_msg)
            return self._generate_fallback_text(system_prompt, user_prompt, error_msg)

    def query_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """Convenience method that queries the LLM and parses the result into a Python dictionary.

        Guaranteed to return a valid dict even in fallback mode.
        """
        raw_json = self.query(system_prompt, user_prompt, response_format="json")
        try:
            return json.loads(raw_json)
        except Exception:
            return json.loads(self._generate_fallback_json(system_prompt, user_prompt, "JSON parse recovery"))
