"""Persistent Database Models for Multi-Agent Cybersecurity Platform.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"

Entities:
- User: Multi-tier SOC operators with single-device authentication lock
- IngestedSource: Raw telemetry items (IMAP email, Syslog, Network targets)
- IncidentRecord: Correlated incidents with severity, root cause, and containment rules
- WarRoomMessage: Inter-agent debate dialogue and action exchanges
- SpecialistFindingRecord: Individual agent forensic indicators and scores
"""

import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utc_now() -> datetime.datetime:
    """Returns current timezone-aware UTC datetime."""
    return datetime.datetime.now(datetime.timezone.utc)


class Base(DeclarativeBase):
    """SQLAlchemy Declarative Base for SOC Persistent Models."""
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="ANALYST")  # ANALYST | ADMIN
    active_device_token: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)  # Enforces single-device lock
    last_login: Mapped[datetime.datetime] = mapped_column(DateTime, default=_utc_now)


class IngestedSource(Base):
    __tablename__ = "ingested_sources"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # UUID
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)  # IMAP_EMAIL | SYSLOG_FILE | NETWORK_TARGET
    raw_content: Mapped[str] = mapped_column(Text, nullable=False)
    received_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=_utc_now)
    processed: Mapped[bool] = mapped_column(Boolean, default=False)


class IncidentRecord(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # UUID
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=_utc_now)
    severity: Mapped[str] = mapped_column(String(32), default="BENIGN")  # BENIGN, LOW, MEDIUM, HIGH, CRITICAL
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    root_cause: Mapped[str] = mapped_column(Text, default="")
    correlated_entities: Mapped[dict] = mapped_column(JSON, default=dict)
    containment_commands: Mapped[list] = mapped_column(JSON, default=list)

    # Relationships
    messages: Mapped[List["WarRoomMessage"]] = relationship(
        "WarRoomMessage", back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )
    findings: Mapped[List["SpecialistFindingRecord"]] = relationship(
        "SpecialistFindingRecord", back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )


class WarRoomMessage(Base):
    __tablename__ = "warroom_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(64), ForeignKey("incidents.id"), nullable=False)
    sender: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient: Mapped[str] = mapped_column(String(64), nullable=False)
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    artifacts: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[str] = mapped_column(String(64), nullable=False)

    incident: Mapped["IncidentRecord"] = relationship("IncidentRecord", back_populates="messages")


class SpecialistFindingRecord(Base):
    __tablename__ = "specialist_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(64), ForeignKey("incidents.id"), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    summary: Mapped[str] = mapped_column(Text, default="")
    technical_indicators: Mapped[list] = mapped_column(JSON, default=list)

    incident: Mapped["IncidentRecord"] = relationship("IncidentRecord", back_populates="findings")


__all__ = [
    "Base",
    "User",
    "IngestedSource",
    "IncidentRecord",
    "WarRoomMessage",
    "SpecialistFindingRecord",
]
