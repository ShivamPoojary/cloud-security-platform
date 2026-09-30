import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy import (
    String,
    Text,
    Float,
    DateTime,
    ForeignKey,
    Integer,
    Index,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.domain.models.base import Base, GUID, TimestampMixin

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    incident_number: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), default="NEW", nullable=False
    )  # NEW, TRIAGED, IN_INVESTIGATION, CONTAINED, RESOLVED, FALSE_POSITIVE
    severity: Mapped[str] = mapped_column(String(32), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    mitre_tactics: Mapped[List[str]] = mapped_column(JSON_TYPE, default=list, nullable=False)
    mitre_techniques: Mapped[List[str]] = mapped_column(JSON_TYPE, default=list, nullable=False)
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    assignee = relationship("User", back_populates="incidents")
    detections = relationship("ThreatDetection", back_populates="incident")
    anomaly_scores = relationship("MLAnomalyScore", back_populates="incident")
    timeline_events = relationship(
        "IncidentTimelineEvent",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentTimelineEvent.sequence_order",
    )
    playbook_executions = relationship(
        "PlaybookExecution", back_populates="incident"
    )

    __table_args__ = (
        Index("idx_incidents_status", status),
        Index("idx_incidents_severity", severity),
        Index("idx_incidents_risk", risk_score.desc()),
    )


class IncidentTimelineEvent(Base, TimestampMixin):
    __tablename__ = "incident_timeline_events"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("normalized_events.id", ondelete="CASCADE"), nullable=False
    )
    correlation_reason: Mapped[str] = mapped_column(String(256), nullable=False)
    sequence_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    incident = relationship("Incident", back_populates="timeline_events")
    event = relationship("NormalizedEvent")

    __table_args__ = (
        Index("idx_timeline_order", incident_id, sequence_order),
    )
