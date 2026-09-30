import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    Index,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.domain.models.base import Base, GUID, TimestampMixin

# Use PostgreSQL JSONB when available, fallback to JSON
JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class RawLog(Base, TimestampMixin):
    __tablename__ = "raw_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    source_system: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_payload: Mapped[Dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)

    # Relationships
    normalized_events = relationship(
        "NormalizedEvent", back_populates="raw_log", cascade="all, delete-orphan"
    )


class NormalizedEvent(Base, TimestampMixin):
    __tablename__ = "normalized_events"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    raw_log_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("raw_logs.id", ondelete="SET NULL"), nullable=True
    )
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    event_category: Mapped[str] = mapped_column(String(64), nullable=False)
    event_name: Mapped[str] = mapped_column(String(128), nullable=False)
    principal_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    principal_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    caller_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target_resource_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target_resource_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    action_status: Mapped[str] = mapped_column(String(32), nullable=False)
    geo_country: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    geo_city: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    security_context: Mapped[Dict[str, Any]] = mapped_column(
        JSON_TYPE, default=dict, nullable=False
    )

    # Relationships
    raw_log = relationship("RawLog", back_populates="normalized_events")
    threat_detections = relationship("ThreatDetection", back_populates="event")
    anomaly_scores = relationship("MLAnomalyScore", back_populates="event")

    __table_args__ = (
        Index("idx_norm_events_ts", event_timestamp.desc()),
        Index("idx_norm_events_principal", principal_name, event_timestamp.desc()),
        Index("idx_norm_events_ip", caller_ip, event_timestamp.desc()),
    )
