import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    String,
    Text,
    DateTime,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.domain.models.base import Base, GUID, TimestampMixin


class ThreatDetection(Base, TimestampMixin):
    __tablename__ = "threat_detections"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("normalized_events.id", ondelete="CASCADE"), nullable=False
    )
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    alert_summary: Mapped[str] = mapped_column(Text, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    rule = relationship("DetectionRule", back_populates="detections")
    event = relationship("NormalizedEvent", back_populates="threat_detections")
    incident = relationship("Incident", back_populates="detections")

    __table_args__ = (
        Index("idx_threat_detections_time", detected_at.desc()),
        Index("idx_threat_detections_severity", severity),
    )
