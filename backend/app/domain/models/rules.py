import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy import (
    String,
    Text,
    Boolean,
    DateTime,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.domain.models.base import Base, GUID, TimestampMixin

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class DetectionRule(Base, TimestampMixin):
    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    rule_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    mitre_tactic: Mapped[str] = mapped_column(String(64), nullable=False)
    mitre_technique_id: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    rule_logic: Mapped[Dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    detections = relationship("ThreatDetection", back_populates="rule")
