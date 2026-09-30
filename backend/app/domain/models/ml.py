import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy import (
    String,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.domain.models.base import Base, GUID, TimestampMixin

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class MLAnomalyScore(Base, TimestampMixin):
    __tablename__ = "ml_anomaly_scores"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("normalized_events.id", ondelete="CASCADE"), nullable=False
    )
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    feature_contributions: Mapped[Dict[str, Any]] = mapped_column(
        JSON_TYPE, default=dict, nullable=False
    )
    is_anomalous: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    event = relationship("NormalizedEvent", back_populates="anomaly_scores")
    incident = relationship("Incident", back_populates="anomaly_scores")

    __table_args__ = (
        Index("idx_ml_scores_event", event_id),
        Index("idx_ml_scores_anomalous", is_anomalous),
    )
