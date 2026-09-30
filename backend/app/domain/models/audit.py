import uuid
from typing import Dict, Any, Optional
from sqlalchemy import (
    String,
    ForeignKey,
    Index,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.domain.models.base import Base, GUID, TimestampMixin

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(128), nullable=False)
    metadata_payload: Mapped[Dict[str, Any]] = mapped_column(
        JSON_TYPE, default=dict, nullable=False
    )

    # Relationships
    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("idx_audit_logs_action", action),
        Index("idx_audit_logs_time", "created_at"),
    )
