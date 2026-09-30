import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy import (
    String,
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


class Playbook(Base, TimestampMixin):
    __tablename__ = "playbooks"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    trigger_severity: Mapped[str] = mapped_column(String(32), nullable=False)
    target_tactics: Mapped[List[str]] = mapped_column(JSON_TYPE, default=list, nullable=False)
    actions_schema: Mapped[Dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    requires_human_approval: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    executions = relationship("PlaybookExecution", back_populates="playbook")


class PlaybookExecution(Base, TimestampMixin):
    __tablename__ = "playbook_executions"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    playbook_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), default="PENDING", nullable=False
    )  # PENDING, RUNNING, COMPLETED, FAILED, DRY_RUN_COMPLETED
    is_dry_run: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    execution_trace: Mapped[Dict[str, Any]] = mapped_column(
        JSON_TYPE, default=dict, nullable=False
    )
    executed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    playbook = relationship("Playbook", back_populates="executions")
    incident = relationship("Incident", back_populates="playbook_executions")
    executor = relationship("User")

    __table_args__ = (
        Index("idx_playbook_exec_incident", incident_id),
    )
