import uuid
from sqlalchemy import (
    String,
    Boolean,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.domain.models.base import Base, GUID, TimestampMixin


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(256), nullable=False)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(
        String(32), default="L1_ANALYST", nullable=False
    )  # SOC_ADMIN, L1_ANALYST, L2_RESPONDER
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    incidents = relationship("Incident", back_populates="assignee")
    audit_logs = relationship("AuditLog", back_populates="user")
