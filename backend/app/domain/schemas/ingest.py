from typing import Optional, List, Dict, Any, Literal
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field
from app.domain.schemas.event import SecurityEventBase


class RawIngestRequest(SecurityEventBase):
    pass


class RawIngestResponse(BaseModel):
    status: str = "queued"
    event_id: uuid.UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SyntheticTriggerRequest(BaseModel):
    scenario_name: Literal[
        "credential_compromise",
        "keyvault_exfiltration",
        "ransomware",
    ] = Field(..., description="Target synthetic attack scenario to trigger")
    custom_target_resource: Optional[str] = Field(
        None, description="Optional override for target Azure resource"
    )


class SyntheticTriggerResponse(BaseModel):
    execution_id: str
    scenario_name: str
    status: str
    events_count: int
    events: List[SecurityEventBase]
