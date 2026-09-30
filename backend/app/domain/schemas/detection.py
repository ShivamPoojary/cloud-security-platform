from typing import Optional
from datetime import datetime
import uuid
from pydantic import BaseModel, ConfigDict


class ThreatDetectionRead(BaseModel):
    id: uuid.UUID
    rule_id: uuid.UUID
    rule_code: str
    rule_title: str
    event_id: uuid.UUID
    severity: str
    alert_summary: str
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    principal_name: Optional[str] = None
    caller_ip: Optional[str] = None
    target_resource_name: Optional[str] = None
    detected_at: datetime

    model_config = ConfigDict(from_attributes=True)
