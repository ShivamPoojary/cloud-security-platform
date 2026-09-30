from typing import Dict, Any, Optional
from datetime import datetime
import uuid
from pydantic import BaseModel, ConfigDict


class DetectionRuleRead(BaseModel):
    id: uuid.UUID
    rule_id: str
    title: str
    severity: str
    mitre_tactic: str
    mitre_technique_id: str
    description: str
    rule_logic: Dict[str, Any]
    is_active: bool
    detection_count: int = 0
    updated_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DetectionRuleToggleResponse(BaseModel):
    rule_id: str
    is_active: bool
    message: str
