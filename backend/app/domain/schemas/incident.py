import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, field_validator

VALID_INCIDENT_STATUSES = {
    "NEW",
    "TRIAGED",
    "IN_INVESTIGATION",
    "CONTAINED",
    "RESOLVED",
    "FALSE_POSITIVE",
}

VALID_INCIDENT_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


class IncidentTimelineEventRead(BaseModel):
    """Pydantic model representing a chronological incident timeline event."""

    id: uuid.UUID
    incident_id: uuid.UUID
    event_id: uuid.UUID
    correlation_reason: str
    sequence_order: int
    event_timestamp: Optional[datetime] = None
    event_name: Optional[str] = None
    principal_name: Optional[str] = None
    caller_ip: Optional[str] = None
    target_resource_name: Optional[str] = None
    action_status: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentDetectionSummary(BaseModel):
    """Concise representation of a ThreatDetection associated with an incident."""

    id: uuid.UUID
    rule_id: uuid.UUID
    rule_code: Optional[str] = None
    rule_title: Optional[str] = None
    severity: str
    alert_summary: str
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    detected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentMLAnomalySummary(BaseModel):
    """Concise representation of an MLAnomalyScore associated with an incident."""

    id: uuid.UUID
    event_id: uuid.UUID
    anomaly_score: float
    confidence: float
    is_anomalous: bool
    model_version: str
    severity: Optional[str] = None
    summary: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentRead(BaseModel):
    """Standard incident representation for lists and summary queries."""

    id: uuid.UUID
    incident_number: str
    title: str
    status: str
    severity: str
    risk_score: float
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    detection_count: int = 0
    anomaly_count: int = 0
    assigned_to: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class IncidentDetailRead(BaseModel):
    """Detailed incident representation including constituent detections, anomalies, and timeline."""

    id: uuid.UUID
    incident_number: str
    title: str
    status: str
    severity: str
    risk_score: float
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    assigned_to: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    detections: List[IncidentDetectionSummary] = Field(default_factory=list)
    anomalies: List[IncidentMLAnomalySummary] = Field(default_factory=list)
    timeline: List[IncidentTimelineEventRead] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class IncidentUpdateStatusRequest(BaseModel):
    """Payload for updating incident status and assignment."""

    status: str = Field(..., description="Target lifecycle status")
    assigned_to: Optional[uuid.UUID] = Field(None, description="Optional assignee user ID")

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        clean = (v or "").strip().upper()
        if clean not in VALID_INCIDENT_STATUSES:
            raise ValueError(
                f"Invalid incident status '{v}'. Allowed statuses: {sorted(list(VALID_INCIDENT_STATUSES))}"
            )
        return clean


class CorrelationSummaryResponse(BaseModel):
    """Response returned when triggering an on-demand correlation evaluation."""

    created_incidents: int
    updated_incidents: int
    correlated_events: int
    message: str = "Correlation evaluation completed successfully"
