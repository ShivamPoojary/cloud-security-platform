import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, ConfigDict


class MLAnomalyRead(BaseModel):
    id: uuid.UUID
    event_id: uuid.UUID
    model_version: str
    anomaly_score: float
    confidence: float
    is_anomalous: bool
    severity: str
    reasons: List[str] = []
    summary: str = ""
    top_deviations: Dict[str, Any] = {}
    principal_id: Optional[str] = None
    principal_name: Optional[str] = None
    caller_ip: Optional[str] = None
    event_name: Optional[str] = None
    event_category: Optional[str] = None
    geo_country: Optional[str] = None
    feature_contributions: Dict[str, Any] = {}
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class MLMetricsResponse(BaseModel):
    total_anomalies: int
    high_risk_anomalies: int
    anomalous_principals: int
    avg_anomaly_score: float
    model_version: str
    active_features_count: int
