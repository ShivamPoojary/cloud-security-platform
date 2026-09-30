from typing import Optional, Dict, Any
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field, ConfigDict


class SecurityEventBase(BaseModel):
    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = Field(..., description="Telemetry source e.g. AzureActivity, SignInLogs, KeyVault")
    event_category: str = Field(..., description="Category e.g. Identity, ResourceManagement, Storage, Network")
    event_name: str = Field(..., description="Action name e.g. Sign-in, RoleAssignment, SecretGet")
    principal_id: Optional[str] = Field(None, description="Azure Object ID or User ID")
    principal_name: Optional[str] = Field(None, description="Username, UPN or SPN name")
    caller_ip: Optional[str] = Field(None, description="IPv4 or IPv6 of caller")
    target_resource_id: Optional[str] = Field(None, description="Azure Resource ID URI")
    target_resource_name: Optional[str] = Field(None, description="Name of affected cloud resource")
    action_status: str = Field(..., description="Outcome: Success, Failure, Denied")
    geo_country: Optional[str] = Field(None, description="Origin country e.g. United States")
    user_agent: Optional[str] = Field(None, description="Client User Agent string")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Contextual key-values")

    model_config = ConfigDict(from_attributes=True)


class SecurityEventCreate(SecurityEventBase):
    pass


class NormalizedEventRead(SecurityEventBase):
    id: uuid.UUID
    raw_log_id: Optional[uuid.UUID] = None
    created_at: datetime
