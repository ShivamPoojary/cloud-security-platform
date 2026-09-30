import uuid
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError
from app.domain.schemas.event import SecurityEventBase
from app.domain.schemas.ingest import SyntheticTriggerRequest


def test_security_event_valid_schema():
    """Test valid security event instantiation and defaults."""
    event = SecurityEventBase(
        source="AzureActivity",
        event_category="ResourceManagement",
        event_name="Microsoft.Compute/virtualMachines/write",
        principal_id="usr-101",
        principal_name="analyst@secplatform.local",
        caller_ip="198.51.100.1",
        target_resource_id="/subscriptions/sub-1/resourceGroups/rg-1",
        target_resource_name="rg-1",
        action_status="Success",
        geo_country="United States",
        user_agent="AzurePortal/1.0",
        metadata={"role": "Contributor"},
    )
    assert isinstance(event.event_id, uuid.UUID)
    assert isinstance(event.timestamp, datetime)
    assert event.source == "AzureActivity"
    assert event.action_status == "Success"


def test_security_event_missing_required_fields():
    """Test schema validation fails when mandatory fields are omitted."""
    with pytest.raises(ValidationError):
        SecurityEventBase(
            # Missing source, event_category, event_name, action_status
            principal_name="incomplete@secplatform.local"
        )


def test_synthetic_trigger_request_validation():
    """Test validation of synthetic scenario names."""
    valid_req = SyntheticTriggerRequest(scenario_name="credential_compromise")
    assert valid_req.scenario_name == "credential_compromise"

    with pytest.raises(ValidationError):
        SyntheticTriggerRequest(scenario_name="unsupported_scenario_name")
