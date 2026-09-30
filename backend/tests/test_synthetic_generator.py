import uuid
from datetime import datetime
from app.ingestion.synthetic_generator import SyntheticAzureTelemetryGenerator


def test_generate_normal_event():
    """Verify normal baseline events contain required security attributes."""
    for _ in range(20):
        event = SyntheticAzureTelemetryGenerator.generate_normal_event()
        assert isinstance(event.event_id, uuid.UUID)
        assert isinstance(event.timestamp, datetime)
        assert event.source in ["SignInLogs", "AzureActivity", "StorageBlobLogs"]
        assert event.event_category in ["Identity", "ResourceManagement", "Storage"]
        assert event.action_status == "Success"
        assert event.caller_ip is not None
        assert event.user_agent is not None
        assert event.geo_country is not None


def test_generate_attack_scenario_credential_compromise():
    """Verify Scenario 1: Credential Stuffing -> MFA Fatigue -> Privilege Escalation."""
    events = SyntheticAzureTelemetryGenerator.generate_attack_scenario("credential_compromise")
    assert len(events) >= 10

    # Ensure failed logins present (Stage 1)
    failed_logins = [e for e in events if e.event_name == "UserLoginFailed"]
    assert len(failed_logins) >= 5
    assert all(e.action_status == "Failure" for e in failed_logins)

    # Ensure MFA fatigue present (Stage 2)
    mfa_prompts = [e for e in events if e.event_name == "MfaPromptSent"]
    assert len(mfa_prompts) >= 2

    # Ensure privilege escalation present (Stage 4)
    role_assigns = [e for e in events if "roleAssignments/write" in e.event_name]
    assert len(role_assigns) >= 1
    assert role_assigns[0].action_status == "Success"


def test_generate_attack_scenario_keyvault_exfiltration():
    """Verify Scenario 2: Service Principal Compromise -> Key Vault Enumeration -> Mass Secret Retrieval."""
    vault_name = "kv-finance-prod"
    events = SyntheticAzureTelemetryGenerator.generate_attack_scenario(
        "keyvault_exfiltration", custom_target=vault_name
    )
    assert len(events) >= 15

    # Check Key Vault enumeration
    vault_read = [e for e in events if "Microsoft.KeyVault/vaults/read" in e.event_name]
    assert len(vault_read) == 1

    # Check bulk secret retrieval
    secret_reads = [e for e in events if "getSecret/action" in e.event_name]
    assert len(secret_reads) >= 10
    assert all(vault_name in e.target_resource_id for e in secret_reads)


def test_generate_attack_scenario_ransomware():
    """Verify Scenario 3: Disable Security Monitoring -> Mass Storage Deletion."""
    events = SyntheticAzureTelemetryGenerator.generate_attack_scenario("ransomware")
    assert len(events) >= 4

    # Check security disabled
    sec_disabled = [e for e in events if "pricings/write" in e.event_name]
    assert len(sec_disabled) == 1
    assert sec_disabled[0].metadata.get("pricing_tier") == "Free"

    # Check container deletions
    deletions = [e for e in events if "containers/delete" in e.event_name]
    assert len(deletions) >= 3
