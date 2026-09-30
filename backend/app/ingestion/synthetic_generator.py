import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from app.domain.schemas.event import SecurityEventBase


class SyntheticAzureTelemetryGenerator:
    """Generates realistic synthetic Azure cloud telemetry for baseline noise

    and multi-stage attack scenarios without incurring cloud costs.
    """

    EMPLOYEES = [
        ("usr-corp-101", "alice.smith@secplatform.local", "198.51.100.10", "United States"),
        ("usr-corp-102", "bob.jones@secplatform.local", "198.51.100.11", "United States"),
        ("usr-corp-103", "charlie.brown@secplatform.local", "198.51.100.12", "Canada"),
        ("usr-corp-104", "dana.scully@secplatform.local", "198.51.100.13", "United Kingdom"),
    ]

    DEVELOPERS = [
        ("usr-dev-201", "dev.lead@secplatform.local", "203.0.113.45", "United States"),
        ("usr-dev-202", "cloud.architect@secplatform.local", "203.0.113.46", "Germany"),
    ]

    SERVICE_PRINCIPALS = [
        ("spn-github-cicd", "spn-github-actions-deploy", "140.82.112.4", "United States"),
        ("spn-backup-job", "spn-nightly-backup-agent", "20.190.159.2", "United States"),
    ]

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
        "AzureCLI/2.58.0 (MSI)",
        "GitHub-Actions-Runner/2.314.0",
        "Python/3.11 aiohttp/3.9.3",
    ]

    @classmethod
    def generate_normal_event(cls, base_time: Optional[datetime] = None) -> SecurityEventBase:
        """Generates a single normal baseline event."""
        now = base_time or datetime.now(timezone.utc)
        event_type = random.choice([
            "employee_login",
            "developer_login",
            "resource_read",
            "deployment",
            "storage_access",
            "cicd_activity",
        ])

        if event_type == "employee_login":
            pid, pname, ip, country = random.choice(cls.EMPLOYEES)
            return SecurityEventBase(
                event_id=uuid.uuid4(),
                timestamp=now,
                source="SignInLogs",
                event_category="Identity",
                event_name="UserLoggedIn",
                principal_id=pid,
                principal_name=pname,
                caller_ip=ip,
                target_resource_id="/tenants/tenant-secplatform/applications/Office365",
                target_resource_name="Microsoft 365 Exchange Online",
                action_status="Success",
                geo_country=country,
                user_agent=cls.USER_AGENTS[0],
                metadata={"auth_method": "Password + FIDO2", "mfa_satisfied": True},
            )

        elif event_type == "developer_login":
            pid, pname, ip, country = random.choice(cls.DEVELOPERS)
            return SecurityEventBase(
                event_id=uuid.uuid4(),
                timestamp=now,
                source="SignInLogs",
                event_category="Identity",
                event_name="UserLoggedIn",
                principal_id=pid,
                principal_name=pname,
                caller_ip=ip,
                target_resource_id="/tenants/tenant-secplatform/applications/AzurePortal",
                target_resource_name="Microsoft Azure Portal",
                action_status="Success",
                geo_country=country,
                user_agent=cls.USER_AGENTS[0],
                metadata={"auth_method": "Azure Authenticator Push", "client_app": "Browser"},
            )

        elif event_type == "resource_read":
            pid, pname, ip, country = random.choice(cls.DEVELOPERS)
            return SecurityEventBase(
                event_id=uuid.uuid4(),
                timestamp=now,
                source="AzureActivity",
                event_category="ResourceManagement",
                event_name="Microsoft.Resources/subscriptions/resourceGroups/read",
                principal_id=pid,
                principal_name=pname,
                caller_ip=ip,
                target_resource_id="/subscriptions/sub-core-01/resourceGroups/rg-app-prod",
                target_resource_name="rg-app-prod",
                action_status="Success",
                geo_country=country,
                user_agent=cls.USER_AGENTS[2],
                metadata={"api_version": "2021-04-01", "http_method": "GET"},
            )

        elif event_type == "deployment":
            pid, pname, ip, country = random.choice(cls.SERVICE_PRINCIPALS)
            return SecurityEventBase(
                event_id=uuid.uuid4(),
                timestamp=now,
                source="AzureActivity",
                event_category="ResourceManagement",
                event_name="Microsoft.Web/sites/deployments/write",
                principal_id=pid,
                principal_name=pname,
                caller_ip=ip,
                target_resource_id="/subscriptions/sub-core-01/resourceGroups/rg-app-prod/providers/Microsoft.Web/sites/api-gateway-prod",
                target_resource_name="api-gateway-prod",
                action_status="Success",
                geo_country=country,
                user_agent=cls.USER_AGENTS[3],
                metadata={"deployment_id": f"deploy-{random.randint(1000, 9999)}", "slot": "production"},
            )

        elif event_type == "storage_access":
            pid, pname, ip, country = random.choice(cls.DEVELOPERS)
            return SecurityEventBase(
                event_id=uuid.uuid4(),
                timestamp=now,
                source="StorageBlobLogs",
                event_category="Storage",
                event_name="GetBlob",
                principal_id=pid,
                principal_name=pname,
                caller_ip=ip,
                target_resource_id="/subscriptions/sub-core-01/resourceGroups/rg-app-prod/providers/Microsoft.Storage/storageAccounts/stappdata/blobServices/default/containers/public-assets",
                target_resource_name="stappdata/public-assets/logo.png",
                action_status="Success",
                geo_country=country,
                user_agent=cls.USER_AGENTS[1],
                metadata={"content_length_bytes": 45120, "tls_version": "1.3"},
            )

        else:  # cicd_activity
            pid, pname, ip, country = cls.SERVICE_PRINCIPALS[0]
            return SecurityEventBase(
                event_id=uuid.uuid4(),
                timestamp=now,
                source="AzureActivity",
                event_category="ResourceManagement",
                event_name="Microsoft.ContainerRegistry/registries/push/action",
                principal_id=pid,
                principal_name=pname,
                caller_ip=ip,
                target_resource_id="/subscriptions/sub-core-01/resourceGroups/rg-app-prod/providers/Microsoft.ContainerRegistry/registries/crplatform",
                target_resource_name="crplatform",
                action_status="Success",
                geo_country=country,
                user_agent=cls.USER_AGENTS[3],
                metadata={"image_tag": "v1.4.2", "layer_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            )

    @classmethod
    def generate_attack_scenario(
        cls, scenario_name: str, custom_target: Optional[str] = None
    ) -> List[SecurityEventBase]:
        """Generates realistic multi-event kill-chain attack scenarios."""
        events: List[SecurityEventBase] = []
        base_time = datetime.now(timezone.utc) - timedelta(minutes=15)

        if scenario_name == "credential_compromise":
            # Scenario 1: Credential Stuffing -> MFA Fatigue -> Privilege Escalation
            attacker_ip = "198.51.100.99"
            target_user_id = "usr-corp-101"
            target_user_email = "alice.smith@secplatform.local"

            # Stage 1: Brute force / credential stuffing (6 failed logins)
            for i in range(6):
                events.append(
                    SecurityEventBase(
                        event_id=uuid.uuid4(),
                        timestamp=base_time + timedelta(seconds=i * 12),
                        source="SignInLogs",
                        event_category="Identity",
                        event_name="UserLoginFailed",
                        principal_id=target_user_id,
                        principal_name=target_user_email,
                        caller_ip=attacker_ip,
                        target_resource_id="/tenants/tenant-secplatform/applications/AzurePortal",
                        target_resource_name="Microsoft Azure Portal",
                        action_status="Failure",
                        geo_country="Russian Federation",
                        user_agent="Python-requests/2.31.0",
                        metadata={"failure_reason": "Invalid password", "attempt_count": i + 1},
                    )
                )

            # Stage 2: Repeated MFA push notifications (MFA Fatigue)
            for i in range(3):
                events.append(
                    SecurityEventBase(
                        event_id=uuid.uuid4(),
                        timestamp=base_time + timedelta(minutes=2, seconds=i * 15),
                        source="SignInLogs",
                        event_category="Identity",
                        event_name="MfaPromptSent",
                        principal_id=target_user_id,
                        principal_name=target_user_email,
                        caller_ip=attacker_ip,
                        target_resource_id="/tenants/tenant-secplatform/applications/AzurePortal",
                        target_resource_name="Microsoft Azure Portal",
                        action_status="Failure",
                        geo_country="Russian Federation",
                        user_agent="Python-requests/2.31.0",
                        metadata={"mfa_result": "PromptTimedOut", "notification_id": f"mfa-{i+1}"},
                    )
                )

            # Stage 3: MFA Approved & Successful Login
            events.append(
                SecurityEventBase(
                    event_id=uuid.uuid4(),
                    timestamp=base_time + timedelta(minutes=3, seconds=5),
                    source="SignInLogs",
                    event_category="Identity",
                    event_name="UserLoggedIn",
                    principal_id=target_user_id,
                    principal_name=target_user_email,
                    caller_ip=attacker_ip,
                    target_resource_id="/tenants/tenant-secplatform/applications/AzurePortal",
                    target_resource_name="Microsoft Azure Portal",
                    action_status="Success",
                    geo_country="Russian Federation",
                    user_agent=cls.USER_AGENTS[0],
                    metadata={"auth_method": "Azure Authenticator Push Approved", "risk_flag": "High"},
                )
            )

            # Stage 4: Privilege Escalation - Assign Owner Role
            events.append(
                SecurityEventBase(
                    event_id=uuid.uuid4(),
                    timestamp=base_time + timedelta(minutes=5),
                    source="AzureActivity",
                    event_category="ResourceManagement",
                    event_name="Microsoft.Authorization/roleAssignments/write",
                    principal_id=target_user_id,
                    principal_name=target_user_email,
                    caller_ip=attacker_ip,
                    target_resource_id="/subscriptions/sub-core-01/providers/Microsoft.Authorization/roleAssignments/ra-shadow-admin",
                    target_resource_name="RoleAssignment: Owner",
                    action_status="Success",
                    geo_country="Russian Federation",
                    user_agent=cls.USER_AGENTS[2],
                    metadata={
                        "role_definition": "Owner (8e3af657-a8ff-443c-a75c-2fe8c4bcb635)",
                        "assigned_principal": "spn-rogue-backdoor",
                        "scope": "/subscriptions/sub-core-01",
                    },
                )
            )

        elif scenario_name == "keyvault_exfiltration":
            # Scenario 2: Service Principal Compromise -> Key Vault Enumeration -> Mass Secret Retrieval
            attacker_ip = "203.0.113.199"
            spn_id = "spn-github-cicd"
            spn_name = "spn-github-actions-deploy"
            target_vault = custom_target or "kv-production-core"

            # Stage 1: Unusual Login from unexpected foreign IP
            events.append(
                SecurityEventBase(
                    event_id=uuid.uuid4(),
                    timestamp=base_time,
                    source="SignInLogs",
                    event_category="Identity",
                    event_name="ServicePrincipalLoggedIn",
                    principal_id=spn_id,
                    principal_name=spn_name,
                    caller_ip=attacker_ip,
                    target_resource_id="/tenants/tenant-secplatform/applications/spn-github-cicd",
                    target_resource_name=spn_name,
                    action_status="Success",
                    geo_country="Netherlands",
                    user_agent="Go-http-client/1.1",
                    metadata={"credential_type": "ClientSecret", "is_novel_location": True},
                )
            )

            # Stage 2: Vault enumeration
            events.append(
                SecurityEventBase(
                    event_id=uuid.uuid4(),
                    timestamp=base_time + timedelta(minutes=1),
                    source="AzureActivity",
                    event_category="ResourceManagement",
                    event_name="Microsoft.KeyVault/vaults/read",
                    principal_id=spn_id,
                    principal_name=spn_name,
                    caller_ip=attacker_ip,
                    target_resource_id=f"/subscriptions/sub-core-01/resourceGroups/rg-app-prod/providers/Microsoft.KeyVault/vaults/{target_vault}",
                    target_resource_name=target_vault,
                    action_status="Success",
                    geo_country="Netherlands",
                    user_agent="AzureCLI/2.58.0",
                    metadata={"operation": "ListVaults"},
                )
            )

            # Stage 3: Mass Secret Retrieval (16 consecutive calls)
            for i in range(16):
                secret_name = f"sec-prod-db-password-{i+1}"
                events.append(
                    SecurityEventBase(
                        event_id=uuid.uuid4(),
                        timestamp=base_time + timedelta(minutes=2, seconds=i * 4),
                        source="KeyVault",
                        event_category="Storage",
                        event_name="Microsoft.KeyVault/vaults/secrets/getSecret/action",
                        principal_id=spn_id,
                        principal_name=spn_name,
                        caller_ip=attacker_ip,
                        target_resource_id=f"/subscriptions/sub-core-01/resourceGroups/rg-app-prod/providers/Microsoft.KeyVault/vaults/{target_vault}/secrets/{secret_name}",
                        target_resource_name=secret_name,
                        action_status="Success",
                        geo_country="Netherlands",
                        user_agent="AzureCLI/2.58.0",
                        metadata={"vault_name": target_vault, "secret_version": "v1", "bytes_read": 128},
                    )
                )

        elif scenario_name == "ransomware":
            # Scenario 3: Ransomware / Defense Evasion -> Disable Security Monitoring -> Mass Storage Deletion
            attacker_ip = "192.0.2.77"
            compromised_admin_id = "usr-dev-201"
            compromised_admin_name = "dev.lead@secplatform.local"

            # Stage 1: Disable Microsoft Defender for Cloud
            events.append(
                SecurityEventBase(
                    event_id=uuid.uuid4(),
                    timestamp=base_time,
                    source="AzureActivity",
                    event_category="Security",
                    event_name="Microsoft.Security/pricings/write",
                    principal_id=compromised_admin_id,
                    principal_name=compromised_admin_name,
                    caller_ip=attacker_ip,
                    target_resource_id="/subscriptions/sub-core-01/providers/Microsoft.Security/pricings/VirtualMachines",
                    target_resource_name="DefenderForContainers",
                    action_status="Success",
                    geo_country="China",
                    user_agent="curl/8.4.0",
                    metadata={"pricing_tier": "Free", "previous_tier": "Standard", "reason": "Defense Evasion"},
                )
            )

            # Stage 2: Mass storage account and container deletion
            containers = ["customer-data-backup", "financial-records-2025", "user-pii-vault", "audit-logs-cold"]
            for i, c_name in enumerate(containers):
                events.append(
                    SecurityEventBase(
                        event_id=uuid.uuid4(),
                        timestamp=base_time + timedelta(minutes=1, seconds=i * 8),
                        source="AzureActivity",
                        event_category="Storage",
                        event_name="Microsoft.Storage/storageAccounts/blobServices/containers/delete",
                        principal_id=compromised_admin_id,
                        principal_name=compromised_admin_name,
                        caller_ip=attacker_ip,
                        target_resource_id=f"/subscriptions/sub-core-01/resourceGroups/rg-app-prod/providers/Microsoft.Storage/storageAccounts/stenterprisedata/blobServices/default/containers/{c_name}",
                        target_resource_name=c_name,
                        action_status="Success",
                        geo_country="China",
                        user_agent="curl/8.4.0",
                        metadata={"deleted_at": (base_time + timedelta(minutes=1, seconds=i * 8)).isoformat()},
                    )
                )

        else:
            raise ValueError(f"Unknown synthetic attack scenario: {scenario_name}")

        return events
