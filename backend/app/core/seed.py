import asyncio
import uuid
from datetime import datetime, timezone
from sqlalchemy import select
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.security import get_password_hash
from app.core.logging import logger
from app.domain.models.users import User
from app.domain.models.rules import DetectionRule


async def seed_data():
    """Seeds initial development users and default detection rules."""
    logger.info("Starting development data seed process...")

    seed_password = settings.DEV_SEED_PASSWORD
    hashed_pwd = get_password_hash(seed_password)

    async with AsyncSessionLocal() as session:
        # 1. Seed Users
        users_to_seed = [
            {
                "email": "admin@secplatform.local",
                "full_name": "Chief Security Architect (Admin)",
                "role": "SOC_ADMIN",
            },
            {
                "email": "analyst1@secplatform.local",
                "full_name": "Tier 1 SOC Analyst",
                "role": "L1_ANALYST",
            },
            {
                "email": "responder1@secplatform.local",
                "full_name": "Senior Incident Responder (L2/L3)",
                "role": "L2_RESPONDER",
            },
        ]

        for u_data in users_to_seed:
            result = await session.execute(
                select(User).where(User.email == u_data["email"])
            )
            existing_user = result.scalars().first()
            if not existing_user:
                new_user = User(
                    id=uuid.uuid4(),
                    email=u_data["email"],
                    hashed_password=hashed_pwd,
                    full_name=u_data["full_name"],
                    role=u_data["role"],
                    is_active=True,
                )
                session.add(new_user)
                logger.info(f"Seeded user: {u_data['email']} ({u_data['role']})")
            else:
                logger.info(f"User already exists: {u_data['email']}")

        # 2. Seed Initial Detection Rules (from Architecture Specification)
        rules_to_seed = [
            {
                "rule_id": "AZ-RULE-0010",
                "title": "Azure Portal Credential Stuffing & Brute Force",
                "severity": "MEDIUM",
                "mitre_tactic": "Initial Access",
                "mitre_technique_id": "T1110.001",
                "description": "Detects 5 or more failed sign-in attempts against Azure Portal from a single IP within 3 minutes.",
                "rule_logic": {
                    "type": "stateful_threshold",
                    "window_seconds": 180,
                    "threshold": 5,
                    "filter": {
                        "event_category": "Identity",
                        "event_name": "UserLoginFailed",
                        "action_status": "Failure",
                    },
                },
            },
            {
                "rule_id": "AZ-RULE-0025",
                "title": "Privileged Azure Role Assignment (Owner/Admin Escalation)",
                "severity": "HIGH",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique_id": "T1484.002",
                "description": "Detects assignment of Owner or Contributor role to a new principal or shadow account.",
                "rule_logic": {
                    "type": "stateless_pattern",
                    "filter": {
                        "event_category": "ResourceManagement",
                        "event_name": "Microsoft.Authorization/roleAssignments/write",
                        "action_status": "Success",
                    },
                },
            },
            {
                "rule_id": "AZ-RULE-0042",
                "title": "Azure Key Vault Mass Secret Retrieval",
                "severity": "HIGH",
                "mitre_tactic": "Credential Access",
                "mitre_technique_id": "T1555.006",
                "description": "Detects an identity retrieving more than 10 secrets from an Azure Key Vault within 3 minutes.",
                "rule_logic": {
                    "type": "stateful_threshold",
                    "window_seconds": 180,
                    "threshold": 10,
                    "filter": {
                        "event_category": "Storage",
                        "event_name": "Microsoft.KeyVault/vaults/secrets/getSecret/action",
                        "action_status": "Success",
                    },
                },
            },
            {
                "rule_id": "AZ-RULE-0080",
                "title": "Microsoft Defender for Cloud Security Monitoring Disabled",
                "severity": "CRITICAL",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique_id": "T1562.008",
                "description": "Detects tampering or disabling of Microsoft Defender for Cloud security pricing and monitoring tiers.",
                "rule_logic": {
                    "type": "stateless_pattern",
                    "filter": {
                        "event_category": "Security",
                        "event_name": "Microsoft.Security/pricings/write",
                        "action_status": "Success",
                    },
                },
            },
            {
                "rule_id": "AZ-RULE-0012",
                "title": "MFA Fatigue & Repeated Push Notification Anomaly",
                "severity": "HIGH",
                "mitre_tactic": "Credential Access",
                "mitre_technique_id": "T1621",
                "description": "Detects 2 or more MFA push notification requests sent to a user in under 3 minutes.",
                "rule_logic": {
                    "type": "stateful_threshold",
                    "window_seconds": 180,
                    "threshold": 2,
                    "filter": {
                        "event_category": "Identity",
                        "event_name": "MfaPromptSent",
                    },
                },
            },
            {
                "rule_id": "AZ-RULE-0040",
                "title": "Azure Key Vault Reconnaissance & Discovery",
                "severity": "MEDIUM",
                "mitre_tactic": "Discovery",
                "mitre_technique_id": "T1580",
                "description": "Detects enumeration and listing of Azure Key Vault instances.",
                "rule_logic": {
                    "type": "stateless_pattern",
                    "filter": {
                        "event_category": "ResourceManagement",
                        "event_name": "Microsoft.KeyVault/vaults/read",
                        "action_status": "Success",
                    },
                },
            },
            {
                "rule_id": "AZ-RULE-0085",
                "title": "Azure Storage Account Mass Container Deletion",
                "severity": "CRITICAL",
                "mitre_tactic": "Impact",
                "mitre_technique_id": "T1485",
                "description": "Detects 3 or more storage blob containers deleted within 3 minutes.",
                "rule_logic": {
                    "type": "stateful_threshold",
                    "window_seconds": 180,
                    "threshold": 3,
                    "filter": {
                        "event_category": "Storage",
                        "event_name": "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
                        "action_status": "Success",
                    },
                },
            },
        ]

        for r_data in rules_to_seed:
            result = await session.execute(
                select(DetectionRule).where(DetectionRule.rule_id == r_data["rule_id"])
            )
            existing_rule = result.scalars().first()
            if not existing_rule:
                new_rule = DetectionRule(
                    id=uuid.uuid4(),
                    rule_id=r_data["rule_id"],
                    title=r_data["title"],
                    severity=r_data["severity"],
                    mitre_tactic=r_data["mitre_tactic"],
                    mitre_technique_id=r_data["mitre_technique_id"],
                    description=r_data["description"],
                    rule_logic=r_data["rule_logic"],
                    is_active=True,
                )
                session.add(new_rule)
                logger.info(f"Seeded detection rule: {r_data['rule_id']} - {r_data['title']}")
            else:
                logger.info(f"Detection rule already exists: {r_data['rule_id']}")

        await session.commit()
        logger.info("Data seeding completed successfully.")


if __name__ == "__main__":
    asyncio.run(seed_data())
