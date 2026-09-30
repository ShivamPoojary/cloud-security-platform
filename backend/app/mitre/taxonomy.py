"""MITRE ATT&CK for Cloud (Enterprise) taxonomy and mappings.

Specifically catalogs the 7 seeded detection rules from app/core/seed.py:
1. T1110.001 - AZ-RULE-0010 (Brute Force / Password Guessing, Initial Access)
2. T1484.002 - AZ-RULE-0025 (Domain Policy / Trust Modification, Privilege Escalation)
3. T1555.006 - AZ-RULE-0042 (Credentials from Password Stores: Cloud Secrets Management, Credential Access)
4. T1562.008 - AZ-RULE-0080 (Impair Defenses: Disable Cloud Security Tools, Defense Evasion)
5. T1621     - AZ-RULE-0012 (Multi-Factor Authentication Request Generation, Credential Access)
6. T1580     - AZ-RULE-0040 (Cloud Infrastructure Discovery, Discovery)
7. T1485     - AZ-RULE-0085 (Data Destruction, Impact)
"""

from typing import Dict, Any, List

# Standard Cloud Matrix Tactics
MITRE_TACTICS: Dict[str, Dict[str, str]] = {
    "TA0001": {
        "id": "TA0001",
        "name": "Initial Access",
        "description": "Techniques that use various entry vectors to gain an initial foothold in a cloud environment.",
    },
    "TA0002": {
        "id": "TA0002",
        "name": "Execution",
        "description": "Techniques that result in adversary-controlled code running on a local or remote system.",
    },
    "TA0003": {
        "id": "TA0003",
        "name": "Persistence",
        "description": "Techniques that adversaries use to keep access to systems across restarts or credential changes.",
    },
    "TA0004": {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "description": "Techniques that adversaries use to gain higher-level permissions on cloud resources.",
    },
    "TA0005": {
        "id": "TA0005",
        "name": "Defense Evasion",
        "description": "Techniques that adversaries use to avoid detection throughout their compromise.",
    },
    "TA0006": {
        "id": "TA0006",
        "name": "Credential Access",
        "description": "Techniques for stealing credentials such as tokens, secrets, passwords, or certificates.",
    },
    "TA0007": {
        "id": "TA0007",
        "name": "Discovery",
        "description": "Techniques an adversary may use to gain knowledge about the cloud system and internal network.",
    },
    "TA0008": {
        "id": "TA0008",
        "name": "Lateral Movement",
        "description": "Techniques that adversaries use to enter and control remote systems on a network.",
    },
    "TA0009": {
        "id": "TA0009",
        "name": "Collection",
        "description": "Techniques adversaries may use to gather data of interest to their goal.",
    },
    "TA0011": {
        "id": "TA0011",
        "name": "Command and Control",
        "description": "Techniques that adversaries use to communicate with systems under their control.",
    },
    "TA0010": {
        "id": "TA0010",
        "name": "Exfiltration",
        "description": "Techniques that adversaries use to steal data from your network or cloud storage.",
    },
    "TA0040": {
        "id": "TA0040",
        "name": "Impact",
        "description": "Techniques that adversaries use to disrupt availability or compromise integrity.",
    },
}

# Mapping of the 7 primary seeded detection techniques
MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1110.001": {
        "id": "T1110.001",
        "name": "Password Guessing",
        "parent_technique": "T1110",
        "tactic": "Initial Access",
        "tactics": ["Initial Access", "Credential Access"],
        "description": "Adversaries may attempt to guess passwords to gain access to accounts. In cloud environments, this manifests as automated brute-force or credential stuffing attempts against portal login interfaces.",
        "data_sources": ["Azure Active Directory Sign-in Logs", "Identity", "Audit Logs"],
        "detection_rules": ["AZ-RULE-0010"],
        "severity_hint": "MEDIUM",
        "is_known": True,
    },
    "T1484.002": {
        "id": "T1484.002",
        "name": "Domain Trust Modification",
        "parent_technique": "T1484",
        "tactic": "Privilege Escalation",
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "description": "Adversaries may modify cloud domain trust configurations or assign elevated RBAC roles (Owner/Contributor) to achieve privilege escalation.",
        "data_sources": ["Azure Activity Logs", "Microsoft.Authorization/roleAssignments"],
        "detection_rules": ["AZ-RULE-0025"],
        "severity_hint": "HIGH",
        "is_known": True,
    },
    "T1555.006": {
        "id": "T1555.006",
        "name": "Credentials from Password Stores: Cloud Secrets Management",
        "parent_technique": "T1555",
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries may search for and extract credentials and secrets from cloud secret repositories like Azure Key Vault.",
        "data_sources": ["Azure Key Vault Diagnostic Logs", "Microsoft.KeyVault/vaults/secrets"],
        "detection_rules": ["AZ-RULE-0042"],
        "severity_hint": "HIGH",
        "is_known": True,
    },
    "T1562.008": {
        "id": "T1562.008",
        "name": "Impair Defenses: Disable Cloud Security Tools",
        "parent_technique": "T1562",
        "tactic": "Defense Evasion",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may disable or modify cloud security defense configurations such as Microsoft Defender for Cloud pricing plans to evade detection.",
        "data_sources": ["Azure Activity Logs", "Microsoft.Security/pricings"],
        "detection_rules": ["AZ-RULE-0080"],
        "severity_hint": "CRITICAL",
        "is_known": True,
    },
    "T1621": {
        "id": "T1621",
        "name": "Multi-Factor Authentication Request Generation",
        "parent_technique": None,
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries may generate repetitive MFA prompt requests (MFA fatigue/push spamming) to coerce authentication from target users.",
        "data_sources": ["Azure AD Sign-in Logs", "MFA Prompt Telemetry"],
        "detection_rules": ["AZ-RULE-0012"],
        "severity_hint": "HIGH",
        "is_known": True,
    },
    "T1580": {
        "id": "T1580",
        "name": "Cloud Infrastructure Discovery",
        "parent_technique": None,
        "tactic": "Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may attempt to discover cloud infrastructure components such as Key Vaults, storage accounts, and compute resources.",
        "data_sources": ["Azure Activity Logs", "Microsoft.KeyVault/vaults/read"],
        "detection_rules": ["AZ-RULE-0040"],
        "severity_hint": "MEDIUM",
        "is_known": True,
    },
    "T1485": {
        "id": "T1485",
        "name": "Data Destruction",
        "parent_technique": None,
        "tactic": "Impact",
        "tactics": ["Impact"],
        "description": "Adversaries may destroy data or cloud storage containers (e.g. Azure Storage blob containers) to interrupt availability or destroy evidence.",
        "data_sources": ["Azure Activity Logs", "Microsoft.Storage/storageAccounts/blobServices/containers/delete"],
        "detection_rules": ["AZ-RULE-0085"],
        "severity_hint": "CRITICAL",
        "is_known": True,
    },
}

# Rule ID to MITRE Technique ID fast lookup
RULE_TO_TECHNIQUE_MAP: Dict[str, str] = {
    "AZ-RULE-0010": "T1110.001",
    "AZ-RULE-0025": "T1484.002",
    "AZ-RULE-0042": "T1555.006",
    "AZ-RULE-0080": "T1562.008",
    "AZ-RULE-0012": "T1621",
    "AZ-RULE-0040": "T1580",
    "AZ-RULE-0085": "T1485",
}
