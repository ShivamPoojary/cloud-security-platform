"""Unit tests for the MITRE ATT&CK Service (Milestone 4.1).

Validates coverage of the 7 seeded detection rules from app/core/seed.py:
1. T1110.001 - AZ-RULE-0010 (Brute Force / Password Guessing, Initial Access)
2. T1484.002 - AZ-RULE-0025 (Domain Policy / Trust Modification, Privilege Escalation)
3. T1555.006 - AZ-RULE-0042 (Cloud Secrets Management, Credential Access)
4. T1562.008 - AZ-RULE-0080 (Disable Cloud Security Tools, Defense Evasion)
5. T1621     - AZ-RULE-0012 (MFA Request Generation / Fatigue, Credential Access)
6. T1580     - AZ-RULE-0040 (Cloud Infrastructure Discovery, Discovery)
7. T1485     - AZ-RULE-0085 (Data Destruction, Impact)
"""

import pytest
from app.mitre.service import MitreService, mitre_service
from app.domain.schemas.mitre import (
    MitreTechniqueRead,
    MitreTacticRead,
    MitreEnrichmentRead,
)


class TestMitreService:
    """Test suite for MITRE ATT&CK service and taxonomies."""

    def test_seeded_techniques_lookups(self):
        """All 7 seeded techniques from seed.py must be registered and resolvable."""
        seeded_expected = [
            ("T1110.001", "Password Guessing", "Initial Access", "AZ-RULE-0010"),
            ("T1484.002", "Domain Trust Modification", "Privilege Escalation", "AZ-RULE-0025"),
            ("T1555.006", "Credentials from Password Stores: Cloud Secrets Management", "Credential Access", "AZ-RULE-0042"),
            ("T1562.008", "Impair Defenses: Disable Cloud Security Tools", "Defense Evasion", "AZ-RULE-0080"),
            ("T1621", "Multi-Factor Authentication Request Generation", "Credential Access", "AZ-RULE-0012"),
            ("T1580", "Cloud Infrastructure Discovery", "Discovery", "AZ-RULE-0040"),
            ("T1485", "Data Destruction", "Impact", "AZ-RULE-0085"),
        ]

        for tech_id, name, tactic, rule_id in seeded_expected:
            tech = mitre_service.get_technique(tech_id)
            assert tech.id == tech_id
            assert tech.name == name
            assert tech.tactic == tactic
            assert rule_id in tech.detection_rules
            assert tech.is_known is True
            assert len(tech.data_sources) > 0
            assert len(tech.description) > 0

    def test_case_insensitivity_and_whitespace_in_lookups(self):
        tech_upper = mitre_service.get_technique("T1110.001")
        tech_lower = mitre_service.get_technique("  t1110.001  ")
        assert tech_upper.id == tech_lower.id
        assert tech_upper.name == tech_lower.name

    def test_rule_to_technique_reverse_mapping(self):
        rule_mappings = {
            "AZ-RULE-0010": "T1110.001",
            "AZ-RULE-0025": "T1484.002",
            "AZ-RULE-0042": "T1555.006",
            "AZ-RULE-0080": "T1562.008",
            "AZ-RULE-0012": "T1621",
            "AZ-RULE-0040": "T1580",
            "AZ-RULE-0085": "T1485",
        }

        for rule_id, expected_tech_id in rule_mappings.items():
            tech = mitre_service.get_technique_by_rule_id(rule_id)
            assert tech is not None
            assert tech.id == expected_tech_id

        # Unknown rule ID returns None
        assert mitre_service.get_technique_by_rule_id("AZ-RULE-9999") is None

    def test_unknown_technique_graceful_fallback(self):
        tech = mitre_service.get_technique("T9999.999")
        assert tech.id == "T9999.999"
        assert tech.is_known is False
        assert "Custom Technique" in tech.name
        assert tech.tactic == "Unknown"

        # Empty string
        tech_empty = mitre_service.get_technique("")
        assert tech_empty.id == "UNKNOWN"
        assert tech_empty.is_known is False

    def test_get_techniques_by_tactic_name_and_id(self):
        # By tactic name
        cred_techniques = mitre_service.get_techniques_by_tactic("Credential Access")
        cred_ids = {t.id for t in cred_techniques}
        assert "T1555.006" in cred_ids
        assert "T1621" in cred_ids
        assert "T1110.001" in cred_ids  # secondary tactic

        # By tactic ID TA0006
        cred_by_id = mitre_service.get_techniques_by_tactic("TA0006")
        assert {t.id for t in cred_by_id} == cred_ids

        # Impact
        impact_techniques = mitre_service.get_techniques_by_tactic("Impact")
        assert any(t.id == "T1485" for t in impact_techniques)

        # Discovery
        disc_techniques = mitre_service.get_techniques_by_tactic("Discovery")
        assert any(t.id == "T1580" for t in disc_techniques)

        # Non-existent tactic returns empty list
        assert mitre_service.get_techniques_by_tactic("NonExistentTactic") == []

    def test_list_tactics_coverage(self):
        tactics = mitre_service.list_tactics()
        assert len(tactics) == 12
        tactic_names = {t.name for t in tactics}
        assert "Initial Access" in tactic_names
        assert "Privilege Escalation" in tactic_names
        assert "Defense Evasion" in tactic_names
        assert "Credential Access" in tactic_names
        assert "Impact" in tactic_names
        assert "Discovery" in tactic_names

    def test_list_all_techniques(self):
        techniques = mitre_service.list_techniques()
        assert len(techniques) >= 7
        tech_ids = {t.id for t in techniques}
        assert "T1110.001" in tech_ids
        assert "T1484.002" in tech_ids
        assert "T1555.006" in tech_ids
        assert "T1562.008" in tech_ids
        assert "T1621" in tech_ids
        assert "T1580" in tech_ids
        assert "T1485" in tech_ids

    def test_enrichment_resolution(self):
        # Enrich by technique ID
        enrichment = mitre_service.enrich(technique_id="T1562.008")
        assert isinstance(enrichment, MitreEnrichmentRead)
        assert enrichment.technique_id == "T1562.008"
        assert enrichment.tactic == "Defense Evasion"
        assert enrichment.severity_hint == "CRITICAL"
        assert enrichment.is_known is True
        assert "AZ-RULE-0080" in enrichment.detection_rules

        # Enrich by rule ID
        enrich_rule = mitre_service.enrich(rule_id="AZ-RULE-0085")
        assert enrich_rule.technique_id == "T1485"
        assert enrich_rule.tactic == "Impact"
        assert enrich_rule.severity_hint == "CRITICAL"
        assert enrich_rule.is_known is True

        # Enrich unknown technique
        enrich_unknown = mitre_service.enrich(technique_id="T8888")
        assert enrich_unknown.is_known is False
        assert enrich_unknown.technique_id == "T8888"
        assert enrich_unknown.tactic == "Unknown"
