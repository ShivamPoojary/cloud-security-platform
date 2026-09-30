"""Unit tests for the Composite Risk Scoring Engine (Milestone 4.1).

Verifies the mathematical model in SYSTEM_ARCHITECTURE.md Section 10:
RiskScore = min(
    100,
    ( Σ(w_i × Sev(alert_i)) + α × ML_AnomalyScore )
    × C_Asset × B_Identity × M_Progression
)
"""

import pytest
import math
from app.scoring.constants import (
    SEVERITY_WEIGHTS,
    ML_SCALAR_ALPHA,
    ASSET_MULTIPLIER_STANDARD,
    ASSET_MULTIPLIER_STORAGE,
    ASSET_MULTIPLIER_CRITICAL,
    IDENTITY_MULTIPLIER_STANDARD,
    IDENTITY_MULTIPLIER_ELEVATED,
    IDENTITY_MULTIPLIER_CRITICAL,
    PROGRESSION_MULTIPLIER_SINGLE,
    PROGRESSION_MULTIPLIER_TWO_STAGE,
    PROGRESSION_MULTIPLIER_MULTI_STAGE,
)
from app.scoring.calculator import (
    calculate_risk_score,
    calculate_base_alert_score,
    calculate_ml_contribution,
    derive_asset_multiplier,
    derive_identity_multiplier,
    derive_progression_multiplier,
    classify_severity,
)
from app.scoring.engine import RiskScoringEngine, risk_scoring_engine
from app.domain.schemas.scoring import RiskCalculationRequest, RiskScoreBreakdown


class TestRiskScoringCalculator:
    """Test suite for pure risk calculation functions."""

    def test_single_alert_base_scores(self):
        """Single alerts should receive un-decayed (w_1 = 1.0) weights."""
        score_low, _ = calculate_base_alert_score(["LOW"])
        assert score_low == 10.0

        score_med, _ = calculate_base_alert_score(["MEDIUM"])
        assert score_med == 25.0

        score_high, _ = calculate_base_alert_score(["HIGH"])
        assert score_high == 50.0

        score_crit, _ = calculate_base_alert_score(["CRITICAL"])
        assert score_crit == 80.0

    def test_multiple_alerts_decay_weighting(self):
        """Alerts should decay by w_i = 1 / sqrt(i) ordered by severity descending."""
        # 1 HIGH (50.0) + 1 MEDIUM (25.0)
        # w_1 = 1.0 * 50 = 50.0
        # w_2 = (1 / sqrt(2)) * 25.0 ≈ 17.6776695
        # Total ≈ 67.6776695
        score, breakdown = calculate_base_alert_score(["HIGH", "MEDIUM"])
        expected = 50.0 + (25.0 / math.sqrt(2))
        assert pytest.approx(score, rel=1e-5) == expected
        assert len(breakdown) == 2
        assert breakdown[0]["severity"] == "HIGH"
        assert breakdown[0]["decay_factor"] == 1.0
        assert breakdown[1]["severity"] == "MEDIUM"

        # Order invariance: ["MEDIUM", "HIGH"] yields same result because sort is descending
        score_reversed, _ = calculate_base_alert_score(["MEDIUM", "HIGH"])
        assert pytest.approx(score_reversed, rel=1e-5) == expected

    def test_empty_alerts_yields_zero_base(self):
        score, breakdown = calculate_base_alert_score([])
        assert score == 0.0
        assert breakdown == []

    def test_ml_anomaly_contribution(self):
        """ML anomaly score scalar alpha = 0.25."""
        contrib, clamped = calculate_ml_contribution(0.0)
        assert contrib == 0.0
        assert clamped == 0.0

        # Anomaly score 74.0 -> contribution = 0.25 * 74.0 = 18.5
        contrib_74, clamped_74 = calculate_ml_contribution(74.0)
        assert contrib_74 == 18.5
        assert clamped_74 == 74.0

        # Out-of-bounds clamping
        contrib_high, clamped_high = calculate_ml_contribution(150.0)
        assert clamped_high == 100.0
        assert contrib_high == 25.0

        contrib_neg, clamped_neg = calculate_ml_contribution(-20.0)
        assert clamped_neg == 0.0
        assert contrib_neg == 0.0

    def test_asset_multiplier_derivation(self):
        # Critical resources -> 1.5
        m1, _ = derive_asset_multiplier("Microsoft.KeyVault/vaults/secrets/getSecret/action")
        assert m1 == ASSET_MULTIPLIER_CRITICAL

        m2, _ = derive_asset_multiplier("Microsoft.Authorization/roleAssignments/write")
        assert m2 == ASSET_MULTIPLIER_CRITICAL

        m3, _ = derive_asset_multiplier("Microsoft.Security/pricings/write")
        assert m3 == ASSET_MULTIPLIER_CRITICAL

        # Storage resources -> 1.3
        m4, _ = derive_asset_multiplier("Microsoft.Storage/storageAccounts/blobServices/containers/delete")
        assert m4 == ASSET_MULTIPLIER_STORAGE

        # Standard resources -> 1.0
        m5, _ = derive_asset_multiplier("Microsoft.Compute/virtualMachines/restart")
        assert m5 == ASSET_MULTIPLIER_STANDARD

        # Custom override
        m6, r6 = derive_asset_multiplier("any-resource", custom_multiplier=2.2)
        assert m6 == 2.2
        assert "Custom asset multiplier" in r6

    def test_identity_multiplier_derivation(self):
        # Admin / privileged -> 1.8
        m1, _ = derive_identity_multiplier(principal_role="Global Administrator")
        assert m1 == IDENTITY_MULTIPLIER_CRITICAL

        m2, _ = derive_identity_multiplier(principal_id="spn-backup-agent-privileged")
        assert m2 == IDENTITY_MULTIPLIER_CRITICAL

        m3, _ = derive_identity_multiplier(principal_role="SOC_ADMIN")
        assert m3 == IDENTITY_MULTIPLIER_CRITICAL

        # Elevated -> 1.4
        m4, _ = derive_identity_multiplier(principal_role="Developer")
        assert m4 == IDENTITY_MULTIPLIER_ELEVATED

        m5, _ = derive_identity_multiplier(principal_role="Contributor")
        assert m5 == IDENTITY_MULTIPLIER_ELEVATED

        # Standard -> 1.0
        m6, _ = derive_identity_multiplier(principal_role="Standard User", principal_id="user1@corp.local")
        assert m6 == IDENTITY_MULTIPLIER_STANDARD

        # Custom override
        m7, r7 = derive_identity_multiplier(custom_multiplier=2.5)
        assert m7 == 2.5
        assert "Custom identity multiplier" in r7

    def test_progression_multiplier_derivation(self):
        # 0 or 1 tactic -> 1.0
        m0, _ = derive_progression_multiplier([])
        assert m0 == PROGRESSION_MULTIPLIER_SINGLE

        m1, _ = derive_progression_multiplier(["Initial Access"])
        assert m1 == PROGRESSION_MULTIPLIER_SINGLE

        # 2 distinct tactics -> 1.4
        m2, _ = derive_progression_multiplier(["Initial Access", "Privilege Escalation"])
        assert m2 == PROGRESSION_MULTIPLIER_TWO_STAGE

        # 3 or more distinct tactics -> 1.8
        m3, _ = derive_progression_multiplier([
            "Initial Access",
            "Privilege Escalation",
            "Credential Access",
        ])
        assert m3 == PROGRESSION_MULTIPLIER_MULTI_STAGE

        # Case normalization and deduplication
        m_dup, _ = derive_progression_multiplier([
            "Initial Access",
            "initial access",
            "INITIAL ACCESS",
        ])
        assert m_dup == PROGRESSION_MULTIPLIER_SINGLE

        # Custom override
        m_custom, r_custom = derive_progression_multiplier([], custom_multiplier=1.75)
        assert m_custom == 1.75
        assert "Custom progression multiplier" in r_custom

    def test_severity_tier_classification(self):
        """Tests boundaries: LOW (<40), MEDIUM (40-69), HIGH (70-89), CRITICAL (90-100)."""
        assert classify_severity(0) == "LOW"
        assert classify_severity(39) == "LOW"
        assert classify_severity(40) == "MEDIUM"
        assert classify_severity(69) == "MEDIUM"
        assert classify_severity(70) == "HIGH"
        assert classify_severity(89) == "HIGH"
        assert classify_severity(90) == "CRITICAL"
        assert classify_severity(100) == "CRITICAL"

    def test_composite_risk_score_verified_example(self):
        """Verifies the exact multi-stage attack example from Section 10 consistency review.

        base_alert_score = 50.0 (1 HIGH alert)
        ml_anomaly_contribution = 18.5 (from ml_score 74.0)
        asset_multiplier = 1.5 (Key Vault)
        identity_multiplier = 1.8 (Global Admin)
        progression_multiplier = 1.8 (3 tactics)

        Calculation:
        combined_base = 50.0 + 18.5 = 68.5
        composite_multiplier = 1.5 * 1.8 * 1.8 = 4.86
        raw_calculated_score = 68.5 * 4.86 = 332.91
        final_score = min(100, 332.91) = 100
        severity = CRITICAL
        """
        breakdown = calculate_risk_score(
            alert_severities=["HIGH"],
            ml_anomaly_score=74.0,
            target_resource_id="Microsoft.KeyVault/vaults/production-vault/secrets",
            principal_role="Global Administrator",
            tactics=["Initial Access", "Privilege Escalation", "Credential Access"],
        )

        assert breakdown.base_alert_score == 50.0
        assert breakdown.ml_anomaly_contribution == 18.5
        assert breakdown.asset_multiplier == 1.5
        assert breakdown.identity_multiplier == 1.8
        assert breakdown.progression_multiplier == 1.8
        assert breakdown.raw_calculated_score == 332.91
        assert breakdown.final_score == 100
        assert breakdown.severity == "CRITICAL"
        assert len(breakdown.reasons) >= 6
        assert breakdown.metadata["unique_tactics"] == [
            "Credential Access",
            "Initial Access",
            "Privilege Escalation",
        ]

    def test_score_unclipped_raw_and_bounded_final(self):
        """Ensure raw_calculated_score remains floating-point unclipped while final_score is clamped 0-100."""
        # Low scenario
        low_res = calculate_risk_score(
            alert_severities=["LOW"],
            ml_anomaly_score=10.0,
            principal_role="standard_user",
            tactics=["Initial Access"],
        )
        # base = 10.0, ml = 2.5, mult = 1.0 -> raw = 12.5, final = 13, LOW
        assert low_res.raw_calculated_score == 12.5
        assert low_res.final_score == 13
        assert low_res.severity == "LOW"

        # Ultra-high scenario (multiple criticals)
        crit_res = calculate_risk_score(
            alert_severities=["CRITICAL", "CRITICAL", "CRITICAL"],
            ml_anomaly_score=95.0,
            target_resource_id="Microsoft.KeyVault/vaults/vault1",
            principal_role="Owner",
            tactics=["Discovery", "Credential Access", "Impact"],
        )
        assert crit_res.raw_calculated_score > 100.0
        assert crit_res.final_score == 100
        assert crit_res.severity == "CRITICAL"

    def test_scoring_determinism(self):
        """Repeated evaluations with identical inputs MUST produce identical outputs."""
        inputs = dict(
            alert_severities=["HIGH", "MEDIUM"],
            ml_anomaly_score=65.0,
            target_resource_id="Microsoft.Storage/storageAccounts/secblob",
            principal_role="Developer",
            tactics=["Initial Access", "Discovery"],
        )
        first = calculate_risk_score(**inputs)
        for _ in range(25):
            repeated = calculate_risk_score(**inputs)
            assert first.raw_calculated_score == repeated.raw_calculated_score
            assert first.final_score == repeated.final_score
            assert first.severity == repeated.severity
            assert first.base_alert_score == repeated.base_alert_score
            assert first.ml_anomaly_contribution == repeated.ml_anomaly_contribution


class TestRiskScoringEngineService:
    """Test suite for the RiskScoringEngine service."""

    def test_evaluate_request(self):
        req = RiskCalculationRequest(
            alert_severities=["HIGH"],
            ml_anomaly_score=40.0,
            target_resource_id="Microsoft.KeyVault/vaults/dev-vault",
            principal_role="Global Administrator",
            tactics=["Initial Access", "Privilege Escalation"],
        )
        result = risk_scoring_engine.evaluate_request(req)
        assert isinstance(result, RiskScoreBreakdown)
        assert result.base_alert_score == 50.0
        assert result.ml_anomaly_contribution == 10.0  # 0.25 * 40.0
        assert result.asset_multiplier == 1.5
        assert result.identity_multiplier == 1.8
        assert result.progression_multiplier == 1.4

        # combined = 60.0 * (1.5 * 1.8 * 1.4) = 60.0 * 3.78 = 226.8
        assert result.raw_calculated_score == 226.8
        assert result.final_score == 100
        assert result.severity == "CRITICAL"

    def test_evaluate_incident_context(self):
        # Mock detections and anomaly scores
        class MockDetection:
            def __init__(self, severity):
                self.severity = severity

        class MockAnomaly:
            def __init__(self, score):
                self.anomaly_score = score

        detections = [MockDetection("MEDIUM"), MockDetection("LOW")]
        anomalies = [MockAnomaly(20.0), MockAnomaly(60.0)]  # max is 60.0

        res = risk_scoring_engine.evaluate_incident_context(
            detections=detections,
            anomaly_scores=anomalies,
            target_resource="Microsoft.Storage/storageAccounts/test",
            principal_role="contributor",
            tactics=["Initial Access", "Persistence"],
        )
        assert res.base_alert_score == pytest.approx(25.0 + 10.0 / math.sqrt(2), rel=1e-4)
        assert res.ml_anomaly_contribution == 15.0  # 0.25 * 60.0
        assert res.asset_multiplier == 1.3
        assert res.identity_multiplier == 1.4
        assert res.progression_multiplier == 1.4
