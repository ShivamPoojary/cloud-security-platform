"""Deterministic, explainable risk score calculation functions.

Implements the exact formula from SYSTEM_ARCHITECTURE.md Section 10:
RiskScore = min(
    100,
    ( Σ(w_i × Sev(alert_i)) + α × ML_AnomalyScore )
    × C_Asset × B_Identity × M_Progression
)
"""

import math
from typing import List, Dict, Any, Optional, Sequence, Tuple
from app.domain.schemas.scoring import RiskScoreBreakdown
from app.scoring.constants import (
    SEVERITY_WEIGHTS,
    DEFAULT_ALERT_WEIGHT,
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


def get_alert_weight(severity: str) -> float:
    """Returns numerical weight for a given alert severity string."""
    clean_sev = (severity or "").strip().upper()
    return SEVERITY_WEIGHTS.get(clean_sev, DEFAULT_ALERT_WEIGHT)


def calculate_base_alert_score(
    severities: Sequence[str],
) -> Tuple[float, List[Dict[str, Any]]]:
    """Calculates decayed base alert score: Σ(w_i × Sev(alert_i)) where w_i = 1 / sqrt(i).

    Alerts are sorted in descending order of severity weight so the highest severity
    alert receives weight 1.0 (w_1), and subsequent alerts decay smoothly.
    """
    if not severities:
        return 0.0, []

    # Map to weights and sort descending
    sorted_items = sorted(
        [
            (sev.strip().upper(), get_alert_weight(sev))
            for sev in severities
            if sev is not None
        ],
        key=lambda x: x[1],
        reverse=True,
    )

    total_base = 0.0
    breakdown = []

    for idx, (sev_name, raw_weight) in enumerate(sorted_items, start=1):
        decay_factor = 1.0 / math.sqrt(idx)
        weighted_val = decay_factor * raw_weight
        total_base += weighted_val
        breakdown.append(
            {
                "index": idx,
                "severity": sev_name,
                "raw_weight": raw_weight,
                "decay_factor": round(decay_factor, 4),
                "decayed_contribution": round(weighted_val, 4),
            }
        )

    return total_base, breakdown


def calculate_ml_contribution(
    ml_anomaly_score: float,
    alpha: float = ML_SCALAR_ALPHA,
) -> Tuple[float, float]:
    """Calculates ML anomaly contribution: α × ML_AnomalyScore.

    Clamps ml_anomaly_score between 0.0 and 100.0 before evaluating.
    """
    clamped_anomaly = max(0.0, min(100.0, float(ml_anomaly_score or 0.0)))
    contribution = alpha * clamped_anomaly
    return contribution, clamped_anomaly


def derive_asset_multiplier(
    target_resource: Optional[str] = None,
    custom_multiplier: Optional[float] = None,
) -> Tuple[float, str]:
    """Derives target asset criticality multiplier C_Asset."""
    if custom_multiplier is not None:
        return float(custom_multiplier), f"Custom asset multiplier override ({custom_multiplier})"

    if not target_resource:
        return ASSET_MULTIPLIER_STANDARD, "Standard cloud resource (default 1.0)"

    resource_lower = target_resource.lower().strip()

    # Critical tier (1.5): Key Vaults, secrets, RBAC role assignments, security pricings, subscription roots
    critical_indicators = [
        "keyvault",
        "vaults",
        "roleassignment",
        "authorization/roleassignments",
        "security/pricings",
        "microsoft.security",
        "subscription",
    ]
    if any(k in resource_lower for k in critical_indicators):
        return (
            ASSET_MULTIPLIER_CRITICAL,
            f"Critical cloud resource detected ({target_resource}) -> multiplier {ASSET_MULTIPLIER_CRITICAL}",
        )

    # Storage tier (1.3): Blobs, storage accounts, container operations
    storage_indicators = [
        "storageaccount",
        "blobservice",
        "container",
        "storage",
        "blob",
    ]
    if any(k in resource_lower for k in storage_indicators):
        return (
            ASSET_MULTIPLIER_STORAGE,
            f"High-value storage asset detected ({target_resource}) -> multiplier {ASSET_MULTIPLIER_STORAGE}",
        )

    return (
        ASSET_MULTIPLIER_STANDARD,
        f"Standard asset ({target_resource}) -> multiplier {ASSET_MULTIPLIER_STANDARD}",
    )


def derive_identity_multiplier(
    principal_role: Optional[str] = None,
    principal_id: Optional[str] = None,
    custom_multiplier: Optional[float] = None,
) -> Tuple[float, str]:
    """Derives identity blast radius multiplier B_Identity."""
    if custom_multiplier is not None:
        return (
            float(custom_multiplier),
            f"Custom identity multiplier override ({custom_multiplier})",
        )

    indicators = []
    if principal_role:
        indicators.append(principal_role.lower())
    if principal_id:
        indicators.append(principal_id.lower())

    text = " ".join(indicators)
    if not text.strip():
        return (
            IDENTITY_MULTIPLIER_STANDARD,
            "Standard user identity (default 1.0)",
        )

    # Admin / Critical tier (1.8): Global Administrator, Owner, Privileged SPN
    critical_roles = [
        "global admin",
        "global administrator",
        "owner",
        "soc_admin",
        "service principal",
        "privileged",
        "spn",
    ]
    if any(r in text for r in critical_roles):
        return (
            IDENTITY_MULTIPLIER_CRITICAL,
            f"High-privilege identity detected ({principal_role or principal_id}) -> multiplier {IDENTITY_MULTIPLIER_CRITICAL}",
        )

    # Elevated tier (1.4): Developer, Contributor, Operator
    elevated_roles = ["developer", "contributor", "operator", "l2_responder"]
    if any(r in text for r in elevated_roles):
        return (
            IDENTITY_MULTIPLIER_ELEVATED,
            f"Elevated identity detected ({principal_role or principal_id}) -> multiplier {IDENTITY_MULTIPLIER_ELEVATED}",
        )

    return (
        IDENTITY_MULTIPLIER_STANDARD,
        f"Standard user identity ({principal_role or principal_id}) -> multiplier {IDENTITY_MULTIPLIER_STANDARD}",
    )


def derive_progression_multiplier(
    tactics: Sequence[str],
    custom_multiplier: Optional[float] = None,
) -> Tuple[float, str]:
    """Derives multi-stage progression penalty multiplier M_Progression."""
    if custom_multiplier is not None:
        return (
            float(custom_multiplier),
            f"Custom progression multiplier override ({custom_multiplier})",
        )

    # Extract distinct non-empty tactics
    unique_tactics = {
        t.strip().title()
        for t in tactics
        if t and t.strip()
    }
    tactic_count = len(unique_tactics)

    if tactic_count >= 3:
        return (
            PROGRESSION_MULTIPLIER_MULTI_STAGE,
            f"Multi-stage kill-chain progression ({tactic_count} distinct tactics: {', '.join(sorted(unique_tactics))}) -> multiplier {PROGRESSION_MULTIPLIER_MULTI_STAGE}",
        )
    elif tactic_count == 2:
        return (
            PROGRESSION_MULTIPLIER_TWO_STAGE,
            f"Two-stage progression ({', '.join(sorted(unique_tactics))}) -> multiplier {PROGRESSION_MULTIPLIER_TWO_STAGE}",
        )
    else:
        return (
            PROGRESSION_MULTIPLIER_SINGLE,
            f"Single-stage activity ({tactic_count} tactic) -> multiplier {PROGRESSION_MULTIPLIER_SINGLE}",
        )


def classify_severity(score: float | int) -> str:
    """Classifies risk score into severity tier.

    Thresholds:
    - 0-39: LOW
    - 40-69: MEDIUM
    - 70-89: HIGH
    - 90-100: CRITICAL
    """
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def calculate_risk_score(
    alert_severities: Optional[Sequence[str]] = None,
    ml_anomaly_score: float = 0.0,
    target_resource_id: Optional[str] = None,
    principal_id: Optional[str] = None,
    principal_role: Optional[str] = None,
    tactics: Optional[Sequence[str]] = None,
    custom_asset_multiplier: Optional[float] = None,
    custom_identity_multiplier: Optional[float] = None,
    custom_progression_multiplier: Optional[float] = None,
) -> RiskScoreBreakdown:
    """Calculates deterministic composite risk score and returns detailed explainability breakdown.

    Formula:
    RiskScore = min(
        100,
        ( Σ(w_i × Sev(alert_i)) + α × ML_AnomalyScore )
        × C_Asset × B_Identity × M_Progression
    )
    """
    alert_severities = alert_severities or []
    tactics = tactics or []

    # 1. Base Alert Score
    base_alert_score, alert_breakdown = calculate_base_alert_score(alert_severities)

    # 2. ML Anomaly Contribution
    ml_contrib, clamped_anomaly = calculate_ml_contribution(ml_anomaly_score)

    # 3. Multipliers
    asset_mult, asset_reason = derive_asset_multiplier(
        target_resource=target_resource_id,
        custom_multiplier=custom_asset_multiplier,
    )
    id_mult, id_reason = derive_identity_multiplier(
        principal_role=principal_role,
        principal_id=principal_id,
        custom_multiplier=custom_identity_multiplier,
    )
    prog_mult, prog_reason = derive_progression_multiplier(
        tactics=tactics,
        custom_multiplier=custom_progression_multiplier,
    )

    # 4. Composite Formula Calculation
    combined_base = base_alert_score + ml_contrib
    composite_multiplier = asset_mult * id_mult * prog_mult
    raw_calculated_score = combined_base * composite_multiplier

    # Round unclipped raw score for presentation precision
    raw_score_rounded = round(raw_calculated_score, 4)

    # Final bounded integer score: 0 to 100 with standard round half-up
    final_score = min(100, max(0, int(math.floor(raw_calculated_score + 0.5))))

    # Severity classification based on final score
    severity = classify_severity(final_score)

    # 5. Build Explainability Reasons
    reasons = [
        f"Base alert score of {round(base_alert_score, 2)} derived from {len(alert_severities)} alerts with square-root decay weighting.",
        f"ML anomaly score of {round(clamped_anomaly, 2)} contributed {round(ml_contrib, 2)} points (alpha={ML_SCALAR_ALPHA}).",
        asset_reason,
        id_reason,
        prog_reason,
        f"Total multiplier {round(composite_multiplier, 3)} applied to combined base {round(combined_base, 2)} yielding raw score {raw_score_rounded}.",
        f"Final clamped risk score {final_score}/100 categorized as {severity} severity.",
    ]

    metadata = {
        "alert_count": len(alert_severities),
        "alert_breakdown": alert_breakdown,
        "raw_ml_anomaly_score": clamped_anomaly,
        "ml_alpha": ML_SCALAR_ALPHA,
        "combined_base_score": round(combined_base, 4),
        "composite_multiplier": round(composite_multiplier, 4),
        "unique_tactics": sorted(list({t.strip().title() for t in tactics if t and t.strip()})),
    }

    return RiskScoreBreakdown(
        raw_calculated_score=raw_score_rounded,
        final_score=final_score,
        severity=severity,
        base_alert_score=round(base_alert_score, 4),
        ml_anomaly_contribution=round(ml_contrib, 4),
        asset_multiplier=round(asset_mult, 4),
        identity_multiplier=round(id_mult, 4),
        progression_multiplier=round(prog_mult, 4),
        reasons=reasons,
        metadata=metadata,
    )
