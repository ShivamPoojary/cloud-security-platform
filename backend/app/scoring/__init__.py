"""Risk scoring module for the Cloud Security Monitoring Platform."""

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
    SEVERITY_TIERS,
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

__all__ = [
    "SEVERITY_WEIGHTS",
    "DEFAULT_ALERT_WEIGHT",
    "ML_SCALAR_ALPHA",
    "ASSET_MULTIPLIER_STANDARD",
    "ASSET_MULTIPLIER_STORAGE",
    "ASSET_MULTIPLIER_CRITICAL",
    "IDENTITY_MULTIPLIER_STANDARD",
    "IDENTITY_MULTIPLIER_ELEVATED",
    "IDENTITY_MULTIPLIER_CRITICAL",
    "PROGRESSION_MULTIPLIER_SINGLE",
    "PROGRESSION_MULTIPLIER_TWO_STAGE",
    "PROGRESSION_MULTIPLIER_MULTI_STAGE",
    "SEVERITY_TIERS",
    "calculate_risk_score",
    "calculate_base_alert_score",
    "calculate_ml_contribution",
    "derive_asset_multiplier",
    "derive_identity_multiplier",
    "derive_progression_multiplier",
    "classify_severity",
    "RiskScoringEngine",
    "risk_scoring_engine",
]
