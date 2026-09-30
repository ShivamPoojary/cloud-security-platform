"""Constants and parameters for the Composite Risk Scoring Engine.

Follows the mathematical model in SYSTEM_ARCHITECTURE.md Section 10:
RiskScore = min(
    100,
    ( Σ(w_i × Sev(alert_i)) + α × ML_AnomalyScore )
    × C_Asset × B_Identity × M_Progression
)
"""

from typing import Dict

# Severity weights for individual alert detections Sev(alert_i)
SEVERITY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 80.0,
    "HIGH": 50.0,
    "MEDIUM": 25.0,
    "LOW": 10.0,
    "INFORMATIONAL": 5.0,
}

# Default alert weight if unknown severity is encountered
DEFAULT_ALERT_WEIGHT: float = 10.0

# Normalized ML anomaly scalar weight α
ML_SCALAR_ALPHA: float = 0.25

# Asset criticality multipliers C_Asset
ASSET_MULTIPLIER_STANDARD: float = 1.0
ASSET_MULTIPLIER_STORAGE: float = 1.3
ASSET_MULTIPLIER_CRITICAL: float = 1.5

# Identity blast radius multipliers B_Identity
IDENTITY_MULTIPLIER_STANDARD: float = 1.0
IDENTITY_MULTIPLIER_ELEVATED: float = 1.4
IDENTITY_MULTIPLIER_CRITICAL: float = 1.8

# Progression penalty multipliers M_Progression
PROGRESSION_MULTIPLIER_SINGLE: float = 1.0
PROGRESSION_MULTIPLIER_TWO_STAGE: float = 1.4
PROGRESSION_MULTIPLIER_MULTI_STAGE: float = 1.8

# Severity classification thresholds
# LOW: < 40, MEDIUM: 40-69, HIGH: 70-89, CRITICAL: 90-100
SEVERITY_TIERS = {
    "LOW": (0, 39),
    "MEDIUM": (40, 69),
    "HIGH": (70, 89),
    "CRITICAL": (90, 100),
}
