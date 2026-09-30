from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class RiskScoreBreakdown(BaseModel):
    """Explainable composite risk score breakdown for security incidents and detections."""

    raw_calculated_score: float = Field(
        ...,
        description="Unclipped floating-point composite risk score produced by the mathematical formula",
    )
    final_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Composite risk score bounded and clamped to 0–100",
    )
    severity: str = Field(
        ...,
        description="Severity classification tier: LOW (<40), MEDIUM (40–69), HIGH (70–89), CRITICAL (90–100)",
    )
    base_alert_score: float = Field(
        ...,
        description="Sum of weighted alert severities: Σ(w_i × Sev(alert_i))",
    )
    ml_anomaly_contribution: float = Field(
        ...,
        description="ML behavioral anomaly score contribution: α × ML_AnomalyScore",
    )
    asset_multiplier: float = Field(
        ...,
        description="Target cloud asset criticality multiplier C_Asset",
    )
    identity_multiplier: float = Field(
        ...,
        description="Identity blast radius multiplier B_Identity",
    )
    progression_multiplier: float = Field(
        ...,
        description="Kill-chain multi-stage progression multiplier M_Progression",
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Human-readable explainability rationale detailing each scoring factor",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional evaluation parameters and context",
    )

    model_config = ConfigDict(from_attributes=True)


class RiskCalculationRequest(BaseModel):
    """Request payload for on-demand risk calculation evaluation."""

    alert_severities: List[str] = Field(
        default_factory=list,
        description="List of alert severity strings, e.g. ['MEDIUM', 'HIGH']",
    )
    ml_anomaly_score: float = Field(
        0.0,
        ge=0.0,
        le=100.0,
        description="Associated ML behavioral anomaly score (0–100)",
    )
    target_resource_id: Optional[str] = Field(
        None,
        description="Target Azure resource ID or name for criticality derivation",
    )
    principal_id: Optional[str] = Field(
        None,
        description="Principal ID or email for identity blast radius derivation",
    )
    principal_role: Optional[str] = Field(
        None,
        description="Explicit principal role (e.g. 'Global Administrator', 'Owner', 'Developer')",
    )
    tactics: List[str] = Field(
        default_factory=list,
        description="List of observed MITRE tactics for progression calculation",
    )
    custom_asset_multiplier: Optional[float] = Field(
        None,
        ge=1.0,
        le=3.0,
        description="Override multiplier for asset criticality",
    )
    custom_identity_multiplier: Optional[float] = Field(
        None,
        ge=1.0,
        le=3.0,
        description="Override multiplier for identity blast radius",
    )
    custom_progression_multiplier: Optional[float] = Field(
        None,
        ge=1.0,
        le=3.0,
        description="Override multiplier for progression",
    )
