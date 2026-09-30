"""High-level Risk Scoring Engine service.

Orchestrates input normalization, entity factor extraction, and composite scoring
for threat detections, ML behavioral anomalies, and correlated security incidents.
"""

from typing import List, Optional, Any, Sequence
from app.domain.schemas.scoring import RiskCalculationRequest, RiskScoreBreakdown
from app.scoring.calculator import calculate_risk_score


class RiskScoringEngine:
    """Service providing composite risk evaluation and explainability."""

    def evaluate_request(
        self,
        request: RiskCalculationRequest,
    ) -> RiskScoreBreakdown:
        """Evaluates a structured RiskCalculationRequest payload."""
        return calculate_risk_score(
            alert_severities=request.alert_severities,
            ml_anomaly_score=request.ml_anomaly_score,
            target_resource_id=request.target_resource_id,
            principal_id=request.principal_id,
            principal_role=request.principal_role,
            tactics=request.tactics,
            custom_asset_multiplier=request.custom_asset_multiplier,
            custom_identity_multiplier=request.custom_identity_multiplier,
            custom_progression_multiplier=request.custom_progression_multiplier,
        )

    def evaluate_components(
        self,
        alert_severities: Optional[Sequence[str]] = None,
        ml_anomaly_score: float = 0.0,
        target_resource: Optional[str] = None,
        principal_id: Optional[str] = None,
        principal_role: Optional[str] = None,
        tactics: Optional[Sequence[str]] = None,
        custom_asset_multiplier: Optional[float] = None,
        custom_identity_multiplier: Optional[float] = None,
        custom_progression_multiplier: Optional[float] = None,
    ) -> RiskScoreBreakdown:
        """Direct component evaluation helper."""
        return calculate_risk_score(
            alert_severities=alert_severities,
            ml_anomaly_score=ml_anomaly_score,
            target_resource_id=target_resource,
            principal_id=principal_id,
            principal_role=principal_role,
            tactics=tactics,
            custom_asset_multiplier=custom_asset_multiplier,
            custom_identity_multiplier=custom_identity_multiplier,
            custom_progression_multiplier=custom_progression_multiplier,
        )

    def evaluate_incident_context(
        self,
        detections: Optional[Sequence[Any]] = None,
        anomaly_scores: Optional[Sequence[Any]] = None,
        target_resource: Optional[str] = None,
        principal_id: Optional[str] = None,
        principal_role: Optional[str] = None,
        tactics: Optional[Sequence[str]] = None,
    ) -> RiskScoreBreakdown:
        """Evaluates risk score from incident context objects (ORM or dict-like)."""
        severities: List[str] = []
        if detections:
            for det in detections:
                if hasattr(det, "severity"):
                    severities.append(det.severity)
                elif isinstance(det, dict) and "severity" in det:
                    severities.append(det["severity"])
                elif isinstance(det, str):
                    severities.append(det)

        highest_ml_score = 0.0
        if anomaly_scores:
            for a in anomaly_scores:
                val = 0.0
                if hasattr(a, "anomaly_score"):
                    val = float(a.anomaly_score)
                elif isinstance(a, dict) and "anomaly_score" in a:
                    val = float(a["anomaly_score"])
                elif isinstance(a, (int, float)):
                    val = float(a)
                if val > highest_ml_score:
                    highest_ml_score = val

        return calculate_risk_score(
            alert_severities=severities,
            ml_anomaly_score=highest_ml_score,
            target_resource_id=target_resource,
            principal_id=principal_id,
            principal_role=principal_role,
            tactics=tactics,
        )


# Global singleton instance
risk_scoring_engine = RiskScoringEngine()
