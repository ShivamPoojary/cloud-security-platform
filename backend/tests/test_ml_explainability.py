import uuid
from datetime import datetime, timezone
import pytest
from app.domain.models.logs import NormalizedEvent
from app.ml.explain import ExplainabilityEngine
from app.ml.features import FEATURE_NAMES


def test_explainability_engine_synthesizes_reasons():
    """Verify ExplainabilityEngine produces relevant reasons based on real feature deviations."""
    event = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=datetime(2026, 9, 25, 23, 15, tzinfo=timezone.utc),
        event_category="Storage",
        event_name="Microsoft.KeyVault/vaults/secrets/getSecret/action",
        principal_id="spn-rogue",
        principal_name="spn-rogue-deploy",
        caller_ip="203.0.113.199",
        geo_country="Netherlands",
        action_status="Success",
    )

    features = {f: 0.0 for f in FEATURE_NAMES}
    features["secret_retrievals"] = 16.0
    features["unique_resources"] = 12.0
    features["is_novel_ip"] = 1.0
    features["is_off_hours"] = 1.0

    deviations = {
        "secret_retrievals": {"observed": 16.0, "baseline_mean": 0.5, "z_score": 5.2, "ratio_to_baseline": 32.0},
        "unique_resources": {"observed": 12.0, "baseline_mean": 2.0, "z_score": 4.1, "ratio_to_baseline": 6.0},
        "is_novel_ip": {"observed": 1.0, "baseline_mean": 0.0, "z_score": 3.0, "ratio_to_baseline": 1.0},
        "is_off_hours": {"observed": 1.0, "baseline_mean": 0.0, "z_score": 2.0, "ratio_to_baseline": 1.0},
    }

    result = ExplainabilityEngine.explain(
        event=event,
        features=features,
        deviations=deviations,
        anomaly_score=92.5,
        severity="critical",
    )

    assert "reasons" in result
    assert "top_deviations" in result
    assert "summary" in result
    assert len(result["reasons"]) > 0

    reasons_text = " ".join(result["reasons"])
    assert "secret" in reasons_text.lower()
    assert "source ip" in reasons_text.lower() or "novel" in reasons_text.lower()
