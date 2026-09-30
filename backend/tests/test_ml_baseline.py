import pytest
from app.ml.baseline import BaselineManager, EntityBaseline
from app.ml.features import FEATURE_NAMES


def test_entity_baseline_statistics():
    """Verify EntityBaseline accumulates observations and computes mean, std, median, IQR."""
    baseline = EntityBaseline(principal_id="usr-test-101")
    assert baseline.sample_count == 0

    # Add several observations with known values for secret_retrievals
    for val in [0.0, 1.0, 0.0, 0.0, 1.0, 2.0]:
        feat = {f: 0.0 for f in FEATURE_NAMES}
        feat["secret_retrievals"] = val
        baseline.add_observation(feat, caller_ip="198.51.100.10", country="United States")

    assert baseline.sample_count == 6
    assert "198.51.100.10" in baseline.known_ips
    assert "United States" in baseline.known_countries
    assert baseline.feature_means["secret_retrievals"] > 0.0
    assert baseline.feature_stds["secret_retrievals"] > 0.0


def test_baseline_manager_entity_and_population():
    """Verify BaselineManager updates both entity baseline and population baseline."""
    mgr = BaselineManager()

    feat1 = {f: 1.0 for f in FEATURE_NAMES}
    mgr.record_event(
        principal_id="usr-user-01",
        features=feat1,
        caller_ip="198.51.100.1",
        country="United States",
    )

    feat2 = {f: 2.0 for f in FEATURE_NAMES}
    mgr.record_event(
        principal_id="spn-service-01",
        features=feat2,
        caller_ip="198.51.100.2",
        country="Canada",
    )

    # Both entity baselines exist
    assert "usr-user-01" in mgr.entity_baselines
    assert "spn-service-01" in mgr.entity_baselines

    # Population baseline contains aggregate observations
    assert mgr.population_baseline.sample_count == 2
    assert "198.51.100.1" in mgr.population_baseline.known_ips
    assert "198.51.100.2" in mgr.population_baseline.known_ips


def test_baseline_compute_deviations():
    """Verify compute_deviations calculates meaningful z-scores and ratios."""
    mgr = BaselineManager()
    pid = "usr-analyst-01"

    # Train baseline with normal low activity
    for _ in range(10):
        feat = {f: 0.0 for f in FEATURE_NAMES}
        feat["unique_resources"] = 2.0
        feat["secret_retrievals"] = 0.0
        mgr.record_event(pid, feat, caller_ip="198.51.100.5", country="United States")

    # Current spike in secret retrievals and resources
    current_features = {f: 0.0 for f in FEATURE_NAMES}
    current_features["unique_resources"] = 25.0
    current_features["secret_retrievals"] = 15.0

    deviations = mgr.compute_deviations(pid, current_features)
    assert "secret_retrievals" in deviations
    assert "unique_resources" in deviations

    sec_dev = deviations["secret_retrievals"]
    assert sec_dev["observed"] == 15.0
    assert sec_dev["z_score"] > 2.0

    res_dev = deviations["unique_resources"]
    assert res_dev["observed"] == 25.0
    assert res_dev["ratio_to_baseline"] > 5.0


def test_baseline_serialization_roundtrip():
    """Verify to_dict and from_dict preserve baseline state."""
    mgr = BaselineManager()
    feat = {f: 5.0 for f in FEATURE_NAMES}
    mgr.record_event("usr-test", feat, caller_ip="10.0.0.1", country="Germany")

    data = mgr.to_dict()
    assert "population" in data
    assert "entities" in data
    assert "usr-test" in data["entities"]

    restored = BaselineManager.from_dict(data)
    assert "usr-test" in restored.entity_baselines
    assert "10.0.0.1" in restored.entity_baselines["usr-test"].known_ips
    assert "Germany" in restored.entity_baselines["usr-test"].known_countries
