import os
import tempfile
import numpy as np
import pytest
from app.ml.model import UEBAIsolationForest
from app.ml.features import FEATURE_NAMES


def test_isolation_forest_training_and_scoring():
    """Verify Isolation Forest model can fit on feature matrix and return calibrated scores."""
    # Create 100 normal baseline samples centered around small positive values
    np.random.seed(42)
    X_normal = np.random.normal(loc=1.0, scale=0.5, size=(100, len(FEATURE_NAMES))).astype(np.float32)

    model = UEBAIsolationForest(model_version="test-model-v1", contamination=0.03, random_state=42)
    model.fit(X_normal)
    assert model.is_trained
    assert model.training_sample_count == 100

    # Score a normal instance
    x_test_normal = np.ones((1, len(FEATURE_NAMES)), dtype=np.float32)
    score_norm, conf_norm, is_anom_norm, sev_norm = model.score_vector(x_test_normal)

    assert 0.0 <= score_norm <= 100.0
    assert 0.5 <= conf_norm <= 1.0
    assert score_norm < 65.0  # Normal should have score below anomaly threshold
    assert not is_anom_norm
    assert sev_norm in ("low", "medium")

    # Score an extreme outlier (e.g. 50x higher activity across all features)
    x_test_outlier = np.full((1, len(FEATURE_NAMES)), 50.0, dtype=np.float32)
    score_out, conf_out, is_anom_out, sev_out = model.score_vector(x_test_outlier)

    assert 0.0 <= score_out <= 100.0
    assert score_out > score_norm  # Outlier must have strictly higher anomaly score
    assert is_anom_out
    assert sev_out in ("high", "critical")


def test_isolation_forest_persistence():
    """Verify model can be saved to disk with Joblib and reloaded with identical behavior."""
    np.random.seed(42)
    X = np.random.uniform(0.0, 5.0, size=(50, len(FEATURE_NAMES))).astype(np.float32)

    model = UEBAIsolationForest(model_version="persist-test-v1", random_state=42)
    model.fit(X)

    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        model.save(tmp_path)
        loaded = UEBAIsolationForest.load(tmp_path)

        assert loaded.is_trained
        assert loaded.model_version == "persist-test-v1"
        assert loaded.training_sample_count == 50

        # Predictions should match
        sample = np.ones((1, len(FEATURE_NAMES)), dtype=np.float32)
        score1, _, _, _ = model.score_vector(sample)
        score2, _, _, _ = loaded.score_vector(sample)
        assert abs(score1 - score2) < 1e-4
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
