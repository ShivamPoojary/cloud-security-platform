import os
from typing import Dict, Any, Optional, Tuple
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from app.ml.features import FeatureExtractor, FEATURE_NAMES

DEFAULT_MODEL_VERSION = "ueba-isolation-forest-v1"
DEFAULT_MODEL_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
DEFAULT_MODEL_PATH = os.path.join(DEFAULT_MODEL_DIR, "isolation_forest_v1.joblib")


class UEBAIsolationForest:
    """Wrapper around scikit-learn IsolationForest providing calibrated 0-100 anomaly scoring,

    explainable thresholds, and model persistence.
    """

    def __init__(
        self,
        model_version: str = DEFAULT_MODEL_VERSION,
        contamination: float = 0.03,
        n_estimators: int = 100,
        random_state: int = 42,
    ):
        self.model_version = model_version
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.is_trained: bool = False
        self.training_sample_count: int = 0
        self.trained_at: Optional[str] = None

    def fit(self, X: np.ndarray) -> "UEBAIsolationForest":
        """Trains the Isolation Forest on a normal feature matrix X (N, num_features)."""
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X)
        self.is_trained = True
        self.training_sample_count = len(X)
        return self

    def score_vector(
        self,
        X: np.ndarray,
        deviations: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Tuple[float, float, bool, str]:
        """Calculates normalized anomaly score, confidence, anomaly flag, and severity.

        Scoring Transformation Formula:
            The raw scikit-learn `decision_function(X)` produces:
                d > 0: Normal observation
                d == 0: Contamination boundary
                d < 0: Anomalous observation

            As specified in SYSTEM_ARCHITECTURE.md, the platform combines the global
            Isolation Forest estimator with the per-identity moving profile (Robust Z-scores):
                base_score = clip(35.0 - (d * 220.0), 5.0, 75.0)
                deviation_boost = min(35.0, sum(max(0, z - 1.5) * 3.5) + novelty_bonuses)
                anomaly_score = clip(base_score + deviation_boost, 0.0, 100.0)

            Thresholds:
                anomaly_score >= 80.0 => Critical
                anomaly_score >= 65.0 => High
                anomaly_score >= 60.0 => Medium / Anomaly Flagged
                anomaly_score < 60.0  => Low (Normal baseline behavior)

        Returns:
            (anomaly_score, confidence, is_anomalous, severity)
        """
        if not self.is_trained or self.model is None:
            # Fallback heuristic if model not trained yet
            return 25.0, 0.60, False, "low"

        # Raw decision function (shape: (1,))
        raw_d = float(self.model.decision_function(X)[0])

        # Base score from Isolation Forest
        base_score = float(np.clip(35.0 - (raw_d * 220.0), 5.0, 75.0))

        # Deviation boost from entity baseline statistics
        boost = 0.0
        if deviations:
            for fname, dev in deviations.items():
                z = dev.get("z_score", 0.0)
                if z >= 2.0:
                    boost += (z - 1.5) * 3.5
            if deviations.get("is_novel_ip", {}).get("observed", 0.0) == 1.0:
                boost += 8.0
            if deviations.get("is_novel_country", {}).get("observed", 0.0) == 1.0:
                boost += 8.0

        anomaly_score = round(float(np.clip(base_score + min(boost, 35.0), 0.0, 100.0)), 1)

        # Confidence: certainty based on distance from ambiguous decision boundary
        confidence = round(float(np.clip(0.60 + abs(raw_d) * 1.5, 0.60, 0.99)), 2)

        # Anomaly threshold: score >= 55.0 is flagged as an anomaly
        is_anomalous = anomaly_score >= 55.0

        # Severity categorization
        if anomaly_score >= 80.0:
            severity = "critical"
        elif anomaly_score >= 65.0:
            severity = "high"
        elif anomaly_score >= 50.0:
            severity = "medium"
        else:
            severity = "low"

        return anomaly_score, confidence, is_anomalous, severity

    def predict_features(
        self,
        features: Dict[str, float],
        deviations: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Tuple[float, float, bool, str]:
        """Convenience method to score a single feature dictionary."""
        X = FeatureExtractor.to_vector(features)
        return self.score_vector(X, deviations=deviations)

    def save(self, filepath: Optional[str] = None) -> str:
        """Saves model and metadata to disk using Joblib."""
        target_path = filepath or DEFAULT_MODEL_PATH
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        bundle = {
            "model": self.model,
            "model_version": self.model_version,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
            "is_trained": self.is_trained,
            "training_sample_count": self.training_sample_count,
            "trained_at": self.trained_at,
            "feature_names": FEATURE_NAMES,
        }
        joblib.dump(bundle, target_path)
        return target_path

    @classmethod
    def load(cls, filepath: Optional[str] = None) -> "UEBAIsolationForest":
        """Loads a saved model bundle from disk."""
        target_path = filepath or DEFAULT_MODEL_PATH
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Model file not found at: {target_path}")

        bundle = joblib.load(target_path)
        inst = cls(
            model_version=bundle.get("model_version", DEFAULT_MODEL_VERSION),
            contamination=bundle.get("contamination", 0.03),
            n_estimators=bundle.get("n_estimators", 100),
            random_state=bundle.get("random_state", 42),
        )
        inst.model = bundle["model"]
        inst.is_trained = bundle.get("is_trained", True)
        inst.training_sample_count = bundle.get("training_sample_count", 0)
        inst.trained_at = bundle.get("trained_at")
        return inst
