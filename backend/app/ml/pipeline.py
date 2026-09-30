import os
import uuid
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from sqlalchemy.ext.asyncio import AsyncSession
import joblib

from app.core.logging import logger
from app.domain.models.logs import NormalizedEvent
from app.domain.models.ml import MLAnomalyScore
from app.ml.features import FeatureExtractor, FEATURE_NAMES
from app.ml.baseline import BaselineManager
from app.ml.model import UEBAIsolationForest, DEFAULT_MODEL_PATH, DEFAULT_MODEL_VERSION
from app.ml.explain import ExplainabilityEngine
from app.ml.trainer import UEBATrainer


class MLInferencePipeline:
    """Singleton-ready ML inference and UEBA scoring pipeline for incoming normalized events."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.model_version = DEFAULT_MODEL_VERSION
        self.model: Optional[UEBAIsolationForest] = None
        self.baseline_mgr: Optional[BaselineManager] = None
        self._lock = threading.Lock()
        self._history_by_principal: Dict[str, List[NormalizedEvent]] = {}
        self.max_principal_history = 50

    def load_or_initialize_model(self):
        """Loads the model and baselines bundle from disk, or automatically trains

        an initial model if none exists.
        """
        with self._lock:
            if self.model is not None and self.baseline_mgr is not None:
                return

            if os.path.exists(self.model_path):
                try:
                    logger.info(f"Loading UEBA model bundle from: {self.model_path}")
                    bundle = joblib.load(self.model_path)
                    inst = UEBAIsolationForest(
                        model_version=bundle.get("model_version", self.model_version),
                        contamination=bundle.get("contamination", 0.03),
                        n_estimators=bundle.get("n_estimators", 100),
                        random_state=bundle.get("random_state", 42),
                    )
                    inst.model = bundle["model"]
                    inst.is_trained = bundle.get("is_trained", True)
                    inst.training_sample_count = bundle.get("training_sample_count", 0)
                    inst.trained_at = bundle.get("trained_at")

                    self.model = inst
                    self.model_version = inst.model_version

                    if "baselines" in bundle:
                        self.baseline_mgr = BaselineManager.from_dict(bundle["baselines"])
                    else:
                        self.baseline_mgr = BaselineManager()

                    logger.info(f"Successfully loaded UEBA model version: {self.model_version}")
                    return
                except Exception as e:
                    logger.warning(f"Failed to load existing model bundle ({e}); training a fresh one...")

            logger.info("Initializing and training default UEBA model...")
            trainer = UEBATrainer(model_version=self.model_version)
            trainer.train_default(sample_count=250, save_path=self.model_path)

            # Now load the trained bundle
            bundle = joblib.load(self.model_path)
            inst = UEBAIsolationForest(
                model_version=bundle.get("model_version", self.model_version),
                contamination=bundle.get("contamination", 0.03),
                n_estimators=bundle.get("n_estimators", 100),
                random_state=bundle.get("random_state", 42),
            )
            inst.model = bundle["model"]
            inst.is_trained = True
            inst.training_sample_count = bundle.get("training_sample_count", 0)
            self.model = inst
            self.baseline_mgr = BaselineManager.from_dict(bundle.get("baselines", {}))

    def record_history(self, event: NormalizedEvent):
        """Maintains an in-memory sliding window of recent events per principal."""
        pid = event.principal_id or event.principal_name or "unknown"
        history = self._history_by_principal.setdefault(pid, [])
        history.append(event)
        if len(history) > self.max_principal_history:
            history.pop(0)

    def get_principal_history(self, principal_id: Optional[str]) -> List[NormalizedEvent]:
        """Returns the recent in-memory event history for a principal."""
        if not principal_id:
            return []
        return list(self._history_by_principal.get(principal_id, []))

    def evaluate_event_sync(
        self,
        event: NormalizedEvent,
        custom_history: Optional[List[NormalizedEvent]] = None,
    ) -> Tuple[float, float, bool, str, Dict[str, Any], Dict[str, float]]:
        """Synchronously performs feature extraction, baseline lookup, ML inference,

        and explainability calculation for an event.

        Returns:
            (anomaly_score, confidence, is_anomalous, severity, explain_dict, features)
        """
        self.load_or_initialize_model()

        pid = event.principal_id or event.principal_name or "unknown"
        history = custom_history if custom_history is not None else self.get_principal_history(pid)

        # Baseline knowledge
        entity_base = self.baseline_mgr.get_or_create(pid) if self.baseline_mgr else None
        known_ips = entity_base.known_ips if entity_base else None
        known_countries = entity_base.known_countries if entity_base else None

        # 1. Feature extraction
        features = FeatureExtractor.extract_features(
            event=event,
            recent_events=history,
            known_ips=known_ips,
            known_countries=known_countries,
        )

        # 2. Deviations against baseline
        deviations = (
            self.baseline_mgr.compute_deviations(pid, features)
            if self.baseline_mgr
            else {}
        )

        # 3. Isolation Forest + Baseline Ensemble inference
        anomaly_score, confidence, is_anomalous, severity = self.model.predict_features(
            features, deviations=deviations
        )

        # 4. Explainability synthesis
        explain_res = ExplainabilityEngine.explain(
            event=event,
            features=features,
            deviations=deviations,
            anomaly_score=anomaly_score,
            severity=severity,
        )

        # Update in-memory sliding window
        self.record_history(event)

        return anomaly_score, confidence, is_anomalous, severity, explain_res, features

    async def evaluate_and_persist(
        self,
        event: NormalizedEvent,
        db: AsyncSession,
        custom_history: Optional[List[NormalizedEvent]] = None,
        persist_all: bool = True,
    ) -> Optional[MLAnomalyScore]:
        """Evaluates an event with the ML model and persists the resulting MLAnomalyScore to PostgreSQL."""
        (
            anomaly_score,
            confidence,
            is_anomalous,
            severity,
            explain_res,
            features,
        ) = self.evaluate_event_sync(event, custom_history=custom_history)

        # If not persisting all, only persist if anomalous or elevated
        if not persist_all and not is_anomalous and anomaly_score < 50.0:
            return None

        # Build feature contributions payload
        feature_contributions = {
            "reasons": explain_res["reasons"],
            "summary": explain_res["summary"],
            "top_deviations": explain_res["top_deviations"],
            "severity": severity,
            "raw_features": features,
            "principal_id": event.principal_id,
            "principal_name": event.principal_name,
            "caller_ip": event.caller_ip,
            "geo_country": event.geo_country,
        }

        ml_score = MLAnomalyScore(
            id=uuid.uuid4(),
            event_id=event.id,
            model_version=self.model_version,
            anomaly_score=anomaly_score,
            confidence=confidence,
            is_anomalous=is_anomalous,
            feature_contributions=feature_contributions,
        )

        db.add(ml_score)
        await db.flush()

        logger.debug(
            f"Evaluated ML anomaly for event {event.id}: score={anomaly_score}, "
            f"anomalous={is_anomalous}, severity={severity}"
        )
        return ml_score


# Global inference pipeline instance
ml_pipeline = MLInferencePipeline()
