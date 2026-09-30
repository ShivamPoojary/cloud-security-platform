import os
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
import numpy as np
from app.core.logging import logger
from app.ingestion.synthetic_generator import SyntheticAzureTelemetryGenerator
from app.ingestion.normalizer import EventNormalizer
from app.domain.models.logs import NormalizedEvent
from app.ml.features import FeatureExtractor, FEATURE_NAMES
from app.ml.baseline import BaselineManager
from app.ml.model import UEBAIsolationForest, DEFAULT_MODEL_PATH, DEFAULT_MODEL_VERSION


class UEBATrainer:
    """Trains the UEBA Isolation Forest model and initializes statistical baselines

    using realistic normal cloud telemetry.
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

    def generate_baseline_dataset(
        self,
        sample_count: int = 300,
        start_time: Optional[datetime] = None,
    ) -> List[NormalizedEvent]:
        """Generates a diverse set of normal operational cloud events simulating realistic

        user logins, developer deployments, storage reads, and CI/CD operations across days.
        """
        base = start_time or (datetime.now(timezone.utc) - timedelta(days=7))
        events: List[NormalizedEvent] = []

        for i in range(sample_count):
            # Spread across days and business hours (mostly 08:00 - 18:00 UTC)
            day_offset = (i % 7)
            # 90% during business hours, 10% off-hours
            if i % 10 == 0:
                hour = (20 + (i % 4)) % 24  # Evening
            else:
                hour = 8 + (i % 10)         # 08:00 to 17:00

            minute = (i * 7) % 60
            second = (i * 13) % 60
            ts = base + timedelta(days=day_offset, hours=hour, minutes=minute, seconds=second)

            raw_sec_event = SyntheticAzureTelemetryGenerator.generate_normal_event(base_time=ts)
            norm_event = EventNormalizer.normalize(raw_sec_event)
            events.append(norm_event)

        return events

    def train_on_events(
        self,
        events: List[NormalizedEvent],
        save_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Extracts features, builds baselines, fits the Isolation Forest model,

        and persists the bundle to disk.
        """
        logger.info(f"Training UEBA model on {len(events)} normal events...")

        # 1. Group events by principal to construct sliding-window features
        events_by_principal: Dict[str, List[NormalizedEvent]] = {}
        for ev in events:
            pid = ev.principal_id or ev.principal_name or "unknown"
            events_by_principal.setdefault(pid, []).append(ev)

        # Sort each principal's events chronologically
        for pid in events_by_principal:
            events_by_principal[pid].sort(key=lambda x: x.event_timestamp or datetime.min)

        baseline_mgr = BaselineManager()
        feature_dicts: List[Dict[str, float]] = []

        # Extract features progressively with history
        for pid, principal_events in events_by_principal.items():
            history: List[NormalizedEvent] = []
            for ev in principal_events:
                # Use recent 20 events as history context
                window = history[-20:]
                entity_base = baseline_mgr.get_or_create(pid)
                features = FeatureExtractor.extract_features(
                    event=ev,
                    recent_events=window,
                    known_ips=entity_base.known_ips,
                    known_countries=entity_base.known_countries,
                )
                feature_dicts.append(features)
                baseline_mgr.record_event(
                    principal_id=pid,
                    features=features,
                    caller_ip=ev.caller_ip,
                    country=ev.geo_country,
                )
                history.append(ev)

        # 2. Build training matrix
        X = FeatureExtractor.to_matrix(feature_dicts)

        # 3. Train Isolation Forest
        model = UEBAIsolationForest(
            model_version=self.model_version,
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
        )
        model.fit(X)
        model.trained_at = datetime.now(timezone.utc).isoformat()

        # 4. Save model bundle alongside baselines
        target_path = save_path or DEFAULT_MODEL_PATH
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        bundle = {
            "model": model.model,
            "model_version": self.model_version,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
            "is_trained": True,
            "training_sample_count": len(X),
            "trained_at": model.trained_at,
            "feature_names": FEATURE_NAMES,
            "baselines": baseline_mgr.to_dict(),
        }
        import joblib
        joblib.dump(bundle, target_path)

        logger.info(f"UEBA model saved successfully to: {target_path}")

        return {
            "model_version": self.model_version,
            "trained_at": model.trained_at,
            "training_sample_count": len(X),
            "feature_count": len(FEATURE_NAMES),
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "saved_path": target_path,
        }

    def train_default(self, sample_count: int = 350, save_path: Optional[str] = None) -> Dict[str, Any]:
        """Convenience method to generate baseline dataset and train model."""
        events = self.generate_baseline_dataset(sample_count=sample_count)
        return self.train_on_events(events=events, save_path=save_path)
