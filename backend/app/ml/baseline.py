from typing import Dict, List, Optional, Any, Set
import numpy as np
from app.ml.features import FEATURE_NAMES


class EntityBaseline:
    """Stores statistical baseline metrics and known identity properties for a specific principal."""

    def __init__(self, principal_id: str):
        self.principal_id = principal_id
        self.sample_count: int = 0
        self.feature_means: Dict[str, float] = {f: 0.0 for f in FEATURE_NAMES}
        self.feature_stds: Dict[str, float] = {f: 0.1 for f in FEATURE_NAMES}
        self.feature_medians: Dict[str, float] = {f: 0.0 for f in FEATURE_NAMES}
        self.feature_iqrs: Dict[str, float] = {f: 0.1 for f in FEATURE_NAMES}
        self.known_ips: Set[str] = set()
        self.known_countries: Set[str] = set()
        self._history_vectors: List[Dict[str, float]] = []

    def add_observation(
        self,
        features: Dict[str, float],
        caller_ip: Optional[str] = None,
        country: Optional[str] = None,
        max_history: int = 100,
    ):
        """Records an observed feature vector and updates running statistics."""
        self._history_vectors.append(features)
        if len(self._history_vectors) > max_history:
            self._history_vectors.pop(0)

        if caller_ip:
            self.known_ips.add(caller_ip)
        if country:
            self.known_countries.add(country)

        self.recompute_statistics()

    def recompute_statistics(self):
        """Recomputes mean, std, median, and IQR across historical observations."""
        n = len(self._history_vectors)
        self.sample_count = n
        if n == 0:
            return

        for f in FEATURE_NAMES:
            values = np.array([v.get(f, 0.0) for v in self._history_vectors], dtype=np.float32)
            self.feature_means[f] = float(np.mean(values))
            std = float(np.std(values))
            self.feature_stds[f] = max(std, 0.1)

            self.feature_medians[f] = float(np.median(values))
            q75, q25 = np.percentile(values, [75, 25])
            iqr = float(q75 - q25)
            self.feature_iqrs[f] = max(iqr, 0.1)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the entity baseline to a dictionary."""
        return {
            "principal_id": self.principal_id,
            "sample_count": self.sample_count,
            "feature_means": self.feature_means,
            "feature_stds": self.feature_stds,
            "feature_medians": self.feature_medians,
            "feature_iqrs": self.feature_iqrs,
            "known_ips": list(self.known_ips),
            "known_countries": list(self.known_countries),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EntityBaseline":
        """Reconstructs an EntityBaseline from serialized data."""
        base = cls(principal_id=data["principal_id"])
        base.sample_count = data.get("sample_count", 0)
        base.feature_means = data.get("feature_means", {f: 0.0 for f in FEATURE_NAMES})
        base.feature_stds = data.get("feature_stds", {f: 0.1 for f in FEATURE_NAMES})
        base.feature_medians = data.get("feature_medians", {f: 0.0 for f in FEATURE_NAMES})
        base.feature_iqrs = data.get("feature_iqrs", {f: 0.1 for f in FEATURE_NAMES})
        base.known_ips = set(data.get("known_ips", []))
        base.known_countries = set(data.get("known_countries", []))
        return base


class BaselineManager:
    """Manages entity-level and population-level behavioral baselines for UEBA."""

    def __init__(self):
        self.entity_baselines: Dict[str, EntityBaseline] = {}
        self.population_baseline = EntityBaseline(principal_id="__population__")

    def get_or_create(self, principal_id: str) -> EntityBaseline:
        """Retrieves or initializes a baseline for a given principal."""
        if not principal_id:
            return self.population_baseline
        if principal_id not in self.entity_baselines:
            self.entity_baselines[principal_id] = EntityBaseline(principal_id=principal_id)
        return self.entity_baselines[principal_id]

    def record_event(
        self,
        principal_id: str,
        features: Dict[str, float],
        caller_ip: Optional[str] = None,
        country: Optional[str] = None,
    ):
        """Records an event observation into both the entity baseline and the global population baseline."""
        if principal_id:
            entity = self.get_or_create(principal_id)
            entity.add_observation(features, caller_ip=caller_ip, country=country)

        self.population_baseline.add_observation(features, caller_ip=caller_ip, country=country)

    def compute_deviations(
        self, principal_id: Optional[str], features: Dict[str, float]
    ) -> Dict[str, Dict[str, Any]]:
        """Computes statistical deviations of the current features against the principal's baseline.

        Uses the entity baseline if it has sufficient samples (>= 3), otherwise falls back
        to the population baseline.
        """
        target_baseline = self.population_baseline
        if principal_id and principal_id in self.entity_baselines:
            if self.entity_baselines[principal_id].sample_count >= 3:
                target_baseline = self.entity_baselines[principal_id]

        deviations: Dict[str, Dict[str, Any]] = {}

        for f in FEATURE_NAMES:
            val = float(features.get(f, 0.0))
            mean = target_baseline.feature_means.get(f, 0.0)
            std = target_baseline.feature_stds.get(f, 0.1)
            median = target_baseline.feature_medians.get(f, 0.0)
            iqr = target_baseline.feature_iqrs.get(f, 0.1)

            # Standard and robust Z-scores
            z_score = (val - mean) / max(std, 0.05)
            robust_z = (val - median) / max(1.349 * iqr, 0.05)

            # Ratio to baseline
            ratio = val / max(mean, 0.1) if val > 0 else 0.0

            deviations[f] = {
                "observed": round(val, 2),
                "baseline_mean": round(mean, 2),
                "baseline_std": round(std, 2),
                "z_score": round(float(z_score), 2),
                "robust_z": round(float(robust_z), 2),
                "ratio_to_baseline": round(float(ratio), 2),
            }

        return deviations

    def to_dict(self) -> Dict[str, Any]:
        """Serializes all baselines to a dictionary."""
        return {
            "population": self.population_baseline.to_dict(),
            "entities": {pid: base.to_dict() for pid, base in self.entity_baselines.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BaselineManager":
        """Reconstructs a BaselineManager from serialized data."""
        mgr = cls()
        if "population" in data:
            mgr.population_baseline = EntityBaseline.from_dict(data["population"])
        if "entities" in data:
            mgr.entity_baselines = {
                pid: EntityBaseline.from_dict(bdata) for pid, bdata in data["entities"].items()
            }
        return mgr
