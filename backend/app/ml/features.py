import math
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set
import numpy as np
from app.domain.models.logs import NormalizedEvent

# Fixed, documented list of UEBA features
FEATURE_NAMES = [
    "failed_auth_count",          # Count of failed sign-ins in recent window
    "successful_auth_count",      # Count of successful sign-ins in recent window
    "failed_auth_ratio",          # Ratio of failed / total sign-in attempts
    "mfa_prompt_count",           # Count of MFA prompts/challenges in window
    "privileged_role_ops",        # Count of RBAC / role assignment actions
    "is_service_principal",       # Binary indicator (1.0 for SPN, 0.0 for user)
    "hour_of_day",                # Event hour in UTC (0 - 23)
    "day_of_week",                # Day of week (0=Mon, 6=Sun)
    "is_off_hours",               # 1.0 if outside 08:00 - 18:00 UTC, else 0.0
    "event_frequency_10m",        # Total events for this principal in recent window
    "unique_source_ips",          # Count of distinct caller IPs in window
    "unique_resources",           # Count of distinct target resources in window
    "keyvault_ops",               # Count of Key Vault operations in window
    "secret_retrievals",          # Count of secret retrieval actions in window
    "storage_ops",                # Count of storage reads/writes/deletions in window
    "admin_ops",                  # Count of Azure ResourceManagement operations
    "security_config_mods",       # Count of security policy/pricing modifications
    "deletion_ops",               # Count of container/resource deletion operations
    "is_novel_ip",                # 1.0 if caller IP is novel for principal, else 0.0
    "is_novel_country",           # 1.0 if country is novel for principal, else 0.0
]


class FeatureExtractor:
    """Extracts security and behavioral UEBA features from NormalizedEvent instances."""

    FEATURE_NAMES = FEATURE_NAMES

    @staticmethod
    def is_service_principal(event: NormalizedEvent) -> float:
        """Determines if the event principal represents an automated service principal."""
        pid = (event.principal_id or "").lower()
        pname = (event.principal_name or "").lower()
        ename = (event.event_name or "").lower()
        uagent = (event.user_agent or "").lower()

        if pid.startswith("spn-") or "serviceprincipal" in ename:
            return 1.0
        if "github-actions" in uagent or "azurecli" in uagent or "curl" in uagent or "python" in uagent:
            if pid.startswith("spn-") or "spn" in pname:
                return 1.0
        return 0.0

    @classmethod
    def extract_features(
        cls,
        event: NormalizedEvent,
        recent_events: Optional[List[NormalizedEvent]] = None,
        known_ips: Optional[Set[str]] = None,
        known_countries: Optional[Set[str]] = None,
    ) -> Dict[str, float]:
        """Extracts a feature dictionary from an event and its historical window.

        Args:
            event: The target NormalizedEvent being evaluated.
            recent_events: Recent historical events for this principal (within sliding window).
            known_ips: Historical known caller IPs for this principal.
            known_countries: Historical known countries for this principal.

        Returns:
            Dictionary mapping feature names to numerical values.
        """
        history = list(recent_events or [])
        # Ensure the current event is included in the context calculation
        if not any(e.id == event.id for e in history if e.id and event.id):
            history.append(event)

        # Apply 10-minute (600s) temporal sliding window filter if timestamps exist
        target_ts = event.event_timestamp
        if target_ts is not None:
            if target_ts.tzinfo is None:
                target_ts = target_ts.replace(tzinfo=timezone.utc)
            filtered_history = []
            for h in history:
                if h.event_timestamp:
                    h_ts = h.event_timestamp
                    if h_ts.tzinfo is None:
                        h_ts = h_ts.replace(tzinfo=timezone.utc)
                    if abs((target_ts - h_ts).total_seconds()) <= 600:
                        filtered_history.append(h)
                else:
                    filtered_history.append(h)
            history = filtered_history

        # 1. Identity & Auth counters
        failed_auth_count = 0
        successful_auth_count = 0
        mfa_prompt_count = 0
        privileged_role_ops = 0
        keyvault_ops = 0
        secret_retrievals = 0
        storage_ops = 0
        admin_ops = 0
        security_config_mods = 0
        deletion_ops = 0

        unique_ips = set()
        unique_resources = set()

        for ev in history:
            ename = ev.event_name or ""
            ecat = ev.event_category or ""
            astatus = (ev.action_status or "").lower()

            if ev.caller_ip:
                unique_ips.add(ev.caller_ip)
            if ev.target_resource_id or ev.target_resource_name:
                unique_resources.add(ev.target_resource_id or ev.target_resource_name)

            # Auth checks
            if ename in ("UserLoginFailed", "ServicePrincipalLoginFailed") or (
                ecat == "Identity" and astatus in ("failure", "denied")
            ):
                failed_auth_count += 1
            elif ename in ("UserLoggedIn", "ServicePrincipalLoggedIn") or (
                ecat == "Identity" and astatus == "success"
            ):
                successful_auth_count += 1

            if ename == "MfaPromptSent" or "mfa" in ename.lower():
                mfa_prompt_count += 1

            # Role assignments & admin ops
            if "roleassignments" in ename.lower() or "authorization" in ename.lower():
                privileged_role_ops += 1

            if ecat == "ResourceManagement" or "subscriptions" in ename.lower():
                admin_ops += 1

            # Key Vault & secrets
            if "keyvault" in ename.lower():
                keyvault_ops += 1
            if "getsecret" in ename.lower():
                secret_retrievals += 1

            # Storage & deletions
            if ecat == "Storage" or "blob" in ename.lower() or "storage" in ename.lower():
                storage_ops += 1

            if "pricings" in ename.lower() or ecat == "Security" or "security" in ename.lower():
                security_config_mods += 1

            if "delete" in ename.lower() or astatus == "deleted":
                deletion_ops += 1

        total_auth = failed_auth_count + successful_auth_count
        failed_auth_ratio = float(failed_auth_count) / max(total_auth, 1)

        # 2. Temporal features
        ts = event.event_timestamp or datetime.now(timezone.utc)
        hour_of_day = float(ts.hour)
        day_of_week = float(ts.weekday())
        # Off-hours defined as outside 08:00 - 18:00 UTC
        is_off_hours = 1.0 if (ts.hour < 8 or ts.hour >= 18) else 0.0

        # 3. Novelty checks
        is_novel_ip = 0.0
        if known_ips is not None and event.caller_ip:
            if len(known_ips) > 0 and event.caller_ip not in known_ips:
                is_novel_ip = 1.0

        is_novel_country = 0.0
        if known_countries is not None and event.geo_country:
            if len(known_countries) > 0 and event.geo_country not in known_countries:
                is_novel_country = 1.0

        features: Dict[str, float] = {
            "failed_auth_count": float(failed_auth_count),
            "successful_auth_count": float(successful_auth_count),
            "failed_auth_ratio": round(failed_auth_ratio, 4),
            "mfa_prompt_count": float(mfa_prompt_count),
            "privileged_role_ops": float(privileged_role_ops),
            "is_service_principal": cls.is_service_principal(event),
            "hour_of_day": hour_of_day,
            "day_of_week": day_of_week,
            "is_off_hours": is_off_hours,
            "event_frequency_10m": float(len(history)),
            "unique_source_ips": float(max(len(unique_ips), 1)),
            "unique_resources": float(max(len(unique_resources), 1)),
            "keyvault_ops": float(keyvault_ops),
            "secret_retrievals": float(secret_retrievals),
            "storage_ops": float(storage_ops),
            "admin_ops": float(admin_ops),
            "security_config_mods": float(security_config_mods),
            "deletion_ops": float(deletion_ops),
            "is_novel_ip": is_novel_ip,
            "is_novel_country": is_novel_country,
        }

        return features

    @classmethod
    def to_vector(cls, features: Dict[str, float]) -> np.ndarray:
        """Converts a feature dictionary to an ordered NumPy array (1, num_features)."""
        vec = [features.get(name, 0.0) for name in cls.FEATURE_NAMES]
        return np.array(vec, dtype=np.float32).reshape(1, -1)

    @classmethod
    def to_matrix(cls, feature_dicts: List[Dict[str, float]]) -> np.ndarray:
        """Converts a list of feature dictionaries to a 2D NumPy array (N, num_features)."""
        rows = [[fd.get(name, 0.0) for name in cls.FEATURE_NAMES] for fd in feature_dicts]
        return np.array(rows, dtype=np.float32)
