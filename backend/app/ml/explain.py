from typing import Dict, List, Any, Optional
from app.domain.models.logs import NormalizedEvent


class ExplainabilityEngine:
    """Generates precise, human-readable explanations and top feature drivers

    for UEBA anomalies based on actual statistical deviations from baseline.
    """

    @classmethod
    def explain(
        cls,
        event: NormalizedEvent,
        features: Dict[str, float],
        deviations: Dict[str, Dict[str, Any]],
        anomaly_score: float,
        severity: str,
        max_reasons: int = 4,
    ) -> Dict[str, Any]:
        """Synthesizes structured explanation details and top human-readable reasons.

        Returns:
            Dictionary containing:
                - reasons: List[str] (top 2-4 human readable explanations)
                - top_deviations: Dict[str, Any] (highest contributing feature deviations)
                - summary: str
        """
        candidates: List[tuple[float, str, str, Dict[str, Any]]] = []

        # 1. Identity & Auth deviations
        failed_auth = features.get("failed_auth_count", 0.0)
        failed_dev = deviations.get("failed_auth_count", {})
        if failed_auth >= 3 or failed_dev.get("z_score", 0.0) >= 2.0:
            weight = max(failed_dev.get("z_score", 0.0), 3.0)
            msg = f"Repeated failed authentication attempts ({int(failed_auth)} failures) exceeding baseline"
            candidates.append((weight, "failed_auth_count", msg, failed_dev))

        mfa_count = features.get("mfa_prompt_count", 0.0)
        mfa_dev = deviations.get("mfa_prompt_count", {})
        if mfa_count >= 2 or mfa_dev.get("z_score", 0.0) >= 2.0:
            weight = max(mfa_dev.get("z_score", 0.0), 3.5)
            msg = f"Repeated MFA push prompts/challenges ({int(mfa_count)} prompts) indicating MFA fatigue attack"
            candidates.append((weight, "mfa_prompt_count", msg, mfa_dev))

        # 2. Privileged operations
        role_ops = features.get("privileged_role_ops", 0.0)
        role_dev = deviations.get("privileged_role_ops", {})
        if role_ops >= 1:
            weight = max(role_dev.get("z_score", 0.0), 4.5)
            msg = f"Privileged RBAC role assignment operation executed by principal"
            candidates.append((weight, "privileged_role_ops", msg, role_dev))

        # 3. Key Vault & Secret access
        secrets = features.get("secret_retrievals", 0.0)
        sec_dev = deviations.get("secret_retrievals", {})
        if secrets >= 5 or sec_dev.get("z_score", 0.0) >= 2.0:
            ratio = sec_dev.get("ratio_to_baseline", secrets)
            weight = max(sec_dev.get("z_score", 0.0), 4.0)
            msg = f"Mass Key Vault secret retrieval activity ({int(secrets)} secrets accessed, {ratio:.1f}x baseline)"
            candidates.append((weight, "secret_retrievals", msg, sec_dev))

        kv_ops = features.get("keyvault_ops", 0.0)
        kv_dev = deviations.get("keyvault_ops", {})
        if kv_ops >= 5 and secrets < 5:
            weight = max(kv_dev.get("z_score", 0.0), 2.5)
            msg = f"Unusual volume of Key Vault access operations ({int(kv_ops)} operations)"
            candidates.append((weight, "keyvault_ops", msg, kv_dev))

        # 4. Storage & Destructive deletions
        deletions = features.get("deletion_ops", 0.0)
        del_dev = deviations.get("deletion_ops", {})
        if deletions >= 1:
            weight = max(del_dev.get("z_score", 0.0), 4.5)
            msg = f"Destructive storage/resource deletion operations detected ({int(deletions)} deletions)"
            candidates.append((weight, "deletion_ops", msg, del_dev))

        sec_mods = features.get("security_config_mods", 0.0)
        sec_mdev = deviations.get("security_config_mods", {})
        if sec_mods >= 1:
            weight = max(sec_mdev.get("z_score", 0.0), 4.0)
            msg = f"Security posture or cloud defense configuration modification detected"
            candidates.append((weight, "security_config_mods", msg, sec_mdev))

        # 5. Resource diversity & Velocity
        res_count = features.get("unique_resources", 0.0)
        res_dev = deviations.get("unique_resources", {})
        if res_dev.get("z_score", 0.0) >= 2.0 and res_count >= 3:
            ratio = res_dev.get("ratio_to_baseline", 2.0)
            weight = res_dev.get("z_score", 2.0)
            msg = f"Principal accessed {int(res_count)} distinct cloud resources ({ratio:.1f}x higher than baseline)"
            candidates.append((weight, "unique_resources", msg, res_dev))

        freq = features.get("event_frequency_10m", 0.0)
        freq_dev = deviations.get("event_frequency_10m", {})
        if freq_dev.get("z_score", 0.0) >= 2.5 and freq >= 10:
            ratio = freq_dev.get("ratio_to_baseline", 2.0)
            weight = freq_dev.get("z_score", 2.0)
            msg = f"Abnormal event velocity ({int(freq)} events in 10-minute window, {ratio:.1f}x baseline rate)"
            candidates.append((weight, "event_frequency_10m", msg, freq_dev))

        # 6. Novelty indicators
        if features.get("is_novel_ip", 0.0) == 1.0:
            ip_str = event.caller_ip or "unknown"
            candidates.append((3.0, "is_novel_ip", f"Activity originated from a previously unseen source IP ({ip_str})", deviations.get("is_novel_ip", {})))

        if features.get("is_novel_country", 0.0) == 1.0:
            country_str = event.geo_country or "unknown"
            candidates.append((3.2, "is_novel_country", f"Activity originated from an unfamiliar geographical location ({country_str})", deviations.get("is_novel_country", {})))

        # 7. Off-hours indicator
        if features.get("is_off_hours", 0.0) == 1.0 and anomaly_score >= 60.0:
            hour = int(features.get("hour_of_day", 0))
            candidates.append((1.8, "is_off_hours", f"Activity occurred outside standard business hours ({hour:02d}:00 UTC)", deviations.get("is_off_hours", {})))

        # Sort candidates by weight (highest deviation first)
        candidates.sort(key=lambda c: c[0], reverse=True)

        # Select top reasons
        selected = candidates[:max_reasons]

        reasons = [c[2] for c in selected]
        top_deviations = {c[1]: c[3] for c in selected}

        # Fallback if anomaly triggered by subtle multi-feature combinations
        if not reasons and anomaly_score >= 65.0:
            reasons.append("Multi-dimensional behavioral anomaly detected across combined activity metrics")

        summary = reasons[0] if reasons else "Normal behavioral profile within baseline expectations."

        return {
            "reasons": reasons,
            "top_deviations": top_deviations,
            "summary": summary,
        }
