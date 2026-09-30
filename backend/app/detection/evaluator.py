import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.logging import logger
from app.domain.models.logs import NormalizedEvent
from app.domain.models.rules import DetectionRule
from app.domain.models.detections import ThreatDetection
from app.detection.window import window_tracker, SlidingWindowTracker


class DetectionEngine:
    """Detection Rule Engine supporting stateless patterns and stateful sliding-window thresholds."""

    def __init__(self, tracker: Optional[SlidingWindowTracker] = None):
        self.tracker = tracker or window_tracker

    def _matches_filter(self, event: NormalizedEvent, filter_dict: Dict[str, Any]) -> bool:
        """Evaluates whether an event satisfies the rule's filter criteria."""
        for field, expected_val in filter_dict.items():
            if field == "event_category":
                if event.event_category != expected_val:
                    return False
            elif field == "event_name":
                if event.event_name != expected_val:
                    return False
            elif field == "action_status":
                if event.action_status != expected_val:
                    return False
            elif field == "target_resource_id":
                if expected_val not in (event.target_resource_id or ""):
                    return False
            elif field == "principal_name":
                if event.principal_name != expected_val:
                    return False
            elif field == "caller_ip":
                if event.caller_ip != expected_val:
                    return False
            else:
                # Match against security_context / metadata JSONB payload
                context = event.security_context or {}
                actual_val = context.get(field)
                if actual_val != expected_val:
                    return False
        return True

    def _get_entity_key(self, event: NormalizedEvent, rule_logic: Dict[str, Any]) -> str:
        """Extracts the entity grouping key (e.g. principal_id, caller_ip, or composite)."""
        group_fields = rule_logic.get("group_by")
        if group_fields and isinstance(group_fields, list):
            parts = []
            for f in group_fields:
                val = getattr(event, f, None)
                if val:
                    parts.append(str(val))
            if parts:
                return ":".join(parts)

        # Default fallback entity priority: principal_id -> principal_name -> caller_ip -> "global"
        return event.principal_id or event.principal_name or event.caller_ip or "global"

    def evaluate_event_sync(
        self,
        event: NormalizedEvent,
        rules: List[DetectionRule],
    ) -> List[ThreatDetection]:
        """Synchronously evaluates an event against a list of active rules without database I/O."""
        detections: List[ThreatDetection] = []

        for rule in rules:
            if not rule.is_active:
                continue

            rule_logic = rule.rule_logic or {}
            rule_type = rule_logic.get("type", "stateless_pattern")
            filter_dict = rule_logic.get("filter", {})

            # 1. Check event filter
            if not self._matches_filter(event, filter_dict):
                continue

            triggered = False

            # 2. Evaluate rule condition based on type
            if rule_type in ["stateless_pattern", "stateless"]:
                triggered = True
            elif rule_type in ["stateful_threshold", "threshold"]:
                window_seconds = int(rule_logic.get("window_seconds", 180))
                # Support both 'threshold' and 'count_greater_than'
                threshold = int(rule_logic.get("threshold", rule_logic.get("count_greater_than", 5)))
                entity_key = self._get_entity_key(event, rule_logic)

                triggered = self.tracker.record_and_check(
                    rule_id=rule.rule_id,
                    entity_key=entity_key,
                    event_time=event.event_timestamp,
                    window_seconds=window_seconds,
                    threshold=threshold,
                )

            # 3. Create ThreatDetection if rule condition is satisfied
            if triggered:
                actor = event.principal_name or event.principal_id or event.caller_ip or "Unknown Actor"
                summary = (
                    f"[{rule.severity}] {rule.title} - "
                    f"Detected on '{actor}' at {event.target_resource_name or event.target_resource_id or 'Cloud Resource'} "
                    f"({rule.mitre_tactic} / {rule.mitre_technique_id})"
                )

                detection = ThreatDetection(
                    id=uuid.uuid4(),
                    rule_id=rule.id,
                    event_id=event.id,
                    severity=rule.severity,
                    alert_summary=summary,
                    detected_at=event.event_timestamp or datetime.now(timezone.utc),
                )
                detections.append(detection)
                logger.info(f"THREAT DETECTION TRIGGERED: rule_id={rule.rule_id} event_id={event.id} severity={rule.severity}")

        return detections

    async def evaluate_and_persist(
        self,
        event: NormalizedEvent,
        db: AsyncSession,
        rules: Optional[List[DetectionRule]] = None,
    ) -> List[ThreatDetection]:
        """Evaluates event against database rules, persists detections, and returns created records."""
        if rules is None:
            result = await db.execute(select(DetectionRule).where(DetectionRule.is_active == True))
            rules = list(result.scalars().all())

        detections = self.evaluate_event_sync(event, rules)
        if detections:
            for d in detections:
                db.add(d)
            await db.flush()

        return detections


# Global detection engine instance
detection_engine = DetectionEngine()
