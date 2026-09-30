from typing import Dict, Any, Union
from datetime import datetime, timezone
import uuid
from app.domain.schemas.event import SecurityEventBase
from app.domain.models.logs import NormalizedEvent, RawLog


class EventNormalizer:
    """Normalizes heterogeneous cloud telemetry into standard NormalizedEvent schema."""

    @staticmethod
    def normalize(
        event: Union[SecurityEventBase, Dict[str, Any]],
        raw_log: Union[RawLog, None] = None,
    ) -> NormalizedEvent:
        if isinstance(event, dict):
            event_obj = SecurityEventBase(**event)
        else:
            event_obj = event

        return NormalizedEvent(
            id=event_obj.event_id,
            raw_log_id=raw_log.id if raw_log else None,
            event_timestamp=event_obj.timestamp,
            event_category=event_obj.event_category,
            event_name=event_obj.event_name,
            principal_id=event_obj.principal_id,
            principal_name=event_obj.principal_name,
            caller_ip=event_obj.caller_ip,
            user_agent=event_obj.user_agent,
            target_resource_id=event_obj.target_resource_id,
            target_resource_name=event_obj.target_resource_name,
            action_status=event_obj.action_status,
            geo_country=event_obj.geo_country,
            geo_city=event_obj.metadata.get("geo_city"),
            security_context=event_obj.metadata,
        )
