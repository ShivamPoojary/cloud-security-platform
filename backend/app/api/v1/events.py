from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, desc
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.domain.models.logs import NormalizedEvent
from app.domain.schemas.event import NormalizedEventRead

router = APIRouter()


@router.get("", summary="Query normalized telemetry events")
async def list_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    category: Optional[str] = Query(None, description="Filter by event_category"),
    action_status: Optional[str] = Query(None, description="Filter by action_status"),
    db: AsyncSession = Depends(get_db),
):
    """Returns paginated normalized security events sorted chronologically."""
    query = select(NormalizedEvent).options(selectinload(NormalizedEvent.raw_log))
    count_query = select(func.count(NormalizedEvent.id))

    if category:
        query = query.where(NormalizedEvent.event_category == category)
        count_query = count_query.where(NormalizedEvent.event_category == category)
    if action_status:
        query = query.where(NormalizedEvent.action_status == action_status)
        count_query = count_query.where(NormalizedEvent.action_status == action_status)

    total_count = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(desc(NormalizedEvent.event_timestamp)).limit(limit).offset(offset)
    result = await db.execute(query)
    events = result.scalars().all()

    items = [
        NormalizedEventRead(
            id=ev.id,
            event_id=ev.id,
            raw_log_id=ev.raw_log_id,
            timestamp=ev.event_timestamp,
            source=ev.raw_log.source_system if ev.raw_log else "Telemetry",
            event_category=ev.event_category,
            event_name=ev.event_name,
            principal_id=ev.principal_id,
            principal_name=ev.principal_name,
            caller_ip=ev.caller_ip,
            target_resource_id=ev.target_resource_id,
            target_resource_name=ev.target_resource_name,
            action_status=ev.action_status,
            geo_country=ev.geo_country,
            user_agent=ev.user_agent,
            metadata=ev.security_context or {},
            created_at=ev.created_at,
        )
        for ev in events
    ]

    return {
        "items": items,
        "total": total_count,
        "limit": limit,
        "offset": offset,
    }
