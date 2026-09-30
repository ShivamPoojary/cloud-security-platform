from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, desc
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.domain.models.detections import ThreatDetection
from app.domain.schemas.detection import ThreatDetectionRead

router = APIRouter()


@router.get("", summary="Query threat detections and security alerts")
async def list_detections(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None, description="Filter by severity e.g. HIGH, CRITICAL"),
    db: AsyncSession = Depends(get_db),
):
    """Returns paginated threat detections triggered by detection rules."""
    query = select(ThreatDetection).options(
        selectinload(ThreatDetection.rule),
        selectinload(ThreatDetection.event),
    )
    count_query = select(func.count(ThreatDetection.id))

    if severity:
        query = query.where(ThreatDetection.severity == severity.upper())
        count_query = count_query.where(ThreatDetection.severity == severity.upper())

    total_count = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(desc(ThreatDetection.detected_at)).limit(limit).offset(offset)
    result = await db.execute(query)
    detections = result.scalars().all()

    items = [
        ThreatDetectionRead(
            id=d.id,
            rule_id=d.rule_id,
            rule_code=d.rule.rule_id if d.rule else "RULE-UNKNOWN",
            rule_title=d.rule.title if d.rule else "Unknown Rule",
            event_id=d.event_id,
            severity=d.severity,
            alert_summary=d.alert_summary,
            mitre_tactic=d.rule.mitre_tactic if d.rule else None,
            mitre_technique_id=d.rule.mitre_technique_id if d.rule else None,
            principal_name=d.event.principal_name if d.event else None,
            caller_ip=d.event.caller_ip if d.event else None,
            target_resource_name=d.event.target_resource_name if d.event else None,
            detected_at=d.detected_at,
        )
        for d in detections
    ]

    return {
        "items": items,
        "total": total_count,
        "limit": limit,
        "offset": offset,
    }
