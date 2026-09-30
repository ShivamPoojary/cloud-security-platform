"""Incident Management & Threat Correlation API endpoints."""

import uuid
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, Path, HTTPException, status
from sqlalchemy import select, func, desc
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.logging import logger
from app.domain.models.incidents import Incident, IncidentTimelineEvent
from app.domain.models.detections import ThreatDetection
from app.domain.models.ml import MLAnomalyScore
from app.domain.schemas.incident import (
    IncidentRead,
    IncidentDetailRead,
    IncidentTimelineEventRead,
    IncidentUpdateStatusRequest,
    CorrelationSummaryResponse,
    IncidentDetectionSummary,
    IncidentMLAnomalySummary,
)
from app.correlation.engine import correlation_engine

router = APIRouter()


@router.get(
    "",
    summary="List paginated security incidents",
    response_model=dict,
)
async def list_incidents(
    limit: int = Query(50, ge=1, le=500, description="Items per page"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    status: Optional[str] = Query(None, description="Filter by status (e.g. NEW, TRIAGED, RESOLVED)"),
    severity: Optional[str] = Query(None, description="Filter by severity (e.g. HIGH, CRITICAL)"),
    min_risk: Optional[float] = Query(None, ge=0.0, le=100.0, description="Filter by minimum risk score"),
    db: AsyncSession = Depends(get_db),
):
    """Returns paginated incidents filtered by status, severity, or risk score."""
    query = (
        select(Incident)
        .options(
            selectinload(Incident.detections),
            selectinload(Incident.anomaly_scores),
        )
    )
    count_query = select(func.count(Incident.id))

    if status:
        query = query.where(Incident.status == status.strip().upper())
        count_query = count_query.where(Incident.status == status.strip().upper())
    if severity:
        query = query.where(Incident.severity == severity.strip().upper())
        count_query = count_query.where(Incident.severity == severity.strip().upper())
    if min_risk is not None:
        query = query.where(Incident.risk_score >= min_risk)
        count_query = count_query.where(Incident.risk_score >= min_risk)

    total_count = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(desc(Incident.risk_score), desc(Incident.created_at)).limit(limit).offset(offset)
    result = await db.execute(query)
    incidents = result.scalars().all()

    items = [
        IncidentRead(
            id=inc.id,
            incident_number=inc.incident_number,
            title=inc.title,
            status=inc.status,
            severity=inc.severity,
            risk_score=inc.risk_score,
            mitre_tactics=inc.mitre_tactics or [],
            mitre_techniques=inc.mitre_techniques or [],
            detection_count=len(inc.detections),
            anomaly_count=len(inc.anomaly_scores),
            assigned_to=inc.assigned_to,
            created_at=inc.created_at,
            updated_at=inc.updated_at,
            resolved_at=inc.resolved_at,
        )
        for inc in incidents
    ]

    return {
        "items": [item.model_dump(mode="json") for item in items],
        "total": total_count,
        "limit": limit,
        "offset": offset,
    }


@router.get(
    "/{incident_id}",
    summary="Get full incident detail with detections, anomalies, and timeline",
    response_model=IncidentDetailRead,
)
async def get_incident_detail(
    incident_id: uuid.UUID = Path(..., description="Target incident ID"),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves full incident detail including constituent alerts, anomalies, and timeline."""
    query = (
        select(Incident)
        .options(
            selectinload(Incident.detections).selectinload(ThreatDetection.rule),
            selectinload(Incident.detections).selectinload(ThreatDetection.event),
            selectinload(Incident.anomaly_scores).selectinload(MLAnomalyScore.event),
            selectinload(Incident.timeline_events).selectinload(IncidentTimelineEvent.event),
        )
        .where(Incident.id == incident_id)
    )
    result = await db.execute(query)
    incident = result.scalars().first()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )

    # Format detections
    detection_summaries = [
        IncidentDetectionSummary(
            id=d.id,
            rule_id=d.rule_id,
            rule_code=d.rule.rule_id if d.rule else "RULE-UNKNOWN",
            rule_title=d.rule.title if d.rule else "Unknown Rule",
            severity=d.severity,
            alert_summary=d.alert_summary,
            mitre_tactic=d.rule.mitre_tactic if d.rule else None,
            mitre_technique_id=d.rule.mitre_technique_id if d.rule else None,
            detected_at=d.detected_at,
        )
        for d in incident.detections
    ]

    # Format anomalies
    anomaly_summaries = []
    for a in incident.anomaly_scores:
        fc = a.feature_contributions or {}
        anomaly_summaries.append(
            IncidentMLAnomalySummary(
                id=a.id,
                event_id=a.event_id,
                anomaly_score=a.anomaly_score,
                confidence=a.confidence,
                is_anomalous=a.is_anomalous,
                model_version=a.model_version,
                severity=fc.get("severity"),
                summary=fc.get("summary"),
                created_at=a.created_at,
            )
        )

    # Format timeline
    timeline_items = [
        IncidentTimelineEventRead(
            id=t.id,
            incident_id=t.incident_id,
            event_id=t.event_id,
            correlation_reason=t.correlation_reason,
            sequence_order=t.sequence_order,
            event_timestamp=t.event.event_timestamp if t.event else None,
            event_name=t.event.event_name if t.event else None,
            principal_name=t.event.principal_name if t.event else None,
            caller_ip=t.event.caller_ip if t.event else None,
            target_resource_name=t.event.target_resource_name if t.event else None,
            action_status=t.event.action_status if t.event else None,
            created_at=t.created_at,
        )
        for t in sorted(incident.timeline_events, key=lambda x: x.sequence_order)
    ]

    return IncidentDetailRead(
        id=incident.id,
        incident_number=incident.incident_number,
        title=incident.title,
        status=incident.status,
        severity=incident.severity,
        risk_score=incident.risk_score,
        mitre_tactics=incident.mitre_tactics or [],
        mitre_techniques=incident.mitre_techniques or [],
        assigned_to=incident.assigned_to,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        resolved_at=incident.resolved_at,
        detections=detection_summaries,
        anomalies=anomaly_summaries,
        timeline=timeline_items,
    )


@router.patch(
    "/{incident_id}/status",
    summary="Update incident lifecycle status and assignment",
    response_model=IncidentRead,
)
async def update_incident_status(
    payload: IncidentUpdateStatusRequest,
    incident_id: uuid.UUID = Path(..., description="Target incident ID"),
    db: AsyncSession = Depends(get_db),
):
    """Transitions incident status and sets resolution timestamp if resolved."""
    query = (
        select(Incident)
        .options(
            selectinload(Incident.detections),
            selectinload(Incident.anomaly_scores),
        )
        .where(Incident.id == incident_id)
    )
    result = await db.execute(query)
    incident = result.scalars().first()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )

    now = datetime.now(timezone.utc)
    new_status = payload.status.upper()
    incident.status = new_status
    incident.updated_at = now

    if payload.assigned_to is not None:
        incident.assigned_to = payload.assigned_to

    if new_status in ("RESOLVED", "FALSE_POSITIVE"):
        incident.resolved_at = now
    else:
        incident.resolved_at = None

    det_count = len(incident.detections) if incident.detections is not None else 0
    anom_count = len(incident.anomaly_scores) if incident.anomaly_scores is not None else 0

    await db.commit()

    logger.info(f"Updated Incident {incident.incident_number} status to {new_status}")

    return IncidentRead(
        id=incident.id,
        incident_number=incident.incident_number,
        title=incident.title,
        status=incident.status,
        severity=incident.severity,
        risk_score=incident.risk_score,
        mitre_tactics=incident.mitre_tactics or [],
        mitre_techniques=incident.mitre_techniques or [],
        detection_count=det_count,
        anomaly_count=anom_count,
        assigned_to=incident.assigned_to,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        resolved_at=incident.resolved_at,
    )



@router.post(
    "/correlate",
    summary="Trigger on-demand event correlation sweep",
    response_model=CorrelationSummaryResponse,
    status_code=status.HTTP_200_OK,
)
async def trigger_correlation(
    db: AsyncSession = Depends(get_db),
):
    """Executes a correlation sweep over unassigned detections and eligible ML anomalies."""
    try:
        summary = await correlation_engine.correlate(db)
        return CorrelationSummaryResponse(
            created_incidents=summary["created_incidents"],
            updated_incidents=summary["updated_incidents"],
            correlated_events=summary["correlated_events"],
            message="Correlation evaluation completed successfully",
        )
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to execute correlation sweep: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute correlation sweep: {str(e)}",
        )
