import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy import select, func, desc, or_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domain.models.ml import MLAnomalyScore
from app.domain.models.logs import NormalizedEvent
from app.domain.schemas.ml import MLAnomalyRead, MLMetricsResponse
from app.ml.features import FEATURE_NAMES
from app.ml.pipeline import ml_pipeline

router = APIRouter()


def _build_anomaly_read(m: MLAnomalyScore) -> MLAnomalyRead:
    contrib = m.feature_contributions or {}
    reasons = contrib.get("reasons", [])
    summary = contrib.get("summary", "")
    top_deviations = contrib.get("top_deviations", {})
    severity = contrib.get("severity", "low")
    if not severity:
        if m.anomaly_score >= 80:
            severity = "critical"
        elif m.anomaly_score >= 65:
            severity = "high"
        elif m.anomaly_score >= 50:
            severity = "medium"
        else:
            severity = "low"

    ev = m.event
    return MLAnomalyRead(
        id=m.id,
        event_id=m.event_id,
        model_version=m.model_version,
        anomaly_score=m.anomaly_score,
        confidence=m.confidence,
        is_anomalous=m.is_anomalous,
        severity=severity,
        reasons=reasons,
        summary=summary,
        top_deviations=top_deviations,
        principal_id=ev.principal_id if ev else contrib.get("principal_id"),
        principal_name=ev.principal_name if ev else contrib.get("principal_name"),
        caller_ip=ev.caller_ip if ev else contrib.get("caller_ip"),
        event_name=ev.event_name if ev else None,
        event_category=ev.event_category if ev else None,
        geo_country=ev.geo_country if ev else contrib.get("geo_country"),
        feature_contributions=contrib,
        created_at=m.created_at,
    )


@router.get("/anomalies", summary="Query ML anomaly scores and UEBA alerts")
async def list_anomalies(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    principal: Optional[str] = Query(None, description="Filter by principal email or ID"),
    severity: Optional[str] = Query(None, description="Filter by severity e.g. low, medium, high, critical"),
    min_score: Optional[float] = Query(None, description="Minimum anomaly score (0 - 100)"),
    is_anomalous: Optional[bool] = Query(None, description="Filter only anomalous detections"),
    db: AsyncSession = Depends(get_db),
):
    """Returns paginated ML anomaly detection scores with explainable reasons and feature deviations."""
    query = select(MLAnomalyScore).options(selectinload(MLAnomalyScore.event))
    count_query = select(func.count(MLAnomalyScore.id))

    if min_score is not None:
        query = query.where(MLAnomalyScore.anomaly_score >= min_score)
        count_query = count_query.where(MLAnomalyScore.anomaly_score >= min_score)

    if is_anomalous is not None:
        query = query.where(MLAnomalyScore.is_anomalous == is_anomalous)
        count_query = count_query.where(MLAnomalyScore.is_anomalous == is_anomalous)

    if principal:
        # Join with NormalizedEvent to filter by principal
        query = query.join(NormalizedEvent, MLAnomalyScore.event_id == NormalizedEvent.id).where(
            or_(
                NormalizedEvent.principal_name.ilike(f"%{principal}%"),
                NormalizedEvent.principal_id.ilike(f"%{principal}%"),
            )
        )
        count_query = count_query.join(
            NormalizedEvent, MLAnomalyScore.event_id == NormalizedEvent.id
        ).where(
            or_(
                NormalizedEvent.principal_name.ilike(f"%{principal}%"),
                NormalizedEvent.principal_id.ilike(f"%{principal}%"),
            )
        )

    total_count = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(desc(MLAnomalyScore.created_at)).limit(limit).offset(offset)
    result = await db.execute(query)
    scores = result.scalars().all()

    items = [_build_anomaly_read(s) for s in scores]

    if severity:
        target_sev = severity.lower()
        items = [item for item in items if item.severity.lower() == target_sev]

    return {
        "items": items,
        "total": total_count,
        "limit": limit,
        "offset": offset,
    }


@router.get("/anomalies/{anomaly_id}", summary="Retrieve single ML anomaly by ID")
async def get_anomaly(
    anomaly_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Retrieves full detail and breakdown for a specific ML anomaly record."""
    query = (
        select(MLAnomalyScore)
        .options(selectinload(MLAnomalyScore.event))
        .where(MLAnomalyScore.id == anomaly_id)
    )
    result = await db.execute(query)
    record = result.scalar_one_or_none()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ML anomaly score with ID '{anomaly_id}' not found",
        )

    return _build_anomaly_read(record)


@router.get("/metrics", summary="Get overall UEBA and ML metric aggregates", response_model=MLMetricsResponse)
async def get_ml_metrics(db: AsyncSession = Depends(get_db)):
    """Computes high-level aggregated UEBA metrics for SOC dashboards."""
    total_anomalies_q = select(func.count(MLAnomalyScore.id)).where(MLAnomalyScore.is_anomalous == True)
    total_anomalies = (await db.execute(total_anomalies_q)).scalar() or 0

    high_risk_q = select(func.count(MLAnomalyScore.id)).where(MLAnomalyScore.anomaly_score >= 80.0)
    high_risk_anomalies = (await db.execute(high_risk_q)).scalar() or 0

    avg_score_q = select(func.avg(MLAnomalyScore.anomaly_score))
    avg_score = (await db.execute(avg_score_q)).scalar() or 0.0

    # Distinct anomalous principals count
    principals_q = (
        select(func.count(func.distinct(NormalizedEvent.principal_name)))
        .join(MLAnomalyScore, MLAnomalyScore.event_id == NormalizedEvent.id)
        .where(MLAnomalyScore.is_anomalous == True)
    )
    anomalous_principals = (await db.execute(principals_q)).scalar() or 0

    return MLMetricsResponse(
        total_anomalies=total_anomalies,
        high_risk_anomalies=high_risk_anomalies,
        anomalous_principals=anomalous_principals,
        avg_anomaly_score=round(float(avg_score), 1),
        model_version=ml_pipeline.model_version,
        active_features_count=len(FEATURE_NAMES),
    )
