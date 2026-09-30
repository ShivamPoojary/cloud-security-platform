from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.domain.models.rules import DetectionRule
from app.domain.models.detections import ThreatDetection
from app.domain.schemas.rule import DetectionRuleRead, DetectionRuleToggleResponse

router = APIRouter()


@router.get("", response_model=List[DetectionRuleRead], summary="List all detection rules")
async def list_rules(
    is_active: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
):
    """Returns all detection rules with their current alert detection count."""
    query = select(DetectionRule)
    if is_active is not None:
        query = query.where(DetectionRule.is_active == is_active)

    query = query.order_by(DetectionRule.rule_id)
    rules_result = await db.execute(query)
    rules = rules_result.scalars().all()

    # Query detection count per rule
    counts_query = (
        select(ThreatDetection.rule_id, func.count(ThreatDetection.id))
        .group_by(ThreatDetection.rule_id)
    )
    counts_result = await db.execute(counts_query)
    counts_map = dict(counts_result.all())

    items = []
    for r in rules:
        count = counts_map.get(r.id, 0)
        items.append(
            DetectionRuleRead(
                id=r.id,
                rule_id=r.rule_id,
                title=r.title,
                severity=r.severity,
                mitre_tactic=r.mitre_tactic,
                mitre_technique_id=r.mitre_technique_id,
                description=r.description,
                rule_logic=r.rule_logic or {},
                is_active=r.is_active,
                detection_count=count,
                updated_at=r.updated_at,
                created_at=r.created_at,
            )
        )

    return items


@router.patch("/{rule_id}/toggle", response_model=DetectionRuleToggleResponse, summary="Toggle rule active state")
async def toggle_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Enables or disables an existing detection rule."""
    query = select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    result = await db.execute(query)
    rule = result.scalars().first()

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found",
        )

    rule.is_active = not rule.is_active
    await db.commit()

    state_str = "enabled" if rule.is_active else "disabled"
    return DetectionRuleToggleResponse(
        rule_id=rule.rule_id,
        is_active=rule.is_active,
        message=f"Detection rule '{rule.rule_id}' has been {state_str}.",
    )
