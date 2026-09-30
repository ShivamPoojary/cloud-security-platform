import json
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.core.redis import get_redis_client
from app.core.logging import logger
from app.domain.models.logs import RawLog, NormalizedEvent
from app.domain.schemas.ingest import (
    RawIngestRequest,
    RawIngestResponse,
    SyntheticTriggerRequest,
    SyntheticTriggerResponse,
)
from app.ingestion.normalizer import EventNormalizer
from app.ingestion.synthetic_generator import SyntheticAzureTelemetryGenerator
from app.detection.evaluator import detection_engine

router = APIRouter()


@router.post(
    "/raw",
    response_model=RawIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a raw security telemetry event",
)
async def ingest_raw_event(
    event_in: RawIngestRequest,
    db: AsyncSession = Depends(get_db),
):
    """Accepts a validated security event, stores raw & normalized records in PostgreSQL,

    and enqueues the event payload into Redis for asynchronous processing.
    """
    try:
        # 1. Store Raw Log
        raw_log = RawLog(
            source_system=event_in.source,
            raw_payload=event_in.model_dump(mode="json"),
        )
        db.add(raw_log)
        await db.flush()

        # 2. Normalize and Store Event
        normalized_event = EventNormalizer.normalize(event_in, raw_log=raw_log)
        db.add(normalized_event)
        await db.flush()

        # 3. Evaluate Detection Rules
        await detection_engine.evaluate_and_persist(normalized_event, db)
        await db.commit()

        # 3. Buffer into Redis Queue / Stream
        try:
            redis = await get_redis_client()
            payload_str = json.dumps(event_in.model_dump(mode="json"), default=str)
            # Push to Redis stream & list buffer
            await redis.rpush("secplatform:raw_events_queue", payload_str)
            await redis.xadd("secplatform:events_stream", {"payload": payload_str})
        except Exception as redis_err:
            logger.warning(f"Event persisted in DB but Redis buffering encountered warning: {redis_err}")

        return RawIngestResponse(
            status="queued",
            event_id=event_in.event_id,
            timestamp=event_in.timestamp,
        )

    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to ingest raw security event: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process and buffer security event: {str(e)}",
        )


@router.post(
    "/synthetic/trigger",
    response_model=SyntheticTriggerResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger generation of a synthetic Azure attack scenario",
)
async def trigger_synthetic_scenario(
    request: SyntheticTriggerRequest,
    db: AsyncSession = Depends(get_db),
):
    """Triggers an Azure multi-stage attack kill-chain scenario without cloud cost.

    Generates realistic events, normalizes and persists them, buffers to Redis,
    and returns the execution details.
    """
    execution_id = f"scen-{uuid.uuid4().hex[:12]}"
    try:
        # 1. Generate scenario events
        events = SyntheticAzureTelemetryGenerator.generate_attack_scenario(
            scenario_name=request.scenario_name,
            custom_target=request.custom_target_resource,
        )

        redis = None
        try:
            redis = await get_redis_client()
        except Exception:
            pass

        # 2. Persist each event and buffer to Redis
        for ev in events:
            raw_log = RawLog(
                source_system=ev.source,
                raw_payload=ev.model_dump(mode="json"),
            )
            db.add(raw_log)
            await db.flush()

            norm_ev = EventNormalizer.normalize(ev, raw_log=raw_log)
            db.add(norm_ev)
            await db.flush()

            # Evaluate detection rules on generated event
            await detection_engine.evaluate_and_persist(norm_ev, db)

            if redis:
                try:
                    payload_str = json.dumps(ev.model_dump(mode="json"), default=str)
                    await redis.rpush("secplatform:raw_events_queue", payload_str)
                    await redis.xadd("secplatform:events_stream", {"payload": payload_str})
                except Exception as r_err:
                    logger.debug(f"Redis buffering skip: {r_err}")

        await db.commit()

        logger.info(
            f"Successfully triggered synthetic scenario '{request.scenario_name}' "
            f"execution_id={execution_id} ({len(events)} events generated)"
        )

        return SyntheticTriggerResponse(
            execution_id=execution_id,
            scenario_name=request.scenario_name,
            status="generated",
            events_count=len(events),
            events=events,
        )

    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to trigger synthetic scenario: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generating scenario: {str(e)}",
        )
