import asyncio
import json
import uuid
from typing import Optional, List, Tuple
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.core.logging import logger
from app.core.database import AsyncSessionLocal
from app.core.redis import get_redis_client
from app.domain.schemas.event import SecurityEventBase
from app.domain.models.logs import RawLog, NormalizedEvent
from app.domain.models.detections import ThreatDetection
from app.ingestion.normalizer import EventNormalizer
from app.detection.evaluator import detection_engine
from app.ml.pipeline import ml_pipeline


class IngestionWorker:
    """Asynchronous worker that consumes security telemetry from Redis streams,

    normalizes them, runs threat detection rules, and persists alerts.
    """

    STREAM_NAME = "secplatform:events_stream"
    QUEUE_NAME = "secplatform:raw_events_queue"
    CONSUMER_GROUP = "secplatform_workers_group"

    def __init__(self, consumer_name: Optional[str] = None):
        self.consumer_name = consumer_name or f"worker-{uuid.uuid4().hex[:8]}"
        self._stop_event = asyncio.Event()
        self.is_running = False
        self.processed_count = 0
        self.error_count = 0

    async def init_consumer_group(self, redis_client) -> bool:
        """Ensures the Redis Stream consumer group exists."""
        try:
            await redis_client.xgroup_create(
                name=self.STREAM_NAME,
                groupname=self.CONSUMER_GROUP,
                id="0",
                mkstream=True,
            )
            logger.info(f"Created Redis stream consumer group: {self.CONSUMER_GROUP}")
            return True
        except Exception as e:
            # BUSYGROUP Consumer Group name already exists is normal on restart
            if "BUSYGROUP" in str(e):
                return True
            logger.debug(f"Consumer group init notice: {e}")
            return False

    async def process_single_payload(
        self,
        payload_data: str,
        db: AsyncSession,
    ) -> Tuple[Optional[NormalizedEvent], List[ThreatDetection]]:
        """Parses a telemetry event payload, normalizes it, and evaluates detection rules.

        Testable in complete isolation without active Redis infrastructure.
        """
        try:
            if isinstance(payload_data, bytes):
                payload_data = payload_data.decode("utf-8")

            data_dict = json.loads(payload_data) if isinstance(payload_data, str) else payload_data
            event_obj = SecurityEventBase(**data_dict)
        except Exception as parse_err:
            self.error_count += 1
            logger.error(f"Malformed security event received by ingestion worker: {parse_err}")
            return None, []

        try:
            # Check if event was already persisted by API layer
            existing_event = await db.get(NormalizedEvent, event_obj.event_id)
            if existing_event is not None:
                normalized_event = existing_event
            else:
                raw_log = RawLog(
                    id=uuid.uuid4(),
                    source_system=event_obj.source,
                    raw_payload=event_obj.model_dump(mode="json"),
                )
                db.add(raw_log)
                await db.flush()

                normalized_event = EventNormalizer.normalize(event_obj, raw_log=raw_log)
                db.add(normalized_event)
                await db.flush()

            # Run Detection Rule Engine
            detections = await detection_engine.evaluate_and_persist(normalized_event, db)

            # Run ML Anomaly Detection / UEBA Engine
            try:
                await ml_pipeline.evaluate_and_persist(normalized_event, db)
            except Exception as ml_err:
                logger.warning(f"ML evaluation warning for event {normalized_event.id}: {ml_err}")

            await db.commit()

            self.processed_count += 1
            return normalized_event, detections

        except Exception as proc_err:
            await db.rollback()
            self.error_count += 1
            logger.error(f"Failed to process and evaluate event {event_obj.event_id}: {proc_err}")
            return None, []

    async def process_stream_batch(self, redis_client, batch_size: int = 10) -> int:
        """Reads and processes a batch of messages from the Redis Stream."""
        processed_in_batch = 0
        try:
            entries = await redis_client.xreadgroup(
                groupname=self.CONSUMER_GROUP,
                consumername=self.consumer_name,
                streams={self.STREAM_NAME: ">"},
                count=batch_size,
                block=1000,
            )

            if not entries:
                return 0

            async with AsyncSessionLocal() as db:
                for stream_name, messages in entries:
                    for msg_id, fields in messages:
                        payload = fields.get("payload")
                        if payload:
                            await self.process_single_payload(payload, db)
                        # Acknowledge message in Redis stream
                        await redis_client.xack(self.STREAM_NAME, self.CONSUMER_GROUP, msg_id)
                        processed_in_batch += 1

        except Exception as e:
            logger.warning(f"Worker stream read warning: {e}")

        return processed_in_batch

    async def run(self, max_iterations: Optional[int] = None):
        """Continuous execution loop with exponential backoff on connection failure."""
        self.is_running = True
        self._stop_event.clear()
        logger.info(f"Starting Ingestion Worker '{self.consumer_name}'...")

        backoff = 1.0
        iterations = 0

        while not self._stop_event.is_set():
            if max_iterations is not None and iterations >= max_iterations:
                break
            iterations += 1

            try:
                redis = await get_redis_client()
                # Test connectivity
                await redis.ping()
                await self.init_consumer_group(redis)

                # Reset backoff on success
                backoff = 1.0

                # Process batch from stream
                count = await self.process_stream_batch(redis)
                if count == 0:
                    # If stream was idle, wait briefly before checking again
                    await asyncio.sleep(0.5)

            except Exception as e:
                logger.warning(f"Ingestion worker Redis connection warning: {e}. Retrying in {backoff:.1f}s...")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2.0, 30.0)

        self.is_running = False
        logger.info(f"Ingestion Worker '{self.consumer_name}' stopped. (Processed: {self.processed_count})")

    def stop(self):
        """Signals the worker to terminate gracefully."""
        self._stop_event.set()
        self.is_running = False


# Default worker instance
ingestion_worker = IngestionWorker()
