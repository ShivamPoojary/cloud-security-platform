import asyncio
from typing import Optional
import redis.asyncio as aioredis
from app.core.config import settings
from app.core.logging import logger

redis_client: Optional[aioredis.Redis] = None


async def get_redis_client() -> aioredis.Redis:
    """Returns or initializes the async Redis client singleton with fast timeout fallback."""
    global redis_client
    if redis_client is None:
        client = aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
            retry_on_timeout=False,
        )
        try:
            await asyncio.wait_for(client.ping(), timeout=1.0)
            logger.info("Connected to Redis server.")
        except Exception as e:
            logger.warning(f"Redis unavailable at {settings.REDIS_URL} ({e}); continuing with standalone fallback.")
        redis_client = client
    return redis_client


async def close_redis_client() -> None:
    """Closes the Redis connection pool."""
    global redis_client
    if redis_client is not None:
        try:
            await redis_client.aclose()
        except Exception as e:
            logger.debug(f"Closing Redis client notice: {e}")
        finally:
            redis_client = None
