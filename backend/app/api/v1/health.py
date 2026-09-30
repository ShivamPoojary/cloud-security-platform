from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.core.database import get_db
from app.core.redis import get_redis_client
from app.core.logging import logger

router = APIRouter()


@router.get("/health")
async def get_v1_health(db: AsyncSession = Depends(get_db)):
    """Detailed health probe checking Database and Redis connectivity."""
    db_status = "disconnected"
    redis_status = "disconnected"

    # Check Database
    try:
        result = await db.execute(text("SELECT 1"))
        if result.scalar() == 1:
            db_status = "connected"
    except Exception as e:
        logger.warning(f"Health probe database check failed: {e}")
        db_status = f"error: {str(e)}"

    # Check Redis
    try:
        redis = await get_redis_client()
        pong = await redis.ping()
        if pong:
            redis_status = "connected"
    except Exception as e:
        logger.warning(f"Health probe redis check failed: {e}")
        redis_status = f"error: {str(e)}"

    return {
        "status": "ok" if db_status == "connected" and redis_status == "connected" else "degraded",
        "service": "cloud-security-platform",
        "version": "0.1.0",
        "database": db_status,
        "redis": redis_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
