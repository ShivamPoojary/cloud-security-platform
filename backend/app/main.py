from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.logging import logger
from app.core.redis import get_redis_client, close_redis_client
from app.api.router import api_router
from app.api.middleware import CorrelationIdMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context for startup and shutdown routines."""
    logger.info("Initializing Cloud Security Monitoring Platform backend...")
    # Pre-warm Redis connection
    try:
        await get_redis_client()
        logger.info("Redis connection initialized successfully.")
    except Exception as e:
        logger.warning(f"Initial Redis connection warning: {e}")

    yield

    logger.info("Shutting down Cloud Security Monitoring Platform backend...")
    await close_redis_client()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="0.1.0",
    description="Production-Grade Cloud SIEM and Threat Detection Platform API",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# 1. CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Correlation ID & Access Logging Middleware
app.add_middleware(CorrelationIdMiddleware)

# 3. Root Health Endpoint (Load Balancer Probe)
@app.get("/health", tags=["Health"])
async def root_health():
    """Root health check probe."""
    return {
        "status": "ok",
        "service": "cloud-security-platform",
    }


# 4. Mount API v1
app.include_router(api_router, prefix=settings.API_V1_STR)
