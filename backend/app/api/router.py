from fastapi import APIRouter
from app.api.v1 import health, ingest, events, detections, rules, ml

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(ingest.router, prefix="/ingest", tags=["Ingestion"])
api_router.include_router(events.router, prefix="/events", tags=["Events"])
api_router.include_router(detections.router, prefix="/detections", tags=["Detections"])
api_router.include_router(rules.router, prefix="/rules", tags=["Rules"])
api_router.include_router(ml.router, prefix="/ml", tags=["ML / UEBA"])
