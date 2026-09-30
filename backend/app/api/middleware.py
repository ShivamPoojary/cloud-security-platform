import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from app.core.logging import logger


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Assigns an X-Request-ID to every incoming HTTP request and logs duration."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        start_time = time.time()

        response = await call_next(request)

        process_time_ms = round((time.time() - start_time) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time-Ms"] = str(process_time_ms)

        logger.info(
            f"{request.method} {request.url.path} completed in {process_time_ms}ms with status {response.status_code}"
        )
        return response
