import logging
import sys
from app.core.config import settings


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("secplatform")
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(log_level)

    # Avoid duplicate handlers if setup_logging is called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [request_id=%(name)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


logger = setup_logging()
