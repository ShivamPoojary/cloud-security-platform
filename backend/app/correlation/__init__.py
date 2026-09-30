"""Threat Correlation module for multi-event graph and temporal sessionizing."""

from app.correlation.graph import (
    CorrelationGraph,
    CorrelationNode,
    MAX_CORRELATION_WINDOW_SECONDS,
)
from app.correlation.engine import (
    ThreatCorrelationEngine,
    correlation_engine,
    ACTIVE_INCIDENT_STATUSES,
    RESOLVED_INCIDENT_STATUSES,
)

__all__ = [
    "CorrelationGraph",
    "CorrelationNode",
    "MAX_CORRELATION_WINDOW_SECONDS",
    "ThreatCorrelationEngine",
    "correlation_engine",
    "ACTIVE_INCIDENT_STATUSES",
    "RESOLVED_INCIDENT_STATUSES",
]
