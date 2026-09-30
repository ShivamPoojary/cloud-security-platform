"""Threat Correlation and Incident Engine.

Coordinates graph-based correlation of threat detections and ML anomalies into
coherent, explainable security incidents with chronological timelines and risk scoring.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Dict, Set, Tuple, Any, Optional
from sqlalchemy import select, func, or_, and_, desc
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.domain.models.incidents import Incident, IncidentTimelineEvent
from app.domain.models.detections import ThreatDetection
from app.domain.models.ml import MLAnomalyScore
from app.domain.models.logs import NormalizedEvent
from app.correlation.graph import (
    CorrelationGraph,
    CorrelationNode,
    MAX_CORRELATION_WINDOW_SECONDS,
)
from app.scoring.engine import risk_scoring_engine
from app.mitre.service import mitre_service


ACTIVE_INCIDENT_STATUSES = {"NEW", "TRIAGED", "IN_INVESTIGATION"}
RESOLVED_INCIDENT_STATUSES = {"RESOLVED", "FALSE_POSITIVE"}


class ActiveIncidentProfile:
    """In-memory profile of an active incident avoiding async lazy-loading hazards."""

    def __init__(
        self,
        incident: Incident,
        entity_keys: Set[Tuple[str, str]],
        timestamps: List[float],
        detections: List[ThreatDetection],
        anomalies: List[MLAnomalyScore],
        max_sequence: int = -1,
    ):
        self.incident = incident
        self.entity_keys = set(entity_keys)
        self.timestamps = list(timestamps)
        self.detections = list(detections)
        self.anomalies = list(anomalies)
        self.max_sequence = max_sequence

    @property
    def latest_timestamp(self) -> float:
        return max(self.timestamps) if self.timestamps else 0.0

    @property
    def earliest_timestamp(self) -> float:
        return min(self.timestamps) if self.timestamps else 0.0

    def add_component(
        self,
        component: List[CorrelationNode],
        new_detections: List[ThreatDetection],
        new_anomalies: List[MLAnomalyScore],
        new_max_seq: int,
    ):
        for node in component:
            self.entity_keys.update(node.entity_keys)
            self.timestamps.append(node.timestamp.timestamp())
        self.detections.extend(new_detections)
        self.anomalies.extend(new_anomalies)
        self.max_sequence = max(self.max_sequence, new_max_seq)


class ThreatCorrelationEngine:
    """Service orchestrating event clustering, incident synthesis, and timeline tracking."""

    def __init__(self, window_seconds: int = MAX_CORRELATION_WINDOW_SECONDS):
        self.window_seconds = window_seconds

    async def correlate(self, db: AsyncSession) -> Dict[str, int]:
        """Executes a correlation sweep over all unassigned detections and eligible ML anomalies."""
        created_count = 0
        updated_count = 0
        correlated_events_count = 0

        # 1. Fetch unassigned detections
        det_query = (
            select(ThreatDetection)
            .options(
                selectinload(ThreatDetection.event),
                selectinload(ThreatDetection.rule),
            )
            .where(ThreatDetection.incident_id.is_(None))
            .order_by(ThreatDetection.detected_at)
        )
        det_res = await db.execute(det_query)
        unassigned_detections = list(det_res.scalars().all())

        # 2. Fetch unassigned eligible ML anomalies (is_anomalous=True OR anomaly_score >= 50.0)
        ml_query = (
            select(MLAnomalyScore)
            .options(selectinload(MLAnomalyScore.event))
            .where(
                and_(
                    MLAnomalyScore.incident_id.is_(None),
                    or_(
                        MLAnomalyScore.is_anomalous.is_(True),
                        MLAnomalyScore.anomaly_score >= 50.0,
                    ),
                )
            )
            .order_by(MLAnomalyScore.created_at)
        )
        ml_res = await db.execute(ml_query)
        unassigned_anomalies = list(ml_res.scalars().all())

        if not unassigned_detections and not unassigned_anomalies:
            logger.debug("No unassigned detections or anomalies found for correlation.")
            return {
                "created_incidents": 0,
                "updated_incidents": 0,
                "correlated_events": 0,
            }

        # 3. Build Correlation Graph
        graph = CorrelationGraph(window_seconds=self.window_seconds)

        for d in unassigned_detections:
            if d.event:
                node = CorrelationNode(
                    node_id=f"det:{d.id}",
                    node_type="DETECTION",
                    record_id=d.id,
                    event_id=d.event_id,
                    timestamp=d.detected_at,
                    record=d,
                    normalized_event=d.event,
                )
                graph.add_node(node)

        for m in unassigned_anomalies:
            if m.event:
                node = CorrelationNode(
                    node_id=f"ml:{m.id}",
                    node_type="ML_ANOMALY",
                    record_id=m.id,
                    event_id=m.event_id,
                    timestamp=m.created_at,
                    record=m,
                    normalized_event=m.event,
                )
                graph.add_node(node)

        # 4. Extract connected components
        components = graph.get_connected_components()
        if not components:
            return {
                "created_incidents": 0,
                "updated_incidents": 0,
                "correlated_events": 0,
            }

        # 5. Fetch existing active incident profiles to allow incremental attachment
        active_profiles = await self._fetch_active_profiles(db)

        # 6. Process each component
        for component in components:
            # Check if this component can attach to an existing active incident
            target_profile = self._find_matching_active_profile(component, active_profiles)

            if target_profile:
                # Update existing incident
                await self._attach_to_existing_incident(
                    db=db,
                    profile=target_profile,
                    component=component,
                )
                updated_count += 1
            else:
                # Create a new incident and record its active profile
                new_profile = await self._create_new_incident(
                    db=db,
                    component=component,
                )
                active_profiles.append(new_profile)
                created_count += 1

            correlated_events_count += len(component)

        await db.commit()

        logger.info(
            f"Correlation sweep complete: {created_count} created, "
            f"{updated_count} updated, {correlated_events_count} events clustered."
        )
        return {
            "created_incidents": created_count,
            "updated_incidents": updated_count,
            "correlated_events": correlated_events_count,
        }

    async def _fetch_active_profiles(self, db: AsyncSession) -> List[ActiveIncidentProfile]:
        """Fetches active incidents along with their detections, anomalies, and timeline events."""
        query = (
            select(Incident)
            .options(
                selectinload(Incident.detections).selectinload(ThreatDetection.event),
                selectinload(Incident.detections).selectinload(ThreatDetection.rule),
                selectinload(Incident.anomaly_scores).selectinload(MLAnomalyScore.event),
                selectinload(Incident.timeline_events).selectinload(IncidentTimelineEvent.event),
            )
            .where(Incident.status.in_(ACTIVE_INCIDENT_STATUSES))
            .order_by(Incident.updated_at.desc())
        )
        res = await db.execute(query)
        incidents = list(res.scalars().all())

        profiles: List[ActiveIncidentProfile] = []
        for inc in incidents:
            inc_keys: Set[Tuple[str, str]] = set()
            inc_timestamps: List[float] = []

            for d in inc.detections:
                if d.event:
                    inc_keys.update(CorrelationNode._extract_entity_keys(d.event))
                    inc_timestamps.append(d.detected_at.timestamp())

            for a in inc.anomaly_scores:
                if a.event:
                    inc_keys.update(CorrelationNode._extract_entity_keys(a.event))
                    inc_timestamps.append(a.created_at.timestamp())

            for t in inc.timeline_events:
                if t.event:
                    inc_keys.update(CorrelationNode._extract_entity_keys(t.event))
                    inc_timestamps.append(t.event.event_timestamp.timestamp())

            max_seq = max([t.sequence_order for t in inc.timeline_events], default=-1)
            profiles.append(
                ActiveIncidentProfile(
                    incident=inc,
                    entity_keys=inc_keys,
                    timestamps=inc_timestamps,
                    detections=list(inc.detections),
                    anomalies=list(inc.anomaly_scores),
                    max_sequence=max_seq,
                )
            )

        return profiles

    def _find_matching_active_profile(
        self,
        component: List[CorrelationNode],
        active_profiles: List[ActiveIncidentProfile],
    ) -> Optional[ActiveIncidentProfile]:
        """Finds an existing active incident profile that shares entities and temporal proximity with component."""
        component_keys: Set[Tuple[str, str]] = set()
        component_timestamps: List[float] = []

        for node in component:
            component_keys.update(node.entity_keys)
            component_timestamps.append(node.timestamp.timestamp())

        if not component_keys or not component_timestamps:
            return None

        earliest_comp_ts = min(component_timestamps)
        latest_comp_ts = max(component_timestamps)

        for profile in active_profiles:
            if not profile.entity_keys or not profile.timestamps:
                continue

            # Check entity overlap
            if not component_keys.intersection(profile.entity_keys):
                continue

            # Check temporal window: component overlaps within window_seconds of incident
            inc_latest = profile.latest_timestamp
            inc_earliest = profile.earliest_timestamp

            # Connected if component earliest is within window of incident latest (or vice versa)
            temporal_overlap = (
                abs(earliest_comp_ts - inc_latest) <= self.window_seconds
                or abs(latest_comp_ts - inc_earliest) <= self.window_seconds
                or (earliest_comp_ts >= inc_earliest and latest_comp_ts <= inc_latest)
            )

            if temporal_overlap:
                return profile

        return None

    async def _generate_incident_number(self, db: AsyncSession) -> str:
        """Generates a sequential, collision-free incident number e.g. INC-2026-0001."""
        year = datetime.now(timezone.utc).year
        count_query = select(func.count(Incident.id))
        res = await db.execute(count_query)
        total = res.scalar() or 0
        candidate = f"INC-{year}-{total + 1:04d}"

        # Ensure uniqueness
        existing = await db.execute(
            select(Incident.id).where(Incident.incident_number == candidate)
        )
        if existing.scalars().first() is not None:
            # Fallback with short unique hex to guarantee no collision
            candidate = f"INC-{year}-{total + 1:04d}-{uuid.uuid4().hex[:4].upper()}"

        return candidate

    def _synthesize_title(
        self,
        component: List[CorrelationNode],
        tactics: List[str],
        primary_actor: Optional[str] = None,
        target_resource: Optional[str] = None,
    ) -> str:
        """Creates a deterministic, informative incident title based on available context."""
        actor_clean = (primary_actor or "").strip() or "Unknown Entity"
        if len(actor_clean) > 40:
            actor_clean = actor_clean[:37] + "..."

        if tactics:
            tactics_str = " & ".join(sorted(tactics)[:2])
            if target_resource and target_resource != "Cloud Resource":
                res_clean = target_resource.split("/")[-1]
                return f"{tactics_str} targeting {res_clean} via {actor_clean}"
            return f"{tactics_str} detected on {actor_clean}"

        # If only detections without explicit tactics
        rule_titles = [
            n.record.rule.title
            for n in component
            if n.node_type == "DETECTION" and getattr(n.record, "rule", None)
        ]
        if rule_titles:
            return f"{rule_titles[0]} involving {actor_clean}"

        # Anomaly only
        return f"Behavioral Anomaly Cluster detected on {actor_clean}"

    async def _create_new_incident(
        self,
        db: AsyncSession,
        component: List[CorrelationNode],
    ) -> ActiveIncidentProfile:
        """Synthesizes a new Incident from a connected component of nodes."""
        incident_number = await self._generate_incident_number(db)
        now = datetime.now(timezone.utc)

        # Separate detections and anomalies
        detections: List[ThreatDetection] = [
            n.record for n in component if n.node_type == "DETECTION"
        ]
        anomalies: List[MLAnomalyScore] = [
            n.record for n in component if n.node_type == "ML_ANOMALY"
        ]

        # Extract tactics and techniques
        tactics_set: Set[str] = set()
        techniques_set: Set[str] = set()

        for d in detections:
            rule = getattr(d, "rule", None)
            if rule:
                if rule.mitre_tactic:
                    tactics_set.add(rule.mitre_tactic.strip())
                if rule.mitre_technique_id:
                    techniques_set.add(rule.mitre_technique_id.strip())

        tactics_list = sorted(list(tactics_set))
        techniques_list = sorted(list(techniques_set))

        # Extract primary actor and target resource
        primary_actor = None
        target_resource = None

        for n in component:
            ev = n.normalized_event
            if ev:
                if not primary_actor:
                    raw_actor = ev.principal_name or ev.principal_id or ev.caller_ip
                    if raw_actor and str(raw_actor).strip():
                        primary_actor = str(raw_actor).strip()
                if not target_resource:
                    raw_res = ev.target_resource_id or ev.target_resource_name
                    if raw_res and str(raw_res).strip():
                        target_resource = str(raw_res).strip()


        # Calculate Risk Score and Severity via Phase 4.1 Scoring Engine
        scoring_breakdown = risk_scoring_engine.evaluate_incident_context(
            detections=detections,
            anomaly_scores=anomalies,
            target_resource=target_resource,
            principal_id=primary_actor,
            tactics=tactics_list,
        )

        title = self._synthesize_title(
            component=component,
            tactics=tactics_list,
            primary_actor=primary_actor,
            target_resource=target_resource,
        )

        incident = Incident(
            id=uuid.uuid4(),
            incident_number=incident_number,
            title=title,
            status="NEW",
            severity=scoring_breakdown.severity,
            risk_score=float(scoring_breakdown.final_score),
            mitre_tactics=tactics_list,
            mitre_techniques=techniques_list,
            created_at=now,
            updated_at=now,
        )
        db.add(incident)
        await db.flush()

        # Link detections and anomalies to the incident
        for d in detections:
            d.incident_id = incident.id
        for a in anomalies:
            a.incident_id = incident.id

        await db.flush()

        # Build chronological timeline
        timeline_count = await self._build_timeline_events(
            db=db,
            incident_id=incident.id,
            component=component,
            start_sequence=0,
        )

        logger.info(
            f"Created Incident {incident.incident_number}: title='{incident.title}', "
            f"severity={incident.severity}, risk_score={incident.risk_score}"
        )

        # Build profile for active tracking
        comp_keys: Set[Tuple[str, str]] = set()
        comp_timestamps: List[float] = []
        for n in component:
            comp_keys.update(n.entity_keys)
            comp_timestamps.append(n.timestamp.timestamp())

        return ActiveIncidentProfile(
            incident=incident,
            entity_keys=comp_keys,
            timestamps=comp_timestamps,
            detections=detections,
            anomalies=anomalies,
            max_sequence=timeline_count - 1,
        )

    async def _attach_to_existing_incident(
        self,
        db: AsyncSession,
        profile: ActiveIncidentProfile,
        component: List[CorrelationNode],
    ):
        """Attaches new component events to an existing active incident and recalculates state."""
        incident = profile.incident
        now = datetime.now(timezone.utc)

        new_detections: List[ThreatDetection] = [
            n.record for n in component if n.node_type == "DETECTION"
        ]
        new_anomalies: List[MLAnomalyScore] = [
            n.record for n in component if n.node_type == "ML_ANOMALY"
        ]

        # Link to incident in database
        for d in new_detections:
            d.incident_id = incident.id
        for a in new_anomalies:
            a.incident_id = incident.id

        await db.flush()

        # Update MITRE tactics and techniques (union)
        tactics_set = set(incident.mitre_tactics or [])
        techniques_set = set(incident.mitre_techniques or [])

        for d in new_detections:
            rule = getattr(d, "rule", None)
            if rule:
                if rule.mitre_tactic:
                    tactics_set.add(rule.mitre_tactic.strip())
                if rule.mitre_technique_id:
                    techniques_set.add(rule.mitre_technique_id.strip())

        incident.mitre_tactics = sorted(list(tactics_set))
        incident.mitre_techniques = sorted(list(techniques_set))

        # Recalculate Risk Score and Severity with combined constituent events
        all_detections = profile.detections + new_detections
        all_anomalies = profile.anomalies + new_anomalies

        # Primary actor / resource
        target_resource = None
        primary_actor = None
        for d in all_detections:
            if d.event:
                if not target_resource:
                    raw_res = d.event.target_resource_id or d.event.target_resource_name
                    if raw_res and str(raw_res).strip():
                        target_resource = str(raw_res).strip()

                if not primary_actor:
                    raw_actor = d.event.principal_name or d.event.principal_id
                    if raw_actor and str(raw_actor).strip():
                        primary_actor = str(raw_actor).strip()

        scoring_breakdown = risk_scoring_engine.evaluate_incident_context(
            detections=all_detections,
            anomaly_scores=all_anomalies,
            target_resource=target_resource,
            principal_id=primary_actor,
            tactics=incident.mitre_tactics,
        )

        incident.risk_score = float(scoring_breakdown.final_score)
        incident.severity = scoring_breakdown.severity
        incident.updated_at = now

        # Append to timeline
        timeline_count = await self._build_timeline_events(
            db=db,
            incident_id=incident.id,
            component=component,
            start_sequence=profile.max_sequence + 1,
        )

        # Update in-memory profile
        profile.add_component(
            component=component,
            new_detections=new_detections,
            new_anomalies=new_anomalies,
            new_max_seq=profile.max_sequence + timeline_count,
        )

        logger.info(
            f"Updated Incident {incident.incident_number}: "
            f"new risk_score={incident.risk_score}, severity={incident.severity}"
        )

    async def _build_timeline_events(
        self,
        db: AsyncSession,
        incident_id: uuid.UUID,
        component: List[CorrelationNode],
        start_sequence: int = 0,
    ) -> int:
        """Creates chronological timeline events for constituent events in component. Returns number of events created."""
        # Deduplicate normalized events
        unique_events: Dict[uuid.UUID, Tuple[NormalizedEvent, List[CorrelationNode]]] = {}
        for node in component:
            if node.event_id not in unique_events:
                unique_events[node.event_id] = (node.normalized_event, [])
            unique_events[node.event_id][1].append(node)

        # Sort distinct events chronologically
        sorted_events = sorted(
            unique_events.values(),
            key=lambda item: item[0].event_timestamp if item[0] else datetime.min,
        )

        now = datetime.now(timezone.utc)
        seq = start_sequence
        created_count = 0

        for norm_ev, nodes in sorted_events:
            if not norm_ev:
                continue

            # Build informative correlation reason
            actor = (norm_ev.principal_name or norm_ev.principal_id or "").strip() or "Unknown Actor"
            ip = (norm_ev.caller_ip or "").strip() or "Unknown IP"
            res = (norm_ev.target_resource_name or norm_ev.target_resource_id or "").strip() or "Cloud Resource"

            reasons: List[str] = []
            for n in nodes:
                if n.node_type == "DETECTION":
                    det = n.record
                    rule_code = getattr(det.rule, "rule_id", "RULE") if getattr(det, "rule", None) else "RULE"
                    tactic = getattr(det.rule, "mitre_tactic", "Detection") if getattr(det, "rule", None) else "Alert"
                    reasons.append(f"Detection Alert: {rule_code} ({tactic}) | Actor: {actor} | IP: {ip} | Target: {res}")
                elif n.node_type == "ML_ANOMALY":
                    anomaly = n.record
                    score = getattr(anomaly, "anomaly_score", 0.0)
                    reasons.append(f"UEBA Anomaly: Score {score:.1f} | Actor: {actor} | IP: {ip}")

            combined_reason = " ; ".join(reasons) if reasons else f"Security Event: {norm_ev.event_name} on {actor}"
            if len(combined_reason) > 255:
                combined_reason = combined_reason[:252] + "..."

            # Avoid duplicate timeline entry for same event_id in this incident
            timeline_event = IncidentTimelineEvent(
                id=uuid.uuid4(),
                incident_id=incident_id,
                event_id=norm_ev.id,
                correlation_reason=combined_reason,
                sequence_order=seq,
                created_at=now,
            )
            db.add(timeline_event)
            seq += 1
            created_count += 1

        await db.flush()
        return created_count


# Global singleton engine instance
correlation_engine = ThreatCorrelationEngine()
