"""Unit & integration tests for the Threat Correlation & Incident Engine (Milestone 4.2).

Validates:
1. Events within 60 minutes correlate.
2. Events beyond 60 minutes do not correlate.
3. Connected components produce one incident.
4. Multiple unrelated components produce separate incidents.
5. Detection + ML anomaly correlate.
6. Risk score uses Phase 4.1 engine.
7. MITRE tactics/techniques aggregate correctly.
8. Timeline ordering is correct.
9. Correlation is idempotent.
10. Late event attaches to active incident.
11. Resolved incident does not absorb new events.
12. Null/empty correlation keys do not create false edges.
"""

import uuid
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models.logs import NormalizedEvent
from app.domain.models.rules import DetectionRule
from app.domain.models.detections import ThreatDetection
from app.domain.models.ml import MLAnomalyScore
from app.domain.models.incidents import Incident, IncidentTimelineEvent
from app.correlation.engine import ThreatCorrelationEngine
from app.scoring.engine import risk_scoring_engine


def make_test_event(
    principal_name="compromised.user@corp.local",
    principal_id=None,
    caller_ip=None,
    target_resource_name=None,
    target_resource_id=None,
    event_category="Identity",
    event_name="UserLoginFailed",
    offset_minutes=0,
    base_time=None,
):

    base = base_time or datetime.now(timezone.utc)
    ts = base + timedelta(minutes=offset_minutes)
    return NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=ts,
        event_category=event_category,
        event_name=event_name,
        principal_id=principal_id,
        principal_name=principal_name,
        caller_ip=caller_ip,
        target_resource_id=target_resource_id,
        target_resource_name=target_resource_name,
        action_status="Failure",
        security_context={},
    )


def make_test_rule(
    rule_id="TEST-RULE-0010",
    title="Brute Force Attempt",
    severity="HIGH",
    mitre_tactic="Initial Access",
    mitre_technique_id="T1110.001",
    filter_event_name=None,
):
    event_match = filter_event_name or f"Event-{rule_id}"
    return DetectionRule(
        id=uuid.uuid4(),
        rule_id=rule_id,
        title=title,
        severity=severity,
        mitre_tactic=mitre_tactic,
        mitre_technique_id=mitre_technique_id,
        description="Test detection rule",
        rule_logic={"type": "stateless_pattern", "filter": {"event_name": event_match}},
        is_active=True,
    )


@pytest.mark.asyncio
async def test_temporal_window_correlation_within_60_minutes(db_session: AsyncSession):
    """Test 1: Events sharing identity within 60 minutes correlate into a single incident."""
    engine = ThreatCorrelationEngine(window_seconds=3600)
    base_time = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)

    rule1 = make_test_rule("R-WIN-1", "Credential Guessing", "MEDIUM", "Initial Access", "T1110.001")
    rule2 = make_test_rule("R-WIN-2", "Privilege Escalation", "HIGH", "Privilege Escalation", "T1484.002")
    db_session.add_all([rule1, rule2])
    await db_session.flush()

    ev1 = make_test_event(principal_name="window.user@corp.local", caller_ip="198.51.10.1", offset_minutes=0, base_time=base_time)
    ev2 = make_test_event(principal_name="window.user@corp.local", caller_ip="198.51.10.1", offset_minutes=35, base_time=base_time)  # 35 min apart <= 60 min
    db_session.add_all([ev1, ev2])
    await db_session.flush()

    det1 = ThreatDetection(
        id=uuid.uuid4(),
        rule_id=rule1.id,
        event_id=ev1.id,
        severity="MEDIUM",
        alert_summary="Alert 1",
        detected_at=ev1.event_timestamp,
    )
    det2 = ThreatDetection(
        id=uuid.uuid4(),
        rule_id=rule2.id,
        event_id=ev2.id,
        severity="HIGH",
        alert_summary="Alert 2",
        detected_at=ev2.event_timestamp,
    )
    db_session.add_all([det1, det2])
    await db_session.commit()

    res = await engine.correlate(db_session)
    assert res["created_incidents"] == 1
    assert res["correlated_events"] == 2

    # Verify incident
    inc_res = await db_session.execute(
        select(Incident)
        .options(selectinload(Incident.detections), selectinload(Incident.timeline_events))
        .where(Incident.id == det1.incident_id)
    )
    inc = inc_res.scalars().first()
    assert inc is not None
    assert det2.incident_id == inc.id
    assert len(inc.detections) == 2
    assert len(inc.timeline_events) == 2


@pytest.mark.asyncio
async def test_temporal_window_isolation_exceeding_60_minutes(db_session: AsyncSession):
    """Test 2: Events sharing identity but separated by > 60 minutes form separate incidents."""
    engine = ThreatCorrelationEngine(window_seconds=3600)
    base_time = datetime(2026, 9, 30, 8, 0, 0, tzinfo=timezone.utc)

    rule = make_test_rule("R-ISO-1", "Isolated Alert", "MEDIUM", "Initial Access", "T1110.001")
    db_session.add(rule)
    await db_session.flush()

    ev1 = make_test_event(principal_name="iso.user@corp.local", caller_ip="198.51.10.2", offset_minutes=0, base_time=base_time)
    ev2 = make_test_event(principal_name="iso.user@corp.local", caller_ip="198.51.10.2", offset_minutes=90, base_time=base_time)  # 90 min apart > 60 min
    db_session.add_all([ev1, ev2])
    await db_session.flush()

    det1 = ThreatDetection(
        id=uuid.uuid4(),
        rule_id=rule.id,
        event_id=ev1.id,
        severity="MEDIUM",
        alert_summary="Early Alert",
        detected_at=ev1.event_timestamp,
    )
    det2 = ThreatDetection(
        id=uuid.uuid4(),
        rule_id=rule.id,
        event_id=ev2.id,
        severity="MEDIUM",
        alert_summary="Late Alert",
        detected_at=ev2.event_timestamp,
    )
    db_session.add_all([det1, det2])
    await db_session.commit()

    res = await engine.correlate(db_session)
    assert res["created_incidents"] == 2
    assert det1.incident_id != det2.incident_id


@pytest.mark.asyncio
async def test_connected_component_clustering_single_incident(db_session: AsyncSession):
    """Test 3: Chain A -> B (via IP & shared resource) and B -> C (via User) merges into 1 connected component."""
    engine = ThreatCorrelationEngine(window_seconds=3600)
    base_time = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)

    rule = make_test_rule("R-CHAIN-1", "Chain Alert", "HIGH", "Credential Access", "T1555.006")
    db_session.add(rule)
    await db_session.flush()

    # ev1 has IP 198.51.100.99 and User Alpha targeting vault-cluster
    ev1 = make_test_event(
        principal_name="alpha@corp.local",
        caller_ip="198.51.100.99",
        target_resource_name="vault-cluster",
        target_resource_id="Microsoft.KeyVault/vaults/vault-cluster",
        offset_minutes=0,
        base_time=base_time,
    )
    # ev2 shares IP 198.51.100.99 and target vault-cluster with ev1, but has User Beta
    ev2 = make_test_event(
        principal_name="beta@corp.local",
        caller_ip="198.51.100.99",
        target_resource_name="vault-cluster",
        target_resource_id="Microsoft.KeyVault/vaults/vault-cluster",
        offset_minutes=15,
        base_time=base_time,
    )
    # ev3 shares User Beta with ev2, but has different IP 203.0.113.1
    ev3 = make_test_event(
        principal_name="beta@corp.local",
        caller_ip="203.0.113.1",
        target_resource_name="vault-cluster",
        target_resource_id="Microsoft.KeyVault/vaults/vault-cluster",
        offset_minutes=25,
        base_time=base_time,
    )
    db_session.add_all([ev1, ev2, ev3])
    await db_session.flush()

    det1 = ThreatDetection(id=uuid.uuid4(), rule_id=rule.id, event_id=ev1.id, severity="HIGH", alert_summary="A", detected_at=ev1.event_timestamp)
    det2 = ThreatDetection(id=uuid.uuid4(), rule_id=rule.id, event_id=ev2.id, severity="HIGH", alert_summary="B", detected_at=ev2.event_timestamp)
    det3 = ThreatDetection(id=uuid.uuid4(), rule_id=rule.id, event_id=ev3.id, severity="HIGH", alert_summary="C", detected_at=ev3.event_timestamp)
    db_session.add_all([det1, det2, det3])
    await db_session.commit()

    res = await engine.correlate(db_session)
    assert res["created_incidents"] == 1
    assert det1.incident_id == det2.incident_id == det3.incident_id


@pytest.mark.asyncio
async def test_multiple_unrelated_components_produce_separate_incidents(db_session: AsyncSession):
    """Test 4: Unrelated actors with distinct IPs and resources form separate incidents."""
    engine = ThreatCorrelationEngine(window_seconds=3600)
    base_time = datetime(2026, 9, 30, 14, 0, 0, tzinfo=timezone.utc)

    rule = make_test_rule("R-SEP-1", "Separate Rule", "HIGH")
    db_session.add(rule)
    await db_session.flush()

    ev_x = make_test_event(
        principal_name="user.x@org.local",
        caller_ip="100.64.0.1",
        target_resource_name="resource-x",
        target_resource_id="res-x-id",
        offset_minutes=5,
        base_time=base_time,
    )
    ev_y = make_test_event(
        principal_name="user.y@org.local",
        caller_ip="100.64.0.2",
        target_resource_name="resource-y",
        target_resource_id="res-y-id",
        offset_minutes=10,
        base_time=base_time,
    )
    db_session.add_all([ev_x, ev_y])
    await db_session.flush()

    det_x = ThreatDetection(id=uuid.uuid4(), rule_id=rule.id, event_id=ev_x.id, severity="HIGH", alert_summary="X", detected_at=ev_x.event_timestamp)
    det_y = ThreatDetection(id=uuid.uuid4(), rule_id=rule.id, event_id=ev_y.id, severity="HIGH", alert_summary="Y", detected_at=ev_y.event_timestamp)
    db_session.add_all([det_x, det_y])
    await db_session.commit()

    res = await engine.correlate(db_session)
    assert res["created_incidents"] == 2
    assert det_x.incident_id != det_y.incident_id


@pytest.mark.asyncio
async def test_hybrid_detection_and_ml_anomaly_correlation(db_session: AsyncSession):
    """Test 5: ThreatDetection and MLAnomalyScore sharing context correlate into one incident."""
    engine = ThreatCorrelationEngine(window_seconds=3600)
    base_time = datetime(2026, 9, 30, 15, 0, 0, tzinfo=timezone.utc)

    rule = make_test_rule("R-HYB-1", "MFA Push Bombing", "HIGH", "Credential Access", "T1621")
    db_session.add(rule)
    await db_session.flush()

    ev1 = make_test_event(principal_name="hybrid.user@corp.local", caller_ip="198.51.20.1", offset_minutes=0, base_time=base_time)
    ev2 = make_test_event(principal_name="hybrid.user@corp.local", caller_ip="198.51.20.1", offset_minutes=10, base_time=base_time)
    db_session.add_all([ev1, ev2])
    await db_session.flush()

    det = ThreatDetection(
        id=uuid.uuid4(),
        rule_id=rule.id,
        event_id=ev1.id,
        severity="HIGH",
        alert_summary="MFA Anomaly",
        detected_at=ev1.event_timestamp,
    )
    anomaly = MLAnomalyScore(
        id=uuid.uuid4(),
        event_id=ev2.id,
        model_version="ueba-v1.0.0",
        anomaly_score=80.0,
        confidence=0.88,
        is_anomalous=True,
        feature_contributions={"reasons": ["Unusual off-hours login"]},
        created_at=ev2.event_timestamp,
    )
    db_session.add_all([det, anomaly])
    await db_session.commit()

    res = await engine.correlate(db_session)
    assert res["created_incidents"] == 1
    assert det.incident_id == anomaly.incident_id

    # Verify incident contains both and risk score is computed
    inc = await db_session.get(Incident, det.incident_id)
    assert inc is not None
    assert inc.risk_score >= 68.0


@pytest.mark.asyncio
async def test_risk_score_uses_phase_4_1_engine(db_session: AsyncSession):
    """Test 6: Incident risk score matches Phase 4.1 risk scoring engine output."""
    engine = ThreatCorrelationEngine(window_seconds=3600)
    base_time = datetime(2026, 9, 30, 16, 0, 0, tzinfo=timezone.utc)

    rule = make_test_rule(
        "R-CRIT-1", "Storage Deletion", "CRITICAL", "Impact", "T1485"
    )
    db_session.add(rule)
    await db_session.flush()

    ev = make_test_event(
        principal_name="admin@corp.local",
        principal_id="spn-admin",
        target_resource_id="Microsoft.KeyVault/vaults/top-secret",
        target_resource_name="top-secret",
        offset_minutes=0,
        base_time=base_time,
    )
    db_session.add(ev)
    await db_session.flush()

    det = ThreatDetection(
        id=uuid.uuid4(),
        rule_id=rule.id,
        event_id=ev.id,
        severity="CRITICAL",
        alert_summary="Critical storage deletion",
        detected_at=ev.event_timestamp,
    )
    db_session.add(det)
    await db_session.commit()

    await engine.correlate(db_session)

    inc = await db_session.get(Incident, det.incident_id)
    assert inc is not None

    # Compare with standalone evaluation
    expected_breakdown = risk_scoring_engine.evaluate_incident_context(
        detections=[det],
        target_resource=ev.target_resource_id,
        principal_id="admin@corp.local",
        tactics=["Impact"],
    )
    assert inc.risk_score == float(expected_breakdown.final_score)
    assert inc.severity == expected_breakdown.severity


@pytest.mark.asyncio
async def test_mitre_tactics_and_techniques_aggregation(db_session: AsyncSession):
    """Test 7: MITRE tactics and techniques are aggregated and deduplicated."""
    engine = ThreatCorrelationEngine(window_seconds=3600)
    base_time = datetime(2026, 9, 30, 17, 0, 0, tzinfo=timezone.utc)

    r1 = make_test_rule("R-MITRE-1", "Brute Force", "MEDIUM", "Initial Access", "T1110.001")
    r2 = make_test_rule("R-MITRE-2", "Secret Extraction", "HIGH", "Credential Access", "T1555.006")
    db_session.add_all([r1, r2])
    await db_session.flush()

    ev1 = make_test_event(principal_name="target.user@corp.local", caller_ip="198.51.30.1", offset_minutes=0, base_time=base_time)
    ev2 = make_test_event(principal_name="target.user@corp.local", caller_ip="198.51.30.1", offset_minutes=15, base_time=base_time)
    db_session.add_all([ev1, ev2])
    await db_session.flush()

    d1 = ThreatDetection(id=uuid.uuid4(), rule_id=r1.id, event_id=ev1.id, severity="MEDIUM", alert_summary="BF", detected_at=ev1.event_timestamp)
    d2 = ThreatDetection(id=uuid.uuid4(), rule_id=r2.id, event_id=ev2.id, severity="HIGH", alert_summary="SE", detected_at=ev2.event_timestamp)
    db_session.add_all([d1, d2])
    await db_session.commit()

    await engine.correlate(db_session)

    inc = await db_session.get(Incident, d1.incident_id)
    assert inc is not None
    assert set(inc.mitre_tactics) == {"Initial Access", "Credential Access"}
    assert set(inc.mitre_techniques) == {"T1110.001", "T1555.006"}


@pytest.mark.asyncio
async def test_timeline_generation_and_ordering(db_session: AsyncSession):
    """Test 8: Timeline events are chronologically ordered (sequence 0, 1, 2...)."""
    engine = ThreatCorrelationEngine(window_seconds=3600)
    base_time = datetime(2026, 9, 30, 18, 0, 0, tzinfo=timezone.utc)

    rule = make_test_rule("R-TIME-1", "Timeline Rule", "MEDIUM")
    db_session.add(rule)
    await db_session.flush()

    # Create 3 events out of insertion order
    ev_late = make_test_event(principal_name="time.user@corp.local", caller_ip="198.51.40.1", offset_minutes=40, base_time=base_time)
    ev_early = make_test_event(principal_name="time.user@corp.local", caller_ip="198.51.40.1", offset_minutes=0, base_time=base_time)
    ev_mid = make_test_event(principal_name="time.user@corp.local", caller_ip="198.51.40.1", offset_minutes=20, base_time=base_time)
    db_session.add_all([ev_late, ev_early, ev_mid])
    await db_session.flush()

    d1 = ThreatDetection(id=uuid.uuid4(), rule_id=rule.id, event_id=ev_late.id, severity="MEDIUM", alert_summary="Late", detected_at=ev_late.event_timestamp)
    d2 = ThreatDetection(id=uuid.uuid4(), rule_id=rule.id, event_id=ev_early.id, severity="MEDIUM", alert_summary="Early", detected_at=ev_early.event_timestamp)
    d3 = ThreatDetection(id=uuid.uuid4(), rule_id=rule.id, event_id=ev_mid.id, severity="MEDIUM", alert_summary="Mid", detected_at=ev_mid.event_timestamp)
    db_session.add_all([d1, d2, d3])
    await db_session.commit()

    await engine.correlate(db_session)

    timeline_res = await db_session.execute(
        select(IncidentTimelineEvent)
        .where(IncidentTimelineEvent.incident_id == d1.incident_id)
        .order_by(IncidentTimelineEvent.sequence_order)
    )
    timeline = list(timeline_res.scalars().all())
    assert len(timeline) == 3

    assert timeline[0].sequence_order == 0
    assert timeline[0].event_id == ev_early.id

    assert timeline[1].sequence_order == 1
    assert timeline[1].event_id == ev_mid.id

    assert timeline[2].sequence_order == 2
    assert timeline[2].event_id == ev_late.id


@pytest.mark.asyncio
async def test_correlation_idempotency(db_session: AsyncSession):
    """Test 9: Re-running correlation produces 0 duplicate incidents or timeline events."""
    engine = ThreatCorrelationEngine(window_seconds=3600)
    rule = make_test_rule("R-IDEM-1", "Idempotency Rule", "HIGH")
    db_session.add(rule)
    await db_session.flush()

    ev = make_test_event(
        principal_name="idempotent.user@corp.local",
        caller_ip="198.51.50.1",
        target_resource_name="res-idem-vault",
        target_resource_id="res-idem-id",
    )
    db_session.add(ev)
    await db_session.flush()

    det = ThreatDetection(id=uuid.uuid4(), rule_id=rule.id, event_id=ev.id, severity="HIGH", alert_summary="Idem", detected_at=ev.event_timestamp)
    db_session.add(det)
    await db_session.commit()

    # First run
    res1 = await engine.correlate(db_session)
    assert res1["created_incidents"] == 1
    incident_id = det.incident_id

    # Second run immediately
    res2 = await engine.correlate(db_session)
    assert res2["created_incidents"] == 0
    assert res2["updated_incidents"] == 0
    assert res2["correlated_events"] == 0

    # Ensure still exactly 1 incident and 1 timeline entry
    all_incs = await db_session.execute(select(Incident).where(Incident.id == incident_id))
    assert len(list(all_incs.scalars().all())) == 1


@pytest.mark.asyncio
async def test_late_event_attaches_to_active_incident(db_session: AsyncSession):
    """Test 10: Late-arriving event merges into active incident and recalculates risk/severity."""
    engine = ThreatCorrelationEngine(window_seconds=3600)
    base_time = datetime(2026, 9, 30, 20, 0, 0, tzinfo=timezone.utc)

    rule1 = make_test_rule("R-LATE-1", "Initial Step", "LOW", "Initial Access", "T1110.001")
    rule2 = make_test_rule("R-LATE-2", "Critical Step", "CRITICAL", "Impact", "T1485")
    db_session.add_all([rule1, rule2])
    await db_session.flush()

    # Initial event
    ev1 = make_test_event(principal_name="late.actor@corp.local", caller_ip="198.51.60.1", offset_minutes=0, base_time=base_time)
    db_session.add(ev1)
    await db_session.flush()

    det1 = ThreatDetection(id=uuid.uuid4(), rule_id=rule1.id, event_id=ev1.id, severity="LOW", alert_summary="Step 1", detected_at=ev1.event_timestamp)
    db_session.add(det1)
    await db_session.commit()

    # First correlation
    res1 = await engine.correlate(db_session)
    assert res1["created_incidents"] == 1
    initial_incident_id = det1.incident_id

    inc = await db_session.get(Incident, initial_incident_id)
    initial_risk = inc.risk_score

    # Late event 25 minutes later
    ev2 = make_test_event(principal_name="late.actor@corp.local", caller_ip="198.51.60.1", offset_minutes=25, base_time=base_time)
    db_session.add(ev2)
    await db_session.flush()

    det2 = ThreatDetection(id=uuid.uuid4(), rule_id=rule2.id, event_id=ev2.id, severity="CRITICAL", alert_summary="Step 2", detected_at=ev2.event_timestamp)
    db_session.add(det2)
    await db_session.commit()

    # Second correlation
    res2 = await engine.correlate(db_session)
    assert res2["updated_incidents"] == 1
    assert det2.incident_id == initial_incident_id

    # Refresh incident
    await db_session.refresh(inc)
    assert inc.risk_score > initial_risk
    assert "Impact" in inc.mitre_tactics


@pytest.mark.asyncio
async def test_resolved_incident_does_not_absorb_new_events(db_session: AsyncSession):
    """Test 11: A resolved incident remains closed; subsequent activity creates a new incident."""
    engine = ThreatCorrelationEngine(window_seconds=3600)
    base_time = datetime(2026, 9, 30, 22, 0, 0, tzinfo=timezone.utc)

    rule = make_test_rule("R-RESOLVED-1", "Test Rule", "HIGH")
    db_session.add(rule)
    await db_session.flush()

    ev1 = make_test_event(principal_name="reopen.test@corp.local", caller_ip="198.51.70.1", offset_minutes=0, base_time=base_time)
    db_session.add(ev1)
    await db_session.flush()

    det1 = ThreatDetection(id=uuid.uuid4(), rule_id=rule.id, event_id=ev1.id, severity="HIGH", alert_summary="A1", detected_at=ev1.event_timestamp)
    db_session.add(det1)
    await db_session.commit()

    await engine.correlate(db_session)
    inc1 = await db_session.get(Incident, det1.incident_id)
    assert inc1 is not None

    # Close incident as RESOLVED
    inc1.status = "RESOLVED"
    inc1.resolved_at = datetime.now(timezone.utc)
    await db_session.commit()

    # New activity 20 minutes later for same user
    ev2 = make_test_event(principal_name="reopen.test@corp.local", caller_ip="198.51.70.1", offset_minutes=20, base_time=base_time)
    db_session.add(ev2)
    await db_session.flush()

    det2 = ThreatDetection(id=uuid.uuid4(), rule_id=rule.id, event_id=ev2.id, severity="HIGH", alert_summary="A2", detected_at=ev2.event_timestamp)
    db_session.add(det2)
    await db_session.commit()

    res = await engine.correlate(db_session)
    assert res["created_incidents"] == 1
    assert det2.incident_id != inc1.id

    # Verify original incident remained RESOLVED
    await db_session.refresh(inc1)
    assert inc1.status == "RESOLVED"


@pytest.mark.asyncio
async def test_null_or_empty_correlation_keys_do_not_create_false_edges(db_session: AsyncSession):
    """Test 12: Events missing principal, IP, and resource keys do not connect to each other."""
    engine = ThreatCorrelationEngine(window_seconds=3600)
    base_time = datetime(2026, 9, 30, 23, 0, 0, tzinfo=timezone.utc)

    rule = make_test_rule("R-NULL-1", "Null Entity Rule", "MEDIUM")
    db_session.add(rule)
    await db_session.flush()

    # Two events with no principal, no caller IP, no resource
    ev1 = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=base_time,
        event_category="System",
        event_name="GenericLog",
        principal_id=None,
        principal_name=None,
        caller_ip=None,
        target_resource_id=None,
        target_resource_name=None,
        action_status="Success",
        security_context={},
    )
    ev2 = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=base_time + timedelta(minutes=5),
        event_category="System",
        event_name="GenericLog",
        principal_id="",
        principal_name="   ",
        caller_ip="127.0.0.1",  # Ignored generic loopback IP
        target_resource_id="",
        target_resource_name=None,
        action_status="Success",
        security_context={},
    )
    db_session.add_all([ev1, ev2])
    await db_session.flush()

    det1 = ThreatDetection(id=uuid.uuid4(), rule_id=rule.id, event_id=ev1.id, severity="MEDIUM", alert_summary="N1", detected_at=ev1.event_timestamp)
    det2 = ThreatDetection(id=uuid.uuid4(), rule_id=rule.id, event_id=ev2.id, severity="MEDIUM", alert_summary="N2", detected_at=ev2.event_timestamp)
    db_session.add_all([det1, det2])
    await db_session.commit()

    res = await engine.correlate(db_session)
    # Because there are no valid entity keys to connect them, they form 2 separate components
    assert res["created_incidents"] == 2
    assert det1.incident_id != det2.incident_id
