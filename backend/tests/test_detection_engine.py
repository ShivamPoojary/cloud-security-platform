import uuid
from datetime import datetime, timezone, timedelta
import pytest
from app.domain.models.logs import NormalizedEvent
from app.domain.models.rules import DetectionRule
from app.detection.evaluator import DetectionEngine
from app.detection.window import SlidingWindowTracker


@pytest.fixture
def local_tracker():
    """Provides a fresh, isolated sliding window tracker."""
    tracker = SlidingWindowTracker()
    yield tracker
    tracker.clear()


@pytest.fixture
def local_engine(local_tracker):
    """Provides a DetectionEngine instance with isolated tracker."""
    return DetectionEngine(tracker=local_tracker)


def test_stateless_rule_positive_match(local_engine):
    """Test 1: Stateless pattern rule triggers on matching criteria."""
    rule = DetectionRule(
        id=uuid.uuid4(),
        rule_id="TEST-RULE-001",
        title="Test Security Pricing Tampering",
        severity="CRITICAL",
        mitre_tactic="Defense Evasion",
        mitre_technique_id="T1562",
        description="Detects tampering with pricing",
        rule_logic={
            "type": "stateless_pattern",
            "filter": {
                "event_category": "Security",
                "event_name": "Microsoft.Security/pricings/write",
                "action_status": "Success",
                "pricing_tier": "Free",
            },
        },
        is_active=True,
    )

    matching_event = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=datetime.now(timezone.utc),
        event_category="Security",
        event_name="Microsoft.Security/pricings/write",
        action_status="Success",
        principal_id="usr-1",
        principal_name="attacker@test.local",
        caller_ip="192.0.2.1",
        security_context={"pricing_tier": "Free"},
    )

    detections = local_engine.evaluate_event_sync(matching_event, [rule])
    assert len(detections) == 1
    assert detections[0].rule_id == rule.id
    assert detections[0].severity == "CRITICAL"
    assert "Test Security Pricing Tampering" in detections[0].alert_summary


def test_stateless_rule_negative_match(local_engine):
    """Test 2: Stateless rule does not trigger when filter fields mismatch."""
    rule = DetectionRule(
        id=uuid.uuid4(),
        rule_id="TEST-RULE-001",
        title="Test Security Pricing Tampering",
        severity="CRITICAL",
        mitre_tactic="Defense Evasion",
        mitre_technique_id="T1562",
        description="Detects tampering with pricing",
        rule_logic={
            "type": "stateless_pattern",
            "filter": {
                "event_category": "Security",
                "event_name": "Microsoft.Security/pricings/write",
                "action_status": "Success",
            },
        },
        is_active=True,
    )

    # Different event category and action_status
    event = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=datetime.now(timezone.utc),
        event_category="Storage",
        event_name="Microsoft.Security/pricings/write",
        action_status="Failure",
        principal_id="usr-1",
    )

    detections = local_engine.evaluate_event_sync(event, [rule])
    assert len(detections) == 0


def test_stateful_sliding_window_threshold(local_engine):
    """Test 3: Stateful rule triggers only once threshold count is reached within window."""
    rule = DetectionRule(
        id=uuid.uuid4(),
        rule_id="TEST-THRESHOLD-001",
        title="Brute Force Login Attempts",
        severity="HIGH",
        mitre_tactic="Initial Access",
        mitre_technique_id="T1110",
        description="Detects 4 failed logins within 60s",
        rule_logic={
            "type": "stateful_threshold",
            "window_seconds": 60,
            "threshold": 4,
            "filter": {
                "event_category": "Identity",
                "event_name": "UserLoginFailed",
                "action_status": "Failure",
            },
        },
        is_active=True,
    )

    base_time = datetime.now(timezone.utc)
    target_ip = "198.51.100.99"

    # Send 3 failed logins (below threshold)
    for i in range(3):
        ev = NormalizedEvent(
            id=uuid.uuid4(),
            event_timestamp=base_time + timedelta(seconds=i * 5),
            event_category="Identity",
            event_name="UserLoginFailed",
            action_status="Failure",
            caller_ip=target_ip,
        )
        dets = local_engine.evaluate_event_sync(ev, [rule])
        assert len(dets) == 0, f"Unexpected trigger at iteration {i}"

    # 4th failed login hits threshold -> triggers alert
    ev_trigger = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=base_time + timedelta(seconds=20),
        event_category="Identity",
        event_name="UserLoginFailed",
        action_status="Failure",
        caller_ip=target_ip,
    )
    dets = local_engine.evaluate_event_sync(ev_trigger, [rule])
    assert len(dets) == 1
    assert dets[0].severity == "HIGH"
    assert "Brute Force Login Attempts" in dets[0].alert_summary


def test_stateful_sliding_window_expiry(local_engine):
    """Test 4: Expired events falling outside window_seconds do not count toward threshold."""
    rule = DetectionRule(
        id=uuid.uuid4(),
        rule_id="TEST-EXPIRY-001",
        title="Fast Bursts Only",
        severity="MEDIUM",
        mitre_tactic="Initial Access",
        mitre_technique_id="T1110",
        description="Threshold 3 in 30 seconds",
        rule_logic={
            "type": "stateful_threshold",
            "window_seconds": 30,
            "threshold": 3,
            "filter": {"event_name": "TestBurst"},
        },
        is_active=True,
    )

    t0 = datetime.now(timezone.utc)

    # Event 1 at T0
    ev1 = NormalizedEvent(id=uuid.uuid4(), event_timestamp=t0, event_category="Any", event_name="TestBurst", action_status="Success", caller_ip="1.1.1.1")
    assert len(local_engine.evaluate_event_sync(ev1, [rule])) == 0

    # Event 2 at T0 + 10s
    ev2 = NormalizedEvent(id=uuid.uuid4(), event_timestamp=t0 + timedelta(seconds=10), event_category="Any", event_name="TestBurst", action_status="Success", caller_ip="1.1.1.1")
    assert len(local_engine.evaluate_event_sync(ev2, [rule])) == 0

    # Event 3 at T0 + 45s (Event 1 has now expired from the 30s window!)
    ev3 = NormalizedEvent(id=uuid.uuid4(), event_timestamp=t0 + timedelta(seconds=45), event_category="Any", event_name="TestBurst", action_status="Success", caller_ip="1.1.1.1")
    assert len(local_engine.evaluate_event_sync(ev3, [rule])) == 0


def test_inactive_rule_does_not_trigger(local_engine):
    """Test 5: Inactive (disabled) rules are skipped during evaluation."""
    rule = DetectionRule(
        id=uuid.uuid4(),
        rule_id="TEST-INACTIVE-001",
        title="Disabled Rule",
        severity="LOW",
        mitre_tactic="Reconnaissance",
        mitre_technique_id="T1595",
        description="Should never fire",
        rule_logic={"type": "stateless_pattern", "filter": {"event_name": "AnyEvent"}},
        is_active=False,
    )

    ev = NormalizedEvent(id=uuid.uuid4(), event_timestamp=datetime.now(timezone.utc), event_category="Any", event_name="AnyEvent", action_status="Success")
    assert len(local_engine.evaluate_event_sync(ev, [rule])) == 0
