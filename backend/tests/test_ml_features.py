import uuid
from datetime import datetime, timezone
import pytest
import numpy as np
from app.domain.models.logs import NormalizedEvent
from app.ml.features import FeatureExtractor, FEATURE_NAMES


def test_feature_extractor_returns_all_features():
    """Verify FeatureExtractor returns all defined features with correct dimensions."""
    event = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=datetime(2026, 9, 25, 14, 30, tzinfo=timezone.utc),
        event_category="Identity",
        event_name="UserLoggedIn",
        principal_id="usr-test-101",
        principal_name="test.user@secplatform.local",
        caller_ip="198.51.100.10",
        target_resource_id="/tenants/app1",
        action_status="Success",
        geo_country="United States",
    )

    features = FeatureExtractor.extract_features(event)
    assert isinstance(features, dict)
    for fname in FEATURE_NAMES:
        assert fname in features, f"Missing feature: {fname}"

    # Check vector shape
    vec = FeatureExtractor.to_vector(features)
    assert vec.shape == (1, len(FEATURE_NAMES))
    assert isinstance(vec, np.ndarray)


def test_feature_extractor_service_principal_detection():
    """Verify service principal indicator properly identifies SPNs vs standard users."""
    user_event = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=datetime.now(timezone.utc),
        event_category="Identity",
        event_name="UserLoggedIn",
        principal_id="usr-corp-01",
        principal_name="john.doe@company.com",
        action_status="Success",
    )
    assert FeatureExtractor.is_service_principal(user_event) == 0.0

    spn_event = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=datetime.now(timezone.utc),
        event_category="Identity",
        event_name="ServicePrincipalLoggedIn",
        principal_id="spn-github-cicd",
        principal_name="spn-github-runner",
        user_agent="GitHub-Actions-Runner/2.314.0",
        action_status="Success",
    )
    assert FeatureExtractor.is_service_principal(spn_event) == 1.0


def test_feature_extractor_off_hours():
    """Verify temporal off-hours calculation (08:00 - 18:00 UTC business hours)."""
    # 11:00 UTC is business hours -> is_off_hours == 0.0
    day_event = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=datetime(2026, 9, 25, 11, 0, tzinfo=timezone.utc),
        event_category="Identity",
        event_name="UserLoggedIn",
        action_status="Success",
    )
    features_day = FeatureExtractor.extract_features(day_event)
    assert features_day["is_off_hours"] == 0.0
    assert features_day["hour_of_day"] == 11.0

    # 02:00 UTC is off hours -> is_off_hours == 1.0
    night_event = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=datetime(2026, 9, 25, 2, 30, tzinfo=timezone.utc),
        event_category="Identity",
        event_name="UserLoggedIn",
        action_status="Success",
    )
    features_night = FeatureExtractor.extract_features(night_event)
    assert features_night["is_off_hours"] == 1.0
    assert features_night["hour_of_day"] == 2.0


def test_feature_extractor_novelty_detection():
    """Verify novel IP and novel country flags based on known baseline sets."""
    known_ips = {"198.51.100.10", "198.51.100.11"}
    known_countries = {"United States"}

    # Normal known IP and country
    event_normal = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=datetime.now(timezone.utc),
        event_category="Identity",
        event_name="UserLoggedIn",
        caller_ip="198.51.100.10",
        geo_country="United States",
        action_status="Success",
    )
    feat_normal = FeatureExtractor.extract_features(
        event_normal, known_ips=known_ips, known_countries=known_countries
    )
    assert feat_normal["is_novel_ip"] == 0.0
    assert feat_normal["is_novel_country"] == 0.0

    # Foreign novel IP and country
    event_foreign = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=datetime.now(timezone.utc),
        event_category="Identity",
        event_name="UserLoggedIn",
        caller_ip="203.0.113.99",
        geo_country="Russian Federation",
        action_status="Success",
    )
    feat_foreign = FeatureExtractor.extract_features(
        event_foreign, known_ips=known_ips, known_countries=known_countries
    )
    assert feat_foreign["is_novel_ip"] == 1.0
    assert feat_foreign["is_novel_country"] == 1.0
