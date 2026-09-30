import asyncio
import json
import uuid
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select, text
from sqlalchemy.orm import selectinload
from app.core.database import AsyncSessionLocal, engine
from app.domain.models.base import Base
import app.domain.models
from app.domain.models.rules import DetectionRule
from app.domain.models.detections import ThreatDetection
from app.core.seed import seed_data
from app.workers.ingestion_worker import IngestionWorker
from app.detection.window import window_tracker
from app.main import app


async def run_phase2_verification():
    print("=" * 65)
    print("PHASE 2 END-TO-END VERIFICATION & DETECTION ENGINE AUDIT")
    print("=" * 65)

    window_tracker.clear()

    # 1. Initialize schema & seed all 7 detection rules
    print("\n[1/6] Initializing Database Schema & Seeding Rules...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await seed_data()

    async with AsyncSessionLocal() as session:
        rules = (await session.execute(select(DetectionRule))).scalars().all()
        print(f"  -> Total Seeded Rules: {len(rules)}")
        for r in rules:
            print(f"     * [{r.severity}] {r.rule_id}: {r.title} ({r.mitre_tactic})")
        assert len(rules) >= 7, f"Expected at least 7 seeded rules, got {len(rules)}"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 2. Trigger Scenario 1: Credential Compromise
        print("\n[2/6] Triggering Scenario 1: Credential Compromise...")
        res1 = await client.post("/api/v1/ingest/synthetic/trigger", json={"scenario_name": "credential_compromise"})
        assert res1.status_code == 200
        print(f"  -> Generated {res1.json()['events_count']} events (Execution: {res1.json()['execution_id']})")

        # 3. Trigger Scenario 2: Key Vault Exfiltration
        print("\n[3/6] Triggering Scenario 2: Key Vault Exfiltration...")
        res2 = await client.post("/api/v1/ingest/synthetic/trigger", json={"scenario_name": "keyvault_exfiltration"})
        assert res2.status_code == 200
        print(f"  -> Generated {res2.json()['events_count']} events (Execution: {res2.json()['execution_id']})")

        # 4. Trigger Scenario 3: Ransomware / Defense Evasion
        print("\n[4/6] Triggering Scenario 3: Ransomware & Defense Evasion...")
        res3 = await client.post("/api/v1/ingest/synthetic/trigger", json={"scenario_name": "ransomware"})
        assert res3.status_code == 200
        print(f"  -> Generated {res3.json()['events_count']} events (Execution: {res3.json()['execution_id']})")

        # 5. Query and Verify Detections Triggered
        print("\n[5/6] Auditing Triggered Threat Detections in Database...")
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ThreatDetection).options(selectinload(ThreatDetection.rule))
            )
            detections = result.scalars().all()
            print(f"  -> Total Threat Detections Triggered: {len(detections)}")
            triggered_rules = set()
            for d in detections:
                rule_code = d.rule.rule_id if d.rule else "UNKNOWN"
                triggered_rules.add(rule_code)
                print(f"     * [{d.severity}] {rule_code}: {d.alert_summary[:90]}...")

            expected_rules = {
                "AZ-RULE-0010",  # Brute force
                "AZ-RULE-0012",  # MFA fatigue
                "AZ-RULE-0025",  # Privileged role assignment
                "AZ-RULE-0040",  # Key Vault discovery
                "AZ-RULE-0042",  # Mass secret retrieval
                "AZ-RULE-0080",  # Security monitoring disabled
                "AZ-RULE-0085",  # Mass container deletion
            }
            missing = expected_rules - triggered_rules
            assert not missing, f"Missing expected detections: {missing}"
            print("  -> All 3 Attack Scenarios successfully produced verified detections!")

        # 6. Verify REST APIs (Events, Detections, Rules, Toggle)
        print("\n[6/6] Verifying REST APIs for Frontend Integration...")
        # GET /api/v1/events
        ev_res = await client.get("/api/v1/events?limit=5")
        assert ev_res.status_code == 200
        print(f"  -> GET /api/v1/events: {ev_res.json()['total']} total events in feed")

        # GET /api/v1/detections
        det_res = await client.get("/api/v1/detections?limit=5")
        assert det_res.status_code == 200
        print(f"  -> GET /api/v1/detections: {det_res.json()['total']} total alerts")

        # GET /api/v1/rules
        rules_res = await client.get("/api/v1/rules")
        assert rules_res.status_code == 200
        rules_data = rules_res.json()
        print(f"  -> GET /api/v1/rules: {len(rules_data)} rules cataloged")

        # PATCH /api/v1/rules/{rule_id}/toggle
        toggle_res = await client.patch("/api/v1/rules/AZ-RULE-0010/toggle")
        assert toggle_res.status_code == 200
        assert toggle_res.json()["is_active"] is False
        # Toggle back
        toggle_back = await client.patch("/api/v1/rules/AZ-RULE-0010/toggle")
        assert toggle_back.status_code == 200
        assert toggle_back.json()["is_active"] is True
        print("  -> PATCH /api/v1/rules/AZ-RULE-0010/toggle: Active state toggled successfully")

        # Test Ingestion Worker directly
        worker = IngestionWorker(consumer_name="audit-worker")
        test_event = {
            "source": "AzureActivity",
            "event_category": "ResourceManagement",
            "event_name": "Microsoft.KeyVault/vaults/read",
            "principal_id": "spn-audit",
            "principal_name": "spn-audit-tester",
            "caller_ip": "198.51.100.88",
            "action_status": "Success",
        }
        async with AsyncSessionLocal() as session:
            norm_ev, worker_dets = await worker.process_single_payload(json.dumps(test_event), session)
            assert norm_ev is not None
            assert len(worker_dets) >= 1
            print(f"  -> Ingestion Worker processed payload and generated detection: {worker_dets[0].alert_summary[:65]}...")

    print("\n" + "=" * 65)
    print("ALL PHASE 2 OBJECTIVES & VERIFICATIONS PASSED SUCCESSFULLY!")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(run_phase2_verification())
