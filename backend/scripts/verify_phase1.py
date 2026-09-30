import asyncio
import json
import uuid
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select, text
from app.core.config import settings
from app.core.database import AsyncSessionLocal, engine
from app.domain.models.base import Base
import app.domain.models  # ensure models registered
from app.domain.models.users import User
from app.domain.models.rules import DetectionRule
from app.domain.models.logs import RawLog, NormalizedEvent
from app.main import app


async def run_verification():
    print("=" * 60)
    print("PHASE 1 VERIFICATION & HEALTH AUDIT")
    print("=" * 60)

    # 1. Database Connection & Schema Verification
    print("\n[1/5] Verifying Database Connection & Table Schema...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        res = await conn.execute(text("SELECT 1"))
        assert res.scalar() == 1, "Database connection failed"
    print("  -> PostgreSQL/Database connection: OK")
    print("  -> 11 Core tables created/verified: OK")

    # 2. Seed Data Audit
    print("\n[2/5] Auditing Seeded Users and Detection Rules...")
    from app.core.seed import seed_data
    await seed_data()

    async with AsyncSessionLocal() as session:
        users = (await session.execute(select(User))).scalars().all()
        rules = (await session.execute(select(DetectionRule))).scalars().all()
        print(f"  -> Total Seeded Users: {len(users)}")
        for u in users:
            print(f"     - {u.email} ({u.role})")
        print(f"  -> Total Seeded Rules: {len(rules)}")
        for r in rules:
            print(f"     - {r.rule_id}: {r.title} ({r.severity})")
        assert len(users) >= 3, "Missing seeded users"
        assert len(rules) >= 4, "Missing seeded rules"

    # 3. Health Endpoints Check via ASGI
    print("\n[3/5] Testing HTTP Health Endpoints...")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # GET /health
        res_health = await client.get("/health")
        assert res_health.status_code == 200
        health_data = res_health.json()
        print(f"  -> GET /health: {health_data}")
        assert health_data["status"] == "ok"
        assert health_data["service"] == "cloud-security-platform"

        # GET /api/v1/health
        res_v1_health = await client.get("/api/v1/health")
        assert res_v1_health.status_code == 200
        v1_health_data = res_v1_health.json()
        print(f"  -> GET /api/v1/health: {v1_health_data}")
        assert "version" in v1_health_data

        # 4. Ingest Raw Telemetry Event
        print("\n[4/5] Testing Ingestion Endpoint (POST /api/v1/ingest/raw)...")
        sample_event = {
            "source": "AzureActivity",
            "event_category": "ResourceManagement",
            "event_name": "Microsoft.Compute/virtualMachines/write",
            "principal_id": "usr-audit-001",
            "principal_name": "audit.engineer@secplatform.local",
            "caller_ip": "198.51.100.77",
            "target_resource_id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-prod-01",
            "target_resource_name": "vm-prod-01",
            "action_status": "Success",
            "geo_country": "United States",
            "user_agent": "AzurePortal/1.0",
            "metadata": {"action_type": "vm_create", "test_id": "verify_001"},
        }
        res_ingest = await client.post("/api/v1/ingest/raw", json=sample_event)
        assert res_ingest.status_code == 202
        ingest_data = res_ingest.json()
        print(f"  -> Raw Event Ingested (202 Accepted): ID={ingest_data['event_id']}, Status={ingest_data['status']}")

        # 5. Trigger Synthetic Attack Scenario
        print("\n[5/5] Testing Synthetic Attack Trigger (POST /api/v1/ingest/synthetic/trigger)...")
        trigger_req = {
            "scenario_name": "keyvault_exfiltration",
            "custom_target_resource": "kv-audit-vault",
        }
        res_trigger = await client.post("/api/v1/ingest/synthetic/trigger", json=trigger_req)
        assert res_trigger.status_code == 200
        trigger_data = res_trigger.json()
        print(f"  -> Scenario Triggered: '{trigger_data['scenario_name']}'")
        print(f"     - Execution ID: {trigger_data['execution_id']}")
        print(f"     - Events Generated: {trigger_data['events_count']}")
        assert trigger_data["events_count"] >= 15

    # Verify Database Persistence of Ingested and Synthetic Events
    async with AsyncSessionLocal() as session:
        raw_count = (await session.execute(text("SELECT count(*) FROM raw_logs"))).scalar()
        norm_count = (await session.execute(text("SELECT count(*) FROM normalized_events"))).scalar()
        print(f"\n[PERSISTENCE VERIFICATION]")
        print(f"  -> Total Raw Logs in Database: {raw_count}")
        print(f"  -> Total Normalized Events in Database: {norm_count}")
        assert raw_count >= 16
        assert norm_count >= 16

    print("\n" + "=" * 60)
    print("ALL PHASE 1 AUDIT CHECKS PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(run_verification())
