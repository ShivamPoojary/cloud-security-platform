#!/usr/bin/env python3
"""ML Calibration & Anomaly Score Distribution Analysis Script

Runs:
1. 350+ normal synthetic telemetry events across realistic time window.
2. Attack scenarios separately:
   - credential_compromise
   - keyvault_exfiltration
   - ransomware
   - stealth_off_hours
3. Computes detailed percentiles, FPR, and TPR across threshold options.
"""
import asyncio
import os
import sys
import uuid
import numpy as np
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Configure clean calibration environment
CALIB_DB = "test_calibration.db"
if os.path.exists(CALIB_DB):
    try:
        os.remove(CALIB_DB)
    except OSError:
        pass

os.environ["ENVIRONMENT"] = "testing"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{CALIB_DB}"

from app.core.config import settings
settings.DATABASE_URL = os.environ["DATABASE_URL"]

from sqlalchemy import select, func
from app.core.database import AsyncSessionLocal, engine
from app.domain.models.base import Base
import app.domain.models  # Register all models
from app.core.seed import seed_data
from app.domain.models.logs import NormalizedEvent
from app.domain.models.ml import MLAnomalyScore
from app.domain.schemas.event import SecurityEventBase
from app.ingestion.synthetic_generator import SyntheticAzureTelemetryGenerator
from app.workers.ingestion_worker import ingestion_worker
from app.ml.pipeline import ml_pipeline


def print_stats(name: str, scores: List[float], thresholds: List[float] = [50.0, 55.0, 60.0, 65.0]):
    arr = np.array(scores)
    n = len(arr)
    print(f"\n--- {name} (N = {n}) ---")
    if n == 0:
        print("  No samples.")
        return
    print(f"  Min:    {arr.min():.1f}")
    print(f"  Max:    {arr.max():.1f}")
    print(f"  Mean:   {arr.mean():.1f} (+/- {arr.std():.1f})")
    print(f"  Median: {np.median(arr):.1f}")
    print(f"  P25:    {np.percentile(arr, 25):.1f}")
    print(f"  P50:    {np.percentile(arr, 50):.1f}")
    print(f"  P75:    {np.percentile(arr, 75):.1f}")
    print(f"  P90:    {np.percentile(arr, 90):.1f}")
    print(f"  P95:    {np.percentile(arr, 95):.1f}")
    print(f"  P99:    {np.percentile(arr, 99):.1f}")
    print("  Threshold Exceedance:")
    for th in thresholds:
        count = int(np.sum(arr >= th))
        pct = (count / n) * 100.0
        print(f"    >= {th:.1f}: {count:>3}/{n} ({pct:>5.1f}%)")


async def run_calibration():
    print("=" * 70)
    print("  ML CALIBRATION EXPERIMENT & SCORE DISTRIBUTION REVIEW")
    print("=" * 70)

    # Step 1: Database init
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    await seed_data()
    ml_pipeline.load_or_initialize_model()
    # Reset in-memory window/history so calibration starts totally fresh
    ml_pipeline._history_by_principal.clear()

    print(f"Model: {ml_pipeline.model_version}")
    print(f"Contamination: {ml_pipeline.model.contamination}")
    print(f"Estimators: {ml_pipeline.model.n_estimators}")

    # Step 2: 350 Normal Events
    print("\n[Step 1] Ingesting 350 Synthetic Normal Events...")
    normal_scores = []
    normal_start_time = datetime(2026, 9, 21, 8, 0, tzinfo=timezone.utc)  # Monday morning
    
    async with AsyncSessionLocal() as db:
        for i in range(350):
            # Spread events over 3 business days, business hours (8 AM to 6 PM)
            day_offset = (i // 120)  # 0, 1, 2 days
            hour_offset = 8 + ((i % 120) * 10 // 120)  # 8 AM to 18 PM
            minute_offset = (i * 7) % 60
            event_time = normal_start_time + timedelta(days=day_offset, hours=hour_offset - 8, minutes=minute_offset)
            
            raw_event = SyntheticAzureTelemetryGenerator.generate_normal_event(base_time=event_time)
            norm_event, _ = await ingestion_worker.process_single_payload(raw_event.model_dump_json(), db)
            if norm_event:
                score_rec = (await db.execute(
                    select(MLAnomalyScore).where(MLAnomalyScore.event_id == norm_event.id)
                )).scalar_one_or_none()
                if score_rec:
                    normal_scores.append(score_rec.anomaly_score)

    print_stats("NORMAL BASELINE TELEMETRY", normal_scores)

    # Step 3: Scenario 1 - Credential Compromise
    print("\n[Step 2] Ingesting Scenario 1: Credential Compromise...")
    scen1_scores = []
    async with AsyncSessionLocal() as db:
        events = SyntheticAzureTelemetryGenerator.generate_attack_scenario("credential_compromise")
        for ev in events:
            norm_event, _ = await ingestion_worker.process_single_payload(ev.model_dump_json(), db)
            if norm_event:
                score_rec = (await db.execute(
                    select(MLAnomalyScore).where(MLAnomalyScore.event_id == norm_event.id)
                )).scalar_one_or_none()
                if score_rec:
                    scen1_scores.append(score_rec.anomaly_score)

    print_stats("SCENARIO 1: CREDENTIAL COMPROMISE", scen1_scores)

    # Step 4: Scenario 2 - Key Vault Exfiltration
    print("\n[Step 3] Ingesting Scenario 2: Key Vault Exfiltration...")
    scen2_scores = []
    async with AsyncSessionLocal() as db:
        events = SyntheticAzureTelemetryGenerator.generate_attack_scenario("keyvault_exfiltration")
        for ev in events:
            norm_event, _ = await ingestion_worker.process_single_payload(ev.model_dump_json(), db)
            if norm_event:
                score_rec = (await db.execute(
                    select(MLAnomalyScore).where(MLAnomalyScore.event_id == norm_event.id)
                )).scalar_one_or_none()
                if score_rec:
                    scen2_scores.append(score_rec.anomaly_score)

    print_stats("SCENARIO 2: KEY VAULT EXFILTRATION", scen2_scores)

    # Step 5: Scenario 3 - Ransomware & Defense Evasion
    print("\n[Step 4] Ingesting Scenario 3: Ransomware & Defense Evasion...")
    scen3_scores = []
    async with AsyncSessionLocal() as db:
        events = SyntheticAzureTelemetryGenerator.generate_attack_scenario("ransomware")
        for ev in events:
            norm_event, _ = await ingestion_worker.process_single_payload(ev.model_dump_json(), db)
            if norm_event:
                score_rec = (await db.execute(
                    select(MLAnomalyScore).where(MLAnomalyScore.event_id == norm_event.id)
                )).scalar_one_or_none()
                if score_rec:
                    scen3_scores.append(score_rec.anomaly_score)

    print_stats("SCENARIO 3: RANSOMWARE & DEFENSE EVASION", scen3_scores)

    # Step 6: Stealth Behavior (Stage 4 style)
    print("\n[Step 5] Ingesting Scenario 4: Stealth Off-Hours Resource Enumeration...")
    stealth_scores = []
    async with AsyncSessionLocal() as db:
        off_hours_time = datetime(2026, 9, 25, 3, 15, tzinfo=timezone.utc)
        novel_ip = "198.51.100.222"
        dev_id = "usr-stealth-dev"

        for i in range(8):
            ev_payload = {
                "source": "AzureActivity",
                "event_category": "ResourceManagement",
                "event_name": "Microsoft.Compute/virtualMachines/extensions/read",
                "principal_id": dev_id,
                "principal_name": "stealth.developer@secplatform.local",
                "caller_ip": novel_ip,
                "target_resource_id": f"/subscriptions/sub-core/resourceGroups/rg-stealth/providers/vm-{i}",
                "target_resource_name": f"vm-{i}",
                "action_status": "Success",
                "geo_country": "Japan",
                "metadata": {"custom_probe": True},
            }
            norm_ev, _ = await ingestion_worker.process_single_payload(ev_payload, db)
            if norm_ev:
                score_rec = (await db.execute(
                    select(MLAnomalyScore).where(MLAnomalyScore.event_id == norm_ev.id)
                )).scalar_one_or_none()
                if score_rec:
                    stealth_scores.append(score_rec.anomaly_score)

    print_stats("SCENARIO 4: STEALTH OFF-HOURS ENUMERATION", stealth_scores)

    # Combined Summary
    all_attacks = scen1_scores + scen2_scores + scen3_scores + stealth_scores
    print_stats("ALL ATTACK & STEALTH SCENARIOS COMBINED", all_attacks)

    # Clean up calibration db
    await engine.dispose()
    if os.path.exists(CALIB_DB):
        try:
            os.remove(CALIB_DB)
        except OSError:
            pass


if __name__ == "__main__":
    asyncio.run(run_calibration())
