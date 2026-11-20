"""Live Phase 1 Verification Script.

Executes full incident lifecycle against the LIVE PostgreSQL database:
1. Registers Workspace and Service.
2. Healthy evaluation -> no incidents.
3. Injects failure into Order API -> detection engine creates persisted Incident and IncidentEvent in PostgreSQL.
4. Second failure evaluation -> deduplication verified (0 duplicate incidents).
5. Restores Order API -> detection engine transitions incident to 'recovered', sets recovered_at, and records verification event.
6. Direct PostgreSQL query to display persisted records.
"""

import sys
import os
import asyncio
import json

# Ensure backend and order-api directories are in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ORDER_API_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "services", "order-api"))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, ORDER_API_DIR)

import httpx
from sqlalchemy import text
from app.db.session import SessionLocal
from app.models.workspace import Workspace
from app.models.service import Service
from app.models.incident import Incident, IncidentEvent
from app.detector.runner import run_evaluation_for_service
from service.main import app as order_app, demo_state


async def main():
    print("=" * 70)
    print("SENTINELOPS AI -- PHASE 1 LIVE VERIFICATION")
    print("=" * 70)

    db = SessionLocal()
    try:
        # Check PostgreSQL connection
        db.execute(text("SELECT 1"))
        print("[OK] PostgreSQL 'sentinelops_dev' is connected and responsive.\n")

        # 1. Setup Workspace and Service in PostgreSQL
        ws_slug = "live-demo-workspace"
        existing_ws = db.query(Workspace).filter(Workspace.slug == ws_slug).first()
        if existing_ws:
            db.delete(existing_ws)
            db.commit()

        workspace = Workspace(
            name="Demo Reliability Workspace",
            slug=ws_slug,
            description="Live Phase 1 Verification Workspace",
        )
        db.add(workspace)
        db.commit()

        service = Service(
            workspace_id=workspace.id,
            name="Order API (Demo)",
            environment="development",
            health_check_url="http://127.0.0.1:8001/health",
            monitoring_method="prometheus",
            execution_policy="demo",
        )
        db.add(service)
        db.commit()
        db.refresh(service)

        print(f"[OK] Created Workspace: '{workspace.name}' (ID: {workspace.id})")
        print(f"[OK] Registered Service: '{service.name}' (ID: {service.id})\n")

        # Create ASGI client connected to actual Order API app
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=order_app), base_url="http://127.0.0.1:8001") as order_client:
            # -------------------------------------------------------------
            # STEP 1: Probe while healthy
            # -------------------------------------------------------------
            print("--- STEP 1: Evaluating Healthy Service ---")
            demo_state.restore_healthy()

            res_step1 = await run_evaluation_for_service(
                service_id=service.id,
                db=db,
                client=order_client,
            )
            print(f"Service Healthy: {res_step1.is_healthy}")
            print(f"Lifecycle Action: {res_step1.lifecycle_action}")
            incident_count_1 = db.query(Incident).filter(Incident.service_id == service.id).count()
            print(f"Total Incidents in DB: {incident_count_1}")
            assert res_step1.is_healthy is True
            assert incident_count_1 == 0
            print("[OK] Step 1 passed: Normal healthy baseline maintained.\n")

            # -------------------------------------------------------------
            # STEP 2: Inject failure & run detection
            # -------------------------------------------------------------
            print("--- STEP 2: Simulating Failure & Triggering Detection ---")
            demo_state.activate_failure("Database connection pool exhausted; queries timing out after 5000ms")
            print("[*] Simulated failure injected: Order API now failing with HTTP 500.")

            res_step2 = await run_evaluation_for_service(
                service_id=service.id,
                db=db,
                client=order_client,
            )
            print(f"Service Healthy: {res_step2.is_healthy}")
            print(f"Lifecycle Action: {res_step2.lifecycle_action}")
            print(f"Trigger Message: {res_step2.report.trigger}")
            assert res_step2.is_healthy is False
            assert res_step2.lifecycle_action == "created"
            assert res_step2.incident is not None
            persisted_inc_id = res_step2.incident.id
            print(f"[OK] Step 2 passed: Incident persisted in PostgreSQL (ID: {persisted_inc_id}).\n")

            # -------------------------------------------------------------
            # STEP 3: Deduplication during repeated evaluation
            # -------------------------------------------------------------
            print("--- STEP 3: Verifying Deduplication on Repeated Polling ---")
            res_step3 = await run_evaluation_for_service(
                service_id=service.id,
                db=db,
                client=order_client,
            )
            print(f"Lifecycle Action: {res_step3.lifecycle_action}")
            total_incidents_step3 = db.query(Incident).filter(Incident.service_id == service.id).count()
            print(f"Total Incidents in DB (Expected: 1): {total_incidents_step3}")
            assert res_step3.lifecycle_action == "deduplicated"
            assert total_incidents_step3 == 1
            print("[OK] Step 3 passed: Deduplication prevented duplicate incident creation.\n")

            # -------------------------------------------------------------
            # STEP 4: Restore healthy operation & verify recovery update
            # -------------------------------------------------------------
            print("--- STEP 4: Restoring Service & Recording Recovery ---")
            demo_state.restore_healthy()
            print("[*] Service restored to healthy state.")

            res_step4 = await run_evaluation_for_service(
                service_id=service.id,
                db=db,
                client=order_client,
            )
            print(f"Service Healthy: {res_step4.is_healthy}")
            print(f"Lifecycle Action: {res_step4.lifecycle_action}")
            assert res_step4.is_healthy is True
            assert res_step4.lifecycle_action == "recovered"
            print("[OK] Step 4 passed: Incident marked as 'recovered'.\n")

        # -------------------------------------------------------------
        # STEP 5: Direct PostgreSQL verification
        # -------------------------------------------------------------
        print("=" * 70)
        print("DIRECT POSTGRESQL DATABASE RECORD INSPECTION")
        print("=" * 70)

        recovered_incident = db.query(Incident).filter(Incident.id == persisted_inc_id).first()
        print(f"Incident ID:      {recovered_incident.id}")
        print(f"Workspace ID:     {recovered_incident.workspace_id}")
        print(f"Service ID:       {recovered_incident.service_id}")
        print(f"Title:            {recovered_incident.title}")
        print(f"Severity:         {recovered_incident.severity}")
        print(f"Status:           {recovered_incident.status}")
        print(f"Trigger:          {recovered_incident.trigger}")
        print(f"Detected At:      {recovered_incident.detected_at.isoformat()}")
        print(f"Recovered At:     {recovered_incident.recovered_at.isoformat()}")

        events = (
            db.query(IncidentEvent)
            .filter(IncidentEvent.incident_id == persisted_inc_id)
            .order_by(IncidentEvent.timestamp.asc())
            .all()
        )
        print(f"\nPersisted Timeline Events ({len(events)} total):")
        for i, ev in enumerate(events, 1):
            print(f"  {i}. [{ev.timestamp.isoformat()}] Type: {ev.event_type.upper()}")
            print(f"     Message: {ev.message}")
            if ev.metadata_json:
                meta = json.loads(ev.metadata_json)
                print(f"     Evidence Snapshot: status_code={meta.get('status_code')}, latency_ms={meta.get('latency_ms')}, error={meta.get('error_message')}")

        print("\n" + "=" * 70)
        print("PHASE 1 ACCEPTANCE CRITERION VERIFIED IN POSTGRESQL!")
        print("=" * 70)

    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(main())
