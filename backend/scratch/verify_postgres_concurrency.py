"""
Verify PostgreSQL partial unique index and concurrent duplicate approval handling
against the live sentinelops_dev PostgreSQL database.
"""
import os
import sys
import uuid
import threading
import concurrent.futures
from datetime import datetime, timezone, timedelta

# Setup path
sys.path.insert(0, r"d:\Sentinal_AI\backend")

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException

from app.core.config import settings
from app.models.remediation import RemediationApproval, PolicyDecision
from app.models.workspace import Workspace
from app.models.user import User
from app.remediation.approval_service import ApprovalService
from app.remediation.schemas import ApprovalCreateRequest

def main():
    print(f"Connecting to database: {settings.DATABASE_URL}")
    engine = create_engine(settings.DATABASE_URL)
    Session = sessionmaker(bind=engine)
    db = Session()
    decision_id = None

    try:
        # 1. Fetch or verify existing workspace and user
        workspace = db.execute(select(Workspace).limit(1)).scalar_one_or_none()
        user = db.execute(select(User).limit(1)).scalar_one_or_none()
        assert workspace is not None, "Workspace not found"
        assert user is not None, "User not found"
        print(f"Using workspace: {workspace.id}, user: {user.id}")

        # 2. Create a test policy decision record
        decision_id = str(uuid.uuid4())
        decision = PolicyDecision(
            id=decision_id,
            workspace_id=workspace.id,
            user_id=user.id,
            action_id="restart_service",
            risk_level="high",
            decision="approval_required",
            decision_reason="Requires human approval",
            policy_version="v1.0",
            validated_parameters={"service_id": str(uuid.uuid4())},
            timestamp=datetime.now(timezone.utc),
        )
        db.add(decision)
        db.commit()
        print(f"Created PolicyDecision: {decision_id}")

        # 3. Test concurrent duplicate creation in PostgreSQL
        results = []
        barrier = threading.Barrier(2)

        def worker(worker_id):
            worker_db = Session()
            try:
                # Synchronize threads so they hit the DB at roughly the exact same moment
                barrier.wait(timeout=5)
                # Attempt to insert directly with same policy_decision_id and pending status
                approval = RemediationApproval(
                    id=str(uuid.uuid4()),
                    workspace_id=workspace.id,
                    policy_decision_id=decision_id,
                    action_id="restart_service",
                    validated_parameters={"service_id": str(uuid.uuid4())},
                    risk_level="high",
                    policy_version="v1.0",
                    approval_status="pending",
                    requested_by=user.id,
                    requested_at=datetime.now(timezone.utc),
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                )
                worker_db.add(approval)
                worker_db.commit()
                results.append((worker_id, "SUCCESS", approval.id))
            except IntegrityError as exc:
                worker_db.rollback()
                results.append((worker_id, "INTEGRITY_ERROR", str(exc.orig)))
            except Exception as exc:
                worker_db.rollback()
                import traceback
                results.append((worker_id, "ERROR", f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"))
            finally:
                worker_db.close()

        t1 = threading.Thread(target=worker, args=(1,))
        t2 = threading.Thread(target=worker, args=(2,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        print("Concurrent insertion results:")
        for res in results:
            print(f"  Worker {res[0]}: {res[1]} -> {res[2] if len(res) > 2 else ''}")

        statuses = [r[1] for r in results]
        assert "SUCCESS" in statuses, "At least one worker should succeed"
        assert "INTEGRITY_ERROR" in statuses, "One worker must fail with PostgreSQL IntegrityError on uq_pending_policy_decision"
        print("PASS: PostgreSQL partial unique index uq_pending_policy_decision successfully rejected concurrent duplicate pending approval!")

        # 4. Verify ApprovalService handles IntegrityError with 409 Conflict
        # Attempt to create another pending via service
        create_req = ApprovalCreateRequest(
            workspace_id=workspace.id,
            policy_decision_id=decision_id,
        )
        try:
            ApprovalService.create_approval_request(
                db=db,
                workspace_id=workspace.id,
                policy_decision_id=decision_id,
                requested_by=user,
            )
            assert False, "Should have raised 409 Conflict"
        except HTTPException as he:
            assert he.status_code == 409, f"Expected 409, got {he.status_code}"
            print(f"PASS: ApprovalService caught duplicate and returned HTTP 409: {he.detail}")

        # 5. Verify that once pending proposal is no longer pending (e.g. rejected), a new pending can be created
        pending_approval = db.execute(
            select(RemediationApproval).where(
                RemediationApproval.policy_decision_id == decision_id,
                RemediationApproval.approval_status == "pending"
            )
        ).scalar_one()

        pending_approval.approval_status = "rejected"
        pending_approval.rejection_reason = "Manual test rejection"
        pending_approval.reviewed_at = datetime.now(timezone.utc)
        pending_approval.reviewed_by = user.id
        db.commit()
        print("Updated existing approval from 'pending' to 'rejected'")

        # Now insert a NEW pending approval for the SAME policy_decision_id
        new_pending = RemediationApproval(
            id=str(uuid.uuid4()),
            workspace_id=workspace.id,
            policy_decision_id=decision_id,
            action_id="restart_service",
            validated_parameters={"service_id": str(uuid.uuid4())},
            risk_level="high",
            policy_version="v1.0",
            approval_status="pending",
            requested_by=user.id,
            requested_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db.add(new_pending)
        db.commit()
        print(f"PASS: Successfully created new pending approval {new_pending.id} after prior was rejected!")

    finally:
        if decision_id is not None:
            try:
                db.rollback()
                db.execute(text(f"DELETE FROM remediation_approvals WHERE policy_decision_id = '{decision_id}'"))
                db.execute(text(f"DELETE FROM policy_decisions WHERE id = '{decision_id}'"))
                db.commit()
                print("Cleaned up test rows successfully in finally block.")
            except Exception as clean_err:
                print(f"Warning during test cleanup: {clean_err}")
        db.close()

if __name__ == "__main__":
    main()
