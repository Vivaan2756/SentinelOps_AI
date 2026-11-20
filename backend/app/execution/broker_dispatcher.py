"""Broker IPC Dispatch Integration Layer for Phase 4.3.6 Milestone E.3.3.

Connects the Local Dispatch Coordinator (Milestone E.3.2) with the
UnixSocketBrokerClient (Milestone 4.3.4.1), ensuring that durable dispatch
intent is recorded and fsynced to the append-only journal before a Docker
operation can be requested over the restricted Unix domain socket.

Key Architectural Guarantees:
1. Strict Dispatch Ordering:
   - Validate operation identity, workspace isolation, and fencing token.
   - Ensure operation is durably reserved in SQLite registry.
   - Ensure DISPATCH_PREPARED is journaled and fsynced.
   - Revalidate operation local identity and state.
   - Append and fsync DOCKER_CALL_STARTED marker.
   - Only then send the broker IPC request over the restricted Unix socket.
   - Persist the broker response or fail-closed uncertain outcome in journal and registry.
2. Pre-Dispatch Persistence Barrier:
   - Never send a broker request if any pre-dispatch persistence step fails.
3. Non-Redispatch Invariant:
   - Never automatically redispatch an operation with an existing DOCKER_CALL_STARTED
     marker, terminal status, or uncertain outcome.
4. Fail-Closed Uncertainty:
   - Any broker timeout, connection loss, malformed response, or process interruption
     after the start marker is treated as potentially uncertain (DISPATCH_UNCERTAIN).
     Never infer that Docker was not contacted.
5. Strict Separation of Concerns:
   - Broker request completion and container process exit code (exit_code=0)
     indicate local execution output ONLY. They do NOT assert post-execution
     verification or incident recovery. Verification and recovery remain the
     exclusive responsibility of PostExecutionVerificationEngine and IncidentRecoveryBridge.
6. Revision 10 Physical Fencing Limitation Notice:
   - This milestone enforces host-level durable intent ordering before broker IPC.
     It does NOT solve Revision 10's physical Docker fencing limitation (TOCTOU).
     Docker daemon container lifecycles are asynchronous; if a worker loses its lease
     or crashes after DOCKER_CALL_STARTED, active Docker containers cannot be physically
     revoked by PostgreSQL fencing alone. All ambiguous outcomes fail closed into UNCERTAIN.
"""

from dataclasses import dataclass
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from app.execution.broker import (
    ALLOWED_BROKER_ACTIONS,
    BrokerExecuteRequest,
    BrokerExecuteResponse,
)
from app.execution.broker_client import UnixSocketBrokerClient
from app.execution.dispatch_coordinator import (
    CoordinatorConflictError,
    CoordinatorError,
    CoordinatorInvalidStateError,
    CoordinatorUncertaintyError,
    CoordinatorValidationError,
    DispatchCoordinator,
    PreDispatchState,
)
from app.execution.exceptions import (
    BrokerSecurityViolation,
    BrokerUnavailableError,
    ExecutionUncertainError,
)
from app.execution.journal import (
    JournalError,
    JournalRecord,
    JournalRecordType,
    JournalUncertaintyError,
    JournalCorruptedError,
)
from app.execution.registry import (
    TERMINAL_STATUSES,
    OperationRecord,
    OperationStatus,
    RegistryConflictError,
    RegistryError,
)

logger = logging.getLogger("sentinelops.broker_dispatcher")


# ============================================================================
# Broker Dispatch Result Data Model
# ============================================================================

@dataclass(frozen=True)
class BrokerDispatchResult:
    """Standardized result of a broker dispatch through the Local Dispatch Coordinator.

    CRITICAL ARCHITECTURAL DISTINCTION:
    - broker_completed: True if broker IPC finished and returned a structured response.
    - exit_code: Container process exit code (0 = process exited successfully).
    - is_uncertain: True if timeout, connection drop, or malformed response occurred
      after DOCKER_CALL_STARTED.
    - is_success: Convenience property (broker_completed and exit_code == 0).

    `is_success` refers strictly to container process exit status. It does NOT
    assert post-execution verification or incident recovery.
    """
    operation_id: str
    execution_id: str
    action_id: str
    fencing_token: int
    status: OperationStatus
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    output_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    error_category: Optional[str] = None
    is_uncertain: bool = False
    broker_completed: bool = False

    @property
    def is_success(self) -> bool:
        """True if container process completed with exit code 0 without uncertainty."""
        return self.broker_completed and not self.is_uncertain and self.exit_code == 0


# ============================================================================
# BrokerDispatcher Implementation
# ============================================================================

class BrokerDispatcher:
    """Narrow integration layer connecting DispatchCoordinator with UnixSocketBrokerClient.

    Enforces strict dispatch ordering and pre-dispatch persistence barriers.
    """

    def __init__(
        self,
        coordinator: DispatchCoordinator,
        broker_client: Optional[UnixSocketBrokerClient] = None,
    ):
        self.coordinator = coordinator
        self.broker_client = broker_client or UnixSocketBrokerClient()

    def dispatch_action(
        self,
        execution_id: str,
        workspace_id: str,
        approval_id: str,
        attempt_number: int,
        fencing_token: int,
        action_id: str,
        target_url: str,
        parameters: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 30,
        environment: str = "development",
        operation_id: Optional[str] = None,
        client_correlation_id: Optional[str] = None,
        raise_on_error: bool = False,
        authorization_manifest: Optional[Dict[str, Any]] = None,
        manifest_signature: Optional[str] = None,
    ) -> BrokerDispatchResult:
        """
        Execute an allowlisted remediation action through the coordinator and broker IPC.

        Ordering:
        1. Validate request parameters and ensure action is in ALLOWED_BROKER_ACTIONS.
        2. Validate or create durable reservation in SQLite registry.
        3. Ensure DISPATCH_PREPARED is journaled and fsynced.
        4. Revalidate operation local identity, workspace, and fencing token.
        5. Append and fsync DOCKER_CALL_STARTED marker to journal and registry.
        6. Only then invoke broker over Unix socket.
        7. Persist completion, nonzero exit failure, or uncertain outcome.

        Pre-Dispatch Persistence Barrier:
        If any step before broker invocation fails, the broker is NEVER contacted.

        Non-Redispatch Invariant:
        Operations with existing DOCKER_CALL_STARTED, terminal, or uncertain states
        are rejected immediately.
        """
        # --------------------------------------------------------------------
        # Step 1: Validate input parameters and action allowlist
        # --------------------------------------------------------------------
        if not action_id or not isinstance(action_id, str):
            raise CoordinatorValidationError("action_id must be a non-empty string.")

        if action_id not in ALLOWED_BROKER_ACTIONS:
            raise CoordinatorValidationError(
                f"Action '{action_id}' is not in allowed broker actions: {ALLOWED_BROKER_ACTIONS}."
            )

        if not execution_id or not isinstance(execution_id, str):
            raise CoordinatorValidationError("execution_id must be a non-empty string.")

        if not workspace_id or not isinstance(workspace_id, str):
            raise CoordinatorValidationError("workspace_id must be a non-empty string.")

        if not approval_id or not isinstance(approval_id, str):
            raise CoordinatorValidationError("approval_id must be a non-empty string.")

        if not target_url or not isinstance(target_url, str):
            raise CoordinatorValidationError("target_url must be a non-empty string.")

        if not isinstance(fencing_token, int) or fencing_token < 0:
            raise CoordinatorValidationError(
                f"fencing_token must be a non-negative integer, got {fencing_token}."
            )

        if not isinstance(attempt_number, int) or attempt_number < 1:
            raise CoordinatorValidationError(
                f"attempt_number must be an integer >= 1, got {attempt_number}."
            )

        if not isinstance(timeout_seconds, int) or not (1 <= timeout_seconds <= 60):
            raise CoordinatorValidationError(
                f"timeout_seconds must be between 1 and 60, got {timeout_seconds}."
            )

        # --------------------------------------------------------------------
        # Step 2: Validate or create durable reservation in SQLite registry
        # --------------------------------------------------------------------
        op: Optional[OperationRecord] = None
        if operation_id:
            op = self.coordinator.registry.get_operation(operation_id)
            if op:
                # Validate identity fields match
                if op.execution_id != execution_id:
                    raise CoordinatorConflictError(
                        f"Conflicting execution_id for operation '{operation_id}': "
                        f"registry has '{op.execution_id}', caller provided '{execution_id}'."
                    )
                if op.workspace_id != workspace_id:
                    raise CoordinatorConflictError(
                        f"Conflicting workspace_id for operation '{operation_id}': "
                        f"registry has '{op.workspace_id}', caller provided '{workspace_id}'."
                    )
                if op.fencing_token != fencing_token:
                    raise CoordinatorConflictError(
                        f"Conflicting fencing_token for operation '{operation_id}': "
                        f"registry has {op.fencing_token}, caller provided {fencing_token}."
                    )
                if op.approval_id != approval_id:
                    raise CoordinatorConflictError(
                        f"Conflicting approval_id for operation '{operation_id}': "
                        f"registry has '{op.approval_id}', caller provided '{approval_id}'."
                    )

        if op is None:
            # Durably reserve operation in SQLite
            op = self.coordinator.reserve_operation(
                execution_id=execution_id,
                workspace_id=workspace_id,
                approval_id=approval_id,
                attempt_number=attempt_number,
                fencing_token=fencing_token,
                operation_id=operation_id,
                metadata={"action_id": action_id, "target_url": target_url},
            )

        op_id = op.operation_id

        # --------------------------------------------------------------------
        # Step 3: Non-Redispatch Invariant Check
        # --------------------------------------------------------------------
        if op.operation_status in (
            OperationStatus.DOCKER_CALL_STARTED,
            OperationStatus.DOCKER_CALL_CONFIRMED,
        ):
            raise CoordinatorInvalidStateError(
                f"Cannot dispatch operation '{op_id}': already started (status '{op.operation_status.value}'). "
                f"Automatic redispatch is strictly forbidden."
            )

        if op.operation_status in TERMINAL_STATUSES:
            raise CoordinatorInvalidStateError(
                f"Cannot dispatch operation '{op_id}': already in terminal/uncertain status '{op.operation_status.value}'. "
                f"Automatic redispatch is strictly forbidden."
            )

        # --------------------------------------------------------------------
        # Step 4: Ensure DISPATCH_PREPARED is journaled and fsynced
        # --------------------------------------------------------------------
        if op.operation_status == OperationStatus.RESERVED:
            _, op = self.coordinator.prepare_dispatch(
                operation_id=op_id,
                execution_id=execution_id,
                fencing_token=fencing_token,
                workspace_id=workspace_id,
                metadata={"action_id": action_id, "target_url": target_url},
            )

        # --------------------------------------------------------------------
        # Step 5: Revalidate operation state before writing start marker
        # --------------------------------------------------------------------
        fresh_op = self.coordinator.registry.get_operation(op_id)
        if not fresh_op or fresh_op.operation_status != OperationStatus.DISPATCH_PREPARED:
            current_st = fresh_op.operation_status.value if fresh_op else "not_found"
            raise CoordinatorInvalidStateError(
                f"Pre-dispatch revalidation failed for operation '{op_id}': "
                f"expected '{OperationStatus.DISPATCH_PREPARED.value}', found '{current_st}'."
            )

        if (
            fresh_op.execution_id != execution_id
            or fresh_op.fencing_token != fencing_token
            or fresh_op.workspace_id != workspace_id
        ):
            raise CoordinatorConflictError(
                f"Pre-dispatch identity revalidation mismatch for operation '{op_id}'."
            )

        # --------------------------------------------------------------------
        # Step 6: Append and fsync DOCKER_CALL_STARTED marker
        # --------------------------------------------------------------------
        # Pre-dispatch persistence barrier: if this fails, broker is NEVER invoked
        start_metadata = {
            "action_id": action_id,
            "target_url": target_url,
            "parameters": parameters or {},
            "environment": environment,
        }
        if authorization_manifest and isinstance(authorization_manifest, dict):
            start_metadata["manifest_id"] = authorization_manifest.get("manifest_id")
        if client_correlation_id:
            start_metadata["client_correlation_id"] = client_correlation_id

        _, op = self.coordinator.record_docker_call_started(
            operation_id=op_id,
            execution_id=execution_id,
            fencing_token=fencing_token,
            workspace_id=workspace_id,
            metadata=start_metadata,
        )

        # --------------------------------------------------------------------
        # Step 7: ONLY THEN invoke broker over restricted Unix socket
        # --------------------------------------------------------------------
        req = BrokerExecuteRequest(
            execution_id=execution_id,
            action_id=action_id,
            parameters=parameters or {},
            target_url=target_url,
            timeout_seconds=timeout_seconds,
            environment=environment,
            authorization_manifest=authorization_manifest,
            manifest_signature=manifest_signature,
        )

        try:
            resp: BrokerExecuteResponse = self.broker_client.execute_action(req)
        except Exception as e:
            # ----------------------------------------------------------------
            # Step 8A: Fail-Closed Uncertainty Handling
            # ----------------------------------------------------------------
            # Because DOCKER_CALL_STARTED was already written to disk, any IPC
            # failure (timeout, connection loss, malformed response) leaves the
            # actual Docker execution outcome indeterminate.
            # Never infer that Docker was not contacted.
            logger.error(
                "Broker IPC failed after DOCKER_CALL_STARTED for operation '%s': %s",
                op_id,
                e,
            )
            unc_reason = f"Broker IPC communication failed after start marker: {e}"
            self.coordinator.record_dispatch_uncertain(
                operation_id=op_id,
                reason=unc_reason,
                metadata={"error_type": type(e).__name__, "details": str(e)},
            )

            if raise_on_error:
                raise ExecutionUncertainError(
                    f"Broker IPC failed after start marker for operation '{op_id}': {e}"
                ) from e

            return BrokerDispatchResult(
                operation_id=op_id,
                execution_id=execution_id,
                action_id=action_id,
                fencing_token=fencing_token,
                status=OperationStatus.DISPATCH_UNCERTAIN,
                is_uncertain=True,
                broker_completed=False,
                error_message=str(e),
                error_category=type(e).__name__,
            )

        # --------------------------------------------------------------------
        # Step 8B: Persist Broker Response (Exit 0 or Nonzero)
        # --------------------------------------------------------------------
        if resp.exit_code == 0:
            self.coordinator.complete_dispatch(
                operation_id=op_id,
                exit_code=0,
                duration_ms=resp.duration_ms,
                output_data=resp.output_data,
                stdout_sample=resp.stdout_sample,
                stderr_sample=resp.stderr_sample,
            )
            return BrokerDispatchResult(
                operation_id=op_id,
                execution_id=execution_id,
                action_id=action_id,
                fencing_token=fencing_token,
                status=OperationStatus.DOCKER_CALL_COMPLETED,
                exit_code=0,
                duration_ms=resp.duration_ms,
                stdout=resp.stdout_sample,
                stderr=resp.stderr_sample,
                output_data=resp.output_data,
                broker_completed=True,
                is_uncertain=False,
            )
        else:
            fail_msg = resp.error_message or f"Container process exited with code {resp.exit_code}"
            fail_category = resp.error_category or "container_nonzero_exit"
            self.coordinator.record_dispatch_failure(
                operation_id=op_id,
                error_message=fail_msg,
                error_category=fail_category,
                exit_code=resp.exit_code,
                metadata={
                    "stdout_sample": resp.stdout_sample,
                    "stderr_sample": resp.stderr_sample,
                    "duration_ms": resp.duration_ms,
                    "output_data": resp.output_data,
                },
            )
            return BrokerDispatchResult(
                operation_id=op_id,
                execution_id=execution_id,
                action_id=action_id,
                fencing_token=fencing_token,
                status=OperationStatus.DISPATCH_FAILED,
                exit_code=resp.exit_code,
                duration_ms=resp.duration_ms,
                stdout=resp.stdout_sample,
                stderr=resp.stderr_sample,
                output_data=resp.output_data,
                error_message=fail_msg,
                error_category=fail_category,
                broker_completed=True,
                is_uncertain=False,
            )
