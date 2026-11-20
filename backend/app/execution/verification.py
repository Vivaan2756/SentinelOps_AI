"""Post-Execution Verification Engine for Phase 4.3.6 Milestone B.

Authoritative Post-Execution Verification Engine implementing:
1. Synthetic health and telemetry probes following remediation execution.
2. Baseline capture (Probe 1 - not counted towards consecutive passing count).
3. Three consecutive passing probes required for cycle success (Probes 2-4).
4. Exactly 4 probe records on standard clean execution (1 baseline + 3 consecutive passing).
5. Bounded timeouts and deadline enforcement:
   - Verification cycle deadline: 45 seconds
   - Individual probe timeout: 6 seconds
   - HTTP request timeout: 2 seconds
6. Telemetry collection per probe:
   - GET /health (Generic: HTTP 200, healthy response - applies to all registered services)
   - GET /demo/status (Demo-specific: failure_active == False - Order API demo workload only)
   - GET /metrics (Telemetry: 5xx error counter delta invariance when Prometheus is configured)
   - See docs/STAGE_3_OPERATIONAL_SECURITY_AND_VERIFICATION_LIMITS.md for detailed generic vs demo contracts.
7. Security:
   - Verification traffic strictly through approved read-only broker action 'inspect_service_health'
   - Zero direct backend network access to remediation target
   - SSRF protection on all probe target URLs
   - Zero remediation actions executed, no redispatch
   - Workspace isolation and fencing checks enforced
   - Worker lease and heartbeat valid during verification_pending
8. State handling:
   - Successful remediation transitions to verification_pending (incident NOT marked recovered)
   - Successful verification prepares transition to verified (incident NOT marked recovered in this milestone)
   - Failed verification marks cycle and execution outcome failed (incident NOT marked recovered)
   - Inconclusive preserves distinction from failure (never treats missing telemetry/broker as success)
"""

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse, urljoin
import uuid

from sqlalchemy.orm import Session

from app.core.config import settings
from app.detector.prober import parse_prometheus_text
from app.execution.exceptions import (
    BrokerSecurityViolation,
    BrokerUnavailableError,
    ConflictingProbePayloadError,
    CrossWorkspaceViolationError,
    ExecutionEnvironmentUnavailable,
    ExecutionUncertainError,
    PreconditionFailedError,
    StaleWorkerFencingError,
    VerificationCycleNotFoundError,
)
from app.execution.manager import RemediationExecutionManager, sanitize_metadata
from app.execution.network import validate_safe_target_url
from app.execution.runner import (
    ExecutionResult,
    ExecutionRunnerInterface,
    get_execution_runner,
)
from app.execution.state_machine import ExecutionState
from app.execution.verification_persistence import (
    VerificationPersistenceService,
    generate_deterministic_probe_id,
)
from app.models.remediation import ExecutionEvent, RemediationExecution
from app.models.service import Service
from app.remediation.registry import ActionRegistry
from app.models.verification import VerificationCycle, VerificationProbeResult

logger = logging.getLogger(__name__)

# Canonical timing constants strictly adhering to Phase 4.3.6 specifications
DEFAULT_CYCLE_DEADLINE_SECONDS = 45
DEFAULT_PROBE_TIMEOUT_SECONDS = 15  # Container dispatch envelope timeout per logical probe
DEFAULT_HTTP_TIMEOUT_SECONDS = 3    # Individual HTTP request timeout inside container
DEFAULT_PROBES_REQUIRED = 3  # 3 consecutive passing probes after baseline capture


class VerificationOutcome(str, Enum):
    """Explicit verification cycle outcomes."""
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class ProbeStatus(str, Enum):
    """Normalized probe result status values."""
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    TIMEOUT = "timeout"


def extract_5xx_metric(metrics_data: Union[str, Dict[str, Any]]) -> Tuple[Optional[float], bool]:
    """
    Extract the relevant 5xx error counter from metrics payload.

    CRITICAL SAFETY INVARIANT:
    A missing metric must NEVER be treated as a successful zero delta.
    Returns (value, is_present). If the metric is missing, is_present is False and value is None.
    """
    if isinstance(metrics_data, dict):
        # 1. Direct key lookups for known Prometheus metric names
        if "order_api_http_5xx_errors_total" in metrics_data:
            return float(metrics_data["order_api_http_5xx_errors_total"]), True

        # Check for any key ending in _5xx_errors_total or http_5xx_errors_total
        for k, v in metrics_data.items():
            k_lower = k.lower()
            if (
                k_lower == "order_api_http_5xx_errors_total"
                or k_lower.endswith("_5xx_errors_total")
                or k_lower == "http_5xx_errors_total"
                or "http_5xx_errors_total" in k_lower
                or k_lower.endswith("_5xx_total")
            ):
                try:
                    return float(v), True
                except (ValueError, TypeError):
                    pass

        # Check if total_5xx_errors was parsed and there were actual 5xx keys
        if "total_5xx_errors" in metrics_data:
            has_explicit_5xx = any(
                "5xx" in k.lower() and k != "total_5xx_errors" for k in metrics_data.keys()
            )
            if has_explicit_5xx:
                try:
                    return float(metrics_data["total_5xx_errors"]), True
                except (ValueError, TypeError):
                    pass

        # Check if raw_text is inside the dictionary (standard broker output)
        if "raw_text" in metrics_data and isinstance(metrics_data["raw_text"], str):
            return extract_5xx_metric(metrics_data["raw_text"])

        return None, False

    elif isinstance(metrics_data, str):
        text = metrics_data.strip()
        if not text:
            return None, False

        # Scan text lines for genuine Prometheus metric lines matching 5xx counters
        has_5xx_counter = False
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line_lower = line.lower()
            if (
                "order_api_http_5xx_errors_total" in line_lower
                or "_5xx_errors_total" in line_lower
                or "http_5xx_errors_total" in line_lower
                or "_5xx_total" in line_lower
                or 'status="5' in line_lower
                or 'status_code="5' in line_lower
            ):
                if not ("_created" in line_lower):
                    has_5xx_counter = True
                    break

        if not has_5xx_counter:
            return None, False

        # Parse text using established prometheus parser
        parsed = parse_prometheus_text(text)
        if "total_5xx_errors" in parsed:
            return float(parsed["total_5xx_errors"]), True

        return None, False

    return None, False


@dataclass
class SingleProbeEvaluation:
    """Detailed evaluation result for a single verification probe."""
    probe_number: int
    probe_type: str  # "baseline" or "health_check"
    target_url: str
    passed: bool
    status: str  # "passed", "failed", "error", "timeout"
    status_code: Optional[int] = None
    latency_ms: Optional[float] = None
    health_healthy: bool = False
    demo_failure_active: Optional[bool] = None
    metrics_5xx_total: Optional[float] = None
    metric_present: bool = False
    delta_5xx: Optional[float] = None
    error_message: Optional[str] = None
    error_category: Optional[str] = None
    probe_output: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationSummary:
    """Structured report returned upon completion of a verification cycle."""
    execution_id: str
    cycle_id: str
    cycle_number: int
    outcome: VerificationOutcome
    status: str
    probes_executed: int
    probes_passed: int
    probes_failed: int
    consecutive_passes: int
    probes_required: int
    baseline_5xx: Optional[float]
    final_5xx: Optional[float]
    duration_ms: float
    error_message: Optional[str] = None
    probe_evaluations: List[SingleProbeEvaluation] = field(default_factory=list)
    sanitized_report: Dict[str, Any] = field(default_factory=dict)


class PostExecutionVerificationEngine:
    """
    Authoritative Post-Execution Verification Engine for Phase 4.3.6 Milestone B.

    Orchestrates synthetic health and telemetry probes following remediation:
    1. Baseline capture (Probe 1 - not counted towards consecutive passing count).
    2. Consecutive passing probes (Probes 2..N until 3 consecutive passes or deadline).
    3. Exactly 4 probe records on standard clean execution (Probe 1 baseline + Probes 2,3,4 passing).
    4. Bounded timeouts:
       - Cycle deadline: 45 seconds
       - Individual probe timeout: 6 seconds
       - HTTP request timeout: 2 seconds
    5. Evaluates 3 read-only telemetry endpoints per probe:
       - GET /health (HTTP 200, healthy response)
       - GET /demo/status (failure_active == False)
       - GET /metrics (valid 5xx metric present, no reset, zero increase vs baseline)
    6. Uses strictly runner.execute("inspect_service_health", ...) — zero direct backend network access.
    7. No remediation actions executed, no redispatch.
    8. Preserves worker lease and heartbeat during verification_pending.
    9. State outcomes: PASS, FAIL, INCONCLUSIVE.
    """

    def __init__(self, runner: Optional[ExecutionRunnerInterface] = None):
        self._runner = runner

    @classmethod
    def transition_to_verification_pending(
        cls,
        *,
        db: Session,
        execution_id: str,
        workspace_id: str,
        worker_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
    ) -> RemediationExecution:
        """
        Transition execution from 'execution_succeeded' (or ensure 'verification_pending')
        while keeping worker lease and fencing token valid.
        """
        execution = (
            db.query(RemediationExecution)
            .filter(RemediationExecution.id == execution_id)
            .with_for_update()
            .first()
        )
        if not execution:
            raise PreconditionFailedError(f"Remediation execution '{execution_id}' not found.")

        if execution.workspace_id != workspace_id:
            raise CrossWorkspaceViolationError(
                f"Cross-workspace violation: Execution belongs to '{execution.workspace_id}', not '{workspace_id}'."
            )

        if fencing_token is not None and execution.fencing_token != fencing_token:
            raise StaleWorkerFencingError(
                f"Stale worker fencing token ({execution.fencing_token} != {fencing_token})."
            )

        if worker_id is not None and execution.locked_by and execution.locked_by != worker_id:
            raise StaleWorkerFencingError(
                f"Execution is locked by worker '{execution.locked_by}', not '{worker_id}'."
            )

        now_utc = datetime.now(timezone.utc)

        # Transition legal from execution_succeeded or execution_uncertain to verification_pending
        if execution.status in (
            ExecutionState.EXECUTION_SUCCEEDED.value,
            ExecutionState.EXECUTION_UNCERTAIN.value,
        ):
            execution.status = ExecutionState.VERIFICATION_PENDING.value
            execution.verification_status = "pending"
            execution.updated_at = now_utc

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type="verification_pending",
                message="Execution transitioned to verification_pending. Post-execution verification cycle initiated.",
                metadata_json=sanitize_metadata({
                    "execution_id": execution.id,
                    "worker_id": worker_id or execution.locked_by,
                    "fencing_token": execution.fencing_token,
                }),
                timestamp=now_utc,
            )
            db.add(event)
            db.flush()
        elif execution.status == ExecutionState.VERIFICATION_PENDING.value:
            # Already verification_pending
            pass
        else:
            raise PreconditionFailedError(
                f"Cannot transition execution '{execution_id}' to verification_pending from status '{execution.status}'."
            )

        return execution

    def execute_single_probe(
        self,
        *,
        runner: ExecutionRunnerInterface,
        service: Service,
        probe_number: int,
        probe_type: str,
        baseline_5xx: Optional[float] = None,
        http_timeout_seconds: int = DEFAULT_HTTP_TIMEOUT_SECONDS,
        probe_timeout_seconds: int = DEFAULT_PROBE_TIMEOUT_SECONDS,
        execution_id: Optional[str] = None,
        action_id: Optional[str] = None,
    ) -> SingleProbeEvaluation:
        """
        Execute an individual synthetic probe against target service:
        Collects:
        1. GET /health (or custom health path)
        2. GET /demo/status (for Order API demo service)
        3. GET /metrics (for Prometheus monitored services)
        Enforces 6s probe timeout and 2s individual HTTP timeout.
        Dispatches strictly through runner.execute('inspect_service_health', ...).
        """
        start_time = time.time()
        health_check_url = service.health_check_url
        if not health_check_url:
            return SingleProbeEvaluation(
                probe_number=probe_number,
                probe_type=probe_type,
                target_url="",
                passed=False,
                status=ProbeStatus.ERROR.value,
                error_message=f"Service '{service.name}' has no configured health_check_url.",
                error_category="service_configuration_error",
            )

        # Base target URL and service-specific diagnostic parameters
        parsed = urlparse(health_check_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        health_url = health_check_url  # Preserves custom path (e.g. /api/v1/system/health)
        demo_status_url = f"{base_url}/demo/status"
        metrics_url = f"{base_url}/metrics"

        service_env = service.environment or "development"
        # STRICT AUDIT-3.1-02: Demo probe / metrics are NEVER triggered by service name alone.
        # Requires action_id to be restore_order_api_demo (or None during standalone probe) AND explicit demo configuration.
        is_demo_service = (action_id in (None, "restore_order_api_demo")) and ActionRegistry.is_demo_service(service, "order_api")
        has_prometheus_metrics = (service.monitoring_method or "").lower() == "prometheus"

        # Validate probe URLs against centralized SSRF protections
        try:
            validate_safe_target_url(health_url, environment=service_env, action_id="inspect_service_health")
            if is_demo_service:
                validate_safe_target_url(demo_status_url, environment=service_env, action_id="inspect_service_health")
            if is_demo_service or has_prometheus_metrics:
                validate_safe_target_url(metrics_url, environment=service_env, action_id="inspect_service_health")
        except BrokerSecurityViolation as e:
            return SingleProbeEvaluation(
                probe_number=probe_number,
                probe_type=probe_type,
                target_url=health_url,
                passed=False,
                status=ProbeStatus.ERROR.value,
                error_message=f"Pre-flight SSRF validation blocked probe: {str(e)}",
                error_category="ssrf_violation",
            )

        probe_output: Dict[str, Any] = {}
        health_healthy = False
        demo_failure_active: Optional[bool] = None
        current_5xx: Optional[float] = None
        metric_present = False
        delta_5xx: Optional[float] = None
        error_msgs: List[str] = []
        is_timeout = False

        params = {
            "service_id": str(service.id),
            "health_path": parsed.path or "/health",
            "is_demo_service": is_demo_service,
            "has_prometheus_metrics": has_prometheus_metrics,
        }

        # Dispatch unified diagnostic probe via runner.execute (single container execution)
        try:
            res = runner.execute(
                action_id="inspect_service_health",
                parameters=params,
                timeout_seconds=probe_timeout_seconds,
                target_url=health_url,
                environment=service_env,
                execution_id=execution_id,
            )
        except (BrokerUnavailableError, ExecutionEnvironmentUnavailable):
            raise
        except Exception as e:
            res = None
            error_msgs.append(f"Runner dispatch error: {str(e)}")

        if res is not None:
            if res.exit_code == 124 or res.error_category == "timeout":
                is_timeout = True
                error_msgs.append(f"Diagnostic probe #{probe_number} timed out after {probe_timeout_seconds}s.")
            elif res.exit_code != 0:
                error_msgs.append(f"Diagnostic probe #{probe_number} container failed (exit code {res.exit_code}): {res.error_message}")
            else:
                out = res.output_data or {}
                endpoints = out.get("endpoints")

                # Resolve endpoint dictionaries (supports both unified schema and legacy single-dict mocks)
                if endpoints and isinstance(endpoints, dict):
                    health_ep = endpoints.get("health") or {}
                    demo_ep = endpoints.get("demo_status") or {}
                    metrics_ep = endpoints.get("metrics") or {}
                else:
                    health_ep = out.get("health") or out
                    demo_ep = out.get("demo_status") or out
                    metrics_ep = out.get("metrics") or out

                # 1. Health evaluation
                health_data = health_ep.get("output_data") or health_ep.get("data") or {}
                health_status = health_ep.get("status_code", 200)
                status_val = str(health_data.get("status", "")).lower() if isinstance(health_data, dict) else ""
                if health_ep.get("success", False) or (health_status == 200 and (status_val in ("healthy", "ok") or not status_val)):
                    health_healthy = True
                else:
                    err = health_ep.get("error_message") or f"GET {parsed.path or '/health'} returned non-healthy status: '{status_val}'."
                    error_msgs.append(err)

                # 2. Demo status evaluation (only required for Order API demo services)
                if is_demo_service:
                    demo_data = demo_ep.get("output_data") or demo_ep.get("data") or {}
                    demo_failure_active = bool(demo_data.get("failure_active", False)) if isinstance(demo_data, dict) else False
                    if demo_failure_active:
                        reason = demo_data.get("failure_reason", "Failure active")
                        error_msgs.append(f"GET /demo/status reports active failure: {reason}.")
                    elif demo_ep.get("error_message"):
                        error_msgs.append(demo_ep["error_message"])
                else:
                    demo_failure_active = False

                # 3. Metrics evaluation
                if is_demo_service or has_prometheus_metrics:
                    metrics_raw = (
                        metrics_ep.get("raw_text")
                        or metrics_ep.get("output_data")
                        or metrics_ep.get("data")
                        or ""
                    )
                    metrics_raw_str = metrics_raw.get("raw_text", "") if isinstance(metrics_raw, dict) else str(metrics_raw)
                    val, is_present = extract_5xx_metric(metrics_raw_str)
                    metric_present = is_present
                    current_5xx = val
                    if (is_demo_service or has_prometheus_metrics) and not is_present:
                        error_msgs.append("Missing required 5xx error counter in /metrics telemetry.")
                    elif is_present and baseline_5xx is not None:
                        if current_5xx < baseline_5xx:
                            error_msgs.append(
                                f"Metric counter reset detected: current 5xx ({current_5xx}) "
                                f"< baseline ({baseline_5xx}). Missing/reset metric rejected."
                            )
                        else:
                            delta_5xx = current_5xx - baseline_5xx
                            if delta_5xx > 0:
                                error_msgs.append(
                                    f"5xx error counter increased: delta = {delta_5xx} "
                                    f"(current: {current_5xx}, baseline: {baseline_5xx})."
                                )
                    else:
                        delta_5xx = 0.0
                else:
                    # Non-Prometheus monitoring (e.g. opentelemetry or builtin): metric not required for health pass
                    metric_present = True
                    delta_5xx = 0.0

                # Assemble structured probe output
                probe_output["health"] = {
                    "exit_code": res.exit_code,
                    "status_code": health_ep.get("status_code", 200 if health_healthy else None),
                    "duration_ms": health_ep.get("duration_ms", res.duration_ms),
                    "output_data": health_data,
                    "error_message": health_ep.get("error_message"),
                }
                if is_demo_service:
                    probe_output["demo_status"] = {
                        "exit_code": res.exit_code,
                        "status_code": demo_ep.get("status_code", 200 if demo_failure_active is False else None),
                        "duration_ms": demo_ep.get("duration_ms", res.duration_ms),
                        "output_data": demo_data,
                        "error_message": demo_ep.get("error_message"),
                    }
                else:
                    probe_output["demo_status"] = {
                        "status": "skipped",
                        "reason": "Not an Order API demo service",
                    }
                if is_demo_service or has_prometheus_metrics:
                    probe_output["metrics"] = {
                        "exit_code": res.exit_code,
                        "status_code": metrics_ep.get("status_code", 200 if metric_present else None),
                        "duration_ms": metrics_ep.get("duration_ms", res.duration_ms),
                        "error_message": metrics_ep.get("error_message"),
                        "extracted_5xx": val,
                        "metric_present": is_present,
                        "delta_5xx": delta_5xx,
                    }
                else:
                    probe_output["metrics"] = {
                        "status": "skipped",
                        "reason": f"Monitoring method '{service.monitoring_method}' does not require Prometheus scrapers",
                    }
                probe_output["total_container_duration_ms"] = res.duration_ms
        else:
            status = ProbeStatus.ERROR.value

        total_latency_ms = round((time.time() - start_time) * 1000, 2)

        # Evaluation criteria for passing probe:
        # 1. Health endpoint returned healthy
        # 2. Demo status returned failure_active == False (for demo services)
        # 3. Metrics returned valid present counter, no counter reset, zero increase (for demo/Prometheus services)
        # 4. No timeouts or execution errors
        passed = (
            health_healthy
            and (demo_failure_active is False)
            and (metric_present if (is_demo_service or has_prometheus_metrics) else True)
            and (delta_5xx == 0.0 or delta_5xx is None)
            and not is_timeout
            and len(error_msgs) == 0
        )

        status = ProbeStatus.PASSED.value if passed else (
            ProbeStatus.TIMEOUT.value if is_timeout else ProbeStatus.FAILED.value
        )
        combined_error = "; ".join(error_msgs) if error_msgs else None

        return SingleProbeEvaluation(
            probe_number=probe_number,
            probe_type=probe_type,
            target_url=health_url,
            passed=passed,
            status=status,
            status_code=200 if passed else None,
            latency_ms=total_latency_ms,
            health_healthy=health_healthy,
            demo_failure_active=demo_failure_active,
            metrics_5xx_total=current_5xx,
            metric_present=metric_present,
            delta_5xx=delta_5xx,
            error_message=combined_error,
            error_category="timeout" if is_timeout else ("validation_failed" if not passed else None),
            probe_output=sanitize_metadata(probe_output),
        )

    def run_verification_cycle(
        self,
        *,
        db: Session,
        execution_id: str,
        workspace_id: str,
        service: Optional[Service] = None,
        runner: Optional[ExecutionRunnerInterface] = None,
        worker_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        cycle_number: int = 1,
        timeout_seconds: int = DEFAULT_CYCLE_DEADLINE_SECONDS,
        probe_timeout_seconds: int = DEFAULT_PROBE_TIMEOUT_SECONDS,
        http_timeout_seconds: int = DEFAULT_HTTP_TIMEOUT_SECONDS,
        probes_required: int = DEFAULT_PROBES_REQUIRED,
        probe_interval_seconds: float = 0.0,
        recover_incident: bool = False,
    ) -> VerificationSummary:
        """
        Orchestrate a complete post-execution verification cycle.

        Sequence:
        1. Pre-flight checks: validates execution, workspace isolation, and monotonic fencing token.
        2. Transition execution to 'verification_pending' (if not already).
        3. Create or retrieve durable VerificationCycle record (deadline = start + 45s).
        4. Probe 1: Baseline capture (NOT counted towards consecutive passes).
        5. Probes 2..N: Consecutive passing probes until 3 consecutive passes or deadline.
           - If a probe flaps/fails, consecutive_passes is RESET to 0.
           - Probes continue until 3 consecutive passes or deadline reached.
        6. Exactly 4 probe records on standard clean execution (Probe 1 baseline + Probes 2,3,4).
        7. Enforce deadline bounds and lease heartbeats.
        8. Atomic outcome finalization:
           - PASS -> cycle passed, execution verified (incident NOT marked recovered).
           - FAIL -> cycle failed, execution verification_failed (incident NOT marked recovered).
           - INCONCLUSIVE -> cycle uncertain, execution inconclusive (incident NOT marked recovered).
        """
        cycle_start_time = time.time()
        now_utc = datetime.now(timezone.utc)
        deadline_time = now_utc + timedelta(seconds=timeout_seconds)

        # 1. Fetch and validate execution
        execution = (
            db.query(RemediationExecution)
            .filter(RemediationExecution.id == execution_id)
            .with_for_update()
            .first()
        )
        if not execution:
            raise PreconditionFailedError(f"Remediation execution '{execution_id}' does not exist.")

        if execution.workspace_id != workspace_id:
            raise CrossWorkspaceViolationError(
                f"Cross-workspace violation: Execution belongs to workspace '{execution.workspace_id}', not '{workspace_id}'."
            )

        expected_token = fencing_token if fencing_token is not None else execution.fencing_token
        if execution.fencing_token != expected_token:
            raise StaleWorkerFencingError(
                f"Stale worker fencing token: execution has {execution.fencing_token}, expected {expected_token}."
            )

        active_worker = worker_id or execution.locked_by
        if active_worker and execution.locked_by and execution.locked_by != active_worker:
            raise StaleWorkerFencingError(
                f"Execution is locked by worker '{execution.locked_by}', not '{active_worker}'."
            )

        # 2. Resolve target service
        target_service = service
        if target_service is None and execution.target_service_id:
            target_service = (
                db.query(Service)
                .filter(Service.id == execution.target_service_id)
                .first()
            )
        if not target_service:
            raise PreconditionFailedError(
                f"Target service for execution '{execution_id}' could not be resolved."
            )
        if target_service.workspace_id != workspace_id:
            raise CrossWorkspaceViolationError(
                f"Target service '{target_service.id}' belongs to workspace '{target_service.workspace_id}', not '{workspace_id}'."
            )

        # 3. Transition execution to verification_pending (preserves worker lease)
        self.transition_to_verification_pending(
            db=db,
            execution_id=execution_id,
            workspace_id=workspace_id,
            worker_id=active_worker,
            fencing_token=expected_token,
        )

        # 4. Resolve runner (fails closed if unavailable outside test environment)
        effective_runner = runner or self._runner or get_execution_runner()

        # 5. Create or retrieve durable VerificationCycle
        cycle = VerificationPersistenceService.create_or_get_verification_cycle(
            db=db,
            execution_id=execution_id,
            workspace_id=workspace_id,
            cycle_number=cycle_number,
            started_at=now_utc,
            deadline_at=deadline_time,
            timeout_seconds=timeout_seconds,
            fencing_token=expected_token,
            verifying_worker_id=active_worker,
            probes_required=probes_required,
            cycle_metadata={
                "probes_required_after_baseline": probes_required,
                "timeout_seconds": timeout_seconds,
                "probe_timeout_seconds": probe_timeout_seconds,
                "http_timeout_seconds": http_timeout_seconds,
            },
        )
        cycle.status = "running"
        db.flush()

        probe_evaluations: List[SingleProbeEvaluation] = []
        consecutive_passes = 0
        baseline_5xx: Optional[float] = None
        is_inconclusive = False
        inconclusive_reason: Optional[str] = None
        fatal_error: Optional[str] = None
        last_probe_error: Optional[str] = None

        # ====================================================================
        # Phase 1: Probe 1 - Baseline Capture (NOT counted towards consecutive passes)
        # ====================================================================
        try:
            probe1 = self.execute_probe_with_persistence(
                db=db,
                cycle=cycle,
                runner=effective_runner,
                service=target_service,
                probe_number=1,
                probe_type="baseline",
                baseline_5xx=None,
                http_timeout_seconds=http_timeout_seconds,
                probe_timeout_seconds=probe_timeout_seconds,
                execution_id=execution_id,
            )
            probe_evaluations.append(probe1)

            # STRICT AUDIT-3.1-02: Demo metrics are NEVER required based on service name alone.
            is_order_api_demo = (
                execution.action_id == "restore_order_api_demo"
                and ActionRegistry.is_demo_service(target_service, "order_api", db=db)
            )
            has_prometheus_metrics = (target_service.monitoring_method or "").lower() == "prometheus"
            requires_metrics = is_order_api_demo or has_prometheus_metrics

            if requires_metrics and (not probe1.metric_present or probe1.metrics_5xx_total is None):
                fatal_error = probe1.error_message or "Baseline capture failed: required metrics telemetry is missing or invalid."
            elif not probe1.passed:
                fatal_error = probe1.error_message or "Baseline capture failed: health check was not healthy."
            else:
                baseline_5xx = probe1.metrics_5xx_total
                # Strict invariant: Probe 1 is baseline capture and NOT counted toward consecutive passes
                consecutive_passes = 0

        except (BrokerUnavailableError, ExecutionEnvironmentUnavailable) as e:
            is_inconclusive = True
            inconclusive_reason = f"Broker infrastructure unavailable during baseline capture: {str(e)}"
        except StaleWorkerFencingError:
            raise
        except Exception as e:
            fatal_error = f"Unexpected error during baseline capture: {str(e)}"

        # ====================================================================
        # Phase 2: Probes 2..N - Consecutive Passing Probes (Target: 3 consecutive passes)
        # ====================================================================
        current_probe_num = 2
        # Maximum safety bounds: stop if deadline exceeded or after 10 probes
        max_probe_attempts = 10

        while (
            not fatal_error
            and not is_inconclusive
            and consecutive_passes < probes_required
            and current_probe_num <= max_probe_attempts
        ):
            # Check cycle deadline expiration
            if time.time() - cycle_start_time >= timeout_seconds:
                fatal_error = f"Verification cycle deadline of {timeout_seconds}s exceeded."
                break

            # Heartbeat lease liveness if worker_id and fencing_token are provided
            if active_worker and expected_token is not None:
                try:
                    RemediationExecutionManager.heartbeat_lease(
                        execution_id=execution_id,
                        worker_id=active_worker,
                        expected_fencing_token=expected_token,
                        lease_seconds=90,
                        db=db,
                    )
                except StaleWorkerFencingError as fencing_err:
                    raise fencing_err
                except Exception as hb_err:
                    logger.warning("Heartbeat during verification warning: %s", str(hb_err))

            # Optional pause between probes (default 0s in fast tests)
            if probe_interval_seconds > 0.0:
                time.sleep(probe_interval_seconds)

            try:
                probe_eval = self.execute_probe_with_persistence(
                    db=db,
                    cycle=cycle,
                    runner=effective_runner,
                    service=target_service,
                    probe_number=current_probe_num,
                    probe_type="health_check",
                    baseline_5xx=baseline_5xx,
                    http_timeout_seconds=http_timeout_seconds,
                    probe_timeout_seconds=probe_timeout_seconds,
                    execution_id=execution_id,
                )
                probe_evaluations.append(probe_eval)

                if probe_eval.passed:
                    consecutive_passes += 1
                else:
                    # FLAPPING RESET: Consecutive passing probe count resets to zero
                    consecutive_passes = 0
                    if probe_eval.error_message:
                        last_probe_error = probe_eval.error_message
                    if probe_eval.status == ProbeStatus.TIMEOUT.value:
                        # Timeout probe
                        pass

            except (BrokerUnavailableError, ExecutionEnvironmentUnavailable) as e:
                is_inconclusive = True
                inconclusive_reason = f"Broker infrastructure unavailable during probe #{current_probe_num}: {str(e)}"
                break
            except StaleWorkerFencingError:
                raise
            except Exception as e:
                fatal_error = f"Probe #{current_probe_num} failed with unexpected exception: {str(e)}"
                break

            current_probe_num += 1

        # Check deadline once more after loop
        if not fatal_error and not is_inconclusive and consecutive_passes < probes_required:
            detail = f": {last_probe_error}" if last_probe_error else ""
            fatal_error = f"Verification cycle failed: reached {consecutive_passes}/{probes_required} consecutive passes within deadline{detail}."

        duration_ms = round((time.time() - cycle_start_time) * 1000, 2)
        now_final = datetime.now(timezone.utc)
        final_5xx = probe_evaluations[-1].metrics_5xx_total if probe_evaluations else None

        # ====================================================================
        # Phase 3: Finalize Outcome & Commit Atomically
        # ====================================================================
        if is_inconclusive:
            outcome = VerificationOutcome.INCONCLUSIVE
            cycle.status = "uncertain"
            cycle.completed_at = now_final
            execution.verification_status = "inconclusive"
            execution.uncertain_reason = f"VERIFICATION_INCONCLUSIVE: {inconclusive_reason}"
            err_msg = inconclusive_reason
            event_type = "verification_uncertain"
            event_msg = f"Verification cycle #{cycle_number} inconclusive: {inconclusive_reason}"

        elif consecutive_passes >= probes_required and not fatal_error:
            outcome = VerificationOutcome.PASS
            cycle.status = "passed"
            cycle.completed_at = now_final
            if not (recover_incident and execution.incident_id):
                execution.status = ExecutionState.VERIFIED.value
                execution.verification_status = "verified"
            err_msg = None
            event_type = "verified"
            event_msg = (
                f"Post-execution verification passed: {probes_required} consecutive passing probes "
                f"confirmed following baseline capture (total probes: {len(probe_evaluations)})."
            )
            # CRITICAL ARCHITECTURAL BOUNDARY:
            # Do NOT independently mark the incident recovered in this milestone.
            # Incident recovery bridge is strictly reserved for the next milestone.

        else:
            outcome = VerificationOutcome.FAIL
            cycle.status = "timed_out" if ("deadline" in (fatal_error or "").lower()) else "failed"
            cycle.completed_at = now_final
            execution.status = ExecutionState.VERIFICATION_FAILED.value
            execution.verification_status = "failed"
            err_msg = fatal_error or "Verification checks failed."
            event_type = "verification_failed"
            event_msg = f"Post-execution verification cycle #{cycle_number} failed: {err_msg}"
            # Incident is NOT marked recovered.

        report = {
            "execution_id": execution.id,
            "cycle_id": cycle.id,
            "cycle_number": cycle_number,
            "outcome": outcome.value,
            "consecutive_passes": consecutive_passes,
            "probes_required": probes_required,
            "total_probes_recorded": len(probe_evaluations),
            "baseline_5xx": baseline_5xx,
            "final_5xx": final_5xx,
            "duration_ms": duration_ms,
            "error_message": err_msg,
            "probes": [
                {
                    "probe_number": p.probe_number,
                    "probe_type": p.probe_type,
                    "passed": p.passed,
                    "status": p.status,
                    "latency_ms": p.latency_ms,
                    "error_message": p.error_message,
                    "metrics_5xx": p.metrics_5xx_total,
                    "delta_5xx": p.delta_5xx,
                }
                for p in probe_evaluations
            ],
        }
        sanitized_rep = sanitize_metadata(report)

        cycle.cycle_metadata = sanitized_rep
        cycle.updated_at = now_final
        execution.verification_output = sanitized_rep
        execution.updated_at = now_final

        if recover_incident and outcome == VerificationOutcome.PASS and execution.incident_id:
            from app.execution.recovery_bridge import IncidentRecoveryBridge
            db.flush()
            IncidentRecoveryBridge.recover_incident_on_verification_success(
                db=db,
                execution_id=execution.id,
                workspace_id=workspace_id,
                cycle_id=cycle.id,
                incident_id=execution.incident_id,
                worker_id=active_worker,
                fencing_token=expected_token,
                auto_commit=True,
            )
        else:
            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type=event_type,
                message=event_msg,
                metadata_json=sanitized_rep,
                timestamp=now_final,
            )
            db.add(event)
            db.commit()

        return VerificationSummary(
            execution_id=execution.id,
            cycle_id=cycle.id,
            cycle_number=cycle_number,
            outcome=outcome,
            status=cycle.status,
            probes_executed=len(probe_evaluations),
            probes_passed=cycle.probes_passed,
            probes_failed=cycle.probes_failed,
            consecutive_passes=consecutive_passes,
            probes_required=probes_required,
            baseline_5xx=baseline_5xx,
            final_5xx=final_5xx,
            duration_ms=duration_ms,
            error_message=err_msg,
            probe_evaluations=probe_evaluations,
            sanitized_report=sanitized_rep,
        )

    def execute_probe_with_persistence(
        self,
        *,
        db: Session,
        cycle: VerificationCycle,
        runner: ExecutionRunnerInterface,
        service: Service,
        probe_number: int,
        probe_type: str,
        baseline_5xx: Optional[float] = None,
        http_timeout_seconds: int = DEFAULT_HTTP_TIMEOUT_SECONDS,
        probe_timeout_seconds: int = DEFAULT_PROBE_TIMEOUT_SECONDS,
        execution_id: Optional[str] = None,
    ) -> SingleProbeEvaluation:
        """Execute a probe and immediately persist the result via VerificationPersistenceService."""
        act_id = getattr(getattr(cycle, "execution", None), "action_id", None)
        probe_eval = self.execute_probe(
            runner=runner,
            service=service,
            probe_number=probe_number,
            probe_type=probe_type,
            baseline_5xx=baseline_5xx,
            http_timeout_seconds=http_timeout_seconds,
            probe_timeout_seconds=probe_timeout_seconds,
            execution_id=execution_id,
            action_id=act_id,
        )

        VerificationPersistenceService.record_probe_result(
            db=db,
            cycle_id=cycle.id,
            probe_number=probe_number,
            probe_type=probe_type,
            target_url=probe_eval.target_url,
            passed=probe_eval.passed,
            status=probe_eval.status,
            status_code=probe_eval.status_code,
            latency_ms=probe_eval.latency_ms,
            probe_output=probe_eval.probe_output,
            error_message=probe_eval.error_message,
        )
        return probe_eval

    # Alias for execute_single_probe
    execute_probe = execute_single_probe
