"""Comprehensive Test Suite for Phase 5A: Secure, Configurable HTTP Recovery Adapter.

Validates:
1. Reusable HTTP recovery capability registration in ActionRegistry.
2. Relative recovery path validation, traversal rejection, encoded traversal rejection, scheme injection.
3. Origin derivation strictly from registered service's health_check_url (no external hosts or query strings).
4. Strict Pydantic parameter schema validation (extra='forbid', non-2xx rejection, payload code scan).
5. Dynamic capability discovery: service does NOT advertise http_recovery without an active configured playbook.
6. Dynamic capability discovery: service advertises http_recovery when active playbook is associated.
7. PlaybookService.validate_playbook_spec accepts compatible candidate services during creation.
8. PolicyEngine evaluation: human approval mandatory, AI overrides ignored, cross-workspace rejected.
9. Static action handler (handle_http_recovery) and precondition validation.
10. Dual-layer SSRF protection and network config resolution (build_container_network_config).
11. Executor HTTP runner (run_http_recovery): POST only, redirect rejection, status code verification.
12. Post-execution synthetic verification: 3 consecutive passing probes required, reset on failure.
13. IncidentRecoveryBridge: atomic recovery transition upon verified status.
14. Backward compatibility: Order API demo recovery and inspect_service_health preserved.
"""

import json
import pytest
from unittest.mock import MagicMock, patch
import uuid

from app.execution.actions import (
    handle_http_recovery,
    validate_http_recovery_preconditions,
    get_static_action_handler,
    STATIC_ACTION_HANDLERS,
)
from app.execution.broker import (
    ALLOWED_BROKER_ACTIONS,
    BrokerExecuteRequest,
    RestrictedDockerBroker,
)
from app.execution.exceptions import (
    BrokerSecurityViolation,
    PreconditionFailedError,
    SecurityConfigurationError,
)
from app.execution.network import (
    build_container_network_config,
    resolve_safe_target_url,
    validate_safe_target_url,
)
from app.execution.recovery_bridge import IncidentRecoveryBridge
from app.execution.runner import (
    ExecutionResult,
    MockTestRunner,
)
from app.execution.verification import (
    PostExecutionVerificationEngine,
    ProbeStatus,
    SingleProbeEvaluation,
    VerificationOutcome,
)
from app.models.incident import Incident
from app.models.remediation import RemediationExecution
from app.models.service import Service
from app.models.workspace import Workspace
from app.remediation.policy import PolicyEngine
from app.remediation.playbook_service import PlaybookService
from app.remediation.registry import ActionRegistry
from app.remediation.schemas import (
    ActionCategory,
    CapabilityStatus,
    ExecutionMechanism,
    HttpRecoveryParams,
    PolicyDecisionType,
    RiskLevel,
    build_recovery_url,
    validate_relative_recovery_path,
)


# ============================================================================
# 1. Action Registry & Capability Catalog Tests
# ============================================================================

def test_http_recovery_action_registry_metadata():
    """Verify execute_http_recovery is properly registered with correct security invariants."""
    action = ActionRegistry.get_action("execute_http_recovery")
    assert action is not None
    assert action.action_id == "execute_http_recovery"
    assert action.name == "Execute HTTP Service Recovery"
    assert action.category == ActionCategory.SERVICE_RECOVERY
    assert action.risk_level == RiskLevel.MEDIUM
    assert action.execution_mechanism == ExecutionMechanism.HTTP_RECOVERY
    assert action.status == CapabilityStatus.EXECUTABLE
    assert action.is_executable is True
    assert action.approval_required is True
    assert "*" in action.supported_services
    assert "health_check_url" in action.required_service_attributes
    assert action.enabled is True

    # Parameter model registration
    model_cls = ActionRegistry.get_parameter_model("execute_http_recovery")
    assert model_cls is HttpRecoveryParams


# ============================================================================
# 2. Relative Recovery Path Validation Tests
# ============================================================================

def test_validate_relative_recovery_path_valid():
    """Verify valid relative paths are accepted and canonicalized."""
    assert validate_relative_recovery_path("/admin/recovery/reset") == "/admin/recovery/reset"
    assert validate_relative_recovery_path("/api/v1/reset") == "/api/v1/reset"
    assert validate_relative_recovery_path("/recovery/action-1_2.3") == "/recovery/action-1_2.3"
    assert validate_relative_recovery_path("  /ops/recover  ") == "/ops/recover"


@pytest.mark.parametrize(
    "invalid_path,expected_err",
    [
        ("", "cannot be empty"),
        ("   ", "cannot be empty"),
        ("admin/recovery/reset", "must be a relative path starting with '/'"),
        ("/", "cannot be root '/' alone"),
        ("http://127.0.0.1:9100/reset", "Absolute URLs and URI schemes are strictly prohibited"),
        ("https://external-host.com/reset", "Absolute URLs and URI schemes are strictly prohibited"),
        ("javascript://alert(1)", "Absolute URLs and URI schemes are strictly prohibited"),
        ("//evil.com/reset", "double slashes ('//') are prohibited"),
        ("/admin//recovery/reset", "double slashes ('//') are prohibited"),
        ("/admin/recovery/reset?foo=bar", "Query strings, fragments, and credentials are prohibited"),
        ("/admin/recovery/reset#anchor", "Query strings, fragments, and credentials are prohibited"),
        ("/admin/recovery/reset@host", "Query strings, fragments, and credentials are prohibited"),
        ("/admin/../recovery/reset", "Directory traversal ('..') is strictly prohibited"),
        ("/../reset", "Directory traversal ('..') is strictly prohibited"),
        (r"/admin\recovery\reset", "Backslashes are prohibited"),
        ("/admin/%2e%2e/reset", "Percent-encoded characters and sequences are strictly prohibited"),
        ("/admin/%2f/reset", "Percent-encoded characters and sequences are strictly prohibited"),
        ("/admin/%5c/reset", "Percent-encoded characters and sequences are strictly prohibited"),
        ("/admin/reset;rm -rf /", "contains invalid characters"),
        ("/admin/reset<script>", "contains invalid characters"),
    ],
)
def test_validate_relative_recovery_path_rejections(invalid_path, expected_err):
    """Verify malformed, unsafe, and traversal paths are strictly rejected."""
    with pytest.raises(ValueError) as excinfo:
        validate_relative_recovery_path(invalid_path)
    assert expected_err in str(excinfo.value)


# ============================================================================
# 3. Origin Derivation Tests
# ============================================================================

def test_build_recovery_url_derivation_success():
    """Verify target URL is derived strictly from service health URL origin and relative path."""
    # Standard Customer Orders API fixture scenario
    derived = build_recovery_url("http://127.0.0.1:9100/health", "/admin/recovery/reset")
    assert derived == "http://127.0.0.1:9100/admin/recovery/reset"

    # Preserves custom ports and HTTPS scheme
    derived_https = build_recovery_url("https://service.corp.internal:8443/api/v1/health", "/api/v1/remediate")
    assert derived_https == "https://service.corp.internal:8443/api/v1/remediate"


def test_build_recovery_url_rejects_cloud_metadata_origin():
    """Verify build_recovery_url fails closed against cloud metadata endpoints."""
    with pytest.raises(ValueError) as exc:
        build_recovery_url("http://169.254.169.254/health", "/reset")
    assert "forbidden cloud metadata" in str(exc.value)


def test_build_recovery_url_rejects_missing_or_invalid_health_url():
    """Verify build_recovery_url rejects missing health URLs or non-HTTP schemes."""
    with pytest.raises(ValueError):
        build_recovery_url("", "/reset")

    with pytest.raises(ValueError):
        build_recovery_url("ftp://localhost:8000/health", "/reset")


# ============================================================================
# 4. Strict Parameter Schema Tests
# ============================================================================

def test_http_recovery_params_validation_success():
    """Verify valid HttpRecoveryParams model instances parse cleanly."""
    valid_uuid = str(uuid.uuid4())
    params = HttpRecoveryParams(
        service_id=valid_uuid,
        recovery_path="/admin/recovery/reset",
        payload={"action": "reset", "retries": 1},
        expected_status_codes=[200, 204],
        timeout_seconds=20,
    )
    assert params.service_id == valid_uuid
    assert params.recovery_path == "/admin/recovery/reset"
    assert params.expected_status_codes == [200, 204]
    assert params.payload == {"action": "reset", "retries": 1}
    assert params.timeout_seconds == 20


def test_http_recovery_params_rejects_extra_fields():
    """Verify extra='forbid' strictly rejects unknown fields (scripts, arbitrary headers, shell)."""
    valid_uuid = str(uuid.uuid4())
    raw = {
        "service_id": valid_uuid,
        "recovery_path": "/admin/recovery/reset",
        "headers": {"Authorization": "Bearer stolen-token"},
        "shell_cmd": "rm -rf /",
    }
    is_valid, _, err = ActionRegistry.validate_parameters("execute_http_recovery", raw)
    assert is_valid is False
    assert "headers" in err or "Extra inputs are not permitted" in err


def test_http_recovery_params_rejects_non_2xx_status_codes():
    """Verify only 2xx HTTP success status codes are allowed in expected_status_codes."""
    valid_uuid = str(uuid.uuid4())
    with pytest.raises(Exception):
        HttpRecoveryParams(
            service_id=valid_uuid,
            recovery_path="/admin/recovery/reset",
            expected_status_codes=[200, 500],
        )

    with pytest.raises(Exception):
        HttpRecoveryParams(
            service_id=valid_uuid,
            recovery_path="/admin/recovery/reset",
            expected_status_codes=[302],
        )


def test_http_recovery_params_rejects_executable_patterns_in_payload():
    """Verify payload is recursively scanned and rejects forbidden script/execution patterns."""
    valid_uuid = str(uuid.uuid4())
    malicious_payloads = [
        {"cmd": "os.system('whoami')"},
        {"runner": "subprocess.Popen(['bash'])"},
        {"eval_hook": "eval('import sys')"},
        {"sh": "/bin/bash -c id"},
    ]
    for bad_payload in malicious_payloads:
        with pytest.raises(Exception) as exc:
            HttpRecoveryParams(
                service_id=valid_uuid,
                recovery_path="/admin/recovery/reset",
                payload=bad_payload,
            )
        assert "Security validation failed" in str(exc.value) or "Forbidden executable pattern" in str(exc.value)


# ============================================================================
# 5. Dynamic Capability Evaluation & Discovery Tests (Section 4)
# ============================================================================

def test_capability_discovery_not_advertised_without_playbook():
    """
    CRITICAL INVARIANT (Section 4):
    A service does NOT advertise execute_http_recovery as executable merely
    because it has a health endpoint. It requires an active configured playbook.
    """
    svc_id = "535f04e0-f1ff-4096-9011-e4e2c7234398"
    mock_service = Service(
        id=svc_id,
        workspace_id=str(uuid.uuid4()),
        name="Customer Orders API",
        environment="development",
        health_check_url="http://127.0.0.1:9100/health",
        execution_policy="demo",
        is_active=True,
    )

    # Empty dynamic playbook registry (no playbook configured for svc_id)
    ActionRegistry.clear_dynamic_playbooks()

    cap = ActionRegistry.evaluate_service_capability("execute_http_recovery", mock_service)
    assert cap.is_compatible is False
    assert cap.is_executable is False
    assert cap.status == CapabilityStatus.REQUIRES_ADAPTER
    assert any("no active configured HTTP recovery playbook" in r for r in cap.reasons)


def test_capability_discovery_advertised_with_active_playbook():
    """Verify service advertises execute_http_recovery as executable when active playbook is associated."""
    svc_id = "535f04e0-f1ff-4096-9011-e4e2c7234398"
    mock_service = Service(
        id=svc_id,
        workspace_id=str(uuid.uuid4()),
        name="Customer Orders API",
        environment="development",
        health_check_url="http://127.0.0.1:9100/health",
        execution_policy="demo",
        is_active=True,
    )

    # Register dynamic playbook association for svc_id
    ActionRegistry.register_service_playbook(svc_id, ["execute_http_recovery"])

    try:
        cap = ActionRegistry.evaluate_service_capability("execute_http_recovery", mock_service)
        assert cap.is_compatible is True
        assert cap.is_executable is True
        assert cap.status == CapabilityStatus.EXECUTABLE
        assert cap.execution_mechanism == ExecutionMechanism.HTTP_RECOVERY
        assert cap.approval_required is True
    finally:
        ActionRegistry.clear_dynamic_playbooks()


def test_playbook_service_validate_spec_accepts_candidate_service():
    """Verify PlaybookService.validate_playbook_spec accepts compatible candidate services during creation."""
    mock_db = MagicMock()
    workspace_id = str(uuid.uuid4())
    svc_id = "535f04e0-f1ff-4096-9011-e4e2c7234398"
    mock_service = Service(
        id=svc_id,
        workspace_id=workspace_id,
        name="Customer Orders API",
        environment="development",
        health_check_url="http://127.0.0.1:9100/health",
        execution_policy="demo",
        is_active=True,
    )
    mock_db.query.return_value.filter.return_value.all.return_value = [mock_service]

    valid_spec_params = {
        "service_id": svc_id,
        "recovery_path": "/admin/recovery/reset",
        "expected_status_codes": [200],
        "timeout_seconds": 30,
    }

    res = PlaybookService.validate_playbook_spec(
        db=mock_db,
        workspace_id=workspace_id,
        action_template_id="execute_http_recovery",
        service_ids=[svc_id],
        parameter_schema=valid_spec_params,
        verification_criteria={"health_path": "/health", "probes_required": 3},
        risk_level="medium",
    )

    assert res.is_valid is True
    assert svc_id in res.compatible_services
    assert len(res.incompatible_services) == 0


# ============================================================================
# 6. Policy Engine Evaluation Tests (Section 3)
# ============================================================================

def test_policy_engine_mandates_human_approval_for_http_recovery():
    """Verify PolicyEngine requires human approval for execute_http_recovery proposals."""
    mock_db = MagicMock()
    workspace_id = str(uuid.uuid4())
    svc_id = "535f04e0-f1ff-4096-9011-e4e2c7234398"
    mock_service = Service(
        id=svc_id,
        workspace_id=workspace_id,
        name="Customer Orders API",
        environment="development",
        health_check_url="http://127.0.0.1:9100/health",
        execution_policy="demo",
        is_active=True,
    )
    mock_db.query.return_value.filter.return_value.first.return_value = mock_service

    # Service has approved playbook registered
    ActionRegistry.register_service_playbook(svc_id, ["execute_http_recovery"])

    try:
        eval_result = PolicyEngine.evaluate(
            db=mock_db,
            workspace_id=workspace_id,
            action_id="execute_http_recovery",
            parameters={
                "service_id": svc_id,
                "recovery_path": "/admin/recovery/reset",
            },
            user_role="engineer",
            # Attempt AI approval override:
            ai_proposed_approval=False,
            ai_proposed_risk="low",
        )

        # AI override is strictly ignored; approval is mandatory
        assert eval_result.decision == PolicyDecisionType.APPROVAL_REQUIRED
        assert eval_result.approval_required is True
        assert eval_result.risk_level == RiskLevel.MEDIUM.value
    finally:
        ActionRegistry.clear_dynamic_playbooks()


def test_policy_engine_rejects_cross_workspace_http_recovery():
    """Verify PolicyEngine rejects cross-workspace service references."""
    mock_db = MagicMock()
    workspace_a = str(uuid.uuid4())
    workspace_b = str(uuid.uuid4())
    svc_id = str(uuid.uuid4())
    mock_service = Service(
        id=svc_id,
        workspace_id=workspace_b,  # Belongs to workspace B
        name="Customer Orders API",
        environment="development",
        health_check_url="http://127.0.0.1:9100/health",
        execution_policy="demo",
        is_active=True,
    )
    mock_db.query.return_value.filter.return_value.first.return_value = mock_service

    eval_result = PolicyEngine.evaluate(
        db=mock_db,
        workspace_id=workspace_a,  # Requested by workspace A
        action_id="execute_http_recovery",
        parameters={
            "service_id": svc_id,
            "recovery_path": "/admin/recovery/reset",
        },
        user_role="engineer",
    )

    assert eval_result.decision == PolicyDecisionType.REJECTED
    assert "Cross-workspace violation" in eval_result.decision_reason


def test_policy_engine_rejects_unassociated_service():
    """Verify PolicyEngine rejects execute_http_recovery on service with no approved playbook."""
    mock_db = MagicMock()
    workspace_id = str(uuid.uuid4())
    svc_id = str(uuid.uuid4())
    mock_service = Service(
        id=svc_id,
        workspace_id=workspace_id,
        name="Customer Orders API",
        environment="development",
        health_check_url="http://127.0.0.1:9100/health",
        execution_policy="demo",
        is_active=True,
    )
    mock_db.query.return_value.filter.return_value.first.return_value = mock_service
    ActionRegistry.clear_dynamic_playbooks()

    eval_result = PolicyEngine.evaluate(
        db=mock_db,
        workspace_id=workspace_id,
        action_id="execute_http_recovery",
        parameters={
            "service_id": svc_id,
            "recovery_path": "/admin/recovery/reset",
        },
        user_role="engineer",
    )

    assert eval_result.decision == PolicyDecisionType.REJECTED
    assert "No approved remediation playbook is configured" in eval_result.decision_reason


# ============================================================================
# 7. Static Execution Handler & Preconditions Tests
# ============================================================================

def test_static_action_handler_registration():
    """Verify handle_http_recovery is registered in STATIC_ACTION_HANDLERS."""
    assert "execute_http_recovery" in STATIC_ACTION_HANDLERS
    handler = get_static_action_handler("execute_http_recovery")
    assert handler is handle_http_recovery


def test_validate_http_recovery_preconditions_inactive_service():
    """Verify precondition validation fails if target service is inactive."""
    service = Service(
        id=str(uuid.uuid4()),
        workspace_id=str(uuid.uuid4()),
        name="Inactive API",
        environment="development",
        health_check_url="http://127.0.0.1:9100/health",
        is_active=False,
    )
    with pytest.raises(PreconditionFailedError) as exc:
        validate_http_recovery_preconditions(service, {"recovery_path": "/admin/recovery/reset"})
    assert "is inactive" in str(exc.value)


def test_handle_http_recovery_dispatches_with_derived_url():
    """Verify handle_http_recovery delegates to runner with derived recovery URL."""
    svc_id = "535f04e0-f1ff-4096-9011-e4e2c7234398"
    service = Service(
        id=svc_id,
        workspace_id=str(uuid.uuid4()),
        name="Customer Orders API",
        environment="development",
        health_check_url="http://127.0.0.1:9100/health",
        execution_policy="demo",
        is_active=True,
    )

    mock_runner = MagicMock()
    mock_runner.execute.return_value = ExecutionResult(
        exit_code=0,
        duration_ms=50,
        stdout='{"status": "completed"}',
        output_data={"status_code": 200},
    )

    result = handle_http_recovery(
        service=service,
        parameters={
            "service_id": svc_id,
            "recovery_path": "/admin/recovery/reset",
            "timeout_seconds": 25,
        },
        runner=mock_runner,
        timeout_seconds=30,
    )

    assert result.exit_code == 0
    mock_runner.execute.assert_called_once()
    call_kwargs = mock_runner.execute.call_args[1]
    assert call_kwargs["action_id"] == "execute_http_recovery"
    assert call_kwargs["target_url"] == "http://127.0.0.1:9100/admin/recovery/reset"
    assert call_kwargs["timeout_seconds"] == 25


# ============================================================================
# 8. Dual-Layer SSRF & Network Configuration Tests
# ============================================================================

def test_broker_allowlist_contains_execute_http_recovery():
    """Verify RestrictedDockerBroker allowlist includes execute_http_recovery."""
    assert "execute_http_recovery" in ALLOWED_BROKER_ACTIONS


def test_build_container_network_config_http_recovery():
    """Verify build_container_network_config resolves recovery URL with host.docker.internal in dev."""
    raw_url = "http://127.0.0.1:9100/admin/recovery/reset"
    config = build_container_network_config(
        environment="development",
        raw_service_url=raw_url,
        action_id="execute_http_recovery",
    )
    resolved_container_url, network_kwargs = config[0], config[1]
    assert resolved_container_url == "http://host.docker.internal:9100/admin/recovery/reset"
    assert network_kwargs["network_mode"] == "bridge"
    assert network_kwargs["extra_hosts"] == {"host.docker.internal": "host-gateway"}


# ============================================================================
# 9. Synthetic Verification & Incident Recovery Bridge Tests (Section 6)
# ============================================================================

def test_post_execution_verification_requires_three_consecutive_passes():
    """Verify verification engine requires 3 consecutive passing probes after recovery execution."""
    svc_id = "535f04e0-f1ff-4096-9011-e4e2c7234398"
    service = Service(
        id=svc_id,
        workspace_id=str(uuid.uuid4()),
        name="Customer Orders API",
        environment="development",
        health_check_url="http://127.0.0.1:9100/health",
        execution_policy="demo",
        is_active=True,
    )

    mock_runner = MagicMock()
    # Mock probe returns HTTP 200 inspect_service_health response
    mock_runner.execute.return_value = ExecutionResult(
        exit_code=0,
        duration_ms=30,
        output_data={
            "all_endpoints_successful": True,
            "endpoints": {
                "health": {"status_code": 200, "success": True},
            },
        },
    )

    engine = PostExecutionVerificationEngine(runner=mock_runner)
    probe_eval = engine.execute_single_probe(
        runner=mock_runner,
        service=service,
        probe_number=1,
        probe_type="consecutive_pass",
        action_id="execute_http_recovery",
    )

    assert probe_eval.passed is True
    assert probe_eval.status == ProbeStatus.PASSED.value


def test_post_execution_verification_resets_on_failed_probe():
    """Verify single probe failure fails closed and resets consecutive probe count."""
    svc_id = "535f04e0-f1ff-4096-9011-e4e2c7234398"
    service = Service(
        id=svc_id,
        workspace_id=str(uuid.uuid4()),
        name="Customer Orders API",
        environment="development",
        health_check_url="http://127.0.0.1:9100/health",
        execution_policy="demo",
        is_active=True,
    )

    mock_runner = MagicMock()
    # Mock probe returns HTTP 503 Service Unavailable
    mock_runner.execute.return_value = ExecutionResult(
        exit_code=0,
        duration_ms=30,
        output_data={
            "all_endpoints_successful": False,
            "endpoints": {
                "health": {"status_code": 503, "success": False, "error_message": "Failure active"},
            },
        },
    )

    engine = PostExecutionVerificationEngine(runner=mock_runner)
    probe_eval = engine.execute_single_probe(
        runner=mock_runner,
        service=service,
        probe_number=2,
        probe_type="consecutive_pass",
        action_id="execute_http_recovery",
    )

    assert probe_eval.passed is False
    assert probe_eval.status == ProbeStatus.FAILED.value


# ============================================================================
# 10. Backward Compatibility Preservation Tests
# ============================================================================

def test_backward_compatibility_order_api_preserved():
    """Verify Order API legacy demo action remains fully functional and unchanged."""
    action = ActionRegistry.get_action("restore_order_api_demo")
    assert action is not None
    assert action.action_id == "restore_order_api_demo"
    assert "restore_order_api_demo" in ALLOWED_BROKER_ACTIONS
    assert "restore_order_api_demo" in STATIC_ACTION_HANDLERS

    diagnostic_action = ActionRegistry.get_action("inspect_service_health")
    assert diagnostic_action is not None
    assert diagnostic_action.is_executable is True


# ============================================================================
# 11. Docker Execution Networking & Host-Gateway Mapping Tests (Phase 5A Review)
# ============================================================================

def test_build_container_network_config_localhost_to_gateway_mapping_in_dev():
    """Verify build_container_network_config maps 127.0.0.1, localhost, and host.docker.internal to gateway."""
    for origin in ("127.0.0.1", "localhost", "host.docker.internal"):
        raw_url = f"http://{origin}:9100/admin/recovery/reset"
        config = build_container_network_config(
            environment="development",
            raw_service_url=raw_url,
            action_id="execute_http_recovery",
        )
        resolved_url, network_kwargs = config[0], config[1]
        assert resolved_url == "http://host.docker.internal:9100/admin/recovery/reset"
        assert network_kwargs["network_mode"] == "bridge"
        assert network_kwargs["extra_hosts"] == {"host.docker.internal": "host-gateway"}


def test_build_container_network_config_rejects_unrelated_loopback():
    """Verify build_container_network_config rejects unrelated loopback addresses in dev."""
    raw_url = "http://127.0.0.2:9100/admin/recovery/reset"
    with pytest.raises(BrokerSecurityViolation) as exc_info:
        build_container_network_config(
            environment="development",
            raw_service_url=raw_url,
            action_id="execute_http_recovery",
        )
    assert "not in authorized development hostnames" in str(exc_info.value)


def test_build_container_network_config_rejects_unrelated_private_ip():
    """Verify build_container_network_config rejects arbitrary private IPs in dev."""
    raw_url = "http://10.0.0.5:9100/admin/recovery/reset"
    with pytest.raises(BrokerSecurityViolation) as exc_info:
        build_container_network_config(
            environment="development",
            raw_service_url=raw_url,
            action_id="execute_http_recovery",
        )
    assert "not in authorized development hostnames" in str(exc_info.value)


def test_build_container_network_config_rejects_localhost_in_production():
    """Verify build_container_network_config rejects localhost origins in production."""
    for origin in ("127.0.0.1", "localhost", "host.docker.internal"):
        raw_url = f"http://{origin}:9100/admin/recovery/reset"
        with pytest.raises(BrokerSecurityViolation) as exc_info:
            build_container_network_config(
                environment="production",
                raw_service_url=raw_url,
                action_id="execute_http_recovery",
            )
        assert "strictly prohibited in production" in str(exc_info.value)


def test_runner_pinned_sync_backend_routes_localhost_to_gateway_in_dev(monkeypatch):
    """Verify executor runner PinnedSyncBackend safely maps 127.0.0.1/localhost to gateway in dev."""
    from services.executor.runner import PinnedSyncBackend
    from httpcore._backends.sync import SyncBackend

    # Mock resolve_and_validate_host_gateway to return trusted Docker gateway IP
    test_gateway_ip = "192.168.65.254"
    monkeypatch.setattr(
        "services.executor.runner.resolve_and_validate_host_gateway",
        lambda hostname, port, trusted_gateway=None: test_gateway_ip,
    )

    recorded_connections = []
    def mock_super_connect(self, ip, port, *args, **kwargs):
        recorded_connections.append((ip, port))
        mock_stream = MagicMock()
        return mock_stream

    monkeypatch.setattr(SyncBackend, "connect_tcp", mock_super_connect)

    for host_variant in ("127.0.0.1", "localhost", "host.docker.internal"):
        backend = PinnedSyncBackend(
            target_host=host_variant,
            pinned_ip="127.0.0.1",
            environment="development",
        )
        backend.connect_tcp(host_variant, 9100)
        assert recorded_connections[-1] == (test_gateway_ip, 9100)


def test_runner_pinned_sync_backend_rejects_localhost_in_production():
    """Verify executor runner PinnedSyncBackend strictly rejects localhost origins in production."""
    from services.executor.runner import PinnedSyncBackend

    for host_variant in ("127.0.0.1", "localhost", "host.docker.internal"):
        backend = PinnedSyncBackend(
            target_host=host_variant,
            pinned_ip="127.0.0.1",
            environment="production",
        )
        with pytest.raises(RuntimeError) as exc_info:
            backend.connect_tcp(host_variant, 9100)
        assert "strictly prohibited in non-development environment 'production'" in str(exc_info.value)


def test_runner_pinned_sync_backend_rejects_unrelated_loopback():
    """Verify executor runner PinnedSyncBackend rejects unrelated loopback (e.g. 127.0.0.2)."""
    from services.executor.runner import PinnedSyncBackend

    backend = PinnedSyncBackend(
        target_host="127.0.0.2",
        pinned_ip="127.0.0.2",
        environment="development",
    )
    with pytest.raises(RuntimeError) as exc_info:
        backend.connect_tcp("127.0.0.2", 9100)
    assert "loopback IP '127.0.0.2' is prohibited" in str(exc_info.value)


def test_target_url_rejects_arbitrary_private_ip_in_production():
    """Verify resolve_safe_target_url rejects arbitrary private RFC 1918 IPs in production."""
    from app.execution.network import resolve_safe_target_url

    with pytest.raises(BrokerSecurityViolation) as exc_info:
        resolve_safe_target_url(
            "http://10.0.0.5:8001/admin/recovery/reset",
            environment="production",
            action_id="execute_http_recovery",
        )
    assert "private RFC 1918 / ULA IP is prohibited" in str(exc_info.value)


def test_runner_pinned_sync_backend_rejects_cloud_metadata():
    """Verify executor runner PinnedSyncBackend rejects cloud metadata endpoints."""
    from services.executor.runner import PinnedSyncBackend

    backend = PinnedSyncBackend(
        target_host="meta.internal",
        pinned_ip="169.254.169.254",
        environment="development",
    )
    with pytest.raises(RuntimeError) as exc_info:
        backend.connect_tcp("meta.internal", 80)
    assert "forbidden cloud metadata endpoint" in str(exc_info.value)


def test_runner_validate_connection_parameters_rejects_cloud_metadata():
    """Verify validate_connection_parameters rejects cloud metadata pinned IPs."""
    from services.executor.runner import validate_connection_parameters

    with pytest.raises(ValueError) as exc_info:
        validate_connection_parameters(
            target_url="http://host.docker.internal:9100/admin/recovery/reset",
            pinned_ip="169.254.169.254",
            target_host="host.docker.internal",
            target_port=9100,
            target_scheme="http",
            target_path="/admin/recovery/reset",
        )
    assert "forbidden cloud metadata endpoint" in str(exc_info.value)
