"""Static Remediation Action Handlers & Pre-Flight Validators for Phase 4.3.

Implements ONLY the two actions defined in docs/PHASE_4_3_EXECUTION_ARCHITECTURE.md:
1. restore_order_api_demo (MEDIUM risk, service recovery, requires human approval)
2. inspect_service_health (LOW risk, read-only diagnostics)

CRITICAL SECURITY RULES:
- Handlers are fixed, predefined functions — no dynamic code execution.
- Parameters validated using strict Pydantic schemas (extra='forbid').
- Zero shell commands, subprocesses, Python scripts, or image names accepted.
- URLs are NEVER constructed from user input; derived strictly from registered Service.
- Environment restricted strictly to 'development'.
"""

from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse

from app.execution.exceptions import BrokerSecurityViolation, PreconditionFailedError
from app.execution.network import validate_safe_target_url
from app.execution.runner import ExecutionResult, ExecutionRunnerInterface
from app.models.service import Service
from app.remediation.registry import ActionRegistry
from app.remediation.schemas import (
    HttpRecoveryParams,
    InspectServiceHealthParams,
    RestoreOrderApiDemoParams,
    build_recovery_url,
)


def _check_service_target_url_ssrf(service: Service, action_id: str) -> None:
    """Centralized pre-flight SSRF validation using network.py validator."""
    if not service.health_check_url:
        raise PreconditionFailedError(f"Service '{service.name}' has no configured health check URL.")
    try:
        validate_safe_target_url(
            service.health_check_url,
            environment=service.environment or "development",
            action_id=action_id,
        )
    except BrokerSecurityViolation as e:
        raise PreconditionFailedError(f"Pre-flight SSRF validation failed: {str(e)}")


def validate_restore_order_api_demo_preconditions(service: Service) -> None:
    """Validate runtime preconditions for restore_order_api_demo."""
    if not service.is_active:
        raise PreconditionFailedError(
            f"Precondition failed: Target service '{service.name}' is inactive."
        )
    if (service.environment or "").lower() != "development":
        raise PreconditionFailedError(
            f"Action 'restore_order_api_demo' is restricted to 'development' environment. "
            f"Target service environment is '{service.environment}'."
        )
    _check_service_target_url_ssrf(service, "restore_order_api_demo")
    if not ActionRegistry.is_action_supported_for_service("restore_order_api_demo", service):
        raise PreconditionFailedError(
            f"Action 'restore_order_api_demo' is not supported for service '{service.name}'."
        )


def validate_inspect_service_health_preconditions(service: Service) -> None:
    """Validate runtime preconditions for inspect_service_health."""
    if not service.is_active:
        raise PreconditionFailedError(
            f"Precondition failed: Target service '{service.name}' is inactive."
        )
    _check_service_target_url_ssrf(service, "inspect_service_health")


def validate_http_recovery_preconditions(service: Service, parameters: Dict[str, Any]) -> str:
    """
    Validate runtime preconditions and derive target URL for execute_http_recovery (Phase 5A).
    - Service is active
    - Service has valid health_check_url
    - Environment is supported
    - Service has explicitly configured and authorized recovery endpoint
    - Method is POST
    - Parameters cannot override the authorized service recovery endpoint
    - Derived target URL passes pre-flight SSRF and DNS checks
    Returns the securely derived full recovery URL.
    """
    if not service.is_active:
        raise PreconditionFailedError(
            f"Precondition failed: Target service '{service.name}' is inactive."
        )
    if not service.health_check_url:
        raise PreconditionFailedError(
            f"Precondition failed: Target service '{service.name}' has no configured health check URL."
        )

    # Recovery configuration check
    if not getattr(service, "recovery_enabled", False) or not getattr(service, "recovery_endpoint", None):
        raise PreconditionFailedError(
            f"Precondition failed: Service '{service.name}' has no authorized recovery endpoint configured."
        )

    # Cross-service mismatch check
    param_service_id = parameters.get("service_id")
    if param_service_id and str(param_service_id) != str(service.id):
        raise PreconditionFailedError(
            f"Cross-service target mismatch: parameter service_id '{param_service_id}' "
            f"does not match execution target service '{service.id}'."
        )

    # Method check
    recovery_method = (getattr(service, "recovery_method", "POST") or "POST").upper().strip()
    if recovery_method != "POST":
        raise PreconditionFailedError(
            f"Precondition failed: Unsupported recovery method '{recovery_method}'. Only POST is supported."
        )

    env = (service.environment or "development").lower().strip()
    if env not in ("development", "staging", "production"):
        raise PreconditionFailedError(
            f"Action 'execute_http_recovery' is not permitted in environment '{service.environment}'."
        )

    authorized_path = service.recovery_endpoint
    param_path = parameters.get("recovery_path")

    # Anti-override check: client-supplied recovery_path cannot override authorized service recovery endpoint
    if param_path and param_path.strip() != authorized_path.strip():
        raise PreconditionFailedError(
            f"Precondition failed: Execution parameter recovery_path ('{param_path}') "
            f"cannot override authorized service recovery endpoint ('{authorized_path}')."
        )

    try:
        derived_url = build_recovery_url(service.health_check_url, authorized_path)
    except ValueError as e:
        raise PreconditionFailedError(f"Precondition failed: Invalid recovery URL configuration: {str(e)}")

    try:
        validate_safe_target_url(
            derived_url,
            environment=env,
            action_id="execute_http_recovery",
        )
    except BrokerSecurityViolation as e:
        raise PreconditionFailedError(f"Pre-flight SSRF validation failed for recovery URL: {str(e)}")

    return derived_url



def handle_restore_order_api_demo(
    *,
    service: Service,
    parameters: Dict[str, Any],
    runner: ExecutionRunnerInterface,
    timeout_seconds: int = 30,
) -> ExecutionResult:
    """
    Fixed static handler for restore_order_api_demo.

    Validates schema, checks service environment, and delegates execution
    strictly to the isolated runner sandbox. Never executes commands on the host OS.
    """
    # 1. Strict schema validation
    validated_params = RestoreOrderApiDemoParams.model_validate(parameters)

    # 2. Service precondition validation
    validate_restore_order_api_demo_preconditions(service)

    # 3. Dispatch to isolated runner sandbox (fails closed if runner unavailable)
    return runner.execute(
        action_id="restore_order_api_demo",
        parameters=validated_params.model_dump(),
        timeout_seconds=timeout_seconds,
    )


def handle_inspect_service_health(
    *,
    service: Service,
    parameters: Dict[str, Any],
    runner: ExecutionRunnerInterface,
    timeout_seconds: int = 15,
) -> ExecutionResult:
    """
    Fixed static handler for inspect_service_health.

    Performs read-only diagnostic telemetry gathering via runner.
    """
    # 1. Strict schema validation
    validated_params = InspectServiceHealthParams.model_validate(parameters)

    # 2. Service precondition validation
    validate_inspect_service_health_preconditions(service)

    # 3. Dispatch to runner
    return runner.execute(
        action_id="inspect_service_health",
        parameters=validated_params.model_dump(),
        timeout_seconds=timeout_seconds,
    )


def handle_http_recovery(
    *,
    service: Service,
    parameters: Dict[str, Any],
    runner: ExecutionRunnerInterface,
    timeout_seconds: int = 30,
) -> ExecutionResult:
    """
    Fixed static handler for execute_http_recovery (Phase 5A).

    Validates parameters, derives target recovery URL strictly from registered
    service health check origin, and delegates execution strictly to the isolated runner.
    """
    # 1. Strict schema validation
    validated_params = HttpRecoveryParams.model_validate(parameters)

    # 2. Service precondition validation and URL derivation
    derived_url = validate_http_recovery_preconditions(service, validated_params.model_dump())

    # 3. Dispatch to isolated runner sandbox
    return runner.execute(
        action_id="execute_http_recovery",
        parameters=validated_params.model_dump(),
        timeout_seconds=min(timeout_seconds, validated_params.timeout_seconds),
        target_url=derived_url,
        environment=service.environment or "development",
    )


# Registry mapping action_id -> fixed static handler function
STATIC_ACTION_HANDLERS: Dict[str, Callable[..., ExecutionResult]] = {
    "restore_order_api_demo": handle_restore_order_api_demo,
    "inspect_service_health": handle_inspect_service_health,
    "execute_http_recovery": handle_http_recovery,
}


def get_static_action_handler(action_id: str) -> Callable[..., ExecutionResult]:
    """Retrieve predefined static handler for an allowlisted action."""
    handler = STATIC_ACTION_HANDLERS.get(action_id)
    if not handler:
        raise PreconditionFailedError(
            f"No static execution handler registered for action '{action_id}'. "
            f"Only predefined actions {list(STATIC_ACTION_HANDLERS.keys())} are supported."
        )
    return handler
