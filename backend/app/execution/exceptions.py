"""Execution Engine Exceptions for Phase 4.3.

Covers:
- ExecutionEnvironmentUnavailable (503 fail-closed when Docker broker is absent)
- SecurityConfigurationError (unsafe fallback or test runner misuse in production)
- IdempotencyConflictError (409 idempotency key collision with different approval)
- ApprovalAlreadyExecutedError (409 approval replay prevention)
- IllegalStateTransitionError (state machine enforcement)
- StaleWorkerFencingError (fencing token mismatch on stale worker)
- PreconditionFailedError (JIT pre-flight check failure)
"""

from fastapi import HTTPException, status


class ExecutionEnvironmentUnavailable(HTTPException):
    """Raised when isolated container execution is required but unavailable on host."""

    def __init__(
        self,
        detail: str = (
            "Docker execution sandbox is not available on this host. Mutating remediation "
            "actions require a verified isolated container environment and cannot be executed in-process."
        ),
    ):
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail,
        )


class SecurityConfigurationError(Exception):
    """Raised when mock or in-process execution is attempted outside authorized test environment."""

    pass


class IdempotencyConflictError(HTTPException):
    """Raised when an idempotency key is reused for another execution within the workspace."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
        )


class ApprovalAlreadyExecutedError(HTTPException):
    """Raised when an approved proposal has already been consumed by an execution."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
        )


class IllegalStateTransitionError(ValueError):
    """Raised when an execution state transition violates canonical state machine rules."""

    pass


class StaleWorkerFencingError(Exception):
    """Raised when a worker attempts an update with an obsolete fencing token."""

    pass


class PreconditionFailedError(HTTPException):
    """Raised when JIT pre-flight checks fail before dispatch."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        )


class BrokerSecurityViolation(Exception):
    """Raised when a broker request violates security allowlists, images, mounts, or parameters."""

    pass


class BrokerUnavailableError(Exception):
    """Raised when the RestrictedDockerBroker daemon or IPC socket is unreachable."""

    pass


class ExecutionUncertainError(Exception):
    """Raised when worker lease expires or connection drops mid-execution, leaving outcome indeterminate."""

    pass


class ConflictingProbePayloadError(HTTPException):
    """Raised when a probe recording request provides a conflicting payload for an existing deterministic probe ID."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
        )


class ConflictingCyclePayloadError(HTTPException):
    """Raised when a verification cycle creation request conflicts with an existing cycle record."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
        )


class VerificationCycleNotFoundError(HTTPException):
    """Raised when the specified verification cycle does not exist."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail,
        )


class CrossWorkspaceViolationError(HTTPException):
    """Raised when an operation targets an entity belonging to a different workspace."""

    def __init__(self, detail: str = "Cross-workspace violation: Resource belongs to another workspace."):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )


class IncidentRecoveryError(HTTPException):
    """Raised when atomic incident recovery cannot be completed."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        )


class IncidentAssociationMismatchError(HTTPException):
    """Raised when an incident is not associated with the given execution or service."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        )


class VerificationPreconditionError(HTTPException):
    """Raised when verification cycle status, probes, or outcome do not satisfy recovery criteria."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        )


class VerificationDeadlineExpiredError(HTTPException):
    """Raised when a verification cycle deadline has expired prior to recovery finalization."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        )
