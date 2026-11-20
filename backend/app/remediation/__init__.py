"""Remediation Foundation Package (Phase 4.1).

Exposes the Allowlisted Action Registry, Parameter Schemas, and Policy Engine.
Execution of remediation is strictly out-of-scope for this phase.
"""

from app.remediation.registry import ActionRegistry
from app.remediation.policy import PolicyEngine, PolicyEvaluationResult
from app.remediation.schemas import (
    ActionCategory,
    ActionDefinition,
    ApprovalApproveRequest,
    ApprovalCancelRequest,
    ApprovalCreateRequest,
    ApprovalRejectRequest,
    ApprovalResponse,
    ApprovalStatus,
    PolicyDecisionType,
    RiskLevel,
)

__all__ = [
    "ActionRegistry",
    "PolicyEngine",
    "PolicyEvaluationResult",
    "ActionCategory",
    "ActionDefinition",
    "ApprovalApproveRequest",
    "ApprovalCancelRequest",
    "ApprovalCreateRequest",
    "ApprovalRejectRequest",
    "ApprovalResponse",
    "ApprovalStatus",
    "PolicyDecisionType",
    "RiskLevel",
]
