"""Deterministic Policy Engine for Remediation Actions.

Blueprint Section 8 & Phase 4.1:
- Authoritative backend policy checks — the AI planner CANNOT authorize actions
- AI-supplied risk downgrades and approval overrides are strictly ignored
- Viewers are prohibited from authorizing operational actions
- Cross-workspace service references are rejected
- Unsupported environments and disabled actions are rejected
- High-risk actions always require human approval
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from app.models.service import Service
from app.remediation.registry import ActionRegistry
from app.remediation.schemas import (
    ActionCategory,
    CapabilityStatus,
    PolicyDecisionType,
    RiskLevel,
)

POLICY_ENGINE_VERSION = "v1.0"


@dataclass
class PolicyEvaluationResult:
    """Internal evaluation outcome produced by the Policy Engine."""
    decision: PolicyDecisionType
    decision_reason: str
    action_id: str
    risk_level: str
    approval_required: bool
    policy_version: str
    target_service_id: Optional[str]
    validated_parameters: Dict[str, Any]
    evaluated_at: datetime


class PolicyEngine:
    """Independent deterministic policy evaluator."""

    @classmethod
    def evaluate(
        cls,
        *,
        workspace_id: str,
        user_role: str,
        action_id: str,
        parameters: Dict[str, Any],
        environment: str = "development",
        db: Session,
        user_id: Optional[str] = None,
        # Intentionally received to verify that AI overrides are completely ignored:
        ai_proposed_risk: Optional[str] = None,
        ai_proposed_approval: Optional[bool] = None,
        playbook_id: Optional[str] = None,
        playbook_version: Optional[int] = None,
    ) -> PolicyEvaluationResult:
        """
        Evaluate an action proposal deterministically against allowlist and safety rules.
        """
        now_utc = datetime.now(timezone.utc)
        normalized_role = (user_role or "").strip().lower()
        normalized_env = (environment or "development").strip().lower()

        # --------------------------------------------------------------------
        # Rule 1: Unknown actions are rejected
        # --------------------------------------------------------------------
        action = ActionRegistry.get_action(action_id)
        if not action:
            return PolicyEvaluationResult(
                decision=PolicyDecisionType.REJECTED,
                decision_reason=f"Action '{action_id}' is not registered in the allowlisted remediation action registry.",
                action_id=action_id,
                risk_level=RiskLevel.HIGH.value,
                approval_required=True,
                policy_version=POLICY_ENGINE_VERSION,
                target_service_id=None,
                validated_parameters={},
                evaluated_at=now_utc,
            )

        # Canonical risk level defined by registry (Rule 9: Never trust AI proposed risk)
        canonical_risk = action.risk_level.value

        # --------------------------------------------------------------------
        # Rule 2: Disabled actions are rejected
        # --------------------------------------------------------------------
        if not action.enabled:
            return PolicyEvaluationResult(
                decision=PolicyDecisionType.REJECTED,
                decision_reason=f"Action '{action_id}' is currently disabled in the action registry.",
                action_id=action_id,
                risk_level=canonical_risk,
                approval_required=True,
                policy_version=POLICY_ENGINE_VERSION,
                target_service_id=None,
                validated_parameters={},
                evaluated_at=now_utc,
            )

        # --------------------------------------------------------------------
        # Rule 3: Strict parameter validation
        # --------------------------------------------------------------------
        is_valid, validated_model, err_msg = ActionRegistry.validate_parameters(
            action_id=action_id,
            raw_params=parameters,
        )
        if not is_valid or not validated_model:
            return PolicyEvaluationResult(
                decision=PolicyDecisionType.REJECTED,
                decision_reason=f"Invalid parameters for action '{action_id}': {err_msg}",
                action_id=action_id,
                risk_level=canonical_risk,
                approval_required=True,
                policy_version=POLICY_ENGINE_VERSION,
                target_service_id=None,
                validated_parameters={},
                evaluated_at=now_utc,
            )

        sanitized_params = validated_model.model_dump()
        target_service_id = getattr(validated_model, "service_id", None)
        svc_policy: Optional[str] = None
        service: Optional[Service] = None

        # Determine if action is operational (vs read-only diagnostics)
        is_operational = (
            action.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
            or action.category in [ActionCategory.SERVICE_RECOVERY, ActionCategory.MONITORING]
        )
        playbook_approval_required: bool = False

        # --------------------------------------------------------------------
        # Rule 4: Target service verification & Cross-workspace check
        # --------------------------------------------------------------------
        if target_service_id:
            service = db.query(Service).filter(Service.id == target_service_id).first()
            if not service:
                return PolicyEvaluationResult(
                    decision=PolicyDecisionType.REJECTED,
                    decision_reason=f"Target service '{target_service_id}' does not exist in the database.",
                    action_id=action_id,
                    risk_level=canonical_risk,
                    approval_required=True,
                    policy_version=POLICY_ENGINE_VERSION,
                    target_service_id=target_service_id,
                    validated_parameters=sanitized_params,
                    evaluated_at=now_utc,
                )

            if service.workspace_id != workspace_id:
                return PolicyEvaluationResult(
                    decision=PolicyDecisionType.REJECTED,
                    decision_reason=(
                        f"Cross-workspace violation: Target service '{target_service_id}' belongs to "
                        f"workspace '{service.workspace_id}', not authorized workspace '{workspace_id}'."
                    ),
                    action_id=action_id,
                    risk_level=canonical_risk,
                    approval_required=True,
                    policy_version=POLICY_ENGINE_VERSION,
                    target_service_id=target_service_id,
                    validated_parameters=sanitized_params,
                    evaluated_at=now_utc,
                )

            # Precondition checks for specific action types
            if action_id == "restart_order_api" and not service.is_active:
                return PolicyEvaluationResult(
                    decision=PolicyDecisionType.REJECTED,
                    decision_reason=f"Precondition failed: Service '{service.name}' is inactive and cannot be restarted.",
                    action_id=action_id,
                    risk_level=canonical_risk,
                    approval_required=True,
                    policy_version=POLICY_ENGINE_VERSION,
                    target_service_id=target_service_id,
                    validated_parameters=sanitized_params,
                    evaluated_at=now_utc,
                )

            if action_id == "disable_service_monitoring" and not service.is_active:
                return PolicyEvaluationResult(
                    decision=PolicyDecisionType.REJECTED,
                    decision_reason=f"Precondition failed: Service '{service.name}' is already inactive.",
                    action_id=action_id,
                    risk_level=canonical_risk,
                    approval_required=True,
                    policy_version=POLICY_ENGINE_VERSION,
                    target_service_id=target_service_id,
                    validated_parameters=sanitized_params,
                    evaluated_at=now_utc,
                )

            # ----------------------------------------------------------------
            # Rule 4A: Role enforcement (Viewers cannot authorize operational actions)
            # ----------------------------------------------------------------
            is_operational = (
                action.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
                or action.category in [ActionCategory.SERVICE_RECOVERY, ActionCategory.MONITORING]
            )
            if normalized_role == "viewer" and is_operational:
                return PolicyEvaluationResult(
                    decision=PolicyDecisionType.REJECTED,
                    decision_reason=(
                        f"Role '{user_role}' is not authorized to request or approve operational action '{action_id}'. "
                        "Operational actions require 'engineer' or 'admin' role."
                    ),
                    action_id=action_id,
                    risk_level=canonical_risk,
                    approval_required=True,
                    policy_version=POLICY_ENGINE_VERSION,
                    target_service_id=target_service_id,
                    validated_parameters=sanitized_params,
                    evaluated_at=now_utc,
                )

            # ----------------------------------------------------------------
            # Rule 4B: Service Execution Policy Enforcement (evaluated before playbook matching)
            # ----------------------------------------------------------------
            raw_policy = service.execution_policy
            if raw_policy is None or not str(raw_policy).strip():
                return PolicyEvaluationResult(
                    decision=PolicyDecisionType.REJECTED,
                    decision_reason=(
                        f"Target service '{service.name}' has null or missing execution policy. "
                        "Failing closed."
                    ),
                    action_id=action_id,
                    risk_level=canonical_risk,
                    approval_required=True,
                    policy_version=POLICY_ENGINE_VERSION,
                    target_service_id=target_service_id,
                    validated_parameters=sanitized_params,
                    evaluated_at=now_utc,
                )

            svc_policy = str(raw_policy).strip().lower()
            if svc_policy not in ("demo", "approval_required", "observe_only"):
                return PolicyEvaluationResult(
                    decision=PolicyDecisionType.REJECTED,
                    decision_reason=(
                        f"Target service '{service.name}' has invalid or unsupported execution policy "
                        f"'{raw_policy}'. Failing closed."
                    ),
                    action_id=action_id,
                    risk_level=canonical_risk,
                    approval_required=True,
                    policy_version=POLICY_ENGINE_VERSION,
                    target_service_id=target_service_id,
                    validated_parameters=sanitized_params,
                    evaluated_at=now_utc,
                )

            # Observe-only: permits read-only diagnostics, rejects operational remediation
            if svc_policy == "observe_only" and is_operational:
                return PolicyEvaluationResult(
                    decision=PolicyDecisionType.REJECTED,
                    decision_reason=(
                        f"Service execution policy is 'observe_only'. Operational remediation is disabled."
                    ),
                    action_id=action_id,
                    risk_level=canonical_risk,
                    approval_required=True,
                    policy_version=POLICY_ENGINE_VERSION,
                    target_service_id=target_service_id,
                    validated_parameters=sanitized_params,
                    evaluated_at=now_utc,
                )

            # Demo policy: strictly restricted to development environment
            if svc_policy == "demo":
                if normalized_env not in [env.lower() for env in action.supported_environments]:
                    return PolicyEvaluationResult(
                        decision=PolicyDecisionType.REJECTED,
                        decision_reason=(
                            f"Unsupported environment '{environment}' for action '{action_id}'. "
                            f"Supported environments: {action.supported_environments}."
                        ),
                        action_id=action_id,
                        risk_level=canonical_risk,
                        approval_required=True,
                        policy_version=POLICY_ENGINE_VERSION,
                        target_service_id=target_service_id,
                        validated_parameters=sanitized_params,
                        evaluated_at=now_utc,
                    )
                svc_env = (service.environment or "").strip().lower()
                if svc_env != "development" or normalized_env != "development":
                    return PolicyEvaluationResult(
                        decision=PolicyDecisionType.REJECTED,
                        decision_reason=(
                            f"Service execution policy 'demo' is restricted to the 'development' environment "
                            f"(service environment: '{service.environment}', requested environment: '{environment}')."
                        ),
                        action_id=action_id,
                        risk_level=canonical_risk,
                        approval_required=True,
                        policy_version=POLICY_ENGINE_VERSION,
                        target_service_id=target_service_id,
                        validated_parameters=sanitized_params,
                        evaluated_at=now_utc,
                    )

            # ----------------------------------------------------------------
            # Rule 4A: Service-Specific Remediation Playbook Authorization & Integrity
            # ----------------------------------------------------------------
            if playbook_id:
                from app.models.playbook import Playbook, ServicePlaybookAssociation
                playbook_rec = (
                    db.query(Playbook)
                    .filter(Playbook.id == playbook_id, Playbook.workspace_id == workspace_id)
                    .first()
                )
                if not playbook_rec:
                    return PolicyEvaluationResult(
                        decision=PolicyDecisionType.REJECTED,
                        decision_reason=f"Referenced dynamic playbook '{playbook_id}' does not exist in authorized workspace.",
                        action_id=action_id,
                        risk_level=canonical_risk,
                        approval_required=True,
                        policy_version=POLICY_ENGINE_VERSION,
                        target_service_id=target_service_id,
                        validated_parameters=sanitized_params,
                        evaluated_at=now_utc,
                    )
                if not playbook_rec.is_active:
                    return PolicyEvaluationResult(
                        decision=PolicyDecisionType.REJECTED,
                        decision_reason=f"Referenced playbook '{playbook_rec.name}' is inactive. Inactive playbooks cannot be executed.",
                        action_id=action_id,
                        risk_level=canonical_risk,
                        approval_required=True,
                        policy_version=POLICY_ENGINE_VERSION,
                        target_service_id=target_service_id,
                        validated_parameters=sanitized_params,
                        evaluated_at=now_utc,
                    )
                if playbook_version is not None and playbook_rec.current_version != playbook_version:
                    return PolicyEvaluationResult(
                        decision=PolicyDecisionType.REJECTED,
                        decision_reason=(
                            f"Playbook version mismatch: Playbook '{playbook_rec.name}' is currently at version v{playbook_rec.current_version}, "
                            f"which differs from requested recommendation version v{playbook_version}. "
                            "Stale playbook versions cannot be executed without re-investigation."
                        ),
                        action_id=action_id,
                        risk_level=canonical_risk,
                        approval_required=True,
                        policy_version=POLICY_ENGINE_VERSION,
                        target_service_id=target_service_id,
                        validated_parameters=sanitized_params,
                        evaluated_at=now_utc,
                    )
                active_v = playbook_rec.active_version
                if active_v:
                    playbook_approval_required = bool(active_v.approval_required)
                if not active_v or active_v.action_template_id != action_id:
                    expected_act = active_v.action_template_id if active_v else "none"
                    return PolicyEvaluationResult(
                        decision=PolicyDecisionType.REJECTED,
                        decision_reason=(
                            f"Action template mismatch: Playbook '{playbook_rec.name}' specifies action template '{expected_act}', "
                            f"which does not match proposed action '{action_id}'."
                        ),
                        action_id=action_id,
                        risk_level=canonical_risk,
                        approval_required=True,
                        policy_version=POLICY_ENGINE_VERSION,
                        target_service_id=target_service_id,
                        validated_parameters=sanitized_params,
                        evaluated_at=now_utc,
                    )
                assoc = (
                    db.query(ServicePlaybookAssociation)
                    .filter(
                        ServicePlaybookAssociation.workspace_id == workspace_id,
                        ServicePlaybookAssociation.service_id == target_service_id,
                        ServicePlaybookAssociation.playbook_id == playbook_id,
                        ServicePlaybookAssociation.is_active == True,
                    )
                    .first()
                )
                if not assoc:
                    return PolicyEvaluationResult(
                        decision=PolicyDecisionType.REJECTED,
                        decision_reason=f"Playbook '{playbook_rec.name}' is not actively associated with service '{target_service_id}'.",
                        action_id=action_id,
                        risk_level=canonical_risk,
                        approval_required=True,
                        policy_version=POLICY_ENGINE_VERSION,
                        target_service_id=target_service_id,
                        validated_parameters=sanitized_params,
                        evaluated_at=now_utc,
                    )

            elif is_operational and not ActionRegistry.is_action_supported_for_service(action_id, service, db=db):
                return PolicyEvaluationResult(
                    decision=PolicyDecisionType.REJECTED,
                    decision_reason="No approved remediation playbook is configured for this service.",
                    action_id=action_id,
                    risk_level=canonical_risk,
                    approval_required=True,
                    policy_version=POLICY_ENGINE_VERSION,
                    target_service_id=target_service_id,
                    validated_parameters=sanitized_params,
                    evaluated_at=now_utc,
                )

        # --------------------------------------------------------------------
        # Rule 5: Environment permission check
        # --------------------------------------------------------------------
        if normalized_env not in [env.lower() for env in action.supported_environments]:
            return PolicyEvaluationResult(
                decision=PolicyDecisionType.REJECTED,
                decision_reason=(
                    f"Unsupported environment '{environment}' for action '{action_id}'. "
                    f"Supported environments: {action.supported_environments}."
                ),
                action_id=action_id,
                risk_level=canonical_risk,
                approval_required=True,
                policy_version=POLICY_ENGINE_VERSION,
                target_service_id=target_service_id,
                validated_parameters=sanitized_params,
                evaluated_at=now_utc,
            )

        # --------------------------------------------------------------------
        # Rule 2B: Capabilities requiring unconfigured adapters are rejected
        # --------------------------------------------------------------------
        if action.status == CapabilityStatus.REQUIRES_ADAPTER or not action.is_executable:
            return PolicyEvaluationResult(
                decision=PolicyDecisionType.REJECTED,
                decision_reason=(
                    f"Action '{action_id}' requires an infrastructure adapter "
                    f"({action.execution_mechanism.value}) that is not configured in current execution runtime."
                ),
                action_id=action_id,
                risk_level=canonical_risk,
                approval_required=True,
                policy_version=POLICY_ENGINE_VERSION,
                target_service_id=target_service_id,
                validated_parameters=sanitized_params,
                evaluated_at=now_utc,
            )

        # --------------------------------------------------------------------
        # Rule 10: Role enforcement (Viewers cannot authorize operational actions)
        # --------------------------------------------------------------------
        is_operational = (
            action.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
            or action.category in [ActionCategory.SERVICE_RECOVERY, ActionCategory.MONITORING]
        )

        if normalized_role == "viewer" and is_operational:
            return PolicyEvaluationResult(
                decision=PolicyDecisionType.REJECTED,
                decision_reason=(
                    f"Role '{user_role}' is not authorized to request or approve operational action '{action_id}'. "
                    "Operational actions require 'engineer' or 'admin' role."
                ),
                action_id=action_id,
                risk_level=canonical_risk,
                approval_required=True,
                policy_version=POLICY_ENGINE_VERSION,
                target_service_id=target_service_id,
                validated_parameters=sanitized_params,
                evaluated_at=now_utc,
            )

        # --------------------------------------------------------------------
        # Rules 6, 7, 8, 9: Risk-based approval requirements
        # (AI proposals CANNOT override approval or downgrade risk)
        # --------------------------------------------------------------------
        if action.risk_level == RiskLevel.HIGH:
            # High-risk actions always require human approval
            return PolicyEvaluationResult(
                decision=PolicyDecisionType.APPROVAL_REQUIRED,
                decision_reason=(
                    f"High-risk action '{action_id}' strictly requires human approval prior to execution."
                ),
                action_id=action_id,
                risk_level=canonical_risk,
                approval_required=True,
                policy_version=POLICY_ENGINE_VERSION,
                target_service_id=target_service_id,
                validated_parameters=sanitized_params,
                evaluated_at=now_utc,
            )

        if action.risk_level == RiskLevel.MEDIUM:
            # Medium-risk actions follow registry configuration or service execution policy
            force_approval = (svc_policy == "approval_required" and is_operational) or playbook_approval_required
            if action.approval_required or force_approval:
                return PolicyEvaluationResult(
                    decision=PolicyDecisionType.APPROVAL_REQUIRED,
                    decision_reason=(
                        f"Medium-risk action '{action_id}' requires human approval per "
                        f"{'playbook policy' if playbook_approval_required else 'service execution policy' if force_approval and not action.approval_required else 'registry policy'}."
                    ),
                    action_id=action_id,
                    risk_level=canonical_risk,
                    approval_required=True,
                    policy_version=POLICY_ENGINE_VERSION,
                    target_service_id=target_service_id,
                    validated_parameters=sanitized_params,
                    evaluated_at=now_utc,
                )
            else:
                return PolicyEvaluationResult(
                    decision=PolicyDecisionType.ALLOWED,
                    decision_reason=f"Medium-risk action '{action_id}' is allowed per registry policy.",
                    action_id=action_id,
                    risk_level=canonical_risk,
                    approval_required=False,
                    policy_version=POLICY_ENGINE_VERSION,
                    target_service_id=target_service_id,
                    validated_parameters=sanitized_params,
                    evaluated_at=now_utc,
                )

        if action.risk_level == RiskLevel.LOW:
            # Low-risk diagnostic actions can be allowed without approval when configured
            force_approval = (svc_policy == "approval_required" and is_operational) or playbook_approval_required
            if action.approval_required or force_approval:
                return PolicyEvaluationResult(
                    decision=PolicyDecisionType.APPROVAL_REQUIRED,
                    decision_reason=(
                        f"Low-risk action '{action_id}' requires approval per "
                        f"{'playbook policy' if playbook_approval_required else 'service execution policy' if force_approval and not action.approval_required else 'configuration'}."
                    ),
                    action_id=action_id,
                    risk_level=canonical_risk,
                    approval_required=True,
                    policy_version=POLICY_ENGINE_VERSION,
                    target_service_id=target_service_id,
                    validated_parameters=sanitized_params,
                    evaluated_at=now_utc,
                )
            else:
                return PolicyEvaluationResult(
                    decision=PolicyDecisionType.ALLOWED,
                    decision_reason=(
                        f"Low-risk diagnostic action '{action_id}' is pre-approved for execution without human approval."
                    ),
                    action_id=action_id,
                    risk_level=canonical_risk,
                    approval_required=False,
                    policy_version=POLICY_ENGINE_VERSION,
                    target_service_id=target_service_id,
                    validated_parameters=sanitized_params,
                    evaluated_at=now_utc,
                )

        # Fallback default safe rejection
        return PolicyEvaluationResult(
            decision=PolicyDecisionType.REJECTED,
            decision_reason=f"Unrecognized policy evaluation state for action '{action_id}'.",
            action_id=action_id,
            risk_level=canonical_risk,
            approval_required=True,
            policy_version=POLICY_ENGINE_VERSION,
            target_service_id=target_service_id,
            validated_parameters=sanitized_params,
            evaluated_at=now_utc,
        )
