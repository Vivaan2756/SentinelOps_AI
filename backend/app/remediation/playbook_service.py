"""Dynamic Remediation Playbook Service.

Encapsulates business logic, validation, versioning, service association,
and safety invariants for persistent remediation playbooks.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.playbook import Playbook, PlaybookVersion, ServicePlaybookAssociation
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace
from app.remediation.registry import ActionRegistry
from app.remediation.schemas import ActionDefinition, RiskLevel
from app.schemas.playbook import (
    IncompatibleServiceReason,
    PlaybookCreate,
    PlaybookDetailResponse,
    PlaybookResponse,
    PlaybookUpdate,
    PlaybookValidationResponse,
    PlaybookVersionResponse,
    ServiceAssociationSummary,
    ServicePlaybookAssociationResponse,
)


FORBIDDEN_SCRIPT_PATTERNS = [
    "__import__",
    "eval(",
    "exec(",
    "subprocess",
    "os.system",
    "sh -c",
    "bash -c",
    "cmd.exe",
    "powershell",
    "/bin/sh",
    "/bin/bash",
]


def _scan_for_arbitrary_code(data: Any) -> Optional[str]:
    """Recursively checks that no raw command injection strings are embedded."""
    if isinstance(data, str):
        lower = data.lower()
        for pat in FORBIDDEN_SCRIPT_PATTERNS:
            if pat in lower:
                return f"Forbidden executable pattern '{pat}' detected."
    elif isinstance(data, dict):
        for k, v in data.items():
            err = _scan_for_arbitrary_code(k) or _scan_for_arbitrary_code(v)
            if err:
                return err
    elif isinstance(data, list):
        for item in data:
            err = _scan_for_arbitrary_code(item)
            if err:
                return err
    return None


class PlaybookService:
    """Core service for managing persistent, versioned remediation playbooks."""

    @classmethod
    def validate_playbook_spec(
        cls,
        *,
        db: Session,
        workspace_id: str,
        action_template_id: str,
        service_ids: Optional[List[str]] = None,
        parameter_schema: Optional[Dict[str, Any]] = None,
        verification_criteria: Optional[Dict[str, Any]] = None,
        risk_level: Optional[str] = None,
    ) -> PlaybookValidationResponse:
        """
        Validates a candidate playbook specification without persisting it.
        Checks allowlisted action template existence, parameter model rules,
        service compatibility, and arbitrary code rejection.
        """
        errors: List[str] = []
        warnings: List[str] = []
        service_ids = service_ids or []
        parameter_schema = parameter_schema or {}
        verification_criteria = verification_criteria or {}

        # 1. Action template allowlist verification
        action_def = ActionRegistry.get_action(action_template_id)
        if not action_def:
            errors.append(
                f"Action template '{action_template_id}' is not in the allowlisted remediation actions catalog."
            )
            return PlaybookValidationResponse(
                is_valid=False,
                errors=errors,
                warnings=warnings,
                action_template_name=None,
            )

        if not action_def.enabled:
            errors.append(f"Action template '{action_template_id}' is currently disabled.")

        # 2. Reject arbitrary code/script patterns
        code_err = _scan_for_arbitrary_code(parameter_schema) or _scan_for_arbitrary_code(verification_criteria)
        if code_err:
            errors.append(f"Security validation failed: {code_err}")

        # 3. Parameter validation against action model
        if parameter_schema:
            is_valid, _, err_msg = ActionRegistry.validate_parameters(action_template_id, parameter_schema)
            if not is_valid:
                errors.append(f"Parameter schema validation failed: {err_msg}")

        # 4. Verification criteria validation
        if verification_criteria:
            if "probes_required" in verification_criteria:
                probes = verification_criteria["probes_required"]
                if not isinstance(probes, int) or probes < 1 or probes > 10:
                    errors.append("Verification criteria 'probes_required' must be an integer between 1 and 10.")
            if "timeout_seconds" in verification_criteria:
                timeout = verification_criteria["timeout_seconds"]
                if not isinstance(timeout, int) or timeout < 5 or timeout > 300:
                    errors.append("Verification criteria 'timeout_seconds' must be an integer between 5 and 300.")
            if "health_path" in verification_criteria:
                hp = str(verification_criteria["health_path"])
                if ".." in hp or not hp.startswith("/"):
                    errors.append("Verification criteria 'health_path' must be a valid relative path starting with '/'.")

        # 5. Service compatibility check
        compatible_services: List[str] = []
        incompatible_services: List[IncompatibleServiceReason] = []

        if service_ids:
            services = (
                db.query(Service)
                .filter(Service.id.in_(service_ids), Service.workspace_id == workspace_id)
                .all()
            )
            found_ids = {s.id for s in services}
            missing_ids = set(service_ids) - found_ids
            for mid in missing_ids:
                errors.append(f"Service '{mid}' does not exist in workspace '{workspace_id}'.")

            for svc in services:
                # Check capability compatibility with service (in candidate association mode)
                cap = ActionRegistry.evaluate_service_capability(
                    action_template_id, svc, db=db, for_playbook_association=True
                )
                if cap.is_compatible and cap.is_executable:
                    compatible_services.append(svc.id)
                else:
                    reason = "; ".join(cap.reasons) if cap.reasons else f"Service '{svc.name}' is not supported by action template '{action_template_id}'."
                    incompatible_services.append(
                        IncompatibleServiceReason(
                            service_id=svc.id,
                            service_name=svc.name,
                            reason=reason,
                        )
                    )
                    warnings.append(reason)

        # 6. Adapter requirement warning
        if not action_def.is_executable:
            warnings.append(
                f"Action template '{action_template_id}' requires infrastructure adapter "
                f"({action_def.execution_mechanism.value}) which is not configured in the current execution runtime. "
                f"Playbooks configuring this template cannot be executed until the adapter is installed."
            )

        # 7. Risk level validation
        if risk_level:
            try:
                RiskLevel(risk_level.lower())
            except ValueError:
                errors.append(f"Invalid risk level '{risk_level}'. Must be 'low', 'medium', or 'high'.")

        is_valid = len(errors) == 0
        return PlaybookValidationResponse(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            action_template_name=action_def.name,
            action_category=action_def.category.value,
            default_risk_level=action_def.risk_level.value,
            compatible_services=compatible_services,
            incompatible_services=incompatible_services,
        )

    @classmethod
    def create_playbook(
        cls,
        *,
        db: Session,
        user: User,
        data: PlaybookCreate,
    ) -> Playbook:
        """
        Creates a new Playbook and its initial PlaybookVersion (v1).
        Optionally associates initial compatible services.
        """
        # 1. Validate candidate specification
        val_res = cls.validate_playbook_spec(
            db=db,
            workspace_id=data.workspace_id,
            action_template_id=data.action_template_id,
            service_ids=data.initial_service_ids,
            parameter_schema=data.parameter_schema,
            verification_criteria=data.verification_criteria,
            risk_level=data.risk_level,
        )
        if not val_res.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Playbook validation failed: {'; '.join(val_res.errors)}",
            )

        # 2. Check name uniqueness within the workspace
        existing = (
            db.query(Playbook)
            .filter(
                Playbook.workspace_id == data.workspace_id,
                Playbook.name.ilike(data.name.strip()),
            )
            .first()
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Playbook named '{data.name.strip()}' already exists in this workspace.",
            )

        # 3. Create Playbook entity
        playbook = Playbook(
            workspace_id=data.workspace_id,
            name=data.name.strip(),
            description=data.description.strip() if data.description else None,
            category=data.category,
            is_active=True,
            current_version=1,
            created_by=user.id,
        )
        db.add(playbook)
        db.flush()

        # 4. Create initial PlaybookVersion entity (v1)
        version = PlaybookVersion(
            playbook_id=playbook.id,
            version_number=1,
            action_template_id=data.action_template_id,
            supported_scenarios=data.supported_scenarios or ["*"],
            parameter_schema=data.parameter_schema or {},
            verification_criteria=data.verification_criteria or {},
            risk_level=data.risk_level.lower(),
            approval_required=data.approval_required,
            timeout_seconds=data.timeout_seconds,
            change_summary="Initial version",
            created_by=user.id,
        )
        db.add(version)
        db.flush()

        # 5. Bind initial services if requested and compatible
        if data.initial_service_ids:
            for sid in val_res.compatible_services:
                assoc = ServicePlaybookAssociation(
                    workspace_id=data.workspace_id,
                    service_id=sid,
                    playbook_id=playbook.id,
                    is_active=True,
                    priority=0,
                    created_by=user.id,
                )
                db.add(assoc)

        db.commit()
        db.refresh(playbook)
        return playbook

    @classmethod
    def update_playbook(
        cls,
        *,
        db: Session,
        user: User,
        playbook_id: str,
        data: PlaybookUpdate,
    ) -> Playbook:
        """
        Updates an existing Playbook.
        If operational/spec fields are modified, increments current_version and
        creates an immutable new PlaybookVersion record.
        """
        playbook = (
            db.query(Playbook)
            .filter(
                Playbook.id == playbook_id,
                Playbook.workspace_id == data.workspace_id,
            )
            .first()
        )
        if not playbook:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Playbook '{playbook_id}' not found in workspace '{data.workspace_id}'.",
            )

        active_v = playbook.active_version

        # Check if name is being changed and conflicts
        if data.name and data.name.strip().lower() != playbook.name.lower():
            conflict = (
                db.query(Playbook)
                .filter(
                    Playbook.workspace_id == data.workspace_id,
                    Playbook.name.ilike(data.name.strip()),
                    Playbook.id != playbook.id,
                )
                .first()
            )
            if conflict:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Another playbook named '{data.name.strip()}' already exists in this workspace.",
                )
            playbook.name = data.name.strip()

        if data.description is not None:
            playbook.description = data.description.strip() if data.description else None
        if data.category is not None:
            playbook.category = data.category
        if data.is_active is not None:
            playbook.is_active = data.is_active

        # Determine if version-affecting fields are provided
        target_action = data.action_template_id or (active_v.action_template_id if active_v else None)
        target_scenarios = data.supported_scenarios if data.supported_scenarios is not None else (active_v.supported_scenarios if active_v else ["*"])
        target_params = data.parameter_schema if data.parameter_schema is not None else (active_v.parameter_schema if active_v else {})
        target_criteria = data.verification_criteria if data.verification_criteria is not None else (active_v.verification_criteria if active_v else {})
        target_risk = data.risk_level or (active_v.risk_level if active_v else "medium")
        target_approval = data.approval_required if data.approval_required is not None else (active_v.approval_required if active_v else True)
        target_timeout = data.timeout_seconds if data.timeout_seconds is not None else (active_v.timeout_seconds if active_v else 30)

        version_fields_touched = any([
            data.action_template_id is not None,
            data.supported_scenarios is not None,
            data.parameter_schema is not None,
            data.verification_criteria is not None,
            data.risk_level is not None,
            data.approval_required is not None,
            data.timeout_seconds is not None,
        ])

        if version_fields_touched and target_action:
            # Validate new specification
            val_res = cls.validate_playbook_spec(
                db=db,
                workspace_id=data.workspace_id,
                action_template_id=target_action,
                parameter_schema=target_params,
                verification_criteria=target_criteria,
                risk_level=target_risk,
            )
            if not val_res.is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Updated playbook validation failed: {'; '.join(val_res.errors)}",
                )

            # Create new PlaybookVersion
            new_version_num = playbook.current_version + 1
            playbook.current_version = new_version_num
            new_version = PlaybookVersion(
                playbook_id=playbook.id,
                version_number=new_version_num,
                action_template_id=target_action,
                supported_scenarios=target_scenarios,
                parameter_schema=target_params,
                verification_criteria=target_criteria,
                risk_level=target_risk.lower(),
                approval_required=target_approval,
                timeout_seconds=target_timeout,
                change_summary=data.change_summary or f"Updated to version {new_version_num}",
                created_by=user.id,
            )
            db.add(new_version)

        playbook.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(playbook)
        return playbook

    @classmethod
    def get_playbook(
        cls,
        *,
        db: Session,
        workspace_id: str,
        playbook_id: str,
    ) -> Playbook:
        """Retrieve a single playbook with tenant boundary enforcement."""
        playbook = (
            db.query(Playbook)
            .filter(
                Playbook.id == playbook_id,
                Playbook.workspace_id == workspace_id,
            )
            .first()
        )
        if not playbook:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Playbook '{playbook_id}' not found in workspace '{workspace_id}'.",
            )
        return playbook

    @classmethod
    def list_playbooks(
        cls,
        *,
        db: Session,
        workspace_id: str,
        service_id: Optional[str] = None,
        is_active: Optional[bool] = None,
        category: Optional[str] = None,
        q: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Playbook]:
        """Lists playbooks scoped to the workspace with optional filtering."""
        query = db.query(Playbook).filter(Playbook.workspace_id == workspace_id)

        if service_id:
            query = query.join(
                ServicePlaybookAssociation,
                ServicePlaybookAssociation.playbook_id == Playbook.id,
            ).filter(
                ServicePlaybookAssociation.service_id == service_id,
                ServicePlaybookAssociation.is_active == True,
            )

        if is_active is not None:
            query = query.filter(Playbook.is_active == is_active)

        if category:
            query = query.filter(Playbook.category == category)

        if q:
            query = query.filter(Playbook.name.ilike(f"%{q.strip()}%"))

        return query.order_by(Playbook.name.asc()).offset(offset).limit(limit).all()

    @classmethod
    def toggle_playbook_activation(
        cls,
        *,
        db: Session,
        workspace_id: str,
        playbook_id: str,
        activate: bool,
    ) -> Playbook:
        """Activate or deactivate a playbook."""
        playbook = cls.get_playbook(db=db, workspace_id=workspace_id, playbook_id=playbook_id)
        playbook.is_active = activate
        playbook.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(playbook)
        return playbook

    @classmethod
    def associate_service(
        cls,
        *,
        db: Session,
        user: User,
        workspace_id: str,
        playbook_id: str,
        service_id: str,
        priority: int = 0,
    ) -> ServicePlaybookAssociation:
        """
        Binds a playbook to a service within the same workspace.
        Enforces tenant isolation and action compatibility.
        """
        playbook = cls.get_playbook(db=db, workspace_id=workspace_id, playbook_id=playbook_id)

        service = (
            db.query(Service)
            .filter(
                Service.id == service_id,
                Service.workspace_id == workspace_id,
            )
            .first()
        )
        if not service:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Service '{service_id}' not found in workspace '{workspace_id}'.",
            )

        # Check compatibility
        active_v = playbook.active_version
        action_id = active_v.action_template_id if active_v else ""
        if action_id:
            action_def = ActionRegistry.get_action(action_id)
            if action_def and action_def.supported_services and "*" not in action_def.supported_services:
                if not ActionRegistry.is_action_supported_for_service(action_id, service):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=(
                            f"Action template '{action_id}' does not support service '{service.name}'. "
                            f"Supported patterns: {action_def.supported_services}."
                        ),
                    )

        # Check if association already exists
        assoc = (
            db.query(ServicePlaybookAssociation)
            .filter(
                ServicePlaybookAssociation.service_id == service_id,
                ServicePlaybookAssociation.playbook_id == playbook_id,
            )
            .first()
        )
        if assoc:
            assoc.is_active = True
            assoc.priority = priority
        else:
            assoc = ServicePlaybookAssociation(
                workspace_id=workspace_id,
                service_id=service_id,
                playbook_id=playbook_id,
                is_active=True,
                priority=priority,
                created_by=user.id,
            )
            db.add(assoc)

        db.commit()
        db.refresh(assoc)
        return assoc

    @classmethod
    def disassociate_service(
        cls,
        *,
        db: Session,
        workspace_id: str,
        playbook_id: str,
        service_id: str,
    ) -> bool:
        """Removes the association between a service and a playbook."""
        assoc = (
            db.query(ServicePlaybookAssociation)
            .filter(
                ServicePlaybookAssociation.workspace_id == workspace_id,
                ServicePlaybookAssociation.playbook_id == playbook_id,
                ServicePlaybookAssociation.service_id == service_id,
            )
            .first()
        )
        if not assoc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Association between playbook '{playbook_id}' and service '{service_id}' not found.",
            )

        db.delete(assoc)
        db.commit()
        return True

    @classmethod
    def get_playbooks_for_service(
        cls,
        db: Session,
        service_id: str,
        scenario: Optional[str] = None,
    ) -> List[Playbook]:
        """
        Retrieves all active playbooks bound to the given service.
        Orders by association priority descending.
        Optionally filters by supported incident scenario.
        """
        assocs = (
            db.query(ServicePlaybookAssociation)
            .join(Playbook, Playbook.id == ServicePlaybookAssociation.playbook_id)
            .filter(
                ServicePlaybookAssociation.service_id == service_id,
                ServicePlaybookAssociation.is_active == True,
                Playbook.is_active == True,
            )
            .order_by(
                ServicePlaybookAssociation.priority.desc(),
                Playbook.name.asc(),
            )
            .all()
        )

        playbooks: List[Playbook] = []
        for a in assocs:
            pb = a.playbook
            if not pb or not pb.is_active:
                continue

            if scenario:
                v = pb.active_version
                if v:
                    scenarios = v.supported_scenarios or []
                    if "*" not in scenarios and scenario not in scenarios:
                        continue
            playbooks.append(pb)

        return playbooks

    @classmethod
    def is_action_supported_for_service(
        cls,
        db: Session,
        action_id: str,
        service: Service,
    ) -> bool:
        """
        Determines whether an action is authorized for a service via dynamic playbooks.
        Checks active associations and playbook versions.
        """
        if not service or not getattr(service, "id", None):
            return False

        # Demo actions require explicit demo integration authorization; cannot be activated via playbook
        if action_id in ("restore_order_api_demo", "restart_order_api"):
            if not ActionRegistry.is_demo_service(service, "order_api", db=db):
                return False

        assocs = (
            db.query(ServicePlaybookAssociation)
            .join(Playbook, Playbook.id == ServicePlaybookAssociation.playbook_id)
            .filter(
                ServicePlaybookAssociation.service_id == service.id,
                ServicePlaybookAssociation.is_active == True,
                Playbook.is_active == True,
            )
            .all()
        )

        for a in assocs:
            v = a.playbook.active_version if a.playbook else None
            if v and v.action_template_id == action_id:
                return True

        return False

    @classmethod
    def seed_default_order_api_playbook(
        cls,
        db: Session,
        workspace_id: str,
        service_id: str,
        user_id: Optional[str] = None,
    ) -> Optional[Playbook]:
        """
        Seeds the default persistent Order API recovery playbook.
        Preserves backward compatibility and unifies Order API under the dynamic architecture.
        """
        service = db.query(Service).filter(Service.id == service_id, Service.workspace_id == workspace_id).first()
        if not service:
            return None

        # Check if already seeded
        pb = (
            db.query(Playbook)
            .filter(
                Playbook.workspace_id == workspace_id,
                Playbook.name == "Order API Failure Recovery",
            )
            .first()
        )
        if not pb:
            pb = Playbook(
                workspace_id=workspace_id,
                name="Order API Failure Recovery",
                description="Resets simulated in-memory failure mode on the Order API demo service instance by calling POST /demo/restore.",
                category="service_recovery",
                is_active=True,
                current_version=1,
                created_by=user_id,
            )
            db.add(pb)
            db.flush()

            v = PlaybookVersion(
                playbook_id=pb.id,
                version_number=1,
                action_template_id="restore_order_api_demo",
                supported_scenarios=["http_5xx_rate_exceeded", "demo_failure", "*"],
                parameter_schema={"service_id": service_id},
                verification_criteria={
                    "probes_required": 3,
                    "timeout_seconds": 15,
                    "endpoints": ["/health", "/demo/status", "/metrics"],
                },
                risk_level="medium",
                approval_required=True,
                timeout_seconds=30,
                change_summary="Canonical Order API recovery playbook",
                created_by=user_id,
            )
            db.add(v)
            db.flush()

        # Check association
        assoc = (
            db.query(ServicePlaybookAssociation)
            .filter(
                ServicePlaybookAssociation.service_id == service_id,
                ServicePlaybookAssociation.playbook_id == pb.id,
            )
            .first()
        )
        if not assoc:
            assoc = ServicePlaybookAssociation(
                workspace_id=workspace_id,
                service_id=service_id,
                playbook_id=pb.id,
                is_active=True,
                priority=100,
                created_by=user_id,
            )
            db.add(assoc)

        db.commit()
        db.refresh(pb)
        return pb

    @classmethod
    def ensure_generic_http_recovery_playbook(
        cls,
        db: Session,
        workspace_id: str,
        service_id: str,
        user_id: Optional[str] = None,
    ) -> Optional[Playbook]:
        """
        Ensures a generic HTTP recovery playbook exists and is associated with the target service.
        Resolves recovery path and parameters strictly from the authorized service configuration.
        """
        service = db.query(Service).filter(Service.id == service_id, Service.workspace_id == workspace_id).first()
        if not service or not getattr(service, "recovery_enabled", False) or not getattr(service, "recovery_endpoint", None):
            return None

        pb_name = f"{service.name} HTTP Recovery"
        pb = (
            db.query(Playbook)
            .filter(
                Playbook.workspace_id == workspace_id,
                Playbook.name == pb_name,
            )
            .first()
        )
        if not pb:
            pb = Playbook(
                workspace_id=workspace_id,
                name=pb_name,
                description=f"Executes authorized HTTP POST recovery to {service.recovery_endpoint} for {service.name}.",
                category="service_recovery",
                is_active=True,
                current_version=1,
                created_by=user_id,
            )
            db.add(pb)
            db.flush()

            v = PlaybookVersion(
                playbook_id=pb.id,
                version_number=1,
                action_template_id="execute_http_recovery",
                supported_scenarios=["http_5xx_rate_exceeded", "health_check_failure", "high_latency", "latency_spike", "demo_failure", "*"],
                parameter_schema={
                    "service_id": service.id,
                    "recovery_path": service.recovery_endpoint,
                    "expected_status_codes": [200],
                    "timeout_seconds": 30,
                },
                verification_criteria={
                    "probes_required": 3,
                    "timeout_seconds": 15,
                    "endpoints": [service.health_check_url],
                },
                risk_level="medium",
                approval_required=True,
                timeout_seconds=30,
                change_summary=f"Automated generic HTTP recovery playbook for {service.name}",
                created_by=user_id,
            )
            db.add(v)
            db.flush()

        assoc = (
            db.query(ServicePlaybookAssociation)
            .filter(
                ServicePlaybookAssociation.workspace_id == workspace_id,
                ServicePlaybookAssociation.service_id == service.id,
                ServicePlaybookAssociation.playbook_id == pb.id,
            )
            .first()
        )
        if not assoc:
            assoc = ServicePlaybookAssociation(
                workspace_id=workspace_id,
                service_id=service.id,
                playbook_id=pb.id,
                is_active=True,
                priority=100,
                created_by=user_id,
            )
            db.add(assoc)

        db.commit()
        db.refresh(pb)
        return pb


def build_playbook_response(playbook: Playbook) -> PlaybookResponse:
    """Helper to convert Playbook ORM into presentation schema."""
    active_v = playbook.active_version
    v_resp = None
    if active_v:
        action_def = ActionRegistry.get_action(active_v.action_template_id)
        v_resp = PlaybookVersionResponse(
            id=active_v.id,
            playbook_id=active_v.playbook_id,
            version_number=active_v.version_number,
            action_template_id=active_v.action_template_id,
            action_name=action_def.name if action_def else active_v.action_template_id,
            supported_scenarios=active_v.supported_scenarios or [],
            parameter_schema=active_v.parameter_schema or {},
            verification_criteria=active_v.verification_criteria or {},
            risk_level=active_v.risk_level,
            approval_required=active_v.approval_required,
            timeout_seconds=active_v.timeout_seconds,
            change_summary=active_v.change_summary,
            created_by=active_v.created_by,
            created_at=active_v.created_at,
        )

    assoc_count = len(playbook.service_associations) if playbook.service_associations else 0

    return PlaybookResponse(
        id=playbook.id,
        workspace_id=playbook.workspace_id,
        name=playbook.name,
        description=playbook.description,
        category=playbook.category,
        is_active=playbook.is_active,
        current_version=playbook.current_version,
        created_by=playbook.created_by,
        created_at=playbook.created_at,
        updated_at=playbook.updated_at,
        active_version=v_resp,
        associated_services_count=assoc_count,
    )


def build_playbook_detail_response(playbook: Playbook) -> PlaybookDetailResponse:
    """Helper to convert Playbook ORM into rich detail schema with all versions and service bindings."""
    base_resp = build_playbook_response(playbook)

    versions_resp = []
    for v in playbook.versions:
        action_def = ActionRegistry.get_action(v.action_template_id)
        versions_resp.append(
            PlaybookVersionResponse(
                id=v.id,
                playbook_id=v.playbook_id,
                version_number=v.version_number,
                action_template_id=v.action_template_id,
                action_name=action_def.name if action_def else v.action_template_id,
                supported_scenarios=v.supported_scenarios or [],
                parameter_schema=v.parameter_schema or {},
                verification_criteria=v.verification_criteria or {},
                risk_level=v.risk_level,
                approval_required=v.approval_required,
                timeout_seconds=v.timeout_seconds,
                change_summary=v.change_summary,
                created_by=v.created_by,
                created_at=v.created_at,
            )
        )

    services_resp = []
    if playbook.service_associations:
        for a in playbook.service_associations:
            svc_name = a.service.name if a.service else "Unknown Service"
            services_resp.append(
                ServiceAssociationSummary(
                    service_id=a.service_id,
                    service_name=svc_name,
                    is_active=a.is_active,
                    priority=a.priority,
                    associated_at=a.created_at,
                )
            )

    return PlaybookDetailResponse(
        **base_resp.model_dump(),
        versions=versions_resp,
        associated_services=services_resp,
    )
