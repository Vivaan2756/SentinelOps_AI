"""Allowlisted Remediation Action Registry.

Blueprint Section 8 & Phase 4.1:
- Explicit allowlist of permissible recovery and diagnostic actions
- AI can propose action IDs from this registry, but CANNOT define commands, scripts, or URLs
- Unknown action IDs are always rejected
- Execution is strictly NOT implemented in this phase
"""

from typing import Any, Dict, List, Optional, Set, Tuple, Type
from urllib.parse import urlparse
from pydantic import BaseModel, ValidationError

from app.remediation.schemas import (
    ActionCategory,
    ActionDefinition,
    CapabilityStatus,
    ClearApplicationCacheParams,
    DisableServiceMonitoringParams,
    ExecutionMechanism,
    HttpRecoveryParams,
    InspectServiceHealthParams,
    RestartOrderApiParams,
    RestartServiceParams,
    RestoreOrderApiDemoParams,
    RiskLevel,
    RollbackDeploymentParams,
    ServiceActionCapability,
    ServiceCapabilitiesResponse,
    build_recovery_url,
    validate_relative_recovery_path,
)


# Registry mapping action_id -> Pydantic parameter validation model
ACTION_PARAMETER_MODELS: Dict[str, Type[BaseModel]] = {
    "restore_order_api_demo": RestoreOrderApiDemoParams,
    "restart_order_api": RestartOrderApiParams,
    "restart_service": RestartServiceParams,
    "inspect_service_health": InspectServiceHealthParams,
    "disable_service_monitoring": DisableServiceMonitoringParams,
    "rollback_deployment": RollbackDeploymentParams,
    "clear_application_cache": ClearApplicationCacheParams,
    "execute_http_recovery": HttpRecoveryParams,
}


# Canonical Allowlisted Actions Catalog (Phase 4.4A Capability Architecture)
ALLOWLISTED_ACTIONS: Dict[str, ActionDefinition] = {
    # ------------------------------------------------------------------------
    # 1. Genuinely Reusable Read-Only Diagnostic Capability (Fully Executable)
    # ------------------------------------------------------------------------
    "inspect_service_health": ActionDefinition(
        action_id="inspect_service_health",
        name="Inspect Service Diagnostic Health",
        description="Performs read-only diagnostic inspection of service endpoints and gathers current metrics snapshot without state changes.",
        category=ActionCategory.DIAGNOSTICS,
        risk_level=RiskLevel.LOW,
        execution_mechanism=ExecutionMechanism.HTTP_DIAGNOSTIC,
        status=CapabilityStatus.EXECUTABLE,
        is_executable=True,
        parameter_schema=InspectServiceHealthParams.model_json_schema(),
        supported_environments=["development", "staging", "production"],
        approval_required=False,
        supported_services=["*"],
        required_service_attributes=["health_check_url"],
        security_restrictions=[
            "SSRF target validation via network boundary policy",
            "Pinned TCP connection DNS/IP (host-gateway or trusted gateway)",
            "Redirect following forbidden (3xx status rejection)",
            "Read-only HTTP GET requests without mutation",
        ],
        target_resource_type="http_endpoint",
        preconditions=[
            "Service exists in the target workspace",
            "Service is marked active",
            "Service has configured health_check_url",
        ],
        verification_criteria="Diagnostic telemetry and health state are collected and attached to incident timeline.",
        timeout_seconds=30,
        enabled=True,
    ),

    # ------------------------------------------------------------------------
    # 2. Genuinely Reusable Monitoring Management Capability (Fully Executable)
    # ------------------------------------------------------------------------
    "disable_service_monitoring": ActionDefinition(
        action_id="disable_service_monitoring",
        name="Disable Service Monitoring",
        description="Deactivates active monitoring polling for a flapping or decommissioned service to prevent false alarm noise.",
        category=ActionCategory.MONITORING,
        risk_level=RiskLevel.HIGH,
        execution_mechanism=ExecutionMechanism.MONITORING_CONTROL,
        status=CapabilityStatus.EXECUTABLE,
        is_executable=True,
        parameter_schema=DisableServiceMonitoringParams.model_json_schema(),
        supported_environments=["development", "staging", "production"],
        approval_required=True,
        supported_services=["*"],
        required_service_attributes=["id"],
        security_restrictions=[
            "Workspace-scoped database mutation only",
            "Requires human approval before deactivation",
            "Audit event emitted to incident log",
        ],
        target_resource_type="monitoring_config",
        preconditions=[
            "Service exists in the target workspace",
            "Service is currently active",
        ],
        verification_criteria="Service is marked is_active=False and verified excluded from active background detection polling.",
        timeout_seconds=30,
        enabled=True,
    ),

    # ------------------------------------------------------------------------
    # 3. Service-Specific Legacy/Demo Capability (Order API Only)
    # ------------------------------------------------------------------------
    "restore_order_api_demo": ActionDefinition(
        action_id="restore_order_api_demo",
        name="Restore Order API Demo Service",
        description="Resets simulated in-memory failure mode on the Order API demo service instance by calling POST /demo/restore.",
        category=ActionCategory.SERVICE_RECOVERY,
        risk_level=RiskLevel.MEDIUM,
        execution_mechanism=ExecutionMechanism.DEMO_SERVICE_RESET,
        status=CapabilityStatus.EXECUTABLE,
        is_executable=True,
        parameter_schema=RestoreOrderApiDemoParams.model_json_schema(),
        supported_environments=["development"],
        approval_required=True,
        supported_services=["Order API", "order-api", "order_api", "demo-order-service"],
        required_service_attributes=["health_check_url"],
        security_restrictions=[
            "Service-specific demo endpoint targeting Order API demo instance",
            "SSRF target validation with DNS/IP pinning",
            "Strictly restricted to 'development' environment",
            "Redirect following forbidden",
        ],
        target_resource_type="demo_http_endpoint",
        preconditions=[
            "Service exists in the target workspace",
            "Service is marked active",
            "Service environment is development",
            "Service health check URL matches registered Order API host and port",
        ],
        verification_criteria="GET /demo/status confirms failure_active == False; GET /health returns HTTP 200 across 3 consecutive probes over a 15-second window.",
        timeout_seconds=30,
        enabled=True,
    ),

    # ------------------------------------------------------------------------
    # 4. Reusable Container Lifecycle Capability (Requires Docker/K8s Adapter)
    # ------------------------------------------------------------------------
    "restart_service": ActionDefinition(
        action_id="restart_service",
        name="Restart Service Container/Process",
        description="Gracefully restarts the container or process running the service via host process/container manager.",
        category=ActionCategory.SERVICE_RECOVERY,
        risk_level=RiskLevel.HIGH,
        execution_mechanism=ExecutionMechanism.CONTAINER_LIFECYCLE,
        status=CapabilityStatus.REQUIRES_ADAPTER,
        is_executable=False,
        parameter_schema=RestartServiceParams.model_json_schema(),
        supported_environments=["development", "staging"],
        approval_required=True,
        supported_services=["*"],
        required_service_attributes=["container_id", "service_process"],
        security_restrictions=[
            "Requires trusted container management adapter (Docker socket or K8s API client)",
            "Container socket must NEVER be exposed directly to untrusted containers",
            "Zero arbitrary shell or script execution",
            "Human approval mandatory",
        ],
        target_resource_type="container",
        preconditions=[
            "Service exists in the target workspace",
            "Service is marked active",
            "Trusted Docker/Kubernetes container management adapter configured in runner",
            "Service has registered container_id or pod_name",
        ],
        verification_criteria="Service container restarts, passes synthetic health probe within 60s.",
        timeout_seconds=60,
        enabled=True,
    ),

    # ------------------------------------------------------------------------
    # 5. Legacy Restart Order API (Maintained for Backward Compatibility)
    # ------------------------------------------------------------------------
    "restart_order_api": ActionDefinition(
        action_id="restart_order_api",
        name="Restart Order API Service",
        description="Initiates a controlled restart of the demo Order API service instance to recover from process hang or transient deadlock.",
        category=ActionCategory.SERVICE_RECOVERY,
        risk_level=RiskLevel.MEDIUM,
        execution_mechanism=ExecutionMechanism.DEMO_SERVICE_RESET,
        status=CapabilityStatus.EXECUTABLE,
        is_executable=True,
        parameter_schema=RestartOrderApiParams.model_json_schema(),
        supported_environments=["development"],
        approval_required=True,
        supported_services=["Order API", "order-api", "order_api", "demo-order-service"],
        required_service_attributes=["health_check_url"],
        security_restrictions=[
            "Restricted to Order API demo instance",
            "Demo service reset simulation",
        ],
        target_resource_type="demo_http_endpoint",
        preconditions=[
            "Service exists in the target workspace",
            "Service is marked active",
            "Target port and endpoint are within permitted localhost/demo bounds",
        ],
        verification_criteria="Service health check URL returns HTTP 200 and passes synthetic health probe within 60s.",
        timeout_seconds=60,
        enabled=True,
    ),

    # ------------------------------------------------------------------------
    # 6. Reusable Deployment Rollback Capability (Requires Orchestrator Adapter)
    # ------------------------------------------------------------------------
    "rollback_deployment": ActionDefinition(
        action_id="rollback_deployment",
        name="Rollback Service Deployment",
        description="Reverts the service deployment to the previous stable revision.",
        category=ActionCategory.SERVICE_RECOVERY,
        risk_level=RiskLevel.HIGH,
        execution_mechanism=ExecutionMechanism.DEPLOYMENT_ROLLBACK,
        status=CapabilityStatus.REQUIRES_ADAPTER,
        is_executable=False,
        parameter_schema=RollbackDeploymentParams.model_json_schema(),
        supported_environments=["development", "staging", "production"],
        approval_required=True,
        supported_services=["*"],
        required_service_attributes=["deployment_manifest"],
        security_restrictions=[
            "Requires deployment orchestrator adapter (Kubernetes Deployment Controller or ArgoCD)",
            "Role-based deployment authorization",
            "Human approval mandatory",
        ],
        target_resource_type="deployment",
        preconditions=[
            "Service exists in the target workspace",
            "Service has deployment revision history",
            "Deployment orchestrator adapter configured",
        ],
        verification_criteria="Previous stable revision deployed, pods become ready, and health probe returns HTTP 200.",
        timeout_seconds=120,
        enabled=True,
    ),

    # ------------------------------------------------------------------------
    # 7. Reusable Application Cache Clear Capability (Requires Cache Adapter)
    # ------------------------------------------------------------------------
    "clear_application_cache": ActionDefinition(
        action_id="clear_application_cache",
        name="Clear Application Cache",
        description="Flushes application cache partition or namespaces to recover from stale data corruption or cache stampede.",
        category=ActionCategory.SERVICE_RECOVERY,
        risk_level=RiskLevel.MEDIUM,
        execution_mechanism=ExecutionMechanism.CACHE_MANAGEMENT,
        status=CapabilityStatus.REQUIRES_ADAPTER,
        is_executable=False,
        parameter_schema=ClearApplicationCacheParams.model_json_schema(),
        supported_environments=["development", "staging"],
        approval_required=True,
        supported_services=["*"],
        required_service_attributes=["cache_endpoint"],
        security_restrictions=[
            "Requires cache provider adapter (Redis or Memcached client)",
            "Restricted cache commands only (scoped partition flush)",
            "Zero arbitrary Redis eval or config commands",
        ],
        target_resource_type="cache_store",
        preconditions=[
            "Service exists in target workspace",
            "Cache provider adapter configured",
            "Target cache endpoint defined in approved network boundaries",
        ],
        verification_criteria="Cache namespace flushed, application latency stabilizes.",
        timeout_seconds=30,
        enabled=True,
    ),

    # ------------------------------------------------------------------------
    # 8. Reusable Configurable HTTP Service Recovery Adapter (Phase 5A)
    # ------------------------------------------------------------------------
    "execute_http_recovery": ActionDefinition(
        action_id="execute_http_recovery",
        name="Execute HTTP Service Recovery",
        description="Executes an authorized HTTP POST recovery operation against a relative recovery endpoint derived from the registered service's trusted health check origin.",
        category=ActionCategory.SERVICE_RECOVERY,
        risk_level=RiskLevel.MEDIUM,
        execution_mechanism=ExecutionMechanism.HTTP_RECOVERY,
        status=CapabilityStatus.EXECUTABLE,
        is_executable=True,
        parameter_schema=HttpRecoveryParams.model_json_schema(),
        supported_environments=["development", "staging", "production"],
        approval_required=True,
        supported_services=["*"],
        required_service_attributes=["health_check_url"],
        security_restrictions=[
            "HTTP method strictly restricted to POST only",
            "Hostname and origin strictly derived from registered service health_check_url",
            "Relative recovery path only; absolute URLs and external hostnames rejected",
            "Query strings, fragments, credentials, and directory traversal strictly rejected",
            "SSRF target validation with connection-time DNS/IP pinning",
            "Redirect following forbidden (3xx status rejection)",
            "Strictly validated JSON request body; arbitrary shell/script patterns rejected",
            "Human approval mandatory prior to execution",
        ],
        target_resource_type="http_endpoint",
        preconditions=[
            "Service exists in the target workspace",
            "Service is marked active",
            "Service has configured health_check_url",
            "Active HTTP recovery playbook configured and associated with service",
        ],
        verification_criteria="Target service passes 3 consecutive synthetic health probes via registered health check endpoint post-execution.",
        timeout_seconds=30,
        enabled=True,
    ),
}


class ActionRegistry:
    """Singleton-style registry for allowlisted remediation actions."""

    _service_id_playbooks: Dict[str, List[str]] = {}
    _registered_demo_services: Dict[str, Set[str]] = {"order_api": set()}

    @classmethod
    def register_service_playbook(cls, service_id: str, action_ids: List[str]) -> None:
        """Dynamically register allowlisted playbooks for a specific service ID."""
        cls._service_id_playbooks[service_id] = list(action_ids)

    @classmethod
    def unregister_service_playbook(cls, service_id: str) -> None:
        """Remove dynamic playbook registration for a service ID."""
        cls._service_id_playbooks.pop(service_id, None)

    @classmethod
    def clear_dynamic_playbooks(cls) -> None:
        """Clear all dynamically registered service playbooks."""
        cls._service_id_playbooks.clear()

    @classmethod
    def register_demo_service(cls, service_id: str, demo_type: str = "order_api") -> None:
        """Register a service ID as an explicit demo service instance (AUDIT-3.1-02)."""
        if demo_type not in cls._registered_demo_services:
            cls._registered_demo_services[demo_type] = set()
        cls._registered_demo_services[demo_type].add(str(service_id))

    @classmethod
    def unregister_demo_service(cls, service_id: str, demo_type: str = "order_api") -> None:
        """Unregister a service ID as a demo service instance."""
        if demo_type in cls._registered_demo_services:
            cls._registered_demo_services[demo_type].discard(str(service_id))

    @classmethod
    def clear_demo_services(cls) -> None:
        """Clear all dynamically registered demo services."""
        cls._registered_demo_services = {"order_api": set()}

    @classmethod
    def is_demo_service(
        cls, service: Optional[Any], demo_type: str = "order_api", db: Optional[Any] = None
    ) -> bool:
        """
        Determine if a service is explicitly configured as a demo service (AUDIT-3.1-02).
        NEVER infers demo status based on service name!
        Requires:
        1. Environment is 'development' AND execution_policy is 'demo'.
        2. AND one of:
           a. Explicit model attribute `demo_integration == demo_type`.
           b. In-memory registration in `_registered_demo_services`.
           c. Active dynamic demo playbook association in database.
        """
        if not service:
            return False

        env = (getattr(service, "environment", None) or "development").lower().strip()
        if env != "development":
            return False

        # 1. Explicit model attribute `demo_integration`
        svc_demo_integ = getattr(service, "demo_integration", None)
        if svc_demo_integ and svc_demo_integ == demo_type:
            return True

        # 2. In-memory explicit service registration (by service.id)
        service_id = str(getattr(service, "id", ""))
        if service_id and service_id in cls._registered_demo_services.get(demo_type, set()):
            return True

        # Stage 3.3 Security Boundary: Playbook associations CANNOT independently activate demo behavior
        return False

    @classmethod
    def evaluate_service_capability(
        cls,
        action_id: str,
        service: Optional[Any],
        db: Optional[Any] = None,
        for_playbook_association: bool = False,
    ) -> ServiceActionCapability:
        """
        Deterministically evaluates capability compatibility between an action and a registered service.
        Evaluates environment compatibility, execution policy, required attributes,
        adapter prerequisites, dynamic playbook associations, and service specificity.
        """
        action = cls.get_action(action_id)
        if not action:
            raise ValueError(f"Unknown action '{action_id}'")

        svc_name = getattr(service, "name", "Unknown Service") if service else "Unknown Service"
        svc_env = (getattr(service, "environment", "") or "development").lower().strip() if service else "unknown"
        svc_policy = getattr(service, "execution_policy", "demo") if service else "observe_only"
        svc_health_url = getattr(service, "health_check_url", "") if service else ""

        reasons: List[str] = []
        is_compat = True
        status_val = action.status

        # 1. Action enabled check
        if not action.enabled:
            is_compat = False
            status_val = CapabilityStatus.DISABLED
            reasons.append(f"Action '{action_id}' is administratively disabled in registry.")

        # 2. Service presence check
        if not service:
            is_compat = False
            reasons.append("Target service is not provided or unresolved.")

        # 3. Environment compatibility check
        if service and action.supported_environments:
            if svc_env not in [e.lower() for e in action.supported_environments]:
                is_compat = False
                reasons.append(
                    f"Service environment '{svc_env}' is not permitted for action '{action_id}' "
                    f"(supported environments: {action.supported_environments})."
                )

        # 4. Service execution policy check
        if service and svc_policy == "observe_only" and action.category == ActionCategory.SERVICE_RECOVERY:
            is_compat = False
            reasons.append(
                f"Service execution policy is 'observe_only'; operational recovery actions cannot be executed."
            )

        # 5. Required service attributes check
        if service and action.required_service_attributes:
            for attr in action.required_service_attributes:
                if attr == "health_check_url":
                    if not svc_health_url:
                        is_compat = False
                        reasons.append(f"Action requires 'health_check_url', but service '{svc_name}' has none configured.")
                    else:
                        # Validate URL syntax and reject blocked metadata endpoints
                        try:
                            parsed_url = urlparse(svc_health_url)
                            if parsed_url.scheme not in ("http", "https"):
                                is_compat = False
                                reasons.append(f"Invalid health check URL scheme '{parsed_url.scheme}'; must be http or https.")
                            host = (parsed_url.hostname or "").lower()
                            if host in ("169.254.169.254", "169.254.170.2", "100.100.100.200"):
                                is_compat = False
                                reasons.append("Health check URL points to forbidden cloud metadata endpoint.")
                        except Exception as e:
                            is_compat = False
                            reasons.append(f"Invalid health check URL format: {str(e)}")

        # 6. Service specificity check (e.g. restore_order_api_demo)
        if service and action.supported_services and "*" not in action.supported_services:
            if action_id in ("restore_order_api_demo", "restart_order_api"):
                # AUDIT-3.1-02: Never identify demo services solely by name!
                matched = cls.is_demo_service(service, "order_api", db=db)
                if not matched:
                    is_compat = False
                    reasons.append(
                        f"Action template '{action_id}' is service-specific and does not support service '{svc_name}': "
                        f"requires explicit demo integration configuration ('order_api'), "
                        f"but service '{svc_name}' is not configured as an order_api demo service."
                    )
            else:
                svc_name_norm = svc_name.lower().replace("-", " ").replace("_", " ").strip()
                patterns_norm = [p.lower().replace("-", " ").replace("_", " ").strip() for p in action.supported_services]
                matched = any(p in svc_name_norm or svc_name_norm in p for p in patterns_norm)

                if not matched:
                    is_compat = False
                    reasons.append(
                        f"Action template '{action_id}' is service-specific and does not support service '{svc_name}' "
                        f"(supported services: {action.supported_services})."
                    )

        # 6B. Dynamic HTTP Recovery configuration check (Phase 5A Section 4)
        # A service should advertise HTTP recovery capability only when an active,
        # validated HTTP recovery playbook is associated with this specific service.
        if is_compat and action_id == "execute_http_recovery" and not for_playbook_association:
            has_active_playbook = False
            service_id = getattr(service, "id", None)
            if getattr(service, "recovery_enabled", False) and getattr(service, "recovery_endpoint", None):
                has_active_playbook = True
            elif db is not None and service_id:
                try:
                    from app.models.playbook import Playbook, ServicePlaybookAssociation
                    assocs = (
                        db.query(ServicePlaybookAssociation)
                        .join(Playbook, Playbook.id == ServicePlaybookAssociation.playbook_id)
                        .filter(
                            ServicePlaybookAssociation.service_id == str(service_id),
                            ServicePlaybookAssociation.is_active == True,
                            Playbook.is_active == True,
                        )
                        .all()
                    )
                    for a in assocs:
                        v = a.playbook.active_version if a.playbook else None
                        if v and v.action_template_id == "execute_http_recovery":
                            has_active_playbook = True
                            break
                except Exception:
                    pass
            if not has_active_playbook and service_id and service_id in cls._service_id_playbooks:
                if "execute_http_recovery" in cls._service_id_playbooks[service_id]:
                    has_active_playbook = True

            if not has_active_playbook:
                is_compat = False
                status_val = CapabilityStatus.REQUIRES_ADAPTER
                reasons.append(
                    f"Service '{svc_name}' has no active configured HTTP recovery playbook associated. "
                    "Configure and activate an HTTP recovery playbook in the Playbooks catalog to enable this capability."
                )

        # 7. Adapter requirement check
        if action.status == CapabilityStatus.REQUIRES_ADAPTER or not action.is_executable:
            is_compat = False
            status_val = CapabilityStatus.REQUIRES_ADAPTER
            reasons.append(
                f"Action requires infrastructure adapter ({action.execution_mechanism.value}) "
                f"which is not configured in current execution runtime."
            )

        if is_compat:
            status_val = CapabilityStatus.EXECUTABLE
            reasons.append(f"Service '{svc_name}' satisfies all capability prerequisites and environment constraints.")

        return ServiceActionCapability(
            action_id=action.action_id,
            action_name=action.name,
            description=action.description,
            category=action.category,
            risk_level=action.risk_level,
            execution_mechanism=action.execution_mechanism,
            status=status_val,
            is_compatible=is_compat,
            is_executable=(is_compat and action.is_executable),
            approval_required=action.approval_required,
            reasons=reasons,
            prerequisites=list(action.preconditions),
            parameter_schema=action.parameter_schema,
            verification_criteria=action.verification_criteria,
            target_resource_type=action.target_resource_type,
            supported_environments=action.supported_environments,
        )

    @classmethod
    def discover_service_capabilities(
        cls, service: Any, db: Optional[Any] = None
    ) -> ServiceCapabilitiesResponse:
        """
        Discovers and evaluates all allowlisted remediation capabilities for a registered service.
        Returns explicit compatibility assessment and execution eligibility for each capability.
        """
        capabilities: List[ServiceActionCapability] = []
        for action_id in ALLOWLISTED_ACTIONS:
            cap = cls.evaluate_service_capability(action_id, service, db=db)
            capabilities.append(cap)

        compat_count = sum(1 for c in capabilities if c.is_compatible)
        exec_count = sum(1 for c in capabilities if c.is_executable)

        return ServiceCapabilitiesResponse(
            service_id=str(getattr(service, "id", "")),
            service_name=getattr(service, "name", "Unknown Service"),
            environment=getattr(service, "environment", "development"),
            execution_policy=getattr(service, "execution_policy", "demo"),
            capabilities=capabilities,
            compatible_count=compat_count,
            executable_count=exec_count,
            total_count=len(capabilities),
        )

    @classmethod
    def is_action_supported_for_service(
        cls, action_id: str, service: Optional[Any], db: Optional[Any] = None
    ) -> bool:
        """
        Check if an action is authorized and supported for the given service.
        """
        if not service:
            return False

        action = cls.get_action(action_id)
        if not action or not action.enabled:
            return False

        # Stage 3.3 Security Boundary: Demo actions strictly require authorized demo service integration.
        # Playbook associations, service names, or heuristics cannot independently activate demo actions on generic services.
        if action_id in ("restore_order_api_demo", "restart_order_api"):
            return cls.is_demo_service(service, "order_api", db=db)

        # 1. Persistent dynamic playbooks in database (if db session available)
        if db is not None:
            try:
                from app.remediation.playbook_service import PlaybookService
                if PlaybookService.is_action_supported_for_service(db, action_id, service):
                    return True
            except Exception:
                pass

        # 2. Explicit per-service registration overrides (by service.id)
        service_id = getattr(service, "id", None)
        if service_id and service_id in cls._service_id_playbooks:
            if action_id in cls._service_id_playbooks[service_id]:
                return True

        # 3. Fallback to action definition's supported_services list (for static/universal actions)
        if action_id == "execute_http_recovery":
            # HTTP recovery is supported if the service explicitly has recovery configured and enabled
            if getattr(service, "recovery_enabled", False) and getattr(service, "recovery_endpoint", None):
                return True
            return False

        if "*" in action.supported_services:
            return True

        svc_name = getattr(service, "name", "")
        svc_health_url = getattr(service, "health_check_url", "")
        svc_name_norm = svc_name.lower().replace("-", " ").replace("_", " ").strip()
        patterns_norm = [p.lower().replace("-", " ").replace("_", " ").strip() for p in action.supported_services]
        return any(p in svc_name_norm or svc_name_norm in p for p in patterns_norm)

    @classmethod
    def get_playbooks_for_service(
        cls, service: Any, db: Optional[Any] = None
    ) -> List[ActionDefinition]:
        """Return all allowlisted remediation playbooks supported for the given service."""
        return [
            act
            for act in cls.list_actions(include_disabled=False)
            if act.category == ActionCategory.SERVICE_RECOVERY
            and act.is_executable
            and cls.is_action_supported_for_service(act.action_id, service, db=db)
        ]

    @classmethod
    def get_action(cls, action_id: str) -> Optional[ActionDefinition]:
        """Lookup an action definition by ID. Returns None if unknown."""
        return ALLOWLISTED_ACTIONS.get(action_id)

    @classmethod
    def list_actions(cls, include_disabled: bool = False) -> List[ActionDefinition]:
        """List all allowlisted actions, optionally including disabled actions."""
        if include_disabled:
            return list(ALLOWLISTED_ACTIONS.values())
        return [act for act in ALLOWLISTED_ACTIONS.values() if act.enabled]

    @classmethod
    def get_parameter_model(cls, action_id: str) -> Optional[Type[BaseModel]]:
        """Return the Pydantic parameter validation model for the given action."""
        if action_id == "execute_http_recovery" and "execute_http_recovery" not in ACTION_PARAMETER_MODELS:
            ACTION_PARAMETER_MODELS["execute_http_recovery"] = HttpRecoveryParams
        return ACTION_PARAMETER_MODELS.get(action_id)

    @classmethod
    def register_parameter_model(cls, action_id: str, model_cls: Type[BaseModel]) -> None:
        """Register or update a parameter validation model for an action ID."""
        ACTION_PARAMETER_MODELS[action_id] = model_cls

    @classmethod
    def register_action(
        cls,
        action_def: ActionDefinition,
        model_cls: Optional[Type[BaseModel]] = None,
    ) -> None:
        """Register or update an allowlisted action definition in the canonical registry."""
        ALLOWLISTED_ACTIONS[action_def.action_id] = action_def
        if model_cls is not None:
            cls.register_parameter_model(action_def.action_id, model_cls)

    @classmethod
    def validate_parameters(
        cls, action_id: str, raw_params: Dict[str, Any]
    ) -> Tuple[bool, Optional[BaseModel], Optional[str]]:
        """
        Validate raw input parameters against the action's strict schema.

        Returns:
            (is_valid, parsed_model_instance, error_message)
        """
        model_cls = cls.get_parameter_model(action_id)
        if not model_cls:
            return False, None, f"No parameter schema defined for action '{action_id}'."

        try:
            validated = model_cls.model_validate(raw_params)
            return True, validated, None
        except ValidationError as err:
            # Extract clean, human-readable validation error messages
            error_details = []
            for err_dict in err.errors():
                loc = ".".join(str(p) for p in err_dict.get("loc", []))
                msg = err_dict.get("msg", "invalid")
                error_details.append(f"Field '{loc}': {msg}")
            return False, None, "; ".join(error_details)
        except Exception as e:
            return False, None, f"Parameter validation error: {str(e)}"
