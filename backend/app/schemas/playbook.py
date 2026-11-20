"""Pydantic schemas for Dynamic Remediation Playbooks."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class PlaybookVersionResponse(BaseModel):
    """Presentation schema for a specific version of a playbook."""
    id: str
    playbook_id: str
    version_number: int
    action_template_id: str
    action_name: Optional[str] = None
    supported_scenarios: List[str] = Field(default_factory=list)
    parameter_schema: Dict[str, Any] = Field(default_factory=dict)
    verification_criteria: Dict[str, Any] = Field(default_factory=dict)
    risk_level: str
    approval_required: bool
    timeout_seconds: int
    change_summary: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ServiceAssociationSummary(BaseModel):
    """Summary of a service associated with a playbook."""
    service_id: str
    service_name: str
    is_active: bool
    priority: int
    associated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlaybookResponse(BaseModel):
    """Presentation schema for a playbook."""
    id: str
    workspace_id: str
    name: str
    description: Optional[str] = None
    category: str
    is_active: bool
    current_version: int
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    active_version: Optional[PlaybookVersionResponse] = None
    associated_services_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class PlaybookDetailResponse(PlaybookResponse):
    """Detailed presentation schema for a playbook with versions and service bindings."""
    versions: List[PlaybookVersionResponse] = Field(default_factory=list)
    associated_services: List[ServiceAssociationSummary] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class PlaybookCreate(BaseModel):
    """Request schema for creating a new playbook."""
    workspace_id: str
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None
    category: str = Field(default="service_recovery")
    action_template_id: str
    supported_scenarios: List[str] = Field(default_factory=lambda: ["*"])
    parameter_schema: Dict[str, Any] = Field(default_factory=dict)
    verification_criteria: Dict[str, Any] = Field(default_factory=dict)
    risk_level: str = Field(default="medium")
    approval_required: bool = True
    timeout_seconds: int = Field(default=30, ge=5, le=300)
    initial_service_ids: List[str] = Field(default_factory=list)


class PlaybookUpdate(BaseModel):
    """Request schema for updating an existing playbook."""
    workspace_id: str
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = None
    category: Optional[str] = None
    is_active: Optional[bool] = None

    # Version updates (if provided, creates a new PlaybookVersion)
    action_template_id: Optional[str] = None
    supported_scenarios: Optional[List[str]] = None
    parameter_schema: Optional[Dict[str, Any]] = None
    verification_criteria: Optional[Dict[str, Any]] = None
    risk_level: Optional[str] = None
    approval_required: Optional[bool] = None
    timeout_seconds: Optional[int] = Field(None, ge=5, le=300)
    change_summary: Optional[str] = None


class PlaybookValidationRequest(BaseModel):
    """Request schema for validating a playbook configuration."""
    workspace_id: str
    action_template_id: str
    service_ids: List[str] = Field(default_factory=list)
    parameter_schema: Dict[str, Any] = Field(default_factory=dict)
    verification_criteria: Dict[str, Any] = Field(default_factory=dict)
    risk_level: Optional[str] = "medium"


class IncompatibleServiceReason(BaseModel):
    """Reason why a service cannot be bound to an action."""
    service_id: str
    service_name: str
    reason: str


class PlaybookValidationResponse(BaseModel):
    """Response schema for playbook validation."""
    is_valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    action_template_name: Optional[str] = None
    action_category: Optional[str] = None
    default_risk_level: Optional[str] = None
    compatible_services: List[str] = Field(default_factory=list)
    incompatible_services: List[IncompatibleServiceReason] = Field(default_factory=list)


class ServicePlaybookAssociationRequest(BaseModel):
    """Request schema for associating a service with a playbook."""
    workspace_id: str
    service_id: str
    priority: int = 0


class ServicePlaybookAssociationResponse(BaseModel):
    """Response schema for service-playbook association."""
    id: str
    workspace_id: str
    service_id: str
    service_name: str
    playbook_id: str
    playbook_name: str
    is_active: bool
    priority: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
