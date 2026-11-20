"""Service registration and presentation schemas per blueprint specifications."""

from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator


class ServiceBase(BaseModel):
    """Common attributes for a registered service."""
    name: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Service name (2-100 characters)"
    )
    environment: Literal["development", "staging", "production"] = Field(
        default="development",
        description="Deployment environment"
    )
    health_check_url: str = Field(
        ...,
        description="URL for health endpoint (validated at registration, not called automatically)"
    )
    monitoring_method: Literal["prometheus", "opentelemetry", "builtin"] = Field(
        default="prometheus",
        description="Telemetry collection method"
    )
    execution_policy: Literal["demo", "approval_required", "observe_only"] = Field(
        default="demo",
        description="Remediation execution policy"
    )
    demo_integration: Optional[Literal["order_api"]] = Field(
        default=None,
        description="Explicit demo integration identifier (only permitted in 'development' environment)"
    )
    recovery_endpoint: Optional[str] = Field(
        default=None,
        description="Relative recovery endpoint path (e.g. /demo/restore or /admin/recovery/reset)",
    )
    recovery_method: Optional[Literal["POST"]] = Field(
        default="POST",
        description="HTTP method for recovery action (initially POST)",
    )
    recovery_enabled: bool = Field(
        default=False,
        description="Whether recovery action is explicitly configured and authorized for this service",
    )

    @field_validator("recovery_endpoint")
    @classmethod
    def validate_recovery_endpoint_path(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and str(v).strip():
            from app.remediation.schemas import validate_relative_recovery_path
            return validate_relative_recovery_path(str(v).strip())
        return None

    @field_validator("demo_integration")
    @classmethod
    def validate_demo_integration(cls, v: Optional[str], info) -> Optional[str]:
        if v is not None:
            data = info.data
            env = data.get("environment", "development")
            if env != "development":
                raise ValueError("demo_integration is only permitted in the 'development' environment.")
        return v

    @field_validator("health_check_url")
    @classmethod
    def validate_url_format(cls, v: str) -> str:
        """Validate URL format without probing or initiating any network connection."""
        v_clean = v.strip()
        if not (v_clean.startswith("http://") or v_clean.startswith("https://")):
            raise ValueError("Health-check URL must start with http:// or https://")
        return v_clean


class ServiceCreate(ServiceBase):
    """Schema for registering a new service within a workspace."""
    workspace_id: str = Field(..., description="Target workspace ID for tenant scoping")


class DemoServiceProvisionRequest(BaseModel):
    """Schema for explicit server-authorized provisioning of the Order API demo service."""
    workspace_id: str = Field(..., description="Target workspace ID for tenant scoping")
    name: str = Field(
        default="Order API",
        min_length=2,
        max_length=100,
        description="Demo service name"
    )
    environment: Literal["development"] = Field(
        default="development",
        description="Demo services are strictly restricted to the development environment"
    )
    health_check_url: str = Field(
        default="http://127.0.0.1:8001/health",
        description="Health-check URL for the Order API demo workload"
    )
    monitoring_method: Literal["prometheus", "opentelemetry", "builtin"] = Field(
        default="prometheus",
        description="Telemetry collection method"
    )
    execution_policy: Literal["demo"] = Field(
        default="demo",
        description="Execution policy for demo service"
    )
    demo_integration: Literal["order_api"] = Field(
        default="order_api",
        description="Explicit demo integration identifier"
    )

    @field_validator("health_check_url")
    @classmethod
    def validate_url_format(cls, v: str) -> str:
        """Validate URL format without probing or initiating any network connection."""
        v_clean = v.strip()
        if not (v_clean.startswith("http://") or v_clean.startswith("https://")):
            raise ValueError("Health-check URL must start with http:// or https://")
        return v_clean


class ServiceResponse(ServiceBase):
    """Schema for returning service details."""
    id: str
    workspace_id: str
    is_active: bool
    health_status: str
    last_checked_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
