"""Dashboard overview data schemas."""

from typing import Dict, List, Any, Optional
from datetime import datetime
from pydantic import BaseModel
from app.schemas.incident import IncidentResponse


class DashboardRecentEvent(BaseModel):
    id: str
    incident_id: str
    incident_title: str
    service_name: str
    event_type: str
    message: str
    timestamp: datetime


class DashboardOverviewResponse(BaseModel):
    workspace_id: str
    workspace_name: str
    total_services: int
    healthy_services: int
    degraded_services: int
    unhealthy_services: int
    active_incidents: int
    incidents_by_severity: Dict[str, int]
    recent_incidents: List[IncidentResponse]
    recent_events: List[DashboardRecentEvent]


class IncidentTrendItem(BaseModel):
    date: str
    detected: int
    recovered: int


class InvestigationAnalytics(BaseModel):
    total_investigations: int
    completed: int
    failed: int
    running_or_pending: int
    avg_confidence: Optional[float] = None
    model_breakdown: Dict[str, int] = {}
    top_diagnosed_causes: List[Dict[str, Any]] = []


class ExecutionAnalytics(BaseModel):
    total_executions: int
    verified: int
    failed: int
    uncertain: int
    in_progress: int
    verification_passed: int
    verification_failed: int
    verification_inconclusive: int
    verification_pending: int


class ServiceAnalyticsItem(BaseModel):
    service_id: str
    service_name: str
    environment: str
    health_status: str
    total_incidents: int
    recovered_incidents: int
    avg_mttr_seconds: Optional[float] = None


class DashboardAnalyticsResponse(BaseModel):
    workspace_id: str
    workspace_name: str
    total_incidents: int
    active_incidents: int
    recovered_incidents: int
    closed_incidents: int
    severity_distribution: Dict[str, int]
    status_distribution: Dict[str, int]
    avg_mttr_seconds: Optional[float] = None
    median_mttr_seconds: Optional[float] = None
    mttr_sample_size: int = 0
    avg_mttd_seconds: Optional[float] = None
    mttd_sample_size: int = 0
    incident_trends: List[IncidentTrendItem] = []
    investigation_analytics: InvestigationAnalytics
    execution_analytics: ExecutionAnalytics
    services: List[ServiceAnalyticsItem] = []
