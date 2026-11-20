"""Dashboard overview metrics and summary endpoints."""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import statistics
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.service import Service
from app.models.incident import Incident, IncidentEvent
from app.models.investigation import Investigation
from app.models.remediation import RemediationExecution
from app.models.verification import VerificationCycle
from app.models.workspace import Workspace
from app.schemas.incident import IncidentResponse
from app.schemas.dashboard import (
    DashboardOverviewResponse,
    DashboardRecentEvent,
    DashboardAnalyticsResponse,
    IncidentTrendItem,
    InvestigationAnalytics,
    ExecutionAnalytics,
    ServiceAnalyticsItem,
)
from app.api.deps import RequireWorkspaceRole


router = APIRouter()


@router.get(
    "/overview",
    response_model=DashboardOverviewResponse,
    summary="Get aggregated operational dashboard metrics",
)
def get_dashboard_overview(
    workspace_id: str = Query(..., description="Workspace ID"),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> DashboardOverviewResponse:
    """Compute real operational metrics from PostgreSQL data for the workspace."""
    workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()

    # 1. Service Counts
    total_services = db.query(Service).filter(Service.workspace_id == workspace_id).count()
    healthy_services = (
        db.query(Service)
        .filter(Service.workspace_id == workspace_id, Service.health_status == "healthy")
        .count()
    )
    degraded_services = (
        db.query(Service)
        .filter(Service.workspace_id == workspace_id, Service.health_status == "degraded")
        .count()
    )
    unhealthy_services = (
        db.query(Service)
        .filter(Service.workspace_id == workspace_id, Service.health_status == "unhealthy")
        .count()
    )

    # 2. Active Incidents (detected, investigating, awaiting_approval, investigation_failed, remediating, verifying)
    active_statuses = [
        "detected",
        "investigating",
        "awaiting_approval",
        "investigation_failed",
        "remediating",
        "verifying",
    ]
    active_incidents = (
        db.query(Incident)
        .filter(
            Incident.workspace_id == workspace_id,
            Incident.status.in_(active_statuses),
        )
        .count()
    )

    # 3. Severity Breakdown
    severities = ["critical", "high", "medium", "low"]
    severity_counts: Dict[str, int] = {s: 0 for s in severities}
    sev_rows = (
        db.query(Incident.severity, func.count(Incident.id))
        .filter(
            Incident.workspace_id == workspace_id,
            Incident.status.in_(active_statuses),
        )
        .group_by(Incident.severity)
        .all()
    )
    for sev, count in sev_rows:
        if sev in severity_counts:
            severity_counts[sev] = count

    # 4. Recent Incidents (latest 5)
    recent_incidents = (
        db.query(Incident)
        .filter(Incident.workspace_id == workspace_id)
        .order_by(Incident.detected_at.desc())
        .limit(5)
        .all()
    )

    # 5. Recent Timeline Events (latest 8)
    recent_events_rows = (
        db.query(
            IncidentEvent.id,
            IncidentEvent.incident_id,
            IncidentEvent.event_type,
            IncidentEvent.message,
            IncidentEvent.timestamp,
            Incident.title.label("incident_title"),
            Service.name.label("service_name"),
        )
        .join(Incident, IncidentEvent.incident_id == Incident.id)
        .outerjoin(Service, Incident.service_id == Service.id)
        .filter(Incident.workspace_id == workspace_id)
        .order_by(IncidentEvent.timestamp.desc())
        .limit(8)
        .all()
    )

    recent_events = [
        DashboardRecentEvent(
            id=row.id,
            incident_id=row.incident_id,
            incident_title=row.incident_title or "Incident",
            service_name=row.service_name or "Service",
            event_type=row.event_type,
            message=row.message,
            timestamp=row.timestamp,
        )
        for row in recent_events_rows
    ]

    return DashboardOverviewResponse(
        workspace_id=workspace.id,
        workspace_name=workspace.name,
        total_services=total_services,
        healthy_services=healthy_services,
        degraded_services=degraded_services,
        unhealthy_services=unhealthy_services,
        active_incidents=active_incidents,
        incidents_by_severity=severity_counts,
        recent_incidents=[IncidentResponse.model_validate(inc) for inc in recent_incidents],
        recent_events=recent_events,
    )


@router.get(
    "/analytics",
    response_model=DashboardAnalyticsResponse,
    summary="Get comprehensive incident, verification, and SRE analytics",
    description="Calculates empirical metrics: MTTD, MTTR, severity distribution, timeline trends, investigation stats, and verification outcomes.",
)
def get_dashboard_analytics(
    workspace_id: str = Query(..., description="Workspace ID for scoping"),
    service_id: Optional[str] = Query(None, description="Optional service ID filter"),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> DashboardAnalyticsResponse:
    """Compute audit-grounded analytics across incidents, investigations, and remediation."""
    workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()
    if not workspace:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workspace '{workspace_id}' not found.",
        )

    # 1. Incidents Query Scoped to Workspace & Optional Service
    inc_query = db.query(Incident).filter(Incident.workspace_id == workspace_id)
    if service_id:
        inc_query = inc_query.filter(Incident.service_id == service_id)
    all_incidents = inc_query.all()

    total_incidents = len(all_incidents)
    active_statuses = {"detected", "investigating", "awaiting_approval", "investigation_failed", "remediating", "verifying"}
    active_incidents = sum(1 for i in all_incidents if i.status in active_statuses)
    recovered_incidents = sum(1 for i in all_incidents if i.status == "recovered")
    closed_incidents = sum(1 for i in all_incidents if i.status == "closed")

    # Severity Breakdown
    severities = ["critical", "high", "medium", "low"]
    severity_distribution = {s: 0 for s in severities}
    for inc in all_incidents:
        if inc.severity in severity_distribution:
            severity_distribution[inc.severity] += 1

    # Status Breakdown
    statuses = ["detected", "investigating", "awaiting_approval", "investigation_failed", "remediating", "verifying", "recovered", "closed"]
    status_distribution = {s: 0 for s in statuses}
    for inc in all_incidents:
        if inc.status in status_distribution:
            status_distribution[inc.status] += 1

    # 2. MTTR Calculation (Empirical: recovered_at - detected_at for recovered incidents)
    mttr_durations: List[float] = []
    for inc in all_incidents:
        if inc.status == "recovered" and inc.detected_at and inc.recovered_at:
            delta = (inc.recovered_at - inc.detected_at).total_seconds()
            if delta >= 0:
                mttr_durations.append(delta)

    avg_mttr = round(statistics.mean(mttr_durations), 2) if mttr_durations else None
    median_mttr = round(statistics.median(mttr_durations), 2) if mttr_durations else None
    mttr_sample_size = len(mttr_durations)

    # 3. MTTD Calculation (Empirical: detection delay from first detection event metadata)
    mttd_delays: List[float] = []
    for inc in all_incidents:
        detection_event = (
            db.query(IncidentEvent)
            .filter(IncidentEvent.incident_id == inc.id, IncidentEvent.event_type == "detection")
            .first()
        )
        if detection_event and detection_event.metadata_json:
            try:
                import json
                meta = json.loads(detection_event.metadata_json)
                if isinstance(meta, dict) and "latency_ms" in meta and meta["latency_ms"] is not None:
                    mttd_delays.append(round(meta["latency_ms"] / 1000.0, 3))
            except Exception:
                pass

    avg_mttd = round(statistics.mean(mttd_delays), 2) if mttd_delays else None
    mttd_sample_size = len(mttd_delays)

    # 4. Incident Trends over time (bucketed by date)
    date_map: Dict[str, Dict[str, int]] = {}
    for inc in all_incidents:
        if inc.detected_at:
            d_str = inc.detected_at.strftime("%Y-%m-%d")
            if d_str not in date_map:
                date_map[d_str] = {"detected": 0, "recovered": 0}
            date_map[d_str]["detected"] += 1

        if inc.recovered_at:
            r_str = inc.recovered_at.strftime("%Y-%m-%d")
            if r_str not in date_map:
                date_map[r_str] = {"detected": 0, "recovered": 0}
            date_map[r_str]["recovered"] += 1

    sorted_dates = sorted(date_map.keys())
    incident_trends = [
        IncidentTrendItem(date=d, detected=date_map[d]["detected"], recovered=date_map[d]["recovered"])
        for d in sorted_dates
    ]

    # 5. Investigation Analytics
    inv_query = db.query(Investigation).filter(Investigation.workspace_id == workspace_id)
    if service_id:
        inv_query = inv_query.join(Incident, Investigation.incident_id == Incident.id).filter(Incident.service_id == service_id)
    all_invs = inv_query.all()

    total_invs = len(all_invs)
    completed_invs = sum(1 for iv in all_invs if iv.status == "completed")
    failed_invs = sum(1 for iv in all_invs if iv.status == "failed")
    running_invs = sum(1 for iv in all_invs if iv.status in ("pending", "running"))

    model_counts: Dict[str, int] = {}
    confidence_scores: List[float] = []
    cause_counts: Dict[str, int] = {}

    for iv in all_invs:
        model_name = iv.model_name or "unknown"
        model_counts[model_name] = model_counts.get(model_name, 0) + 1

        if iv.summary and isinstance(iv.summary, dict):
            cause = iv.summary.get("likely_root_cause")
            if cause:
                cause_counts[cause] = cause_counts.get(cause, 0) + 1

        if iv.hypotheses and isinstance(iv.hypotheses, list):
            for h in iv.hypotheses:
                if isinstance(h, dict) and "confidence" in h and h["confidence"] is not None:
                    confidence_scores.append(float(h["confidence"]))

    avg_conf = round(statistics.mean(confidence_scores), 2) if confidence_scores else None
    top_causes = [
        {"root_cause": cause, "count": count}
        for cause, count in sorted(cause_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    inv_analytics = InvestigationAnalytics(
        total_investigations=total_invs,
        completed=completed_invs,
        failed=failed_invs,
        running_or_pending=running_invs,
        avg_confidence=avg_conf,
        model_breakdown=model_counts,
        top_diagnosed_causes=top_causes,
    )

    # 6. Execution & Verification Analytics
    exec_query = db.query(RemediationExecution).filter(RemediationExecution.workspace_id == workspace_id)
    if service_id:
        exec_query = exec_query.filter(RemediationExecution.target_service_id == service_id)
    all_execs = exec_query.all()

    total_execs = len(all_execs)
    verified_execs = sum(1 for e in all_execs if e.status == "verified")
    failed_execs = sum(1 for e in all_execs if e.status == "failed")
    uncertain_execs = sum(1 for e in all_execs if e.status == "execution_uncertain")
    in_progress_execs = sum(1 for e in all_execs if e.status in ("queued", "running", "dispatched", "verifying"))

    v_passed = sum(1 for e in all_execs if e.verification_status == "passed")
    v_failed = sum(1 for e in all_execs if e.verification_status == "failed")
    v_inconclusive = sum(1 for e in all_execs if e.verification_status == "inconclusive")
    v_pending = sum(1 for e in all_execs if e.verification_status in ("pending", "running"))

    # Also count from VerificationCycle records if available
    cycle_query = db.query(VerificationCycle).filter(VerificationCycle.workspace_id == workspace_id)
    all_cycles = cycle_query.all()
    if all_cycles:
        v_passed = max(v_passed, sum(1 for c in all_cycles if c.status == "passed"))
        v_failed = max(v_failed, sum(1 for c in all_cycles if c.status == "failed"))
        v_inconclusive = max(v_inconclusive, sum(1 for c in all_cycles if c.status in ("uncertain", "timed_out")))
        v_pending = max(v_pending, sum(1 for c in all_cycles if c.status in ("pending", "running")))

    exec_analytics = ExecutionAnalytics(
        total_executions=total_execs,
        verified=verified_execs,
        failed=failed_execs,
        uncertain=uncertain_execs,
        in_progress=in_progress_execs,
        verification_passed=v_passed,
        verification_failed=v_failed,
        verification_inconclusive=v_inconclusive,
        verification_pending=v_pending,
    )

    # 7. Service-Level Breakdown
    services = db.query(Service).filter(Service.workspace_id == workspace_id).all()
    service_items: List[ServiceAnalyticsItem] = []
    for svc in services:
        svc_incs = [i for i in all_incidents if i.service_id == svc.id]
        svc_recovered = [i for i in svc_incs if i.status == "recovered"]
        svc_mttr_durations = [
            (i.recovered_at - i.detected_at).total_seconds()
            for i in svc_recovered
            if i.detected_at and i.recovered_at and (i.recovered_at - i.detected_at).total_seconds() >= 0
        ]
        svc_avg_mttr = round(statistics.mean(svc_mttr_durations), 2) if svc_mttr_durations else None

        service_items.append(
            ServiceAnalyticsItem(
                service_id=svc.id,
                service_name=svc.name,
                environment=svc.environment,
                health_status=svc.health_status,
                total_incidents=len(svc_incs),
                recovered_incidents=len(svc_recovered),
                avg_mttr_seconds=svc_avg_mttr,
            )
        )

    return DashboardAnalyticsResponse(
        workspace_id=workspace.id,
        workspace_name=workspace.name,
        total_incidents=total_incidents,
        active_incidents=active_incidents,
        recovered_incidents=recovered_incidents,
        closed_incidents=closed_incidents,
        severity_distribution=severity_distribution,
        status_distribution=status_distribution,
        avg_mttr_seconds=avg_mttr,
        median_mttr_seconds=median_mttr,
        mttr_sample_size=mttr_sample_size,
        avg_mttd_seconds=avg_mttd,
        mttd_sample_size=mttd_sample_size,
        incident_trends=incident_trends,
        investigation_analytics=inv_analytics,
        execution_analytics=exec_analytics,
        services=service_items,
    )
