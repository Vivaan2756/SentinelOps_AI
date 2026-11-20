"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { api, evaluateProposalEligibility, executeProposalWorkflow } from "@/lib/api";
import { Incident, IncidentEvent, Investigation, Hypothesis, EvidenceItem, Service } from "@/lib/types";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  AlertCircle,
  Activity,
  RefreshCw,
  Server,
  FileText,
  Calendar,
  Zap,
  Sparkles,
  BrainCircuit,
  HelpCircle,
  ShieldAlert,
  Clock,
  ChevronRight,
  Info,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

interface IncidentDetailState {
  incident: Incident;
  service: {
    id: string;
    name: string;
    environment: string;
  };
  timeline: IncidentEvent[];
}

export default function IncidentDetailPage() {
  const params = useParams();
  const incidentId = params?.incidentId as string;
  const { activeWorkspace, token } = useAuth();

  const [data, setData] = useState<IncidentDetailState | null>(null);
  const [serviceDetail, setServiceDetail] = useState<Service | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Investigation state
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [investigationError, setInvestigationError] = useState<string | null>(null);

  // Remediation proposal state (Phase 4.1 & 4.2)
  const [isProposing, setIsProposing] = useState(false);
  const [proposalSuccess, setProposalSuccess] = useState<{
    id: string;
    message: string;
    action_name: string;
  } | null>(null);
  const [proposalError, setProposalError] = useState<{
    type: "rejected" | "allowed" | "conflict" | "auth" | "validation" | "network" | "unexpected" | "error";
    message: string;
  } | null>(null);

  const userRole = activeWorkspace?.role?.toLowerCase() || "viewer";

  const rec = investigation?.summary?.remediation_recommendation || investigation?.remediation_recommendation;

  // Eligibility evaluation via centralized logic
  const eligibility = evaluateProposalEligibility({
    role: activeWorkspace?.role,
    investigationStatus: investigation?.status,
    hasTargetService: Boolean(data?.service?.id),
    serviceName: serviceDetail?.name || data?.service?.name,
    serviceEnvironment: serviceDetail?.environment || data?.service?.environment,
    executionPolicy: serviceDetail?.execution_policy,
    workspaceId: activeWorkspace?.workspace_id,
    incidentWorkspaceId: data?.incident?.workspace_id,
    serviceWorkspaceId: serviceDetail?.workspace_id,
    investigationWorkspaceId: investigation?.workspace_id,
    investigationIncidentId: investigation?.incident_id,
    incidentId: data?.incident?.id,
    recommendation: rec,
  });

  const {
    canInvestigate,
    isInvestigationComplete,
    hasPlaybook,
    isSupportedActionEnvironment,
    isObserveOnly,
    canPropose,
  } = eligibility;
  const targetEnvironment = (serviceDetail?.environment || data?.service?.environment || "").toLowerCase();
  const serviceExecutionPolicy = (serviceDetail?.execution_policy || "").toLowerCase();

  const fetchDetail = async () => {
    if (!incidentId || !activeWorkspace || !token) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.incidents.getDetail(incidentId, activeWorkspace.workspace_id, token);
      setData(res as IncidentDetailState);

      // Load authoritative service detail to inspect execution_policy
      if (res.service?.id) {
        try {
          const sDetail = await api.services.getDetail(res.service.id, activeWorkspace.workspace_id, token);
          setServiceDetail(sDetail.service);
        } catch {
          setServiceDetail(null);
        }
      }

      // Attempt to load existing investigation
      try {
        const inv = await api.investigations.getLatest(incidentId, activeWorkspace.workspace_id, token);
        setInvestigation(inv);
      } catch {
        // 404 indicates no investigation conducted yet - normal behavior
        setInvestigation(null);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load incident detail.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDetail();
  }, [incidentId, activeWorkspace?.workspace_id, token]);

  const handleStartInvestigation = async () => {
    if (!incidentId || !activeWorkspace || !token || !canInvestigate) return;
    setIsInvestigating(true);
    setInvestigationError(null);
    try {
      const inv = await api.investigations.start(incidentId, activeWorkspace.workspace_id, token, true);
      setInvestigation(inv);
      // Refresh incident timeline to show new investigation audit events
      const res = await api.incidents.getDetail(incidentId, activeWorkspace.workspace_id, token);
      setData(res as IncidentDetailState);
    } catch (err: any) {
      setInvestigationError(err.message || "Failed to execute AI investigation.");
    } finally {
      setIsInvestigating(false);
    }
  };

  const handleProposeRecoveryAction = async () => {
    if (isProposing || !canPropose || !incidentId || !activeWorkspace || !token || !data?.service?.id) {
      return;
    }

    setIsProposing(true);
    setProposalError(null);
    setProposalSuccess(null);

    const result = await executeProposalWorkflow({
      workspaceId: activeWorkspace.workspace_id,
      serviceId: data.service.id,
      incidentId,
      investigationId: investigation?.id,
      token,
      actionId: rec?.action_template_id || undefined,
      parameters: rec?.parameters || { service_id: data.service.id },
      environment: data.service.environment,
      playbookId: rec?.playbook_id || undefined,
      playbookVersion: rec?.playbook_version || undefined,
    });

    if (result.success) {
      setProposalSuccess({
        id: result.approvalId,
        message: result.message,
        action_name: result.actionName,
      });
      // Refresh incident detail to reflect newly recorded timeline event
      fetchDetail();
    } else {
      setProposalError({
        type: result.errorType,
        message: result.message,
      });
    }

    setIsProposing(false);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case "critical":
        return <Badge variant="error">Critical</Badge>;
      case "high":
        return <Badge variant="error">High</Badge>;
      case "medium":
        return <Badge variant="warning">Medium</Badge>;
      case "low":
        return <Badge variant="info">Low</Badge>;
      default:
        return <Badge variant="neutral">{sev}</Badge>;
    }
  };

  const getStatusBadge = (st: string) => {
    switch (st?.toLowerCase()) {
      case "detected":
        return <Badge variant="error">Detected</Badge>;
      case "investigating":
        return <Badge variant="warning">Investigating</Badge>;
      case "awaiting_approval":
        return <Badge variant="awaiting_approval">Awaiting Approval</Badge>;
      case "investigation_failed":
        return <Badge variant="investigation_failed">Investigation Failed</Badge>;
      case "remediating":
        return <Badge variant="warning">Remediating</Badge>;
      case "verifying":
        return <Badge variant="info">Verifying</Badge>;
      case "recovered":
        return <Badge variant="success">Recovered</Badge>;
      case "closed":
        return <Badge variant="neutral">Closed</Badge>;
      default:
        return <Badge variant="neutral">{st}</Badge>;
    }
  };

  const getEventIcon = (eventType: string) => {
    switch (eventType?.toLowerCase()) {
      case "detection":
        return <AlertTriangle className="w-4 h-4 text-rose-400" />;
      case "investigation":
        return <BrainCircuit className="w-4 h-4 text-cyan-400" />;
      case "verification":
        return <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
      case "evidence":
        return <Activity className="w-4 h-4 text-cyan-400" />;
      case "action":
        return <Zap className="w-4 h-4 text-amber-400" />;
      default:
        return <FileText className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Back button & Breadcrumb */}
      <div className="flex items-center gap-3">
        <Link
          href="/incidents"
          className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Incidents
        </Link>
        <span className="text-slate-600">/</span>
        <span className="text-xs text-slate-400 font-mono truncate max-w-xs">
          {data?.incident?.title || incidentId}
        </span>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
          <Button size="sm" variant="outline" onClick={fetchDetail}>
            Retry
          </Button>
        </div>
      )}

      {isLoading ? (
        <div className="p-12 text-center text-slate-500 flex flex-col items-center justify-center gap-3">
          <RefreshCw className="w-6 h-6 animate-spin text-cyan-500" />
          <p className="text-sm">Retrieving incident audit trail and timeline from database...</p>
        </div>
      ) : data ? (
        <>
          {/* Header Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-2.5">
                  {getSeverityBadge(data.incident.severity)}
                  {getStatusBadge(data.incident.status)}
                  <span className="text-xs font-mono text-slate-400">
                    ID: {data.incident.id}
                  </span>
                </div>
                <h1 className="text-xl font-bold text-white tracking-tight">
                  {data.incident.title}
                </h1>
                <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400 pt-1">
                  <div className="flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Affected Service:</span>
                    <Link
                      href={`/services/${data.service.id}`}
                      className="text-cyan-400 hover:text-cyan-300 font-medium underline-offset-2 hover:underline"
                    >
                      {data.service.name} ({data.service.environment})
                    </Link>
                  </div>
                  <div className="flex items-center gap-1.5 font-mono">
                    <Calendar className="w-3.5 h-3.5 text-slate-500" />
                    <span>Detected:</span>
                    <span className="text-slate-300">
                      {new Date(data.incident.detected_at).toLocaleString()}
                    </span>
                  </div>
                  {data.incident.recovered_at && (
                    <div className="flex items-center gap-1.5 font-mono text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Recovered:</span>
                      <span>{new Date(data.incident.recovered_at).toLocaleString()}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={fetchDetail}
                  disabled={isLoading || isInvestigating}
                >
                  <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${isLoading ? "animate-spin" : ""}`} />
                  Refresh
                </Button>

                {/* Agentic AI Investigation Trigger */}
                <Button
                  size="sm"
                  onClick={handleStartInvestigation}
                  disabled={isInvestigating || !canInvestigate}
                  className="bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-medium border-0 shadow-lg shadow-cyan-950/50"
                  title={
                    !canInvestigate
                      ? "Requires Engineer or Admin workspace role to trigger investigation"
                      : "Execute LangGraph automated diagnostic workflow"
                  }
                >
                  {isInvestigating ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                      Investigating with AI...
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-3.5 h-3.5 mr-1.5 text-cyan-200" />
                      {investigation ? "Re-Investigate with AI" : "Investigate with AI"}
                    </>
                  )}
                </Button>

                {/* Propose Recovery Action (Phase 4.1 & 4.2) */}
                {canPropose && !proposalSuccess && (
                  <Button
                    size="sm"
                    onClick={handleProposeRecoveryAction}
                    disabled={isProposing}
                    className="bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-medium border-0 shadow-lg shadow-emerald-950/50"
                    title="Submit allowlisted recovery proposal to human approval queue"
                  >
                    {isProposing ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                        Proposing Action...
                      </>
                    ) : (
                      <>
                        <Zap className="w-3.5 h-3.5 mr-1.5 text-emerald-200" />
                        Propose Recovery Action
                      </>
                    )}
                  </Button>
                )}

                {proposalSuccess && (
                  <Link
                    href="/remediation/approvals"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20 transition-colors shadow-sm"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>View in Approvals &rarr;</span>
                  </Link>
                )}
              </div>
            </div>

            {/* Role Warning for Viewer */}
            {!canInvestigate && (
              <div className="mt-4 p-2.5 rounded bg-slate-950/60 border border-slate-800 text-[11px] text-slate-400 flex items-center gap-2">
                <Info className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                <span>
                  Your workspace role is <strong>{userRole}</strong>. Only Engineers and Admins are authorized to initiate AI investigations.
                </span>
              </div>
            )}

            {investigationError && (
              <div className="mt-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{investigationError}</span>
              </div>
            )}
          </div>

          {/* AI INVESTIGATION REPORT PANEL (PHASE 3) */}
          {investigation && (
            <div className="space-y-6">
              {/* Investigation Header Card */}
              <div className="rounded-xl border border-cyan-800/50 bg-gradient-to-b from-slate-900/90 to-slate-950 p-6 shadow-xl relative overflow-hidden">
                <div className="absolute top-0 right-0 p-8 opacity-5 pointer-events-none">
                  <BrainCircuit className="w-48 h-48 text-cyan-400" />
                </div>

                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center text-cyan-300">
                      <BrainCircuit className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h2 className="text-lg font-bold text-white tracking-tight">
                          Agentic AI Investigation Report
                        </h2>
                        <Badge variant={investigation.status === "completed" ? "success" : "warning"}>
                          {investigation.status.toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-xs text-slate-400">
                        Orchestrated via LangGraph • Model: <span className="text-cyan-300 font-mono">{investigation.model_name}</span> • Prompt: <span className="font-mono text-slate-300">{investigation.prompt_version}</span>
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-slate-500" />
                      <span>Completed:</span>
                      <span className="text-slate-300">
                        {investigation.completed_at
                          ? new Date(investigation.completed_at).toLocaleTimeString()
                          : "In progress"}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Primary Diagnosis Callout */}
                {investigation.summary && (
                  <div className="mt-5 space-y-4">
                    <div className="p-4 rounded-lg bg-cyan-950/30 border border-cyan-500/30 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">
                          Identified Primary Root Cause
                        </span>
                        {investigation.hypotheses.length > 0 && (
                          <span className="text-xs font-mono text-cyan-300">
                            Evidential Support: {(investigation.hypotheses[0].confidence * 100).toFixed(0)}%
                          </span>
                        )}
                      </div>
                      <h3 className="text-base font-bold text-white">
                        {investigation.summary.likely_root_cause}
                      </h3>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {investigation.summary.incident_summary}
                      </p>
                    </div>

                    {/* Evidential Score Limitation Notice */}
                    <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-[11px] text-slate-400 flex items-start gap-2.5">
                      <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <span className="font-medium text-slate-300">Confidence Metric Clarification: </span>
                        <span>{investigation.summary.confidence_and_limitations}</span>
                      </div>
                    </div>

                    {/* Remediation Recovery Proposal Card (Phase 4 Stage 1) */}
                    <div className="p-4 rounded-xl bg-slate-950/70 border border-emerald-500/30 space-y-3.5 shadow-sm">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                        <div className="flex items-center gap-2.5">
                          <div className="w-7 h-7 rounded-lg bg-emerald-500/20 border border-emerald-400/30 flex items-center justify-center text-emerald-400">
                            <Zap className="w-4 h-4" />
                          </div>
                          <div>
                            <h4 className="text-sm font-semibold text-white tracking-tight">
                              Remediation Recovery Proposal
                            </h4>
                            <p className="text-[11px] text-slate-400">
                              Deterministic allowlisted recovery action • Requires human approval
                            </p>
                          </div>
                        </div>

                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant="warning">Medium Risk</Badge>
                          <Badge variant="awaiting_approval">Approval Required</Badge>
                          {serviceExecutionPolicy && (
                            <Badge variant="neutral">
                              Policy: {serviceExecutionPolicy}
                            </Badge>
                          )}
                        </div>
                      </div>

                      {/* Action Scope & Target Details */}
                      {!hasPlaybook ? (
                        <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs flex items-center gap-2">
                          <AlertCircle className="w-4 h-4 shrink-0 text-amber-400" />
                          <span>
                            {rec?.explanation || "No approved remediation playbook is configured for this service."}
                          </span>
                        </div>
                      ) : rec ? (
                        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-xs space-y-2">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2 font-mono">
                              <span className="text-slate-400">Playbook:</span>
                              <span className="text-emerald-300 font-semibold">
                                {rec.playbook_name || "Custom Playbook"}
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-800 text-cyan-300 text-[10px]">
                                v{rec.playbook_version || 1}
                              </span>
                              <span className="text-slate-500 text-[11px]">
                                ({rec.action_template_id})
                              </span>
                            </div>
                            <div className="flex items-center gap-2 text-slate-400">
                              <span>Target:</span>
                              <span className="text-white font-medium">
                                {data.service.name}
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-mono">
                                {targetEnvironment || "unknown"}
                              </span>
                            </div>
                          </div>
                          <p className="text-[11px] text-slate-300 leading-relaxed">
                            {rec.explanation}
                          </p>
                          {rec.parameters && Object.keys(rec.parameters).length > 0 && (
                            <div className="pt-1 text-[11px] font-mono text-slate-400">
                              <span>Validated Parameters: </span>
                              <span className="text-cyan-300">{JSON.stringify(rec.parameters)}</span>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-xs space-y-2">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2 font-mono">
                              <span className="text-slate-400">Action:</span>
                              <span className="text-emerald-300 font-semibold">
                                restore_order_api_demo
                              </span>
                              <span className="text-slate-500 text-[11px]">
                                (Restore Order API Demo Service)
                              </span>
                            </div>
                            <div className="flex items-center gap-2 text-slate-400">
                              <span>Target:</span>
                              <span className="text-white font-medium">
                                {data.service.name}
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-mono">
                                {targetEnvironment || "unknown"}
                              </span>
                            </div>
                          </div>
                          <p className="text-[11px] text-slate-300 leading-relaxed">
                            Restores Order API Demo service health by dispatching an allowlisted container recovery sequence. The action executes only after formal human review and approval.
                          </p>
                        </div>
                      )}

                      {/* Informational Policy/Environment/Role Guardrail Notices */}
                      {isObserveOnly && (
                        <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs flex items-center gap-2">
                          <Info className="w-4 h-4 shrink-0 text-amber-400" />
                          <span>
                            Service execution policy is <strong>observe_only</strong>. Automated remediation proposals are prohibited for this service.
                          </span>
                        </div>
                      )}

                      {!isSupportedActionEnvironment && targetEnvironment && (
                        <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 text-xs flex items-center gap-2">
                          <AlertCircle className="w-4 h-4 shrink-0 text-amber-400" />
                          <span>
                            Action <code>restore_order_api_demo</code> is only supported in the <strong>development</strong> environment (current: <code>{targetEnvironment}</code>).
                          </span>
                        </div>
                      )}

                      {!canInvestigate && (
                        <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 text-xs flex items-center gap-2">
                          <Info className="w-4 h-4 shrink-0 text-slate-400" />
                          <span>
                            Role <strong>{userRole}</strong> is restricted to read-only access. Only Engineers and Admins are authorized to propose recovery actions.
                          </span>
                        </div>
                      )}

                      {!isInvestigationComplete && (
                        <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 text-xs flex items-center gap-2">
                          <Clock className="w-4 h-4 shrink-0 text-amber-400" />
                          <span>
                            Investigation must reach <strong>completed</strong> status before proposing recovery actions (current: <code>{investigation.status}</code>).
                          </span>
                        </div>
                      )}

                      {/* Proposal Creation Success Feedback */}
                      {proposalSuccess && (
                        <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2 font-semibold text-emerald-200">
                              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                              <span>Recovery Proposal Created</span>
                            </div>
                            <span className="font-mono text-[11px] text-emerald-400">
                              ID: {proposalSuccess.id}
                            </span>
                          </div>
                          <p className="text-slate-300">
                            {proposalSuccess.message}
                          </p>
                          <div className="pt-1">
                            <Link
                              href="/remediation/approvals"
                              className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400 hover:text-emerald-300 underline underline-offset-4"
                            >
                              <span>Navigate to Remediation Approvals queue &rarr;</span>
                            </Link>
                          </div>
                        </div>
                      )}

                      {/* Proposal Creation Error Feedback */}
                      {proposalError && (
                        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs space-y-1.5">
                          <div className="flex items-start gap-2">
                            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
                            <div className="space-y-1">
                              <span className="font-semibold text-rose-200 block">
                                {proposalError.type === "rejected"
                                  ? "Policy Evaluation Rejected"
                                  : proposalError.type === "conflict"
                                  ? "Proposal Already Pending"
                                  : "Proposal Creation Failed"}
                              </span>
                              <span>{proposalError.message}</span>
                              {proposalError.type === "conflict" && (
                                <div className="pt-1">
                                  <Link
                                    href="/remediation/approvals"
                                    className="text-amber-300 hover:text-amber-200 underline font-medium"
                                  >
                                    View existing proposal in Approvals queue &rarr;
                                  </Link>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Action Trigger Button */}
                      {canPropose && !proposalSuccess && (
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 border-t border-slate-800">
                          <p className="text-[11px] text-slate-400 max-w-lg">
                            Submitting evaluates policy safety invariants and creates a pending proposal in the human approval queue.
                          </p>
                          <Button
                            size="sm"
                            onClick={handleProposeRecoveryAction}
                            disabled={isProposing}
                            className="bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-medium border-0 shadow-lg shadow-emerald-950/50 shrink-0"
                          >
                            {isProposing ? (
                              <>
                                <RefreshCw className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                                Evaluating & Submitting...
                              </>
                            ) : (
                              <>
                                <Zap className="w-3.5 h-3.5 mr-1.5 text-emerald-200" />
                                Propose Recovery Action
                              </>
                            )}
                          </Button>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Hypotheses & Evidence Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Left: Ranked Candidate Root-Cause Hypotheses */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                      <BrainCircuit className="w-4 h-4 text-cyan-400" />
                      Evaluated Root-Cause Hypotheses ({investigation.hypotheses.length})
                    </h3>
                    <span className="text-[11px] text-slate-500 font-mono">Ranked by Evidence</span>
                  </div>

                  <div className="space-y-3">
                    {investigation.hypotheses.map((hyp: Hypothesis, idx: number) => (
                      <div
                        key={hyp.hypothesis_id || idx}
                        className={`p-4 rounded-xl border transition-all ${
                          idx === 0
                            ? "bg-slate-900 border-cyan-500/40 shadow-sm"
                            : "bg-slate-950/60 border-slate-800"
                        }`}
                      >
                        <div className="flex items-start justify-between gap-3 mb-2">
                          <div className="flex items-center gap-2">
                            <span className="w-5 h-5 rounded-full bg-slate-800 border border-slate-700 text-[11px] font-bold text-cyan-300 flex items-center justify-center font-mono">
                              #{hyp.rank || idx + 1}
                            </span>
                            <span className="text-xs font-semibold text-white">
                              {hyp.root_cause}
                            </span>
                          </div>
                          <Badge variant={hyp.is_supported ? "success" : "neutral"}>
                            {(hyp.confidence * 100).toFixed(0)}% Score
                          </Badge>
                        </div>

                        <p className="text-xs text-slate-300 mb-3 leading-relaxed">
                          {hyp.explanation}
                        </p>

                        {/* Evidence Citations */}
                        <div className="flex flex-wrap items-center gap-2 text-[11px] pt-2 border-t border-slate-800/80">
                          <span className="text-slate-500">Supporting:</span>
                          {hyp.supporting_evidence_ids.length > 0 ? (
                            hyp.supporting_evidence_ids.map((eid) => (
                              <span
                                key={eid}
                                className="px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 font-mono text-[10px]"
                              >
                                {eid}
                              </span>
                            ))
                          ) : (
                            <span className="text-slate-500 italic">None cited</span>
                          )}

                          {hyp.contradicting_evidence_ids && hyp.contradicting_evidence_ids.length > 0 && (
                            <>
                              <span className="text-slate-500 ml-2">Contradicting:</span>
                              {hyp.contradicting_evidence_ids.map((eid) => (
                                <span
                                  key={eid}
                                  className="px-1.5 py-0.5 rounded bg-rose-950/60 border border-rose-800/60 text-rose-300 font-mono text-[10px]"
                                >
                                  {eid}
                                </span>
                              ))}
                            </>
                          )}
                        </div>

                        {hyp.evaluation_notes && (
                          <div className="mt-2 text-[10px] text-slate-400 font-mono italic">
                            Validation: {hyp.evaluation_notes}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Right: Diagnostic Evidence Items Collected */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                      <Activity className="w-4 h-4 text-emerald-400" />
                      Collected Diagnostic Evidence ({investigation.evidence.length})
                    </h3>
                    <span className="text-[11px] text-slate-500 font-mono">Restricted Read-Only Probes</span>
                  </div>

                  <div className="space-y-3">
                    {investigation.evidence.map((ev: EvidenceItem) => (
                      <div
                        key={ev.evidence_id}
                        className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2"
                      >
                        <div className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-cyan-300 font-mono text-[11px] font-semibold">
                              {ev.evidence_id}
                            </span>
                            <span className="text-slate-300 font-medium capitalize">
                              {ev.source.replace("_", " ")}
                            </span>
                          </div>
                          <Badge variant={ev.collection_status === "success" ? "success" : ev.collection_status === "degraded" ? "warning" : "error"}>
                            {ev.collection_status}
                          </Badge>
                        </div>

                        {/* Untrusted observation display with clear boundary */}
                        <div className="p-2.5 rounded bg-slate-950 border border-slate-800/90 text-xs text-slate-300 font-mono leading-relaxed overflow-x-auto">
                          {ev.observation}
                        </div>

                        {ev.data && Object.keys(ev.data).length > 0 && (
                          <details className="text-[11px] text-slate-500 pt-1">
                            <summary className="cursor-pointer hover:text-slate-300 transition-colors font-mono">
                              View Raw Diagnostic Payload ({Object.keys(ev.data).length} fields)
                            </summary>
                            <pre className="mt-2 p-2 rounded bg-slate-950 border border-slate-800 text-cyan-400/90 text-[10px] overflow-x-auto max-h-40">
                              {JSON.stringify(ev.data, null, 2)}
                            </pre>
                          </details>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* SRE Informational Recommendations & Unresolved Questions */}
              {investigation.summary && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Recommended Next Diagnostic Steps */}
                  <Card
                    title="Recommended SRE Diagnostic Steps"
                    subtitle="Informational actions for human site reliability engineers"
                  >
                    <div className="space-y-2.5 text-xs text-slate-300">
                      {investigation.summary.recommended_next_steps.map((step: string, i: number) => (
                        <div key={i} className="flex items-start gap-2.5 p-2.5 rounded bg-slate-950/40 border border-slate-800/80">
                          <ChevronRight className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                          <span>{step}</span>
                        </div>
                      ))}
                    </div>
                  </Card>

                  {/* Unresolved Diagnostic Questions */}
                  <Card
                    title="Unresolved Diagnostic Questions"
                    subtitle="Open telemetry questions identified during investigation"
                  >
                    <div className="space-y-2.5 text-xs text-slate-300">
                      {investigation.summary.unresolved_questions.map((q: string, i: number) => (
                        <div key={i} className="flex items-start gap-2.5 p-2.5 rounded bg-slate-950/40 border border-slate-800/80">
                          <HelpCircle className="w-3.5 h-3.5 text-indigo-400 shrink-0 mt-0.5" />
                          <span>{q}</span>
                        </div>
                      ))}
                    </div>
                  </Card>
                </div>
              )}
            </div>
          )}

          {/* Incident Context & Timeline Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Incident Context & Scope */}
            <div className="lg:col-span-2 space-y-6">
              {/* Trigger & Summary Card */}
              <Card title="Incident Root Trigger & Scope">
                <div className="space-y-4 text-xs">
                  <div>
                    <span className="text-slate-400 block mb-1.5 font-medium">Detection Trigger</span>
                    <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg text-slate-200 font-mono">
                      {data.incident.trigger}
                    </div>
                  </div>

                  {data.incident.summary && (
                    <div>
                      <span className="text-slate-400 block mb-1.5 font-medium">Deterministic Summary</span>
                      <p className="text-slate-300 leading-relaxed bg-slate-950/40 p-3 rounded-lg border border-slate-800/80">
                        {data.incident.summary}
                      </p>
                    </div>
                  )}

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
                    <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800/80">
                      <span className="text-slate-400 block mb-1 text-[11px] uppercase tracking-wider font-semibold">
                        Lifecycle State
                      </span>
                      <span className="font-mono text-slate-200 uppercase font-semibold">
                        {data.incident.status}
                      </span>
                      <p className="text-[11px] text-slate-500 mt-1">
                        Managed deterministically via evaluation and recovery transitions.
                      </p>
                    </div>

                    <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800/80">
                      <span className="text-slate-400 block mb-1 text-[11px] uppercase tracking-wider font-semibold">
                        Read-Only Guardrails
                      </span>
                      <span className="text-emerald-400 font-mono font-medium">Enforced</span>
                      <p className="text-[11px] text-slate-500 mt-1">
                        Automated remediation execution is strictly restricted to Phase 4.
                      </p>
                    </div>
                  </div>
                </div>
              </Card>

              {/* Initial Detection Raw Snapshot */}
              <Card
                title="Detector Evidence Snapshot"
                subtitle="Telemetry captures attached during initial incident detection"
              >
                <div className="space-y-3">
                  {data.timeline
                    .filter((ev) => ev.metadata && Object.keys(ev.metadata).length > 0)
                    .map((ev) => (
                      <div key={ev.id} className="space-y-1.5">
                        <div className="text-xs text-slate-400 flex items-center justify-between font-mono">
                          <span>Captured during: <code className="text-cyan-400">{ev.event_type}</code></span>
                          <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div className="bg-slate-950 rounded-lg p-3 border border-slate-800 font-mono text-xs overflow-x-auto text-cyan-300/90 max-h-72">
                          <pre>{JSON.stringify(ev.metadata, null, 2)}</pre>
                        </div>
                      </div>
                    ))}

                  {data.timeline.filter(
                    (ev) => ev.metadata && Object.keys(ev.metadata).length > 0
                  ).length === 0 && (
                    <p className="text-xs text-slate-500 italic p-4 text-center">
                      No raw JSON metadata attached to timeline events.
                    </p>
                  )}
                </div>
              </Card>
            </div>

            {/* Right 1 Col: Chronological Event Timeline */}
            <div className="space-y-6">
              <Card
                title="Audit Event Timeline"
                subtitle="Append-only event log recorded in PostgreSQL"
              >
                {data.timeline.length === 0 ? (
                  <p className="text-xs text-slate-500 italic p-4 text-center">
                    No timeline events recorded for this incident.
                  </p>
                ) : (
                  <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                    {data.timeline.map((event) => (
                      <div key={event.id} className="relative group">
                        {/* Dot indicator */}
                        <div className="absolute -left-6 top-0.5 w-4 h-4 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center">
                          {getEventIcon(event.event_type)}
                        </div>

                        <div className="space-y-1 text-xs">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-semibold text-slate-200 capitalize">
                              {event.event_type}
                            </span>
                            <span className="text-[10px] text-slate-500 font-mono">
                              {new Date(event.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                          <p className="text-slate-300 leading-normal bg-slate-950/40 p-2.5 rounded border border-slate-800/60">
                            {event.message}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>
          </div>
        </>
      ) : (
        <div className="p-12 text-center text-slate-500">
          <AlertCircle className="w-8 h-8 mx-auto text-slate-600 mb-2" />
          <p className="text-sm font-medium text-slate-400">Incident Not Found</p>
          <p className="text-xs text-slate-500 mt-1">
            The requested incident does not exist in this workspace.
          </p>
        </div>
      )}
    </div>
  );
}
