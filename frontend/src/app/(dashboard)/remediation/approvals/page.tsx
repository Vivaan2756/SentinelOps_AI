"use client";

import React, { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import { RemediationApproval, ApprovalStatus, RemediationExecution } from "@/lib/types";
import {
  evaluateExecutionEligibility,
  executeRemediationWorkflow,
} from "@/lib/api";
import {
  ShieldAlert,
  ShieldCheck,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Search,
  ExternalLink,
  Server,
  Lock,
  FileCode,
  Ban,
  ChevronRight,
  Play,
  AlertCircle,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";

function generateIdempotencyKey(approvalId: string): string {
  return `exec-${approvalId.slice(0, 8)}-${Date.now()}`;
}

export default function RemediationApprovalsPage() {
  const { activeWorkspace, token, user } = useAuth();
  const [approvals, setApprovals] = useState<RemediationApproval[]>([]);
  const [activeTab, setActiveTab] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Detail Modal state
  const [selectedApproval, setSelectedApproval] = useState<RemediationApproval | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState<boolean>(false);
  const [actionNotes, setActionNotes] = useState<string>("");
  const [rejectionReason, setRejectionReason] = useState<string>("");
  const [isRejecting, setIsRejecting] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [modalError, setModalError] = useState<string | null>(null);

  // Executions state (Stage 2A)
  const [executions, setExecutions] = useState<RemediationExecution[]>([]);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [isConfirmingExecution, setIsConfirmingExecution] = useState<boolean>(false);
  const [currentIdempotencyKey, setCurrentIdempotencyKey] = useState<string>("");
  const [executionResult, setExecutionResult] = useState<{
    success: boolean;
    executionId?: string;
    status?: string;
    errorType?: string;
    message: string;
  } | null>(null);

  // Role permissions
  const userRole = (activeWorkspace?.role || "viewer").toLowerCase();
  const isAuthorizedReviewer = userRole === "admin" || userRole === "engineer";
  const isViewer = userRole === "viewer";

  // Executions lookup by approval ID
  const executionsByApprovalId = useMemo(() => {
    const map = new Map<string, RemediationExecution>();
    executions.forEach((e) => map.set(e.approval_id, e));
    return map;
  }, [executions]);

  const executedApprovalIds = useMemo(() => {
    return new Set(executions.map((e) => e.approval_id));
  }, [executions]);

  const fetchData = async () => {
    if (!activeWorkspace || !token) return;
    setIsLoading(true);
    setError(null);
    try {
      const [data, execsRes] = await Promise.all([
        api.remediation.listApprovals(
          activeWorkspace.workspace_id,
          token,
          activeTab === "all" ? undefined : activeTab
        ),
        api.remediation.listExecutions(activeWorkspace.workspace_id, token),
      ]);
      setApprovals(data);
      setExecutions(execsRes.executions || []);
    } catch (err: any) {
      setError(err.message || "Failed to load remediation approvals.");
    } finally {
      setIsLoading(false);
    }
  };

  const fetchApprovals = fetchData;

  useEffect(() => {
    fetchData();
  }, [activeWorkspace?.workspace_id, token, activeTab]);

  // Filtered by search
  const filteredApprovals = useMemo(() => {
    return approvals.filter((app) => {
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        app.action_id.toLowerCase().includes(q) ||
        (app.action_name && app.action_name.toLowerCase().includes(q)) ||
        (app.target_service_name && app.target_service_name.toLowerCase().includes(q)) ||
        app.target_service_id.toLowerCase().includes(q) ||
        app.id.toLowerCase().includes(q) ||
        (app.requested_by_email && app.requested_by_email.toLowerCase().includes(q))
      );
    });
  }, [approvals, searchQuery]);

  // Counts for tabs
  const counts = useMemo(() => {
    const res = { all: approvals.length, pending: 0, approved: 0, rejected: 0, expired: 0, cancelled: 0 };
    approvals.forEach((a) => {
      if (a.approval_status in res) {
        res[a.approval_status as keyof typeof res]++;
      }
    });
    return res;
  }, [approvals]);

  const openDetail = (approval: RemediationApproval) => {
    setSelectedApproval(approval);
    setIsDetailOpen(true);
    setIsRejecting(false);
    setIsConfirmingExecution(false);
    setCurrentIdempotencyKey("");
    setExecutionResult(null);
    setRejectionReason("");
    setActionNotes("");
    setModalError(null);
  };

  const openDetailForExecution = (approval: RemediationApproval) => {
    setSelectedApproval(approval);
    setIsDetailOpen(true);
    setIsRejecting(false);
    setIsConfirmingExecution(true);
    setCurrentIdempotencyKey(generateIdempotencyKey(approval.id));
    setExecutionResult(null);
    setRejectionReason("");
    setActionNotes("");
    setModalError(null);
  };

  const closeDetail = () => {
    setIsDetailOpen(false);
    setSelectedApproval(null);
    setIsRejecting(false);
    setIsConfirmingExecution(false);
    setCurrentIdempotencyKey("");
    setExecutionResult(null);
    setRejectionReason("");
    setActionNotes("");
    setModalError(null);
  };

  const handleExecute = async () => {
    if (!selectedApproval || !activeWorkspace || !token || isExecuting) return;

    const isAlreadyExecuted = executionsByApprovalId.has(selectedApproval.id);
    const eligibility = evaluateExecutionEligibility({
      role: userRole,
      approvalStatus: selectedApproval.approval_status,
      isExpired: selectedApproval.is_expired,
      workspaceId: activeWorkspace.workspace_id,
      approvalWorkspaceId: selectedApproval.workspace_id,
      isAlreadyExecuted,
    });

    if (!eligibility.canExecute) {
      setModalError(eligibility.rejectionReason || "Execution eligibility check failed.");
      return;
    }

    setIsExecuting(true);
    setModalError(null);

    const keyToUse = currentIdempotencyKey || generateIdempotencyKey(selectedApproval.id);
    if (!currentIdempotencyKey) {
      setCurrentIdempotencyKey(keyToUse);
    }

    const res = await executeRemediationWorkflow({
      approvalId: selectedApproval.id,
      workspaceId: activeWorkspace.workspace_id,
      idempotencyKey: keyToUse,
      token,
    });

    if (res.success) {
      setExecutionResult({
        success: true,
        executionId: res.execution.id,
        status: res.execution.status,
        message: res.message,
      });
      setSuccessMessage(
        `Remediation action '${selectedApproval.action_name || selectedApproval.action_id}' enqueued successfully (Execution ID: ${res.execution.id}).`
      );
      setIsConfirmingExecution(false);
      fetchData();
    } else {
      setExecutionResult({
        success: false,
        errorType: res.errorType,
        message: res.message,
      });
    }
    setIsExecuting(false);
  };

  const isEligibleForExecution = (app: RemediationApproval) => {
    const isAlreadyExecuted = executionsByApprovalId.has(app.id);
    return evaluateExecutionEligibility({
      role: userRole,
      approvalStatus: app.approval_status,
      isExpired: app.is_expired,
      workspaceId: activeWorkspace?.workspace_id,
      approvalWorkspaceId: app.workspace_id,
      isAlreadyExecuted,
    }).canExecute;
  };

  const handleApprove = async () => {
    if (!selectedApproval || !activeWorkspace || !token) return;
    setIsSubmitting(true);
    setModalError(null);
    try {
      const updated = await api.remediation.approve(
        selectedApproval.id,
        activeWorkspace.workspace_id,
        token,
        actionNotes.trim() || undefined
      );
      setSuccessMessage(`Proposal '${updated.action_name}' approved successfully. Eligible for Phase 4.3 execution.`);
      closeDetail();
      fetchApprovals();
    } catch (err: any) {
      setModalError(err.message || "Failed to approve proposal.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleReject = async () => {
    if (!selectedApproval || !activeWorkspace || !token) return;
    if (!rejectionReason.trim() || rejectionReason.trim().length < 3) {
      setModalError("A specific rejection reason (at least 3 characters) is mandatory.");
      return;
    }
    setIsSubmitting(true);
    setModalError(null);
    try {
      const updated = await api.remediation.reject(
        selectedApproval.id,
        activeWorkspace.workspace_id,
        token,
        rejectionReason.trim()
      );
      setSuccessMessage(`Proposal '${updated.action_name}' was rejected.`);
      closeDetail();
      fetchApprovals();
    } catch (err: any) {
      setModalError(err.message || "Failed to reject proposal.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancel = async () => {
    if (!selectedApproval || !activeWorkspace || !token) return;
    if (!confirm("Are you sure you want to cancel this pending approval request?")) return;
    setIsSubmitting(true);
    setModalError(null);
    try {
      const updated = await api.remediation.cancel(
        selectedApproval.id,
        activeWorkspace.workspace_id,
        token,
        "Cancelled by requester via dashboard"
      );
      setSuccessMessage(`Proposal '${updated.action_name}' was cancelled.`);
      closeDetail();
      fetchApprovals();
    } catch (err: any) {
      setModalError(err.message || "Failed to cancel proposal.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const getStatusBadge = (status: ApprovalStatus, isExpired: boolean) => {
    if (isExpired && status === "pending") {
      return <Badge variant="neutral" className="bg-slate-800 text-slate-400 border-slate-700">Expired</Badge>;
    }
    switch (status) {
      case "pending":
        return <Badge variant="warning" className="bg-amber-500/10 text-amber-400 border-amber-500/30 animate-pulse">Pending Review</Badge>;
      case "approved":
        return <Badge variant="success" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">Approved</Badge>;
      case "rejected":
        return <Badge variant="error" className="bg-rose-500/10 text-rose-400 border-rose-500/30">Rejected</Badge>;
      case "expired":
        return <Badge variant="neutral" className="bg-slate-800 text-slate-400 border-slate-700">Expired</Badge>;
      case "cancelled":
        return <Badge variant="neutral" className="bg-slate-800 text-slate-400 border-slate-700">Cancelled</Badge>;
      default:
        return <Badge variant="neutral">{status}</Badge>;
    }
  };

  const getRiskBadge = (risk: string) => {
    switch (risk.toLowerCase()) {
      case "low":
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">Low Risk</span>;
      case "medium":
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30">Medium Risk</span>;
      case "high":
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30">High Risk</span>;
      default:
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800 text-slate-400">{risk}</span>;
    }
  };

  // Check self-approval warning
  const isSelfProposal = selectedApproval && user && selectedApproval.requested_by === user.id;
  const isHighRisk = selectedApproval?.risk_level === "high";

  return (
    <div className="space-y-6">
      {/* Page Title & Breadcrumbs */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <span>Remediation</span>
            <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
            <span className="text-slate-200">Human Approval Workflow</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
            Remediation Approvals
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Human-in-the-loop authorization workflow for automated remediation proposals (Phase 4.2)
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="secondary"
            size="sm"
            onClick={fetchApprovals}
            disabled={isLoading}
            className="flex items-center gap-2 border-slate-700 bg-slate-900/80 text-slate-200 hover:bg-slate-800"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin text-emerald-400" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Safety Banner */}
      <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-500/5 backdrop-blur-sm flex items-start gap-3">
        <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 leading-relaxed">
          <span className="font-semibold text-amber-300">Phase 4.2 Safety Invariant:</span> Approving a proposal strictly authorizes future execution (Phase 4.3). Approval{" "}
          <span className="font-semibold text-amber-200 underline decoration-amber-500/50">does not execute</span> any action immediately, does not run background processes, and does not mutate any monitored service.
        </div>
      </div>

      {/* Feedback Messages */}
      {successMessage && (
        <div className="p-3.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{successMessage}</span>
          </div>
          <button onClick={() => setSuccessMessage(null)} className="text-slate-400 hover:text-slate-200">✕</button>
        </div>
      )}
      {error && (
        <div className="p-3.5 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-slate-400 hover:text-slate-200">✕</button>
        </div>
      )}

      {/* Stats Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="p-4 bg-slate-900/60 border-slate-800/80">
          <div className="text-xs text-slate-400 font-medium">Pending Review</div>
          <div className="text-2xl font-bold text-amber-400 mt-1 flex items-center gap-2">
            {counts.pending}
            {counts.pending > 0 && <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />}
          </div>
          <div className="text-[11px] text-slate-500 mt-0.5">Require Engineer or Admin review</div>
        </Card>
        <Card className="p-4 bg-slate-900/60 border-slate-800/80">
          <div className="text-xs text-slate-400 font-medium">Approved Proposals</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">{counts.approved}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Authorized for Phase 4.3 execution</div>
        </Card>
        <Card className="p-4 bg-slate-900/60 border-slate-800/80">
          <div className="text-xs text-slate-400 font-medium">Rejected Proposals</div>
          <div className="text-2xl font-bold text-rose-400 mt-1">{counts.rejected}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Declined with documented rationale</div>
        </Card>
        <Card className="p-4 bg-slate-900/60 border-slate-800/80">
          <div className="text-xs text-slate-400 font-medium">Expired / Cancelled</div>
          <div className="text-2xl font-bold text-slate-400 mt-1">{counts.expired + counts.cancelled}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Past deadline or retracted</div>
        </Card>
      </div>

      {/* Filter Tabs & Search Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-1 overflow-x-auto">
          {[
            { id: "all", label: "All Proposals", count: counts.all },
            { id: "pending", label: "Pending", count: counts.pending },
            { id: "approved", label: "Approved", count: counts.approved },
            { id: "rejected", label: "Rejected", count: counts.rejected },
            { id: "expired", label: "Expired", count: counts.expired },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
                activeTab === tab.id
                  ? "bg-emerald-600/20 text-emerald-400 border border-emerald-500/40"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
              }`}
            >
              <span>{tab.label}</span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded-full ${
                activeTab === tab.id ? "bg-emerald-500/20 text-emerald-300" : "bg-slate-800 text-slate-500"
              }`}>
                {tab.count}
              </span>
            </button>
          ))}
        </div>

        <div className="relative w-full md:w-64">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search action or service..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500/50"
          />
        </div>
      </div>

      {/* Main Table / List */}
      <Card className="bg-slate-900/40 border-slate-800/80 overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center text-slate-400 flex flex-col items-center justify-center gap-3">
            <RefreshCw className="w-6 h-6 animate-spin text-emerald-400" />
            <div className="text-xs">Loading remediation proposals...</div>
          </div>
        ) : filteredApprovals.length === 0 ? (
          <div className="p-12 text-center text-slate-400 flex flex-col items-center justify-center gap-3">
            <ShieldCheck className="w-10 h-10 text-slate-600" />
            <div className="text-sm font-medium text-slate-300">No remediation proposals found</div>
            <p className="text-xs text-slate-500 max-w-sm">
              {searchQuery
                ? "No approvals match your current search query."
                : activeTab !== "all"
                ? `No proposals currently in '${activeTab}' state.`
                : "When the PolicyEngine evaluates remediation actions that require human authorization, proposals will appear here."}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800/80">
                <tr>
                  <th className="px-4 py-3">Action & Proposal ID</th>
                  <th className="px-4 py-3">Target Service</th>
                  <th className="px-4 py-3">Risk Level</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Requester</th>
                  <th className="px-4 py-3">Expiry Deadline</th>
                  <th className="px-4 py-3 text-right">Review</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {filteredApprovals.map((app) => (
                  <tr
                    key={app.id}
                    onClick={() => openDetail(app)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="px-4 py-3.5">
                      <div className="font-medium text-slate-100 group-hover:text-emerald-300 transition-colors">
                        {app.action_name || app.action_id}
                      </div>
                      <div className="font-mono text-[10px] text-slate-500 mt-0.5">
                        {app.action_id} • ID: {app.id.slice(0, 8)}...
                      </div>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-1.5 text-slate-200">
                        <Server className="w-3.5 h-3.5 text-slate-400" />
                        <span>{app.target_service_name || "Service"}</span>
                      </div>
                      <div className="font-mono text-[10px] text-slate-500">
                        {app.target_service_id.slice(0, 8)}...
                      </div>
                    </td>
                    <td className="px-4 py-3.5">
                      {getRiskBadge(app.risk_level)}
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="flex flex-col gap-1">
                        {getStatusBadge(app.approval_status, app.is_expired)}
                        {executedApprovalIds.has(app.id) && (
                          <span className="inline-flex items-center gap-1 text-[10px] text-cyan-400 font-mono">
                            <CheckCircle2 className="w-3 h-3 text-cyan-400" />
                            Executed
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="text-slate-200 text-xs">
                        {app.requested_by_email || app.requested_by.slice(0, 8)}
                      </div>
                      <div className="text-[10px] text-slate-500">
                        {new Date(app.requested_at).toLocaleDateString()} {new Date(app.requested_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </div>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-1 text-slate-300 font-mono text-[11px]">
                        <Clock className="w-3 h-3 text-slate-400" />
                        <span>
                          {new Date(app.expires_at).toLocaleDateString()} {new Date(app.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>
                      {app.is_expired && (
                        <div className="text-[10px] text-rose-400 mt-0.5">Deadline passed</div>
                      )}
                    </td>
                    <td className="px-4 py-3.5 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        {isEligibleForExecution(app) && (
                          <Button
                            variant="primary"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              openDetailForExecution(app);
                            }}
                            className="text-xs h-7 px-2.5 bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm"
                          >
                            <Play className="w-3 h-3 mr-1" />
                            Execute
                          </Button>
                        )}
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            openDetail(app);
                          }}
                          className="text-xs h-7 px-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700"
                        >
                          Inspect
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Detail & Review Modal */}
      {selectedApproval && (
        <Modal
          isOpen={isDetailOpen}
          onClose={closeDetail}
          title={selectedApproval.action_name || selectedApproval.action_id}
          description={`Proposal ID: ${selectedApproval.id} • Workspace Policy ${selectedApproval.policy_version}`}
        >
          <div className="space-y-4 text-xs">
            {/* Modal Warning Banner */}
            <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-200 text-[11px] flex items-start gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <strong>Safety Policy:</strong> Approving this remediation proposal authorizes future execution in Phase 4.3. It does not run or apply changes right now.
              </div>
            </div>

            {/* Error Message inside modal */}
            {modalError && (
              <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{modalError}</span>
              </div>
            )}

            {/* Proposal Overview Grid */}
            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-950/60 rounded-lg border border-slate-800">
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Status</span>
                <div className="mt-1">{getStatusBadge(selectedApproval.approval_status, selectedApproval.is_expired)}</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Risk Classification</span>
                <div className="mt-1">{getRiskBadge(selectedApproval.risk_level)}</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Target Service</span>
                <div className="mt-1 font-medium text-slate-200">{selectedApproval.target_service_name || "Unknown"}</div>
                <div className="text-[10px] font-mono text-slate-500">{selectedApproval.target_service_id}</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Policy Decision ID</span>
                <div className="mt-1 font-mono text-[11px] text-slate-300">{selectedApproval.policy_decision_id.slice(0, 16)}...</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Requested By</span>
                <div className="mt-1 text-slate-200">{selectedApproval.requested_by_email || selectedApproval.requested_by}</div>
                <div className="text-[10px] text-slate-500">{new Date(selectedApproval.requested_at).toLocaleString()}</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Expiry Deadline</span>
                <div className="mt-1 text-slate-200 font-mono">{new Date(selectedApproval.expires_at).toLocaleString()}</div>
                {selectedApproval.is_expired && <span className="text-[10px] text-rose-400">Proposal Expired</span>}
              </div>
            </div>

            {/* Action Description & Verification Criteria */}
            {selectedApproval.action_description && (
              <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800/80">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold block mb-1">
                  Action Blueprint Description
                </span>
                <p className="text-slate-300 leading-relaxed">{selectedApproval.action_description}</p>
                {selectedApproval.verification_criteria && (
                  <div className="mt-2 pt-2 border-t border-slate-800/60 text-slate-400">
                    <span className="font-semibold text-slate-300">Verification Criteria:</span> {selectedApproval.verification_criteria}
                  </div>
                )}
              </div>
            )}

            {/* Exact Validated Parameters (Immutable) */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-emerald-400" />
                  Exact Validated Parameters (Policy Bound)
                </span>
                <span className="text-[10px] text-slate-500">Immutable</span>
              </div>
              <pre className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-emerald-400 overflow-x-auto">
                {JSON.stringify(selectedApproval.validated_parameters, null, 2)}
              </pre>
            </div>

            {/* Rejection / Review Info if already reviewed */}
            {selectedApproval.approval_status === "rejected" && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-200">
                <div className="font-semibold text-xs text-rose-300 flex items-center gap-1.5 mb-1">
                  <XCircle className="w-4 h-4 text-rose-400" />
                  Rejection Rationale:
                </div>
                <p className="text-xs text-rose-200/90 italic">{selectedApproval.rejection_reason}</p>
                <div className="text-[10px] text-rose-400/80 mt-1.5">
                  Reviewed by {selectedApproval.reviewed_by_email || selectedApproval.reviewed_by} on {selectedApproval.reviewed_at ? new Date(selectedApproval.reviewed_at).toLocaleString() : "N/A"}
                </div>
              </div>
            )}

            {selectedApproval.approval_status === "approved" && (
              <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-200">
                <div className="font-semibold text-xs text-emerald-300 flex items-center gap-1.5 mb-1">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  Proposal Approved & Ready for Phase 4.3:
                </div>
                <div className="text-[10px] text-emerald-400/80">
                  Reviewed by {selectedApproval.reviewed_by_email || selectedApproval.reviewed_by} on {selectedApproval.reviewed_at ? new Date(selectedApproval.reviewed_at).toLocaleString() : "N/A"}
                </div>
              </div>
            )}

            {/* Related Incident & Investigation Links */}
            {(selectedApproval.incident_id || selectedApproval.investigation_id) && (
              <div className="p-2.5 bg-slate-950/40 rounded-lg border border-slate-800/80 flex items-center gap-4">
                {selectedApproval.incident_id && (
                  <Link
                    href={`/incidents/${selectedApproval.incident_id}`}
                    className="text-emerald-400 hover:text-emerald-300 flex items-center gap-1 text-[11px]"
                  >
                    <ExternalLink className="w-3 h-3" />
                    View Related Incident
                  </Link>
                )}
                {selectedApproval.investigation_id && (
                  <Link
                    href={`/investigations/${selectedApproval.investigation_id}`}
                    className="text-indigo-400 hover:text-indigo-300 flex items-center gap-1 text-[11px]"
                  >
                    <ExternalLink className="w-3 h-3" />
                    View AI Investigation
                  </Link>
                )}
              </div>
            )}

            {/* Role restriction banner for viewers */}
            {isViewer && (
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/80 text-slate-400 text-xs flex items-center gap-2">
                <Lock className="w-4 h-4 text-slate-500 shrink-0" />
                <span>
                  <strong>Read-only access:</strong> Your workspace role (Viewer) does not permit approving or rejecting operational actions.
                </span>
              </div>
            )}

            {/* Self-approval high risk warning */}
            {isSelfProposal && isHighRisk && selectedApproval.approval_status === "pending" && (
              <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs flex items-center gap-2">
                <Ban className="w-4 h-4 text-rose-400 shrink-0" />
                <span>
                  <strong>Two-Person Integrity Enforced:</strong> As the requester of this high-risk action, backend policy prevents you from self-approving. Another Engineer or Admin must review.
                </span>
              </div>
            )}

            {/* Rejection input when toggled */}
            {isRejecting && selectedApproval.approval_status === "pending" && (
              <div className="p-3 bg-slate-950 rounded-lg border border-rose-500/40 space-y-2">
                <label className="text-[11px] font-semibold text-rose-300 block">
                  Mandatory Rejection Reason *
                </label>
                <textarea
                  rows={3}
                  value={rejectionReason}
                  onChange={(e) => setRejectionReason(e.target.value)}
                  placeholder="Explain why this proposal is rejected (e.g., active peak checkout traffic, false positive detection, alternate fix in progress)..."
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-rose-500/60"
                />
                <div className="flex items-center justify-end gap-2 pt-1">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => setIsRejecting(false)}
                    className="text-xs h-7"
                  >
                    Cancel
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={handleReject}
                    disabled={isSubmitting || rejectionReason.trim().length < 3}
                    className="text-xs h-7 bg-rose-600 hover:bg-rose-500 text-white"
                  >
                    {isSubmitting ? "Rejecting..." : "Confirm Rejection"}
                  </Button>
                </div>
              </div>
            )}

            {/* Controls for authorized reviewers on pending proposals */}
            {selectedApproval.approval_status === "pending" && !selectedApproval.is_expired && !isRejecting && (
              <div className="pt-2 border-t border-slate-800 flex items-center justify-between gap-3">
                {/* Cancel option for requester or admin */}
                {(userRole === "admin" || (user && selectedApproval.requested_by === user.id)) && (
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={handleCancel}
                    disabled={isSubmitting}
                    className="text-xs h-8 text-slate-400 hover:text-slate-200 border-slate-800"
                  >
                    Cancel Proposal
                  </Button>
                )}

                <div className="flex items-center gap-2 ml-auto">
                  {isAuthorizedReviewer && (
                    <>
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => setIsRejecting(true)}
                        disabled={isSubmitting}
                        className="text-xs h-8 border-rose-500/40 text-rose-400 hover:bg-rose-500/10"
                      >
                        <XCircle className="w-3.5 h-3.5 mr-1.5" />
                        Reject Proposal
                      </Button>
                      <Button
                        variant="primary"
                        size="sm"
                        onClick={handleApprove}
                        disabled={isSubmitting || Boolean(isSelfProposal && isHighRisk)}
                        className="text-xs h-8 bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-900/30"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />
                        {isSubmitting ? "Approving..." : "Approve Proposal"}
                      </Button>
                    </>
                  )}
                </div>
              </div>
            )}

            {/* Execution Controls for Approved Proposals (Stage 2A) */}
            {selectedApproval.approval_status === "approved" && (
              <div className="pt-3 border-t border-slate-800 space-y-3">
                {/* Already Executed Banner */}
                {executionsByApprovalId.has(selectedApproval.id) && (
                  <div className="p-3.5 rounded-lg bg-cyan-950/40 border border-cyan-500/40 text-cyan-300 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 font-semibold">
                        <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                        <span>Remediation Action Executed</span>
                      </div>
                      <span className="font-mono text-[11px] text-cyan-400">
                        Status: {executionsByApprovalId.get(selectedApproval.id)?.status}
                      </span>
                    </div>
                    <p className="text-slate-300 text-xs">
                      Execution ID: <span className="font-mono text-cyan-200">{executionsByApprovalId.get(selectedApproval.id)?.id}</span>
                    </p>
                    <div className="pt-1">
                      <Link
                        href="/verification"
                        className="inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300 underline underline-offset-4"
                      >
                        <span>View Verification Records &rarr;</span>
                      </Link>
                    </div>
                  </div>
                )}

                {/* Execution Result Feedback (Success, Conflict, Uncertain, Error) */}
                {executionResult && (
                  <div
                    className={`p-3.5 rounded-lg border text-xs space-y-2 ${
                      executionResult.success
                        ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-300"
                        : executionResult.errorType === "uncertain"
                        ? "bg-amber-500/10 border-amber-500/40 text-amber-300"
                        : executionResult.errorType === "conflict"
                        ? "bg-amber-500/10 border-amber-500/40 text-amber-300"
                        : "bg-rose-500/10 border-rose-500/30 text-rose-300"
                    }`}
                  >
                    <div className="flex items-center justify-between font-semibold">
                      <div className="flex items-center gap-2">
                        {executionResult.success ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        ) : executionResult.errorType === "uncertain" ? (
                          <AlertTriangle className="w-4 h-4 text-amber-400" />
                        ) : (
                          <AlertCircle className="w-4 h-4 text-rose-400" />
                        )}
                        <span>
                          {executionResult.success
                            ? "Action Enqueued for Execution"
                            : executionResult.errorType === "uncertain"
                            ? "Execution Status Uncertain"
                            : executionResult.errorType === "conflict"
                            ? "Already Executed (Conflict)"
                            : "Execution Request Failed"}
                        </span>
                      </div>
                      {executionResult.executionId && (
                        <span className="font-mono text-[11px]">
                          ID: {executionResult.executionId}
                        </span>
                      )}
                    </div>
                    <p className="text-slate-300 leading-relaxed">
                      {executionResult.message}
                    </p>
                    {(executionResult.success || executionResult.errorType === "uncertain" || executionResult.errorType === "conflict") && (
                      <div className="pt-1">
                        <Link
                          href="/verification"
                          className="inline-flex items-center gap-1.5 font-semibold underline underline-offset-4 text-cyan-400 hover:text-cyan-300"
                        >
                          <span>Inspect in Verification & Recovery &rarr;</span>
                        </Link>
                      </div>
                    )}
                  </div>
                )}

                {/* Confirmation Dialog Card */}
                {!executionsByApprovalId.has(selectedApproval.id) && isConfirmingExecution && (
                  <div className="p-4 rounded-xl bg-slate-950 border border-emerald-500/40 space-y-3.5 shadow-lg">
                    <div className="flex items-center gap-2.5 pb-2 border-b border-slate-800">
                      <div className="w-7 h-7 rounded-lg bg-emerald-500/20 border border-emerald-400/40 flex items-center justify-center text-emerald-400">
                        <Play className="w-4 h-4" />
                      </div>
                      <div>
                        <h4 className="text-sm font-semibold text-white tracking-tight">
                          Confirm Remediation Execution
                        </h4>
                        <p className="text-[11px] text-slate-400">
                          This action will submit the approved recovery job to the broker and worker daemon.
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-2.5 p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs">
                      <div>
                        <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Action</span>
                        <span className="font-mono text-emerald-300 font-semibold">{selectedApproval.action_name || selectedApproval.action_id}</span>
                      </div>
                      <div>
                        <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Target Service</span>
                        <span className="text-slate-200 font-medium">{selectedApproval.target_service_name || "Order API"}</span>
                      </div>
                      <div>
                        <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Risk Level</span>
                        <span className="text-amber-300 capitalize font-medium">{selectedApproval.risk_level} Risk</span>
                      </div>
                      <div>
                        <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Approval Authority</span>
                        <span className="text-slate-200">{selectedApproval.reviewed_by_email || "Authorized Reviewer"}</span>
                      </div>
                      <div className="col-span-2 pt-1 border-t border-slate-800/80">
                        <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Idempotency Key</span>
                        <span className="font-mono text-[11px] text-cyan-300">{currentIdempotencyKey}</span>
                      </div>
                    </div>

                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Approved parameters are locked and cannot be modified. Verification probes will run immediately following container execution to determine service health.
                    </p>

                    <div className="flex items-center justify-end gap-2 pt-1 border-t border-slate-800">
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => setIsConfirmingExecution(false)}
                        disabled={isExecuting}
                        className="text-xs h-8 border-slate-700 text-slate-300 hover:bg-slate-800"
                      >
                        Cancel
                      </Button>
                      <Button
                        variant="primary"
                        size="sm"
                        onClick={handleExecute}
                        disabled={isExecuting}
                        className="text-xs h-8 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-medium shadow-md"
                      >
                        {isExecuting ? (
                          <>
                            <RefreshCw className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                            Submitting to Execution Queue...
                          </>
                        ) : (
                          <>
                            <Play className="w-3.5 h-3.5 mr-1.5" />
                            Confirm & Execute Action
                          </>
                        )}
                      </Button>
                    </div>
                  </div>
                )}

                {/* Pre-Confirmation Action Trigger */}
                {!executionsByApprovalId.has(selectedApproval.id) && !isConfirmingExecution && !executionResult?.success && (
                  <div className="flex items-center justify-between pt-1">
                    <p className="text-[11px] text-slate-400">
                      This proposal has been approved and is authorized for execution.
                    </p>
                    {isAuthorizedReviewer ? (
                      <Button
                        variant="primary"
                        size="sm"
                        onClick={() => {
                          setIsConfirmingExecution(true);
                          if (!currentIdempotencyKey) {
                            setCurrentIdempotencyKey(generateIdempotencyKey(selectedApproval.id));
                          }
                        }}
                        disabled={isExecuting}
                        className="text-xs h-8 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-medium shadow-md"
                      >
                        <Play className="w-3.5 h-3.5 mr-1.5" />
                        Execute Approved Action
                      </Button>
                    ) : (
                      <span className="text-[11px] text-slate-500 italic">
                        Role &apos;{userRole}&apos; is restricted from triggering execution.
                      </span>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}
