"use client";

import React, { useState, useEffect, useMemo, useCallback } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { api, mapRecoveryPresentationState, isTerminalExecutionState } from "@/lib/api";
import {
  VerificationCycle,
  RemediationExecution,
  RecoveryPresentationResult,
} from "@/lib/types";
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  RefreshCw,
  Search,
  ExternalLink,
  ShieldCheck,
  Server,
  Activity,
  ChevronDown,
  ChevronRight,
  Info,
  Timer,
  FileCheck,
  AlertCircle,
  Play,
  FileCode,
  ShieldAlert,
  Pause,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";

export default function VerificationRecoveryPage() {
  const { activeWorkspace, token } = useAuth();
  const [cycles, setCycles] = useState<VerificationCycle[]>([]);
  const [executions, setExecutions] = useState<RemediationExecution[]>([]);
  const [activeTab, setActiveTab] = useState<string>("all");
  const [viewMode, setViewMode] = useState<"executions" | "cycles">("executions");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Selected execution detail modal state
  const [selectedExecution, setSelectedExecution] = useState<RemediationExecution | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState<boolean>(false);
  const [expandedCycleIds, setExpandedCycleIds] = useState<Set<string>>(new Set());

  // Polling / Auto-refresh state (bounded, safe, read-only)
  const [isAutoRefresh, setIsAutoRefresh] = useState<boolean>(false);
  const [pollCount, setPollCount] = useState<number>(0);
  const MAX_POLL_COUNT = 60; // 5 minutes max at 5-second intervals

  const toggleCycleExpand = (id: string) => {
    setExpandedCycleIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const fetchData = useCallback(async (isBackground = false) => {
    if (!activeWorkspace || !token) return;
    if (!isBackground) {
      setIsLoading(true);
      setError(null);
    }
    try {
      const [cyclesRes, execsRes] = await Promise.all([
        api.remediation.listVerificationCycles(activeWorkspace.workspace_id, token),
        api.remediation.listExecutions(activeWorkspace.workspace_id, token),
      ]);
      setCycles(cyclesRes.cycles || []);
      setExecutions(execsRes.executions || []);
    } catch (err: any) {
      if (!isBackground) {
        setError(err.message || "Failed to load verification and execution records.");
      }
    } finally {
      if (!isBackground) {
        setIsLoading(false);
      }
    }
  }, [activeWorkspace, token]);

  // Initial load
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Index cycles by execution ID
  const cyclesByExecutionId = useMemo(() => {
    const map = new Map<string, VerificationCycle[]>();
    cycles.forEach((c) => {
      const list = map.get(c.execution_id) || [];
      list.push(c);
      map.set(c.execution_id, list);
    });
    return map;
  }, [cycles]);

  // Check if all executions are in terminal states
  const isAllTerminal = useMemo(() => {
    if (executions.length === 0) return true;
    return executions.every((e) => isTerminalExecutionState(e.status));
  }, [executions]);

  // Safe bounded polling effect
  useEffect(() => {
    if (!isAutoRefresh || !activeWorkspace || !token) return;

    if (isAllTerminal) {
      // Pause polling automatically when all executions reach terminal state
      setIsAutoRefresh(false);
      return;
    }

    if (pollCount >= MAX_POLL_COUNT) {
      // Bounded polling threshold reached
      setIsAutoRefresh(false);
      return;
    }

    const interval = setInterval(() => {
      setPollCount((prev) => prev + 1);
      fetchData(true);
    }, 5000);

    return () => clearInterval(interval);
  }, [isAutoRefresh, activeWorkspace, token, isAllTerminal, pollCount, fetchData]);

  // Execution presentation metadata map
  const executionPresentationMap = useMemo(() => {
    const map = new Map<string, RecoveryPresentationResult>();
    executions.forEach((e) => {
      const execCycles = cyclesByExecutionId.get(e.id) || [];
      const primaryCycle = execCycles[0] || null;
      const res = mapRecoveryPresentationState({
        execution: e,
        cycle: primaryCycle,
        cycles: execCycles,
        incidentStatus: primaryCycle?.recovery_status || null,
      });
      map.set(e.id, res);
    });
    return map;
  }, [executions, cyclesByExecutionId]);

  // Tab filtering for executions
  const filteredExecutions = useMemo(() => {
    return executions.filter((exec) => {
      const presentation = executionPresentationMap.get(exec.id);
      const category = presentation?.category || "verification_pending";

      // Tab filter
      if (activeTab === "in_progress") {
        if (!["verification_pending", "verification_in_progress"].includes(category) &&
            !["queued", "validating", "executing", "verification_pending"].includes(exec.status)) {
          return false;
        }
      } else if (activeTab === "verified") {
        if (category !== "recovery_confirmed" && exec.status !== "verified") {
          return false;
        }
      } else if (activeTab === "failed") {
        if (category !== "verification_failed" && category !== "escalation_required" && exec.status !== "execution_failed" && exec.status !== "verification_failed") {
          return false;
        }
      } else if (activeTab === "uncertain") {
        if (category !== "execution_outcome_uncertain" && exec.status !== "execution_uncertain" && exec.status !== "timed_out") {
          return false;
        }
      }

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchId = exec.id.toLowerCase().includes(q);
        const matchApproval = exec.approval_id.toLowerCase().includes(q);
        const matchAction = exec.action_id.toLowerCase().includes(q);
        const matchService = (exec.target_service_id || "").toLowerCase().includes(q);
        const matchIncident = (exec.incident_id || "").toLowerCase().includes(q);
        return matchId || matchApproval || matchAction || matchService || matchIncident;
      }
      return true;
    });
  }, [executions, activeTab, searchQuery, executionPresentationMap]);

  // Filtered cycles for cycle-centric view
  const filteredCycles = useMemo(() => {
    return cycles.filter((c) => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchId = c.id.toLowerCase().includes(q);
        const matchExec = c.execution_id.toLowerCase().includes(q);
        const matchAction = (c.action_id || "").toLowerCase().includes(q);
        const matchService = (c.service_name || "").toLowerCase().includes(q);
        const matchIncident = (c.incident_title || c.incident_id || "").toLowerCase().includes(q);
        return matchId || matchExec || matchAction || matchService || matchIncident;
      }
      return true;
    });
  }, [cycles, searchQuery]);

  // KPI Counts
  const kpis = useMemo(() => {
    let inProgress = 0;
    let verified = 0;
    let failed = 0;
    let uncertain = 0;

    executions.forEach((e) => {
      const pres = executionPresentationMap.get(e.id);
      const cat = pres?.category;
      if (cat === "recovery_confirmed") {
        verified++;
      } else if (cat === "execution_outcome_uncertain") {
        uncertain++;
      } else if (cat === "escalation_required" || cat === "verification_failed") {
        failed++;
      } else {
        inProgress++;
      }
    });

    return {
      totalExecutions: executions.length,
      inProgress,
      verified,
      failed,
      uncertain,
      totalCycles: cycles.length,
    };
  }, [executions, cycles, executionPresentationMap]);

  const openExecutionDetail = (exec: RemediationExecution) => {
    setSelectedExecution(exec);
    setIsDetailOpen(true);
  };

  const closeDetail = () => {
    setIsDetailOpen(false);
    setSelectedExecution(null);
  };

  const renderExecutionStatusBadge = (status: string) => {
    const s = status.toLowerCase();
    switch (s) {
      case "verified":
        return <Badge variant="success" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">verified</Badge>;
      case "execution_succeeded":
        return <Badge variant="warning" className="bg-amber-500/10 text-amber-300 border-amber-500/30">execution_succeeded</Badge>;
      case "execution_failed":
      case "verification_failed":
        return <Badge variant="error" className="bg-rose-500/10 text-rose-400 border-rose-500/30">{s}</Badge>;
      case "execution_uncertain":
      case "timed_out":
        return <Badge variant="warning" className="bg-amber-500/10 text-amber-400 border-amber-500/30">{s}</Badge>;
      case "executing":
      case "validating":
      case "verification_pending":
        return <Badge variant="info" className="bg-sky-500/10 text-sky-400 border-sky-500/30 animate-pulse">{s}</Badge>;
      case "cancelled":
        return <Badge variant="neutral" className="bg-slate-800 text-slate-400 border-slate-700">cancelled</Badge>;
      case "queued":
      default:
        return <Badge variant="neutral" className="bg-slate-800 text-slate-300 border-slate-700">{s}</Badge>;
    }
  };

  const renderPresentationBadge = (pres?: RecoveryPresentationResult) => {
    if (!pres) return <Badge variant="neutral">Pending</Badge>;
    switch (pres.badgeVariant) {
      case "success":
        return <Badge variant="success" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">{pres.label}</Badge>;
      case "warning":
        return <Badge variant="warning" className="bg-amber-500/10 text-amber-300 border-amber-500/30">{pres.label}</Badge>;
      case "error":
        return <Badge variant="error" className="bg-rose-500/10 text-rose-400 border-rose-500/30">{pres.label}</Badge>;
      case "info":
        return <Badge variant="info" className="bg-sky-500/10 text-sky-400 border-sky-500/30">{pres.label}</Badge>;
      default:
        return <Badge variant="neutral" className="bg-slate-800 text-slate-400 border-slate-700">{pres.label}</Badge>;
    }
  };

  const selectedExecPresentation = selectedExecution
    ? executionPresentationMap.get(selectedExecution.id)
    : null;

  const selectedExecCycles = selectedExecution
    ? cyclesByExecutionId.get(selectedExecution.id) || []
    : [];

  return (
    <div className="space-y-6">
      {/* Top Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              Post-Execution Verification & Recovery
            </h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/80">
              Revision 10
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Authoritative lifecycle tracking from remediation execution to empirical health verification for{" "}
            <span className="text-slate-200 font-semibold">{activeWorkspace?.workspace_name}</span>
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              setIsAutoRefresh((prev) => !prev);
              setPollCount(0);
            }}
            className={`flex items-center gap-1.5 border-slate-700 text-xs ${
              isAutoRefresh ? "bg-emerald-950/40 text-emerald-300 border-emerald-500/40" : "bg-slate-900 text-slate-300"
            }`}
          >
            {isAutoRefresh ? (
              <>
                <Pause className="w-3.5 h-3.5 text-emerald-400" />
                Auto-Refresh (Active)
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 text-slate-400" />
                Auto-Refresh (5s)
              </>
            )}
          </Button>

          <Button
            variant="secondary"
            size="sm"
            onClick={() => fetchData()}
            isLoading={isLoading}
            className="flex items-center gap-1.5 text-xs border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin text-emerald-400" : ""}`} />
            Refresh
          </Button>

          <Link href="/remediation/approvals">
            <Button size="sm" className="text-xs bg-emerald-600 hover:bg-emerald-500 text-white">
              <ShieldCheck className="w-3.5 h-3.5 mr-1.5" />
              Approvals Queue
            </Button>
          </Link>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 flex items-center justify-between text-rose-300 text-xs">
          <div className="flex items-center gap-2.5">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-slate-400 hover:text-slate-200">✕</button>
        </div>
      )}

      {/* SRE Architecture Notice Banner */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-start gap-3.5 text-xs text-slate-300">
        <Info className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="font-semibold text-slate-200">
            Authoritative Three-Stage Verification & Recovery Invariants:
          </p>
          <p className="text-slate-400 leading-relaxed">
            1. <strong className="text-slate-300">Container Execution:</strong> Exit code 0 indicates container command completion only, NOT service recovery.
            <br />
            2. <strong className="text-slate-300">Synthetic Verification:</strong> <span className="font-mono text-slate-300">PostExecutionVerificationEngine</span> executes health probes requiring 3 consecutive passes.
            <br />
            3. <strong className="text-slate-300">Incident Recovery Bridge:</strong> Only upon verified PASS outcome does <span className="font-mono text-slate-300">IncidentRecoveryBridge</span> atomically update incident state to recovered.
          </p>
        </div>
      </div>

      {/* Summary KPI Cards Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3.5">
        <Card className="p-3.5 bg-slate-900/60 border-slate-800/80">
          <div className="text-xs font-medium text-slate-400">Total Executions</div>
          <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">{kpis.totalExecutions}</div>
          <div className="text-[11px] text-slate-500 mt-0.5 font-mono">Dispatched by workflow</div>
        </Card>

        <Card className="p-3.5 bg-slate-900/60 border-slate-800/80">
          <div className="text-xs font-medium text-slate-400">In Progress / Pending</div>
          <div className="text-2xl font-bold text-sky-400 mt-1 font-mono">{kpis.inProgress}</div>
          <div className="text-[11px] text-slate-500 mt-0.5 font-mono">Executing or probing</div>
        </Card>

        <Card className="p-3.5 bg-slate-900/60 border-slate-800/80">
          <div className="text-xs font-medium text-slate-400">Recovery Confirmed</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1 font-mono">{kpis.verified}</div>
          <div className="text-[11px] text-emerald-500 mt-0.5 font-mono">3/3 passes + bridge confirmed</div>
        </Card>

        <Card className="p-3.5 bg-slate-900/60 border-slate-800/80">
          <div className="text-xs font-medium text-slate-400">Failed / Unrecovered</div>
          <div className="text-2xl font-bold text-rose-400 mt-1 font-mono">{kpis.failed}</div>
          <div className="text-[11px] text-rose-400 mt-0.5 font-mono">Requires engineer escalation</div>
        </Card>

        <Card className="p-3.5 bg-slate-900/60 border-slate-800/80 col-span-2 lg:col-span-1">
          <div className="text-xs font-medium text-slate-400">Uncertain Outcome</div>
          <div className="text-2xl font-bold text-amber-400 mt-1 font-mono">{kpis.uncertain}</div>
          <div className="text-[11px] text-amber-400 mt-0.5 font-mono">Hold state — do not blind retry</div>
        </Card>
      </div>

      {/* Filter Tabs & Search Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-2">
        <div className="flex items-center gap-1 bg-slate-900/80 p-1 rounded-xl border border-slate-800/80 overflow-x-auto">
          {[
            { id: "all", label: "All Executions", count: executions.length },
            { id: "in_progress", label: "In Progress", count: kpis.inProgress },
            { id: "verified", label: "Recovered (PASS)", count: kpis.verified },
            { id: "failed", label: "Failed / Escalated", count: kpis.failed },
            { id: "uncertain", label: "Uncertain (Hold)", count: kpis.uncertain },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                activeTab === tab.id
                  ? "bg-slate-800 text-slate-100 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
              }`}
            >
              <span>{tab.label}</span>
              <span
                className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
                  activeTab === tab.id ? "bg-slate-700 text-slate-200" : "bg-slate-800/60 text-slate-500"
                }`}
              >
                {tab.count}
              </span>
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search action, execution, incident..."
              className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div className="flex items-center rounded-lg bg-slate-900 p-0.5 border border-slate-800 text-xs">
            <button
              onClick={() => setViewMode("executions")}
              className={`px-2.5 py-1 rounded text-xs font-medium ${
                viewMode === "executions" ? "bg-slate-800 text-slate-100" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Executions
            </button>
            <button
              onClick={() => setViewMode("cycles")}
              className={`px-2.5 py-1 rounded text-xs font-medium ${
                viewMode === "cycles" ? "bg-slate-800 text-slate-100" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Cycles ({cycles.length})
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      {viewMode === "executions" ? (
        filteredExecutions.length === 0 ? (
          <Card className="py-16 text-center border-dashed border-slate-800">
            <div className="max-w-md mx-auto space-y-4">
              <div className="w-12 h-12 rounded-xl bg-slate-800/50 border border-slate-700/60 flex items-center justify-center mx-auto text-slate-400">
                <FileCheck className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-slate-200">
                  No Remediation Executions Found
                </h3>
                <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                  {executions.length === 0
                    ? "No remediation jobs have been submitted in this workspace yet. When an approved remediation action is executed, it appears here to track container execution and post-execution synthetic verification."
                    : "No executions match the active filter criteria."}
                </p>
              </div>
              {executions.length === 0 && (
                <div className="pt-2 flex justify-center gap-3">
                  <Link href="/incidents">
                    <Button variant="secondary" size="sm">
                      View Incidents
                    </Button>
                  </Link>
                  <Link href="/remediation/approvals">
                    <Button size="sm">
                      View Approvals Queue
                    </Button>
                  </Link>
                </div>
              )}
            </div>
          </Card>
        ) : (
          <Card className="bg-slate-900/40 border-slate-800/80 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800/80">
                  <tr>
                    <th className="px-4 py-3">Execution ID & Action</th>
                    <th className="px-4 py-3">Target Service</th>
                    <th className="px-4 py-3">Execution Status</th>
                    <th className="px-4 py-3">Recovery Bridge Status</th>
                    <th className="px-4 py-3">Related Incident</th>
                    <th className="px-4 py-3">Timestamps</th>
                    <th className="px-4 py-3 text-right">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {filteredExecutions.map((exec) => {
                    const pres = executionPresentationMap.get(exec.id);
                    const execCycles = cyclesByExecutionId.get(exec.id) || [];
                    return (
                      <tr
                        key={exec.id}
                        onClick={() => openExecutionDetail(exec)}
                        className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                      >
                        <td className="px-4 py-3.5">
                          <div className="font-medium text-slate-100 group-hover:text-emerald-300 transition-colors">
                            {exec.action_id}
                          </div>
                          <div className="font-mono text-[10px] text-slate-500 mt-0.5">
                            ID: {exec.id.slice(0, 8)}... • Appr: {exec.approval_id.slice(0, 8)}...
                          </div>
                        </td>

                        <td className="px-4 py-3.5">
                          <div className="flex items-center gap-1.5 text-slate-200">
                            <Server className="w-3.5 h-3.5 text-slate-400" />
                            <span>{exec.target_service_id || "Order API"}</span>
                          </div>
                          <div className="font-mono text-[10px] text-slate-500">
                            Fencing Token: {exec.fencing_token}
                          </div>
                        </td>

                        <td className="px-4 py-3.5">
                          <div className="flex flex-col gap-1 items-start">
                            {renderExecutionStatusBadge(exec.status)}
                            {exec.locked_by && (
                              <span className="text-[10px] text-slate-500 font-mono">
                                Worker: {exec.locked_by}
                              </span>
                            )}
                          </div>
                        </td>

                        <td className="px-4 py-3.5">
                          <div className="space-y-1">
                            {renderPresentationBadge(pres)}
                            {execCycles.length > 0 && (
                              <div className="text-[10px] text-slate-400 font-mono">
                                Passes: {execCycles[0].probes_passed}/{execCycles[0].probes_required}
                              </div>
                            )}
                          </div>
                        </td>

                        <td className="px-4 py-3.5">
                          {exec.incident_id ? (
                            <Link
                              href={`/incidents/${exec.incident_id}`}
                              onClick={(e) => e.stopPropagation()}
                              className="text-emerald-400 hover:text-emerald-300 font-mono text-xs flex items-center gap-1"
                            >
                              <span>{exec.incident_id.slice(0, 8)}...</span>
                              <ExternalLink className="w-3 h-3" />
                            </Link>
                          ) : (
                            <span className="text-slate-500 font-mono text-[11px]">Standalone</span>
                          )}
                        </td>

                        <td className="px-4 py-3.5">
                          <div className="flex items-center gap-1 text-slate-300 font-mono text-[11px]">
                            <Clock className="w-3 h-3 text-slate-500" />
                            <span>
                              {new Date(exec.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                            </span>
                          </div>
                          {exec.completed_at && (
                            <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                              Done: {new Date(exec.completed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                            </div>
                          )}
                        </td>

                        <td className="px-4 py-3.5 text-right">
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              openExecutionDetail(exec);
                            }}
                            className="text-xs h-7 px-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700"
                          >
                            Inspect
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Card>
        )
      ) : (
        /* Cycle-Centric View */
        filteredCycles.length === 0 ? (
          <Card className="py-16 text-center border-dashed border-slate-800">
            <div className="max-w-md mx-auto space-y-3">
              <FileCheck className="w-10 h-10 text-slate-600 mx-auto" />
              <h3 className="text-sm font-semibold text-slate-200">No Verification Cycles Found</h3>
              <p className="text-xs text-slate-400">
                Verification probe cycles will appear here when an execution enters the verification stage.
              </p>
            </div>
          </Card>
        ) : (
          <div className="space-y-4">
            {filteredCycles.map((cycle) => {
              const isExpanded = expandedCycleIds.has(cycle.id);
              const probes = cycle.probes || [];
              const requiredCount = cycle.probes_required || 3;
              const passedCount = cycle.probes_passed || 0;
              const progressPercent = Math.min(100, Math.round((passedCount / requiredCount) * 100));

              return (
                <Card key={cycle.id} className="overflow-hidden border-slate-800/90 hover:border-slate-700 transition-colors">
                  <div className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/60">
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <Badge
                          variant={cycle.status === "passed" ? "success" : cycle.status === "failed" ? "error" : "warning"}
                        >
                          {cycle.status.toUpperCase()}
                        </Badge>
                        <span className="font-mono text-xs font-semibold text-slate-200">
                          Cycle #{cycle.cycle_number}
                        </span>
                        <span className="text-slate-600">•</span>
                        <span className="text-xs font-mono text-slate-400">
                          Execution: {cycle.execution_id.slice(0, 8)}...
                        </span>
                        {cycle.action_id && (
                          <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 font-mono text-slate-300">
                            {cycle.action_id}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-3 text-xs text-slate-400 flex-wrap">
                        {cycle.service_name && (
                          <span className="flex items-center gap-1 text-slate-300">
                            <Server className="w-3.5 h-3.5 text-slate-400" />
                            {cycle.service_name}
                          </span>
                        )}
                        {cycle.incident_id && (
                          <span className="flex items-center gap-1 text-slate-400">
                            Incident:{" "}
                            <Link
                              href={`/incidents/${cycle.incident_id}`}
                              className="text-emerald-400 hover:underline font-mono"
                            >
                              {cycle.incident_id.slice(0, 8)}...
                            </Link>
                          </span>
                        )}
                        <span className="flex items-center gap-1 text-slate-400">
                          <Timer className="w-3.5 h-3.5 text-slate-500" />
                          Started: {new Date(cycle.started_at).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 shrink-0">
                      <div className="text-right">
                        <div className="text-[11px] text-slate-400 font-mono">
                          Consecutive Passes: <span className="font-semibold text-slate-200">{passedCount}/{requiredCount}</span>
                        </div>
                        <div className="w-32 bg-slate-800 h-1.5 rounded-full overflow-hidden mt-1.5">
                          <div
                            className={`h-full rounded-full transition-all ${
                              progressPercent >= 100 ? "bg-emerald-500" : progressPercent > 0 ? "bg-amber-500" : "bg-slate-700"
                            }`}
                            style={{ width: `${progressPercent}%` }}
                          />
                        </div>
                      </div>

                      <button
                        onClick={() => toggleCycleExpand(cycle.id)}
                        className="p-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
                        title={isExpanded ? "Collapse probe details" : "Expand probe details"}
                      >
                        {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div className="px-4 py-2 bg-slate-950/40 flex items-center justify-between text-xs text-slate-400 border-b border-slate-800/40">
                    <div className="flex items-center gap-2">
                      {cycle.status === "passed" && cycle.recovery_status === "recovered" ? (
                        <>
                          <ShieldCheck className="w-4 h-4 text-emerald-400" />
                          <span>
                            Recovery Bridge:{" "}
                            <span className="font-semibold text-emerald-400">
                              Incident Recovered
                            </span>
                          </span>
                        </>
                      ) : cycle.status === "failed" ? (
                        <>
                          <ShieldAlert className="w-4 h-4 text-rose-400" />
                          <span>
                            Recovery Bridge:{" "}
                            <span className="font-semibold text-rose-400">
                              Recovery Blocked (Verification Failed)
                            </span>
                          </span>
                        </>
                      ) : cycle.status === "uncertain" || cycle.status === "timed_out" ? (
                        <>
                          <AlertTriangle className="w-4 h-4 text-amber-400" />
                          <span>
                            Recovery Bridge:{" "}
                            <span className="font-semibold text-amber-400">
                              Recovery Blocked (Verification Uncertain)
                            </span>
                          </span>
                        </>
                      ) : (
                        <>
                          <ShieldCheck className="w-4 h-4 text-slate-400" />
                          <span>
                            Recovery Bridge:{" "}
                            <span className="font-semibold text-amber-400">
                              Pending Recovery Gate
                            </span>
                          </span>
                        </>
                      )}
                    </div>
                    <div className="text-[11px] font-mono text-slate-500">
                      Fencing Token: {cycle.fencing_token}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="p-4 bg-slate-950/60 space-y-3">
                      <div className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                        <span>Granular Synthetic Probes ({probes.length} recorded):</span>
                        <span className="text-[11px] font-mono text-slate-500">
                          Deadline: {new Date(cycle.deadline_at).toLocaleTimeString()}
                        </span>
                      </div>

                      {probes.length === 0 ? (
                        <p className="text-xs text-slate-500 italic py-2">
                          No individual probe records available for this cycle.
                        </p>
                      ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                          {probes.map((probe) => {
                            const isProbePassed = probe.passed || probe.status === "passed";
                            return (
                              <div
                                key={probe.id}
                                className={`p-3 rounded-lg border text-xs space-y-1.5 ${
                                  isProbePassed
                                    ? "bg-emerald-950/20 border-emerald-800/40 text-emerald-300"
                                    : "bg-rose-950/20 border-rose-800/40 text-rose-300"
                                }`}
                              >
                                <div className="flex items-center justify-between">
                                  <span className="font-semibold font-mono text-[11px]">
                                    Probe #{probe.probe_number} ({probe.probe_type})
                                  </span>
                                  <span
                                    className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold ${
                                      isProbePassed ? "bg-emerald-900/60 text-emerald-300" : "bg-rose-900/60 text-rose-300"
                                    }`}
                                  >
                                    {isProbePassed ? "PASS" : "FAIL"}
                                  </span>
                                </div>

                                <div className="text-[11px] text-slate-400 truncate" title={probe.target_url}>
                                  {probe.target_url}
                                </div>

                                <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800/60 font-mono">
                                  <span>Code: {probe.status_code || "N/A"}</span>
                                  <span>{probe.latency_ms ? `${probe.latency_ms.toFixed(1)}ms` : "N/A"}</span>
                                </div>

                                {probe.error_message && (
                                  <p className="text-[10px] text-rose-400 pt-1 line-clamp-2" title={probe.error_message}>
                                    {probe.error_message}
                                  </p>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  )}
                </Card>
              );
            })}
          </div>
        )
      )}

      {/* Selected Execution Detail Modal */}
      {selectedExecution && (
        <Modal
          isOpen={isDetailOpen}
          onClose={closeDetail}
          title={`Remediation Execution: ${selectedExecution.action_id}`}
          description={`Execution ID: ${selectedExecution.id} • Fencing Token: ${selectedExecution.fencing_token}`}
        >
          <div className="space-y-4 text-xs">
            {/* Recovery Presentation Banner */}
            {selectedExecPresentation && (
              <div
                className={`p-3.5 rounded-lg border text-xs space-y-1.5 ${
                  selectedExecPresentation.badgeVariant === "success"
                    ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-200"
                    : selectedExecPresentation.badgeVariant === "warning"
                    ? "bg-amber-500/10 border-amber-500/40 text-amber-200"
                    : selectedExecPresentation.badgeVariant === "error"
                    ? "bg-rose-500/10 border-rose-500/30 text-rose-200"
                    : "bg-slate-900 border-slate-800 text-slate-300"
                }`}
              >
                <div className="flex items-center justify-between font-semibold">
                  <div className="flex items-center gap-2">
                    {selectedExecPresentation.badgeVariant === "success" ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : selectedExecPresentation.badgeVariant === "warning" ? (
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                    ) : selectedExecPresentation.badgeVariant === "error" ? (
                      <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                    ) : (
                      <Clock className="w-4 h-4 text-slate-400 shrink-0" />
                    )}
                    <span>{selectedExecPresentation.label}</span>
                  </div>
                  <span className="font-mono text-[11px] uppercase tracking-wider">
                    {selectedExecPresentation.category}
                  </span>
                </div>
                <p className="text-slate-300 leading-relaxed text-[11px]">
                  {selectedExecPresentation.description}
                </p>
                {selectedExecPresentation.evidenceSummary && (
                  <div className="text-[11px] font-mono pt-1 text-slate-400">
                    Evidence: {selectedExecPresentation.evidenceSummary}
                  </div>
                )}
              </div>
            )}

            {/* Invariant Alert for Execution Success vs Verification */}
            {selectedExecution.status === "execution_succeeded" && (
              <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-500/5 text-amber-200 text-[11px] flex items-start gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <strong>Phase 4.3 Safety Invariant:</strong> Container execution succeeded with exit code 0. However, execution success alone does NOT indicate service recovery. Awaiting synthetic verification probe results.
                </div>
              </div>
            )}

            {/* Execution Overview Grid */}
            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-950/60 rounded-lg border border-slate-800">
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Execution Status</span>
                <div className="mt-1">{renderExecutionStatusBadge(selectedExecution.status)}</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Target Service</span>
                <div className="mt-1 font-medium text-slate-200">{selectedExecution.target_service_id || "Order API"}</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Approval Authority</span>
                <div className="mt-1 text-slate-300 font-mono text-[11px]">
                  ID: {selectedExecution.approval_id.slice(0, 16)}...
                </div>
                <div className="pt-0.5">
                  <Link
                    href="/remediation/approvals"
                    className="text-emerald-400 hover:underline text-[11px] flex items-center gap-1"
                  >
                    View in Approvals Queue &rarr;
                  </Link>
                </div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Associated Incident</span>
                {selectedExecution.incident_id ? (
                  <div className="mt-1">
                    <Link
                      href={`/incidents/${selectedExecution.incident_id}`}
                      className="text-emerald-400 hover:underline font-mono text-[11px] flex items-center gap-1"
                    >
                      <span>{selectedExecution.incident_id.slice(0, 16)}...</span>
                      <ExternalLink className="w-3 h-3" />
                    </Link>
                  </div>
                ) : (
                  <div className="mt-1 text-slate-500 italic">None / Standalone</div>
                )}
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Idempotency Key</span>
                <div className="mt-1 font-mono text-[11px] text-cyan-300 truncate" title={selectedExecution.idempotency_key}>
                  {selectedExecution.idempotency_key}
                </div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Fencing Token</span>
                <div className="mt-1 font-mono text-[11px] text-slate-200">{selectedExecution.fencing_token}</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Triggered At</span>
                <div className="mt-1 text-slate-200 font-mono text-[11px]">
                  {new Date(selectedExecution.triggered_at || selectedExecution.created_at).toLocaleString()}
                </div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Completed At</span>
                <div className="mt-1 text-slate-200 font-mono text-[11px]">
                  {selectedExecution.completed_at ? new Date(selectedExecution.completed_at).toLocaleString() : "In progress / Pending"}
                </div>
              </div>
            </div>

            {/* Exact Approved Parameters (Locked) */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-emerald-400" />
                  Exact Approved Parameters (Policy Locked)
                </span>
                <span className="text-[10px] text-slate-500">Immutable</span>
              </div>
              <pre className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-emerald-400 overflow-x-auto">
                {JSON.stringify(selectedExecution.approved_parameters, null, 2)}
              </pre>
            </div>

            {/* Verification Cycles for this Execution */}
            <div className="space-y-2 pt-2 border-t border-slate-800">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-emerald-400" />
                  Associated Verification Cycles ({selectedExecCycles.length})
                </h4>
              </div>

              {selectedExecCycles.length === 0 ? (
                <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 text-slate-400 text-xs">
                  {selectedExecution.status === "queued" || selectedExecution.status === "executing"
                    ? "Verification probes have not started. Probes will run after container execution completes."
                    : selectedExecution.status === "execution_failed"
                    ? "Execution failed. Verification was aborted."
                    : "No verification cycle records are currently persisted for this execution."}
                </div>
              ) : (
                selectedExecCycles.map((cyc) => {
                  const probes = cyc.probes || [];
                  const requiredCount = cyc.probes_required || 3;
                  const passedCount = cyc.probes_passed || 0;
                  return (
                    <div key={cyc.id} className="p-3 bg-slate-950/80 rounded-lg border border-slate-800 space-y-2.5">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Badge variant={cyc.status === "passed" ? "success" : cyc.status === "failed" ? "error" : "warning"}>
                            {cyc.status.toUpperCase()}
                          </Badge>
                          <span className="font-semibold text-slate-200 font-mono">Cycle #{cyc.cycle_number}</span>
                        </div>
                        <span className="font-mono text-[11px] text-slate-400">
                          Passes: {passedCount}/{requiredCount} (3 required for recovery)
                        </span>
                      </div>

                      {/* Granular Probes Table */}
                      {probes.length > 0 && (
                        <div className="space-y-1.5 pt-1">
                          <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-semibold">
                            Granular Probe Evidence
                          </span>
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                            {probes.map((pr) => {
                              const isPass = pr.passed || pr.status === "passed";
                              return (
                                <div
                                  key={pr.id}
                                  className={`p-2 rounded border font-mono text-[11px] space-y-1 ${
                                    isPass ? "bg-emerald-950/30 border-emerald-800/40 text-emerald-300" : "bg-rose-950/30 border-rose-800/40 text-rose-300"
                                  }`}
                                >
                                  <div className="flex items-center justify-between">
                                    <span>Probe #{pr.probe_number}</span>
                                    <span>{isPass ? "PASS" : "FAIL"}</span>
                                  </div>
                                  <div className="text-[10px] text-slate-400 truncate">
                                    {pr.target_url}
                                  </div>
                                  <div className="flex justify-between text-[10px] text-slate-500">
                                    <span>HTTP {pr.status_code || "N/A"}</span>
                                    <span>{pr.latency_ms ? `${pr.latency_ms.toFixed(1)}ms` : "N/A"}</span>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>

            {/* Close Button */}
            <div className="pt-2 flex justify-end">
              <Button variant="secondary" size="sm" onClick={closeDetail}>
                Close
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
