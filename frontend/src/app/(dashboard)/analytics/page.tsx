"use client";

import React, { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import {
  DashboardAnalytics,
  Service,
  Incident,
} from "@/lib/types";
import {
  FileBarChart,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  Clock,
  RefreshCw,
  Server,
  Activity,
  Layers,
  BrainCircuit,
  ShieldCheck,
  Filter,
  BarChart3,
  Calendar,
  AlertCircle,
  HelpCircle,
  ArrowUpRight,
  Database,
  PieChart,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

export default function AnalyticsPage() {
  const { activeWorkspace, token } = useAuth();
  const [analytics, setAnalytics] = useState<DashboardAnalytics | null>(null);
  const [services, setServices] = useState<Service[]>([]);
  const [selectedServiceId, setSelectedServiceId] = useState<string>("all");
  const [timeWindow, setTimeWindow] = useState<string>("all");
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchServices = async () => {
    if (!activeWorkspace || !token) return;
    try {
      const data = await api.services.list(activeWorkspace.workspace_id, token);
      setServices(data || []);
    } catch {
      // Non-fatal
    }
  };

  const fetchAnalytics = async () => {
    if (!activeWorkspace || !token) return;
    setIsLoading(true);
    setError(null);
    try {
      const svcFilter = selectedServiceId === "all" ? undefined : selectedServiceId;
      const data = await api.dashboard.getAnalytics(activeWorkspace.workspace_id, token, svcFilter);
      setAnalytics(data);
    } catch (err: any) {
      setError(err.message || "Failed to load operational analytics.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchServices();
  }, [activeWorkspace?.workspace_id, token]);

  useEffect(() => {
    fetchAnalytics();
  }, [activeWorkspace?.workspace_id, token, selectedServiceId]);

  // Format seconds into human readable duration
  const formatDuration = (seconds: number | null | undefined): string => {
    if (seconds === null || seconds === undefined || isNaN(seconds)) {
      return "N/A";
    }
    if (seconds < 60) {
      return `${seconds.toFixed(1)}s`;
    }
    const mins = Math.floor(seconds / 60);
    const remainingSecs = Math.round(seconds % 60);
    if (mins < 60) {
      return `${mins}m ${remainingSecs}s`;
    }
    const hours = Math.floor(mins / 60);
    const remainingMins = mins % 60;
    return `${hours}h ${remainingMins}m`;
  };

  const recoveryRate = useMemo(() => {
    if (!analytics || analytics.total_incidents === 0) return 0;
    return Math.round((analytics.recovered_incidents / analytics.total_incidents) * 100);
  }, [analytics]);

  return (
    <div className="space-y-6">
      {/* Top Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
              Reports & SRE Analytics
            </h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/80">
              Audit Telemetry
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Empirical MTTR, MTTD, incident distributions, and investigation metrics for{" "}
            <span className="text-slate-200 font-semibold">{activeWorkspace?.workspace_name}</span>
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="secondary"
            size="sm"
            onClick={fetchAnalytics}
            isLoading={isLoading}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh Analytics
          </Button>
          <Link href="/incidents">
            <Button size="sm">
              <AlertTriangle className="w-3.5 h-3.5" />
              Incident Audit
            </Button>
          </Link>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 flex items-center gap-3 text-rose-300 text-xs">
          <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-wrap items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 text-slate-400">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <span>Scope Filter:</span>
          </div>

          {/* Service Filter */}
          <select
            value={selectedServiceId}
            onChange={(e) => setSelectedServiceId(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            <option value="all">All Services ({services.length})</option>
            {services.map((svc) => (
              <option key={svc.id} value={svc.id}>
                {svc.name} ({svc.environment})
              </option>
            ))}
          </select>

          {/* Time Window (Informational Scope) */}
          <select
            value={timeWindow}
            onChange={(e) => setTimeWindow(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            <option value="all">All Available History</option>
            <option value="30d">Last 30 Days</option>
            <option value="7d">Last 7 Days</option>
          </select>
        </div>

        <div className="text-[11px] font-mono text-slate-500 flex items-center gap-1.5">
          <Database className="w-3.5 h-3.5 text-emerald-400/80" />
          PostgreSQL Ground Truth (sentinelops_dev)
        </div>
      </div>

      {/* Top 4 KPI Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total & Active Incidents */}
        <Card className="relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs font-medium text-slate-400">Total Incidents Recorded</div>
              <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">
                {analytics?.total_incidents ?? 0}
              </div>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-800/80 text-slate-400">
              <Activity className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-[11px] text-slate-400 flex items-center justify-between">
            <span>
              Active: <span className="font-semibold text-rose-400">{analytics?.active_incidents ?? 0}</span>
            </span>
            <span>
              Recovered: <span className="font-semibold text-emerald-400">{analytics?.recovered_incidents ?? 0}</span>
            </span>
          </div>
        </Card>

        {/* Empirical MTTR */}
        <Card className="relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs font-medium text-slate-400 flex items-center gap-1">
                Mean Time to Recover (MTTR)
                <span title="Average duration between detected_at and recovered_at across verified incidents">
                  <HelpCircle className="w-3 h-3 text-slate-500 cursor-help" />
                </span>
              </div>
              <div className="text-2xl font-bold text-emerald-400 mt-1 font-mono">
                {formatDuration(analytics?.avg_mttr_seconds)}
              </div>
            </div>
            <div className="p-2.5 rounded-lg bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
              <Clock className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Median: <span className="font-mono text-slate-300">{formatDuration(analytics?.median_mttr_seconds)}</span></span>
            <span className="text-slate-500 font-mono">n={analytics?.mttr_sample_size ?? 0}</span>
          </div>
        </Card>

        {/* Empirical MTTD */}
        <Card className="relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs font-medium text-slate-400 flex items-center gap-1">
                Mean Time to Detect (MTTD)
                <span title="Detection delay recorded during autonomous health probe cycles">
                  <HelpCircle className="w-3 h-3 text-slate-500 cursor-help" />
                </span>
              </div>
              <div className="text-2xl font-bold text-sky-400 mt-1 font-mono">
                {analytics?.avg_mttd_seconds ? `${analytics.avg_mttd_seconds.toFixed(2)}s` : "< 10.0s"}
              </div>
            </div>
            <div className="p-2.5 rounded-lg bg-sky-950/60 text-sky-400 border border-sky-800/60">
              <TrendingUp className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Poller Cycle: <span className="font-mono text-slate-300">10s</span></span>
            <span className="text-slate-500 font-mono">Bounded SLA</span>
          </div>
        </Card>

        {/* Recovery Success Rate */}
        <Card className="relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs font-medium text-slate-400">Recovery Success Rate</div>
              <div className="text-2xl font-bold text-emerald-400 mt-1 font-mono">
                {recoveryRate}%
              </div>
            </div>
            <div className="p-2.5 rounded-lg bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
              <CheckCircle2 className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-[11px] text-slate-400">
            <span className="text-emerald-400 font-semibold">{analytics?.recovered_incidents ?? 0}</span> of{" "}
            <span className="text-slate-200">{analytics?.total_incidents ?? 0}</span> incidents resolved
          </div>
        </Card>
      </div>

      {/* Second Row: Distributions & Trends */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Incident Severity & Status Distribution */}
        <Card className="p-5 space-y-5">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <PieChart className="w-4 h-4 text-emerald-400" />
              Incident Severity & State Breakdown
            </h3>
            <span className="text-[11px] font-mono text-slate-500">
              Active Tenant
            </span>
          </div>

          {/* Severity Progress Bars */}
          <div className="space-y-3">
            <div className="text-xs font-medium text-slate-400">By Severity Level:</div>
            {[
              { level: "critical", label: "Critical", color: "bg-rose-500", text: "text-rose-400" },
              { level: "high", label: "High", color: "bg-orange-500", text: "text-orange-400" },
              { level: "medium", label: "Medium", color: "bg-amber-500", text: "text-amber-400" },
              { level: "low", label: "Low", color: "bg-sky-500", text: "text-sky-400" },
            ].map(({ level, label, color, text }) => {
              const count = analytics?.severity_distribution[level] ?? 0;
              const total = analytics?.total_incidents || 1;
              const pct = Math.round((count / total) * 100);
              return (
                <div key={level} className="space-y-1">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className={text}>{label}</span>
                    <span className="text-slate-400">{count} ({pct}%)</span>
                  </div>
                  <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                    <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>

          {/* Status Pills */}
          <div className="pt-2 border-t border-slate-800/60">
            <div className="text-xs font-medium text-slate-400 mb-2">By Operational State:</div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(analytics?.status_distribution || {}).map(([statusKey, count]) => (
                <div
                  key={statusKey}
                  className="px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700/60 text-[11px] font-mono flex items-center gap-1.5 text-slate-300"
                >
                  <span className="capitalize">{statusKey.replace("_", " ")}:</span>
                  <span className="font-bold text-slate-100">{count}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>

        {/* Timeline Trends */}
        <Card className="p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-emerald-400" />
              Incident Velocity Over Time
            </h3>
            <span className="text-[11px] font-mono text-slate-500">
              Daily Buckets
            </span>
          </div>

          {analytics?.incident_trends && analytics.incident_trends.length > 0 ? (
            <div className="space-y-3">
              {analytics.incident_trends.map((item) => (
                <div
                  key={item.date}
                  className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-center justify-between text-xs font-mono"
                >
                  <span className="text-slate-300 font-semibold">{item.date}</span>
                  <div className="flex items-center gap-4">
                    <span className="text-rose-400">
                      Detected: <span className="font-bold">{item.detected}</span>
                    </span>
                    <span className="text-emerald-400">
                      Recovered: <span className="font-bold">{item.recovered}</span>
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-12 text-center text-xs text-slate-500 italic">
              No historical trend buckets recorded yet.
            </div>
          )}
        </Card>
      </div>

      {/* Third Row: AI Investigation & Remediation Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* AI Investigation Diagnostics */}
        <Card className="p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <BrainCircuit className="w-4 h-4 text-purple-400" />
              Agentic AI Diagnostic Telemetry
            </h3>
            <span className="text-[11px] font-mono text-purple-400">
              LangGraph SRE
            </span>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/60 text-center">
              <div className="text-[11px] text-slate-400">Total Invs</div>
              <div className="text-lg font-bold font-mono text-slate-100 mt-1">
                {analytics?.investigation_analytics.total_investigations ?? 0}
              </div>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/60 text-center">
              <div className="text-[11px] text-slate-400">Completed</div>
              <div className="text-lg font-bold font-mono text-emerald-400 mt-1">
                {analytics?.investigation_analytics.completed ?? 0}
              </div>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/60 text-center">
              <div className="text-[11px] text-slate-400">Avg Conf</div>
              <div className="text-lg font-bold font-mono text-purple-400 mt-1">
                {analytics?.investigation_analytics.avg_confidence
                  ? `${(analytics.investigation_analytics.avg_confidence * 100).toFixed(0)}%`
                  : "N/A"}
              </div>
            </div>
          </div>

          {/* Top Diagnosed Root Causes */}
          <div className="space-y-2 pt-2">
            <div className="text-xs font-medium text-slate-400">Top Diagnosed Root Causes:</div>
            {analytics?.investigation_analytics.top_diagnosed_causes &&
            analytics.investigation_analytics.top_diagnosed_causes.length > 0 ? (
              <div className="space-y-1.5">
                {analytics.investigation_analytics.top_diagnosed_causes.map((cause) => (
                  <div
                    key={cause.root_cause}
                    className="p-2 rounded bg-slate-800/50 flex items-center justify-between text-xs text-slate-300"
                  >
                    <span className="truncate pr-2">{cause.root_cause}</span>
                    <span className="font-mono text-purple-400 font-semibold shrink-0">
                      {cause.count} cases
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500 italic">No root causes recorded yet.</p>
            )}
          </div>
        </Card>

        {/* Remediation & Verification Pipeline Health */}
        <Card className="p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Remediation & Verification Gate Health
            </h3>
            <span className="text-[11px] font-mono text-emerald-400">
              Revision 10
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/60 space-y-1">
              <div className="text-[11px] text-slate-400">Verification Passes (PASS)</div>
              <div className="text-xl font-bold font-mono text-emerald-400">
                {analytics?.execution_analytics.verification_passed ?? 0}
              </div>
              <div className="text-[10px] text-slate-500 font-mono">3/3 probes satisfied</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/60 space-y-1">
              <div className="text-[11px] text-slate-400">Failures / Timeouts</div>
              <div className="text-xl font-bold font-mono text-rose-400">
                {analytics?.execution_analytics.verification_failed ?? 0}
              </div>
              <div className="text-[10px] text-slate-500 font-mono">Prevented false recoveries</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/60 space-y-1">
              <div className="text-[11px] text-slate-400">Inconclusive / Uncertain</div>
              <div className="text-xl font-bold font-mono text-amber-400">
                {analytics?.execution_analytics.verification_inconclusive ?? 0}
              </div>
              <div className="text-[10px] text-slate-500 font-mono">Fail-closed safety locks</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/60 space-y-1">
              <div className="text-[11px] text-slate-400">Pending Execution / Queue</div>
              <div className="text-xl font-bold font-mono text-sky-400">
                {analytics?.execution_analytics.in_progress ?? 0}
              </div>
              <div className="text-[10px] text-slate-500 font-mono">Awaiting verification</div>
            </div>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 text-[11px] text-slate-400 font-mono flex items-center justify-between">
            <span>Recovery Bridge Gate:</span>
            <span className="text-emerald-400 font-semibold">Strict 3-Probe Barrier Active</span>
          </div>
        </Card>
      </div>

      {/* Fourth Row: Monitored Services SRE Table */}
      <Card className="p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <Server className="w-4 h-4 text-emerald-400" />
            Monitored Service Breakdown
          </h3>
          <span className="text-[11px] font-mono text-slate-500">
            {analytics?.services.length ?? 0} Services Registered
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950 text-slate-400 font-mono border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Service Name</th>
                <th className="py-2.5 px-3">Environment</th>
                <th className="py-2.5 px-3">Health Status</th>
                <th className="py-2.5 px-3 text-right">Incidents Total</th>
                <th className="py-2.5 px-3 text-right">Recovered</th>
                <th className="py-2.5 px-3 text-right">Mean MTTR</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {analytics?.services && analytics.services.length > 0 ? (
                analytics.services.map((svc) => (
                  <tr key={svc.service_id} className="hover:bg-slate-900/40">
                    <td className="py-3 px-3 font-semibold text-slate-200">
                      <Link
                        href={`/services/${svc.service_id}`}
                        className="text-emerald-400 hover:underline flex items-center gap-1.5"
                      >
                        {svc.service_name}
                        <ArrowUpRight className="w-3 h-3 opacity-60" />
                      </Link>
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-400">
                      {svc.environment}
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium ${
                          svc.health_status === "healthy"
                            ? "bg-emerald-950 text-emerald-400 border border-emerald-800/60"
                            : svc.health_status === "unhealthy"
                            ? "bg-rose-950 text-rose-400 border border-rose-800/60"
                            : "bg-amber-950 text-amber-400 border border-amber-800/60"
                        }`}
                      >
                        {svc.health_status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-slate-200">
                      {svc.total_incidents}
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-emerald-400 font-semibold">
                      {svc.recovered_incidents}
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-slate-300">
                      {formatDuration(svc.avg_mttr_seconds)}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 italic">
                    No services found for this workspace.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
