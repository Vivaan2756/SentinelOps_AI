"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import { DashboardOverview } from "@/lib/types";
import {
  Server,
  AlertTriangle,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Clock,
  ArrowRight,
  ShieldAlert,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

export default function OverviewPage() {
  const { activeWorkspace, token } = useAuth();
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchOverview = async () => {
    if (!activeWorkspace || !token) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.dashboard.getOverview(activeWorkspace.workspace_id, token);
      setData(res);
    } catch (err: any) {
      setError(err.message || "Failed to load dashboard metrics.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchOverview();
  }, [activeWorkspace?.workspace_id, token]);

  if (!activeWorkspace) {
    return (
      <div className="p-8 text-center bg-slate-900/50 border border-slate-800 rounded-xl">
        <p className="text-slate-400 text-sm">Please select an authorized workspace to view the dashboard.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
            Operational Overview
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/80">
              Live DB
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time health, incident detection, and telemetry for{" "}
            <span className="text-slate-200 font-semibold">{activeWorkspace.workspace_name}</span>
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <Button
            variant="secondary"
            size="sm"
            onClick={fetchOverview}
            isLoading={isLoading}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh Metrics
          </Button>
          <Link href="/services">
            <Button size="sm">
              <Server className="w-3.5 h-3.5" />
              Manage Services
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

      {/* Primary KPI Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Services */}
        <Card className="relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Total Registered Services</span>
            <Server className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-3xl font-bold text-slate-100 mt-2">
            {isLoading ? "—" : data?.total_services ?? 0}
          </div>
          <div className="mt-3 flex items-center gap-3 text-xs text-slate-400">
            <span className="flex items-center gap-1 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              {data?.healthy_services ?? 0} Healthy
            </span>
            <span className="flex items-center gap-1 text-rose-400">
              <span className="w-2 h-2 rounded-full bg-rose-500" />
              {data?.unhealthy_services ?? 0} Failing
            </span>
          </div>
        </Card>

        {/* Active Incidents */}
        <Card className="relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Active Incidents</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-3xl font-bold text-slate-100 mt-2">
            {isLoading ? "—" : data?.active_incidents ?? 0}
          </div>
          <div className="mt-3 text-xs text-slate-400">
            {(data?.active_incidents ?? 0) === 0 ? (
              <span className="text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> All services operating normally
              </span>
            ) : (
              <span className="text-amber-400">Requires SRE attention</span>
            )}
          </div>
        </Card>

        {/* Critical Severity Incidents */}
        <Card className="relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Critical / High Severity</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-3xl font-bold text-rose-400 mt-2">
            {isLoading
              ? "—"
              : (data?.incidents_by_severity.critical ?? 0) +
                (data?.incidents_by_severity.high ?? 0)}
          </div>
          <div className="mt-3 text-xs text-slate-400 flex gap-2">
            <span>Critical: {data?.incidents_by_severity.critical ?? 0}</span>
            <span>•</span>
            <span>High: {data?.incidents_by_severity.high ?? 0}</span>
          </div>
        </Card>

        {/* Detection Engine Status */}
        <Card className="relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Detector Engine</span>
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          </div>
          <div className="text-base font-semibold text-slate-100 mt-2">
            Deterministic Rules
          </div>
          <p className="text-xs text-slate-400 mt-1">
            SSRF protected • Bounded 3.0s probes
          </p>
          <div className="mt-3">
            <span className="text-[10px] text-emerald-400 font-mono bg-emerald-950/60 border border-emerald-800 px-2 py-0.5 rounded">
              PostgreSQL Sync Active
            </span>
          </div>
        </Card>
      </div>

      {/* Main Dual-Column Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Incidents (2 Columns) */}
        <div className="lg:col-span-2 space-y-4">
          <Card
            title="Recent Incidents"
            subtitle="Persisted incidents detected by deterministic alert rules"
            action={
              <Link href="/incidents" className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1">
                View all <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            }
          >
            {isLoading ? (
              <div className="py-12 text-center text-xs text-slate-500">Loading incidents...</div>
            ) : !data?.recent_incidents || data.recent_incidents.length === 0 ? (
              <div className="py-12 text-center">
                <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2 opacity-80" />
                <p className="text-sm text-slate-300 font-medium">No incidents recorded</p>
                <p className="text-xs text-slate-500 mt-1">
                  Trigger failure simulation on Order API to observe detection.
                </p>
              </div>
            ) : (
              <div className="divide-y divide-slate-800/80">
                {data.recent_incidents.map((inc) => (
                  <Link
                    key={inc.id}
                    href={`/incidents/${inc.id}`}
                    className="flex items-start justify-between py-3 px-2 rounded-lg hover:bg-slate-800/50 transition-colors group"
                  >
                    <div className="space-y-1 pr-4">
                      <div className="flex items-center gap-2">
                        <Badge variant={inc.severity as any}>{inc.severity}</Badge>
                        <Badge variant={inc.status as any}>{inc.status}</Badge>
                        <span className="text-xs font-semibold text-slate-200 group-hover:text-emerald-400 transition-colors">
                          {inc.title}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 line-clamp-1">{inc.trigger}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <span className="text-[11px] text-slate-500 font-mono flex items-center gap-1 justify-end">
                        <Clock className="w-3 h-3" />
                        {new Date(inc.detected_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </span>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </Card>
        </div>

        {/* Timeline Activity Stream (1 Column) */}
        <div>
          <Card
            title="Operational Activity"
            subtitle="Chronological audit & detection trail"
          >
            {isLoading ? (
              <div className="py-12 text-center text-xs text-slate-500">Loading activity...</div>
            ) : !data?.recent_events || data.recent_events.length === 0 ? (
              <div className="py-12 text-center text-xs text-slate-500">
                No activity recorded in this workspace.
              </div>
            ) : (
              <div className="space-y-3 relative before:absolute before:left-2 before:top-2 before:bottom-2 before:w-px before:bg-slate-800">
                {data.recent_events.map((ev) => (
                  <div key={ev.id} className="relative pl-6 text-xs">
                    <span className="absolute left-1 top-1 w-2 h-2 rounded-full bg-emerald-500 ring-4 ring-slate-900" />
                    <div className="flex items-center justify-between text-slate-400 mb-0.5">
                      <span className="font-semibold uppercase text-[10px] text-emerald-400 font-mono">
                        {ev.event_type}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono">
                        {new Date(ev.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </span>
                    </div>
                    <p className="text-slate-300 font-medium leading-relaxed">{ev.message}</p>
                    <p className="text-[11px] text-slate-500 mt-0.5">Service: {ev.service_name}</p>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
