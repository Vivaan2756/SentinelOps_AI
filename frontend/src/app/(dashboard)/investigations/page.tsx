"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import { Incident } from "@/lib/types";
import {
  BrainCircuit,
  RefreshCw,
  AlertTriangle,
  ArrowRight,
  Sparkles,
  ShieldCheck,
  CheckCircle2,
  Clock,
} from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

export default function InvestigationsPage() {
  const { activeWorkspace, token } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);


  const fetchData = async () => {
    if (!activeWorkspace || !token) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.incidents.list(activeWorkspace.workspace_id, token, {});
      setIncidents(data);
    } catch (err: any) {
      setError(err.message || "Failed to load incidents for investigation.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [activeWorkspace?.workspace_id, token]);

  const activeIncidents = incidents.filter(
    (i) => i.status !== "recovered" && i.status !== "closed"
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <BrainCircuit className="w-6 h-6 text-cyan-400" />
            Agentic AI Incident Investigation
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Orchestrated multi-step diagnostic reasoning powered by LangGraph & Gemini 2.5 Flash
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={fetchData} disabled={isLoading}>
          <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${isLoading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {/* Guardrails Banner */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-slate-900 to-slate-950 border border-cyan-800/40 flex items-start gap-3">
        <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
        <div className="space-y-1 text-xs">
          <div className="font-semibold text-slate-200">
            Read-Only SRE Diagnostic Guardrails Enforced
          </div>
          <p className="text-slate-400 leading-relaxed">
            The AI investigation workflow operates strictly under read-only diagnostic constraints.
            It gathers real telemetry from registered health and Prometheus metrics endpoints, validates evidential references,
            and produces structured root-cause hypotheses to assist human SRE engineers. Autonomous mutations, shell execution, and remediation actions are strictly disabled in Phase 3.
          </p>
        </div>
      </div>

      {/* Incidents Table / Cards for Investigation */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">
            Workspace Incidents Eligible for AI Investigation ({incidents.length})
          </h2>
          <span className="text-xs text-slate-500 font-mono">
            {activeIncidents.length} active • {incidents.length - activeIncidents.length} resolved
          </span>
        </div>

        {isLoading ? (
          <div className="p-12 text-center text-slate-500 flex flex-col items-center justify-center gap-3">
            <RefreshCw className="w-6 h-6 animate-spin text-cyan-500" />
            <p className="text-sm">Loading workspace incidents...</p>
          </div>
        ) : incidents.length === 0 ? (
          <div className="p-12 text-center rounded-xl bg-slate-900 border border-slate-800 text-slate-500">
            <CheckCircle2 className="w-8 h-8 mx-auto text-emerald-500/50 mb-2" />
            <p className="text-sm font-medium text-slate-300">No Incidents Recorded</p>
            <p className="text-xs text-slate-500 mt-1">
              Your registered services are operating normally. When an anomaly is detected, it will appear here for AI investigation.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3">
            {incidents.map((incident) => {
              const isResolved = incident.status === "recovered" || incident.status === "closed";
              return (
                <div
                  key={incident.id}
                  className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2">
                      <Badge variant={incident.severity === "critical" || incident.severity === "high" ? "error" : "warning"}>
                        {incident.severity.toUpperCase()}
                      </Badge>
                      <Badge variant={isResolved ? "success" : "neutral"}>
                        {incident.status.toUpperCase()}
                      </Badge>
                      <span className="text-[11px] font-mono text-slate-500">
                        {incident.id.slice(0, 8)}...
                      </span>
                    </div>

                    <h3 className="text-sm font-semibold text-white">
                      {incident.title}
                    </h3>

                    <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
                      <div className="flex items-center gap-1 font-mono">
                        <Clock className="w-3.5 h-3.5 text-slate-500" />
                        <span>{new Date(incident.detected_at).toLocaleString()}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                        <span className="font-mono text-slate-300">{incident.trigger}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2.5 shrink-0">
                    <Link href={`/incidents/${incident.id}`}>
                      <Button
                        size="sm"
                        className="bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white border-0 shadow-md"
                      >
                        <Sparkles className="w-3.5 h-3.5 mr-1.5 text-cyan-200" />
                        Investigate Report
                        <ArrowRight className="w-3.5 h-3.5 ml-1.5" />
                      </Button>
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
