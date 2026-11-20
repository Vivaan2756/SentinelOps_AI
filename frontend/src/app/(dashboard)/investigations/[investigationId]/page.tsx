"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import { Investigation, Hypothesis, EvidenceItem } from "@/lib/types";
import {
  BrainCircuit,
  ArrowLeft,
  RefreshCw,
  AlertCircle,
  Activity,
  ShieldAlert,
  Clock,
  ChevronRight,
  HelpCircle,
  BookOpen,
  Zap,
  CheckCircle2,
  Info,
} from "lucide-react";

import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

export default function InvestigationDetailPage() {
  const params = useParams();
  const investigationId = params?.investigationId as string;
  const { activeWorkspace, token } = useAuth();

  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchInvestigation = async () => {
    if (!investigationId || !activeWorkspace || !token) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.investigations.getDetail(
        investigationId,
        activeWorkspace.workspace_id,
        token
      );
      setInvestigation(data);
    } catch (err: any) {
      setError(err.message || "Failed to load investigation report.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchInvestigation();
  }, [investigationId, activeWorkspace?.workspace_id, token]);

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-3">
        <Link
          href="/investigations"
          className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Investigations
        </Link>
        <span className="text-slate-600">/</span>
        <span className="text-xs text-slate-400 font-mono truncate max-w-xs">
          {investigationId}
        </span>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
          <Button size="sm" variant="outline" onClick={fetchInvestigation}>
            Retry
          </Button>
        </div>
      )}

      {isLoading ? (
        <div className="p-12 text-center text-slate-500 flex flex-col items-center justify-center gap-3">
          <RefreshCw className="w-6 h-6 animate-spin text-cyan-500" />
          <p className="text-sm">Loading complete diagnostic report from PostgreSQL...</p>
        </div>
      ) : investigation ? (
        <div className="space-y-6">
          {/* Header Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-2.5">
                  <Badge variant={investigation.status === "completed" ? "success" : "warning"}>
                    {investigation.status.toUpperCase()}
                  </Badge>
                  <span className="text-xs font-mono text-slate-400">
                    ID: {investigation.id}
                  </span>
                </div>
                <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
                  <BrainCircuit className="w-5 h-5 text-cyan-400" />
                  {investigation.summary?.likely_root_cause || "Investigation Report"}
                </h1>
                <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400 pt-1">
                  <div>
                    <span>Target Incident: </span>
                    <Link
                      href={`/incidents/${investigation.incident_id}`}
                      className="text-cyan-400 hover:text-cyan-300 font-mono underline"
                    >
                      {investigation.incident_id}
                    </Link>
                  </div>
                  <div className="flex items-center gap-1.5 font-mono">
                    <Clock className="w-3.5 h-3.5 text-slate-500" />
                    <span>Completed:</span>
                    <span className="text-slate-300">
                      {investigation.completed_at
                        ? new Date(investigation.completed_at).toLocaleString()
                        : "In progress"}
                    </span>
                  </div>
                  <div className="font-mono text-slate-400">
                    Model: <span className="text-cyan-300">{investigation.model_name}</span> ({investigation.prompt_version})
                  </div>
                </div>
              </div>

              <Button variant="outline" size="sm" onClick={fetchInvestigation}>
                <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
                Refresh
              </Button>
            </div>
          </div>

          {/* Executive Summary & Heuristic Disclaimer */}
          {investigation.summary && (
            <div className="p-5 rounded-xl bg-slate-900/90 border border-cyan-800/40 space-y-4">
              <div className="space-y-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">
                  Executive Diagnostic Summary
                </span>
                <p className="text-sm text-slate-200 leading-relaxed">
                  {investigation.summary.incident_summary}
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 text-[11px] text-slate-400 flex items-start gap-2.5">
                <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-medium text-slate-300">Evidential Calibration Notice: </span>
                  <span>{investigation.summary.confidence_and_limitations}</span>
                </div>
              </div>
            </div>
          )}

          {/* Dynamic Remediation Playbook Recommendation (Phase 4.3) */}
          {(() => {
            const rec = investigation.summary?.remediation_recommendation || investigation.remediation_recommendation;
            if (!rec) return null;

            return (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                  <div className="flex items-center gap-2.5">
                    <BookOpen className="w-5 h-5 text-cyan-400" />
                    <div>
                      <h2 className="text-base font-semibold text-white">
                        Dynamic Remediation Playbook Recommendation
                      </h2>
                      <p className="text-xs text-slate-400">
                        Synthesized through deterministic evaluation of active playbooks and incident telemetry
                      </p>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {rec.status === "actionable" ? (
                      <Badge variant="success">ACTIONABLE RECOMMENDATION</Badge>
                    ) : rec.outcome === "missing_parameters" ? (
                      <Badge variant="warning">MISSING PARAMETERS</Badge>
                    ) : (
                      <Badge variant="warning">HUMAN ESCALATION REQUIRED</Badge>
                    )}
                    {rec.risk_level && (
                      <Badge variant={rec.risk_level.toLowerCase() === "low" ? "info" : rec.risk_level.toLowerCase() === "high" ? "error" : "warning"}>
                        Risk: {rec.risk_level.toUpperCase()}
                      </Badge>
                    )}
                    {rec.playbook_version && (
                      <span className="px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800 text-cyan-300 font-mono text-xs font-semibold">
                        v{rec.playbook_version}
                      </span>
                    )}
                  </div>
                </div>

                {rec.status === "actionable" ? (
                  <div className="space-y-4">
                    <div className="p-4 rounded-xl bg-slate-950/70 border border-emerald-500/20 space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-slate-400">Recommended Playbook:</span>
                          <span className="text-sm font-semibold text-emerald-300">
                            {rec.playbook_name}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 text-xs font-mono">
                          <span className="text-slate-400">Action Template:</span>
                          <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300">
                            {rec.action_template_id}
                          </span>
                        </div>
                      </div>

                      <p className="text-xs text-slate-200 leading-relaxed">
                        {rec.explanation}
                      </p>

                      <div className="flex flex-wrap items-center gap-4 text-xs pt-1 border-t border-slate-900">
                        {rec.supporting_evidence_ids && rec.supporting_evidence_ids.length > 0 && (
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-500">Supporting Evidence:</span>
                            {rec.supporting_evidence_ids.map((eid) => (
                              <span key={eid} className="px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 font-mono text-[10px]">
                                {eid}
                              </span>
                            ))}
                          </div>
                        )}
                        {rec.compatible_playbooks?.[0]?.matching_scenarios && (
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-500">Matched Scenarios:</span>
                            {rec.compatible_playbooks[0].matching_scenarios.map((sc) => (
                              <span key={sc} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
                                {sc}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>

                      {rec.parameters && Object.keys(rec.parameters).length > 0 && (
                        <div className="pt-2">
                          <span className="text-[11px] font-semibold text-slate-400 block mb-1">
                            Validated Parameters:
                          </span>
                          <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-[11px] overflow-x-auto">
                            {JSON.stringify(rec.parameters, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>

                    <div className="flex items-center justify-between pt-1">
                      <span className="text-xs text-slate-400">
                        Ready for policy evaluation and human approval workflow.
                      </span>
                      <Link href={`/incidents/${investigation.incident_id}`}>
                        <Button size="sm" className="bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-medium border-0 shadow-lg">
                          <Zap className="w-3.5 h-3.5 mr-1.5 text-emerald-200" />
                          View Incident & Propose Recovery
                        </Button>
                      </Link>
                    </div>
                  </div>
                ) : rec.outcome === "missing_parameters" ? (
                  <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-500/30 space-y-3">
                    <div className="flex items-center gap-2 text-rose-300 font-semibold text-xs">
                      <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                      <span>Missing Required Parameters for Playbook '{rec.playbook_name}'</span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {rec.explanation}
                    </p>
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className="text-slate-400">Required missing fields:</span>
                      {rec.missing_parameters.map((p) => (
                        <span key={p} className="px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300 font-mono text-[11px]">
                          {p}
                        </span>
                      ))}
                    </div>
                    <p className="text-[11px] text-slate-400 italic">
                      Notice: SentinelOps deterministic safety policies forbid fabricating parameter values. Please configure defaults on the playbook or provide them via approval.
                    </p>
                  </div>
                ) : (
                  <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 space-y-3">
                    <div className="flex items-center gap-2 text-amber-300 font-semibold text-xs">
                      <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
                      <span>Human SRE Intervention Required</span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {rec.explanation}
                    </p>
                    {rec.escalation_reason && (
                      <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-400 font-mono">
                        {rec.escalation_reason}
                      </div>
                    )}
                    <div className="flex items-center justify-between pt-1">
                      <span className="text-xs text-slate-400">
                        Create and associate a dynamic playbook to automate recovery for this service condition.
                      </span>
                      <Link href="/playbooks/new">
                        <Button size="sm" variant="outline">
                          <BookOpen className="w-3.5 h-3.5 mr-1.5" />
                          Create Playbook
                        </Button>
                      </Link>
                    </div>
                  </div>
                )}

                {/* Rejected Candidate Playbooks (if any) */}
                {rec.rejected_playbooks && rec.rejected_playbooks.length > 0 && (
                  <details className="text-xs text-slate-400 pt-2 border-t border-slate-800">
                    <summary className="cursor-pointer hover:text-slate-200 transition-colors font-medium">
                      View Incompatible Evaluated Playbooks ({rec.rejected_playbooks.length})
                    </summary>
                    <div className="space-y-2 mt-2.5">
                      {rec.rejected_playbooks.map((rej) => (
                        <div key={rej.playbook_id} className="p-2.5 rounded bg-slate-950/70 border border-slate-800/80 space-y-1">
                          <div className="flex items-center justify-between text-[11px]">
                            <span className="font-semibold text-slate-300">{rej.playbook_name} (v{rej.version_number})</span>
                            <span className="font-mono text-slate-500">{rej.action_template_id}</span>
                          </div>
                          <ul className="text-[11px] text-rose-400/90 list-disc list-inside">
                            {rej.rejection_reasons.map((r, i) => (
                              <li key={i}>{r}</li>
                            ))}
                          </ul>
                        </div>
                      ))}
                    </div>
                  </details>
                )}
              </div>
            );
          })()}

          {/* Hypotheses & Evidence Side-by-Side */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left: Ranked Hypotheses */}
            <div className="space-y-4">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <BrainCircuit className="w-4 h-4 text-cyan-400" />
                Ranked Root-Cause Hypotheses ({investigation.hypotheses.length})
              </h2>

              <div className="space-y-3">
                {investigation.hypotheses.map((hyp: Hypothesis, idx: number) => (
                  <div
                    key={hyp.hypothesis_id || idx}
                    className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5"
                  >
                    <div className="flex items-start justify-between gap-3">
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

                    <p className="text-xs text-slate-300 leading-relaxed">
                      {hyp.explanation}
                    </p>

                    <div className="flex flex-wrap items-center gap-2 text-[11px] pt-2 border-t border-slate-800/80">
                      <span className="text-slate-500">Supporting:</span>
                      {hyp.supporting_evidence_ids.map((eid) => (
                        <span
                          key={eid}
                          className="px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 font-mono text-[10px]"
                        >
                          {eid}
                        </span>
                      ))}

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
                      <div className="text-[10px] text-slate-400 font-mono italic">
                        Validation: {hyp.evaluation_notes}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Right: Collected Diagnostic Evidence */}
            <div className="space-y-4">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-emerald-400" />
                Collected Evidence Items ({investigation.evidence.length})
              </h2>

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

                    <div className="p-2.5 rounded bg-slate-950 border border-slate-800/90 text-xs text-slate-300 font-mono leading-relaxed overflow-x-auto">
                      {ev.observation}
                    </div>

                    {ev.data && Object.keys(ev.data).length > 0 && (
                      <details className="text-[11px] text-slate-500 pt-1">
                        <summary className="cursor-pointer hover:text-slate-300 transition-colors font-mono">
                          Raw Diagnostic Payload
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

          {/* SRE Next Diagnostic Steps & Unresolved Questions */}
          {investigation.summary && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card
                title="Recommended Next Diagnostic Steps"
                subtitle="Informational actions for human SRE engineers (Strict read-only)"
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

              <Card
                title="Unresolved Diagnostic Questions"
                subtitle="Telemetry boundaries and open incident questions"
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
      ) : (
        <div className="p-12 text-center text-slate-500">
          <AlertCircle className="w-8 h-8 mx-auto text-slate-600 mb-2" />
          <p className="text-sm font-medium text-slate-400">Investigation Not Found</p>
          <p className="text-xs text-slate-500 mt-1">
            The requested investigation report does not exist in this workspace.
          </p>
        </div>
      )}
    </div>
  );
}
