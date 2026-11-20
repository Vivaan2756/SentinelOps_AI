"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import { Service, Incident, ServiceCapabilitiesResponse, ServiceActionCapability } from "@/lib/types";
import {
  Server,
  ArrowLeft,
  Activity,
  CheckCircle2,
  AlertCircle,
  Clock,
  ShieldCheck,
  ShieldAlert,
  PlayCircle,
  RefreshCw,
  AlertTriangle,
  ExternalLink,
  Wrench,
  Layers,
  Sparkles,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

export default function ServiceDetailPage() {
  const params = useParams();
  const serviceId = params?.serviceId as string;
  const { activeWorkspace, token } = useAuth();

  const [service, setService] = useState<Service | null>(null);
  const [recentIncidents, setRecentIncidents] = useState<Incident[]>([]);
  const [capabilities, setCapabilities] = useState<ServiceCapabilitiesResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isCapabilitiesLoading, setIsCapabilitiesLoading] = useState(true);
  const [capabilitiesError, setCapabilitiesError] = useState<string | null>(null);
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [evalResult, setEvalResult] = useState<{
    success: boolean;
    message: string;
    action?: string;
  } | null>(null);

  const fetchCapabilities = async (targetServiceId: string, workspaceId: string, authToken: string) => {
    setIsCapabilitiesLoading(true);
    setCapabilitiesError(null);
    try {
      const caps = await api.services.getCapabilities(targetServiceId, workspaceId, authToken);
      if (targetServiceId === serviceId) {
        setCapabilities(caps);
      }
    } catch (err: any) {
      if (targetServiceId === serviceId) {
        setCapabilitiesError(err.message || "Failed to evaluate service capabilities.");
        setCapabilities(null);
      }
    } finally {
      if (targetServiceId === serviceId) {
        setIsCapabilitiesLoading(false);
      }
    }
  };

  const fetchServiceDetail = async () => {
    if (!serviceId || !activeWorkspace?.workspace_id || !token) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.services.getDetail(serviceId, activeWorkspace.workspace_id, token);
      setService(data.service);
      setRecentIncidents(data.recent_incidents || []);
    } catch (err: any) {
      setError(err.message || "Failed to load service details.");
    } finally {
      setIsLoading(false);
    }
    fetchCapabilities(serviceId, activeWorkspace.workspace_id, token);
  };

  useEffect(() => {
    if (!serviceId || !activeWorkspace?.workspace_id || !token) return;

    let isMounted = true;

    const loadData = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const data = await api.services.getDetail(serviceId, activeWorkspace.workspace_id, token);
        if (isMounted) {
          setService(data.service);
          setRecentIncidents(data.recent_incidents || []);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err.message || "Failed to load service details.");
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }

      if (isMounted) {
        setIsCapabilitiesLoading(true);
        setCapabilitiesError(null);
        try {
          const caps = await api.services.getCapabilities(serviceId, activeWorkspace.workspace_id, token);
          if (isMounted) {
            setCapabilities(caps);
          }
        } catch (err: any) {
          if (isMounted) {
            setCapabilitiesError(err.message || "Failed to evaluate service capabilities.");
            setCapabilities(null);
          }
        } finally {
          if (isMounted) {
            setIsCapabilitiesLoading(false);
          }
        }
      }
    };

    loadData();

    return () => {
      isMounted = false;
    };
  }, [serviceId, activeWorkspace?.workspace_id, token]);

  const handleRetryCapabilities = () => {
    if (!serviceId || !activeWorkspace?.workspace_id || !token) return;
    fetchCapabilities(serviceId, activeWorkspace.workspace_id, token);
  };

  const handleRunDiagnostic = async () => {
    if (!service || !token) return;
    setIsEvaluating(true);
    setEvalResult(null);
    try {
      const res = await api.detector.evaluate(service.id, token);
      setEvalResult({
        success: res.is_healthy,
        message: res.is_healthy
          ? "Service probe returned 200 OK. Target is operational."
          : `Alert rule triggered: ${res.trigger || "Service degraded"}`,
        action: res.lifecycle_action,
      });
      // Refresh service detail and recent incidents
      await fetchServiceDetail();
    } catch (err: any) {
      setEvalResult({
        success: false,
        message: err.message || "Failed to execute diagnostic check.",
      });
    } finally {
      setIsEvaluating(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status?.toLowerCase()) {
      case "healthy":
        return <Badge variant="success">Healthy</Badge>;
      case "degraded":
        return <Badge variant="warning">Degraded</Badge>;
      case "unhealthy":
        return <Badge variant="error">Unhealthy</Badge>;
      default:
        return <Badge variant="neutral">Unverified / Unknown</Badge>;
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case "critical":
        return <Badge variant="error">Critical</Badge>;
      case "high":
        return <Badge variant="error">High</Badge>;
      case "medium":
        return <Badge variant="warning">Medium</Badge>;
      default:
        return <Badge variant="info">Low</Badge>;
    }
  };

  const getIncidentStatusBadge = (st: string) => {
    switch (st?.toLowerCase()) {
      case "detected":
        return <Badge variant="error">Detected</Badge>;
      case "investigating":
        return <Badge variant="warning">Investigating</Badge>;
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

  return (
    <div className="space-y-6">
      {/* Back button & Breadcrumb */}
      <div className="flex items-center gap-3">
        <Link
          href="/services"
          className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Services
        </Link>
        <span className="text-slate-600">/</span>
        <span className="text-xs text-slate-400 font-mono truncate max-w-xs">
          {service?.name || serviceId}
        </span>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
          <Button size="sm" variant="outline" onClick={fetchServiceDetail}>
            Retry
          </Button>
        </div>
      )}

      {isLoading ? (
        <div className="p-12 text-center text-slate-500 flex flex-col items-center justify-center gap-3">
          <RefreshCw className="w-6 h-6 animate-spin text-cyan-500" />
          <p className="text-sm">Loading service telemetry and configuration...</p>
        </div>
      ) : service ? (
        <>
          {/* Header Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400 shrink-0">
                  <Server className="w-6 h-6" />
                </div>
                <div>
                  <div className="flex items-center gap-3">
                    <h1 className="text-xl font-bold text-white tracking-tight">{service.name}</h1>
                    {getStatusBadge(service.health_status)}
                    <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-slate-800 text-slate-300 border border-slate-700 uppercase">
                      {service.environment}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 font-mono">
                    Service ID: <span className="text-slate-300">{service.id}</span>
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={fetchServiceDetail}
                  disabled={isLoading || isEvaluating}
                >
                  <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${isLoading ? "animate-spin" : ""}`} />
                  Refresh
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleRunDiagnostic}
                  disabled={isEvaluating}
                >
                  <PlayCircle className={`w-4 h-4 mr-1.5 ${isEvaluating ? "animate-spin" : ""}`} />
                  {isEvaluating ? "Running Probe..." : "Run Diagnostic Check"}
                </Button>
              </div>
            </div>

            {/* Diagnostic Result Banner */}
            {evalResult && (
              <div
                className={`mt-5 p-3.5 rounded-lg border text-xs flex items-center justify-between ${
                  evalResult.success
                    ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-300"
                    : "bg-rose-500/10 border-rose-500/20 text-rose-300"
                }`}
              >
                <div className="flex items-center gap-2.5">
                  {evalResult.success ? (
                    <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
                  )}
                  <span>
                    <strong>Diagnostic Result:</strong> {evalResult.message}{" "}
                    {evalResult.action && (
                      <span className="opacity-80">
                        (Lifecycle action: <code className="font-mono">{evalResult.action}</code>)
                      </span>
                    )}
                  </span>
                </div>
                <button
                  onClick={() => setEvalResult(null)}
                  className="text-slate-400 hover:text-white text-xs px-2 py-1"
                >
                  Dismiss
                </button>
              </div>
            )}
          </div>

          {/* Grid Layout: Config Details & Health Status */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Left 2 Cols: Endpoint & Monitoring Target */}
            <div className="md:col-span-2 space-y-6">
              <Card title="Monitoring Target & Endpoint">
                <div className="space-y-4 text-xs">
                  <div>
                    <span className="text-slate-400 block mb-1 font-medium">Health Check Target URL</span>
                    <div className="flex items-center gap-2 p-2.5 bg-slate-950/60 rounded-md border border-slate-800 font-mono text-slate-200 break-all">
                      <span className="text-cyan-400 select-none">GET</span>
                      <span>{service.health_check_url}</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
                    <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800/80">
                      <span className="text-slate-400 block mb-1">Telemetry Method</span>
                      <div className="flex items-center gap-2 text-slate-200 font-medium">
                        <Activity className="w-4 h-4 text-cyan-400" />
                        <span className="capitalize">{service.monitoring_method}</span>
                      </div>
                      <p className="text-[11px] text-slate-500 mt-1">
                        Scrapes Prometheus-format latency & 5xx counter vectors.
                      </p>
                    </div>

                    <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800/80">
                      <span className="text-slate-400 block mb-1">Execution Safety Policy</span>
                      <div className="flex items-center gap-2 text-slate-200 font-medium">
                        <ShieldCheck className="w-4 h-4 text-emerald-400" />
                        <span className="capitalize">
                          {service.execution_policy.replace("_", " ")}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500 mt-1">
                        Governs automated vs human-in-the-loop remediation permissions.
                      </p>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-slate-400">
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5" />
                      <span>Registered at:</span>
                      <span className="text-slate-300 font-mono">
                        {new Date(service.created_at).toLocaleString()}
                      </span>
                    </div>
                    <div>
                      <span>Status:</span>{" "}
                      <span className={service.is_active ? "text-emerald-400" : "text-slate-500"}>
                        {service.is_active ? "Active" : "Disabled"}
                      </span>
                    </div>
                  </div>
                </div>
              </Card>

              {/* Remediation & Diagnostic Capabilities (Phase 4.4A) */}
              <Card
                title="Remediation & Diagnostic Capabilities"
                subtitle="Dynamically evaluated action capabilities for this service based on execution mechanism and environment constraints"
              >
                {isCapabilitiesLoading ? (
                  <div className="py-8 text-center text-xs text-slate-400 flex flex-col items-center justify-center gap-2">
                    <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />
                    <span>Evaluating service capabilities...</span>
                  </div>
                ) : capabilitiesError ? (
                  <div className="p-4 rounded border border-rose-800/60 bg-rose-950/20 text-xs space-y-3">
                    <div className="flex items-start gap-2.5 text-rose-300">
                      <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
                      <div>
                        <p className="font-medium text-rose-200">Failed to evaluate service capabilities</p>
                        <p className="text-[11px] text-rose-300/80 mt-0.5 font-mono">{capabilitiesError}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 pt-1">
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={handleRetryCapabilities}
                        className="text-xs h-7 gap-1.5"
                      >
                        <RefreshCw className="w-3 h-3" />
                        Retry Evaluation
                      </Button>
                    </div>
                  </div>
                ) : !capabilities || capabilities.capabilities.length === 0 ? (
                  <div className="py-6 text-center text-xs text-slate-500">
                    No capabilities registered or available for this service.
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-xs text-slate-400 pb-2 border-b border-slate-800">
                      <div className="flex items-center gap-3">
                        <span>
                          Compatible: <strong className="text-emerald-400">{capabilities.compatible_count}</strong>
                        </span>
                        <span>
                          Executable: <strong className="text-cyan-400">{capabilities.executable_count}</strong>
                        </span>
                        <span>
                          Total Evaluated: <strong className="text-slate-300">{capabilities.total_count}</strong>
                        </span>
                      </div>
                      <Link href={`/playbooks/new?service_id=${service?.id || serviceId}`}>
                        <Button size="sm" variant="secondary" className="text-xs h-7 gap-1">
                          <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                          Configure Playbook
                        </Button>
                      </Link>
                    </div>

                    <div className="divide-y divide-slate-800/60">
                      {capabilities.capabilities.map((cap) => (
                        <div key={cap.action_id} className="py-3 space-y-1.5">
                          <div className="flex items-start justify-between gap-2">
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="text-xs font-semibold text-slate-200">
                                  {cap.action_name}
                                </span>
                                <code className="text-[10px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                                  {cap.action_id}
                                </code>
                              </div>
                              <p className="text-[11px] text-slate-400 mt-0.5">{cap.description}</p>
                            </div>

                            <div className="flex items-center gap-1.5 shrink-0">
                              {cap.is_compatible && cap.is_executable ? (
                                <Badge variant="success">Executable</Badge>
                              ) : cap.status === "requires_adapter" ? (
                                <Badge variant="warning">Requires Adapter</Badge>
                              ) : (
                                <Badge variant="neutral">Incompatible</Badge>
                              )}
                              <Badge variant={cap.risk_level === "high" ? "error" : cap.risk_level === "medium" ? "warning" : "info"}>
                                {cap.risk_level.toUpperCase()}
                              </Badge>
                            </div>
                          </div>

                          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-500 font-mono">
                            <span>Mechanism: <code className="text-slate-400">{cap.execution_mechanism}</code></span>
                            <span>Target: <code className="text-slate-400">{cap.target_resource_type}</code></span>
                            <span>Approval: <span className={cap.approval_required ? "text-amber-400" : "text-emerald-400"}>{cap.approval_required ? "Required" : "Pre-approved"}</span></span>
                          </div>

                          {/* Reasons / Prerequisites */}
                          {cap.reasons.length > 0 && (
                            <div className="text-[11px] text-slate-400 bg-slate-950/40 p-2 rounded border border-slate-800/60">
                              <span className="text-slate-500 font-medium block mb-0.5">Evaluation Assessment:</span>
                              <ul className="list-disc list-inside space-y-0.5 text-slate-300">
                                {cap.reasons.map((r, i) => (
                                  <li key={i}>{r}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </Card>

              {/* Related Incidents */}
              <Card
                title="Service Incidents History"
                subtitle="Recent incident occurrences and lifecycle transitions tracked for this service"
              >
                {recentIncidents.length === 0 ? (
                  <div className="p-8 text-center text-slate-500">
                    <CheckCircle2 className="w-8 h-8 mx-auto text-emerald-500/50 mb-2" />
                    <p className="text-sm font-medium text-slate-400">No Incidents Recorded</p>
                    <p className="text-xs text-slate-500 mt-1">
                      This service has maintained operational health with no active or past incidents.
                    </p>
                  </div>
                ) : (
                  <div className="divide-y divide-slate-800/80">
                    {recentIncidents.map((incident) => (
                      <div
                        key={incident.id}
                        className="py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-800/30 px-3 -mx-3 rounded transition-colors"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            {getSeverityBadge(incident.severity)}
                            {getIncidentStatusBadge(incident.status)}
                            <Link
                              href={`/incidents/${incident.id}`}
                              className="text-sm font-medium text-white hover:text-cyan-400 transition-colors flex items-center gap-1"
                            >
                              {incident.title}
                              <ExternalLink className="w-3 h-3 text-slate-500" />
                            </Link>
                          </div>
                          <p className="text-xs text-slate-400 font-mono">
                            Trigger: <span className="text-slate-300">{incident.trigger}</span>
                          </p>
                        </div>

                        <div className="text-right text-xs text-slate-400 shrink-0 font-mono">
                          <div>Detected: {new Date(incident.detected_at).toLocaleTimeString()}</div>
                          {incident.recovered_at && (
                            <div className="text-emerald-400/80">
                              Recovered: {new Date(incident.recovered_at).toLocaleTimeString()}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>

            {/* Right 1 Col: Health & Verification Safeguards */}
            <div className="space-y-6">
              <Card title="Health Verification Status">
                <div className="space-y-4 text-xs">
                  <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1 text-[11px] uppercase tracking-wider font-semibold">
                      Current Health State
                    </span>
                    <div className="flex items-center gap-2 mt-1">
                      {getStatusBadge(service.health_status)}
                    </div>
                    <div className="text-slate-400 text-[11px] mt-2 flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      <span>Last evaluated:</span>
                      <span className="text-slate-300 font-mono">
                        {service.last_checked_at
                          ? new Date(service.last_checked_at).toLocaleTimeString()
                          : "Never probed"}
                      </span>
                    </div>
                  </div>

                  <div className="p-3.5 bg-slate-950/40 rounded-lg border border-slate-800/80 space-y-2">
                    <div className="flex items-center gap-2 text-slate-300 font-medium">
                      <ShieldAlert className="w-4 h-4 text-cyan-400 shrink-0" />
                      <span>SSRF & Network Safeguards</span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Target URLs are strictly validated against loopback restrictions, metadata IP
                      ranges (169.254.169.254), and multi-tenant isolation boundaries before probes
                      are dispatched.
                    </p>
                  </div>

                  <div className="p-3.5 bg-slate-950/40 rounded-lg border border-slate-800/80 space-y-2">
                    <div className="flex items-center gap-2 text-slate-300 font-medium">
                      <Activity className="w-4 h-4 text-amber-400 shrink-0" />
                      <span>Deterministic Rules</span>
                    </div>
                    <ul className="text-[11px] text-slate-400 space-y-1 list-disc list-inside">
                      <li>Probe timeout threshold: 5.0 seconds</li>
                      <li>HTTP 5xx error counter anomaly rule</li>
                      <li>Latency histogram degradation detector</li>
                    </ul>
                  </div>
                </div>
              </Card>
            </div>
          </div>
        </>
      ) : (
        <div className="p-12 text-center text-slate-500">
          <AlertCircle className="w-8 h-8 mx-auto text-slate-600 mb-2" />
          <p className="text-sm font-medium text-slate-400">Service Not Found</p>
          <p className="text-xs text-slate-500 mt-1">
            The requested service does not exist in this workspace.
          </p>
        </div>
      )}
    </div>
  );
}
