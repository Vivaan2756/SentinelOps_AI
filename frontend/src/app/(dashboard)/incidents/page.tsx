"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import { Incident, Service } from "@/lib/types";
import {
  Filter,
  RefreshCw,
  ExternalLink,
  CheckCircle2,
  AlertCircle,
  Layers,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

const STATUS_FILTERS = [
  { label: "All Statuses", value: "" },
  { label: "Detected", value: "detected" },
  { label: "Investigating", value: "investigating" },
  { label: "Awaiting Approval", value: "awaiting_approval" },
  { label: "Investigation Failed", value: "investigation_failed" },
  { label: "Remediating", value: "remediating" },
  { label: "Verifying", value: "verifying" },
  { label: "Recovered", value: "recovered" },
  { label: "Closed", value: "closed" },
];

const SEVERITY_FILTERS = [
  { label: "All Severities", value: "" },
  { label: "Critical", value: "critical" },
  { label: "High", value: "high" },
  { label: "Medium", value: "medium" },
  { label: "Low", value: "low" },
];

export default function IncidentsPage() {
  const { activeWorkspace, token } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [selectedStatus, setSelectedStatus] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState("");
  const [selectedService, setSelectedService] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    if (!activeWorkspace || !token) return;
    setIsLoading(true);
    setError(null);
    try {
      const [incidentsData, servicesData] = await Promise.all([
        api.incidents.list(activeWorkspace.workspace_id, token, {
          status: selectedStatus || undefined,
          severity: selectedSeverity || undefined,
          service_id: selectedService || undefined,
        }),
        api.services.list(activeWorkspace.workspace_id, token),
      ]);
      setIncidents(incidentsData);
      setServices(servicesData);
    } catch (err: any) {
      setError(err.message || "Failed to load workspace incidents.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [activeWorkspace?.workspace_id, token, selectedStatus, selectedSeverity, selectedService]);

  const getServiceName = (serviceId: string) => {
    const s = services.find((srv) => srv.id === serviceId);
    return s ? s.name : "Registered Service";
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

  const activeCount = incidents.filter(
    (i) => !["recovered", "closed"].includes(i.status.toLowerCase())
  ).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Incidents & Events</h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time incident detection records, root trigger evidence, and recovery lifecycle.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchData}
            disabled={isLoading}
          >
            <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Filter and Quick Stats Bar */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Quick summary stats */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 flex items-center justify-between">
          <span className="text-xs text-slate-400">Total Tracked</span>
          <span className="text-base font-bold text-white font-mono">{incidents.length}</span>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 flex items-center justify-between">
          <span className="text-xs text-slate-400">Active Incidents</span>
          <span
            className={`text-base font-bold font-mono ${
              activeCount > 0 ? "text-rose-400" : "text-emerald-400"
            }`}
          >
            {activeCount}
          </span>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 flex items-center justify-between">
          <span className="text-xs text-slate-400">Recovered</span>
          <span className="text-base font-bold text-emerald-400 font-mono">
            {incidents.filter((i) => i.status.toLowerCase() === "recovered").length}
          </span>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 flex items-center justify-between">
          <span className="text-xs text-slate-400">Critical / High</span>
          <span className="text-base font-bold text-amber-400 font-mono">
            {
              incidents.filter((i) =>
                ["critical", "high"].includes(i.severity.toLowerCase())
              ).length
            }
          </span>
        </div>
      </div>

      {/* Filter Controls */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center gap-4">
        {/* Status Dropdown */}
        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-xs text-slate-400">Status:</span>
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-md px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            {STATUS_FILTERS.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
          </select>
        </div>

        {/* Severity Dropdown */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Severity:</span>
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-md px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            {SEVERITY_FILTERS.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
          </select>
        </div>

        {/* Service Filter */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Service:</span>
          <select
            value={selectedService}
            onChange={(e) => setSelectedService(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-md px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 max-w-[200px] truncate"
          >
            <option value="">All Services</option>
            {services.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        </div>

        {(selectedStatus || selectedSeverity || selectedService) && (
          <button
            onClick={() => {
              setSelectedStatus("");
              setSelectedSeverity("");
              setSelectedService("");
            }}
            className="text-xs text-cyan-400 hover:text-cyan-300 ml-auto"
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* Error alert */}
      {error && (
        <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
          <Button size="sm" variant="outline" onClick={fetchData}>
            Retry
          </Button>
        </div>
      )}

      {/* Incidents Table / List */}
      <Card>
        {isLoading ? (
          <div className="p-12 text-center text-slate-500 flex flex-col items-center justify-center gap-3">
            <RefreshCw className="w-6 h-6 animate-spin text-cyan-500" />
            <p className="text-sm">Loading incident registry from PostgreSQL...</p>
          </div>
        ) : incidents.length === 0 ? (
          <div className="p-12 text-center text-slate-500">
            <CheckCircle2 className="w-8 h-8 mx-auto text-emerald-500/60 mb-2" />
            <p className="text-sm font-medium text-slate-400">No Incidents Found</p>
            <p className="text-xs text-slate-500 mt-1">
              {selectedStatus || selectedSeverity || selectedService
                ? "No incidents match the active filter criteria."
                : "All monitored services in this workspace are running smoothly."}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Title & Trigger</th>
                  <th className="py-3 px-4">Affected Service</th>
                  <th className="py-3 px-4">Detected At</th>
                  <th className="py-3 px-4">Recovered At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {incidents.map((incident) => (
                  <tr
                    key={incident.id}
                    className="hover:bg-slate-800/30 transition-colors"
                  >
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getSeverityBadge(incident.severity)}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getStatusBadge(incident.status)}
                    </td>
                    <td className="py-3.5 px-4 max-w-md">
                      <Link
                        href={`/incidents/${incident.id}`}
                        className="font-medium text-white hover:text-cyan-400 transition-colors block text-sm"
                      >
                        {incident.title}
                      </Link>
                      <div className="text-[11px] text-slate-400 font-mono truncate mt-0.5">
                        Trigger: {incident.trigger}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <Link
                        href={`/services/${incident.service_id}`}
                        className="text-slate-300 hover:text-cyan-400 font-medium flex items-center gap-1.5"
                      >
                        <Layers className="w-3.5 h-3.5 text-slate-500" />
                        <span>{getServiceName(incident.service_id)}</span>
                      </Link>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap text-slate-400 font-mono text-[11px]">
                      {new Date(incident.detected_at).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap font-mono text-[11px]">
                      {incident.recovered_at ? (
                        <span className="text-emerald-400">
                          {new Date(incident.recovered_at).toLocaleString()}
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap text-right">
                      <Link
                        href={`/incidents/${incident.id}`}
                        className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-medium"
                      >
                        <span>Details</span>
                        <ExternalLink className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
