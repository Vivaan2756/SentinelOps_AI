"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import { Service } from "@/lib/types";
import {
  Server,
  Plus,
  Search,
  ExternalLink,
  RefreshCw,
  PlayCircle,
  AlertCircle,
  CheckCircle2,
  Clock,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";

export default function ServicesPage() {
  const { activeWorkspace, token } = useAuth();
  const [services, setServices] = useState<Service[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [envFilter, setEnvFilter] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [evaluatingId, setEvaluatingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Registration Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalLoading, setModalLoading] = useState(false);
  const [formName, setFormName] = useState("");
  const [formEnv, setFormEnv] = useState("development");
  const [formUrl, setFormUrl] = useState("http://127.0.0.1:8001/health");
  const [formMethod, setFormMethod] = useState("prometheus");
  const [formPolicy, setFormPolicy] = useState("demo");
  const [formRecoveryPath, setFormRecoveryPath] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const fetchServices = async () => {
    if (!activeWorkspace || !token) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.services.list(activeWorkspace.workspace_id, token, {
        q: searchQuery,
        environment: envFilter || undefined,
      });
      setServices(data);
    } catch (err: any) {
      setError(err.message || "Failed to load registered services.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchServices();
  }, [activeWorkspace?.workspace_id, token, envFilter]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchServices();
  };

  const handleEvaluateService = async (serviceId: string) => {
    if (!token) return;
    setEvaluatingId(serviceId);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await api.detector.evaluate(serviceId, token);
      setSuccessMsg(
        `Evaluation complete: ${res.is_healthy ? "Service Healthy" : "Failure Detected"} (${res.lifecycle_action})`
      );
      await fetchServices();
    } catch (err: any) {
      setError(err.message || "Failed to execute diagnostic check.");
    } finally {
      setEvaluatingId(null);
    }
  };

  const handleCreateService = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeWorkspace || !token) return;
    setFormError(null);
    setModalLoading(true);

    try {
      await api.services.create(
        {
          workspace_id: activeWorkspace.workspace_id,
          name: formName,
          environment: formEnv,
          health_check_url: formUrl,
          monitoring_method: formMethod,
          execution_policy: formPolicy,
          recovery_endpoint: formRecoveryPath ? formRecoveryPath.trim() : undefined,
          recovery_method: "POST",
          recovery_enabled: Boolean(formRecoveryPath && formRecoveryPath.trim()),
        },
        token
      );
      setIsModalOpen(false);
      setFormName("");
      setFormUrl("http://127.0.0.1:8001/health");
      setFormRecoveryPath("");
      setSuccessMsg(`Service '${formName}' registered successfully.`);
      await fetchServices();
    } catch (err: any) {
      setFormError(err.message || "Failed to register service.");
    } finally {
      setModalLoading(false);
    }
  };

  const canRegister = activeWorkspace?.role === "admin" || activeWorkspace?.role === "engineer";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            Services & Monitoring
            <span className="text-xs font-normal text-slate-400">({services.length} registered)</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Registered endpoints, health status, and monitoring configurations in{" "}
            <span className="text-slate-200 font-semibold">{activeWorkspace?.workspace_name}</span>
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <Button variant="secondary" size="sm" onClick={fetchServices} isLoading={isLoading}>
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
          <Button
            size="sm"
            onClick={() => setIsModalOpen(true)}
            disabled={!canRegister}
            title={!canRegister ? "Requires Engineer or Admin role" : undefined}
          >
            <Plus className="w-3.5 h-3.5" />
            Register Service
          </Button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-3.5 rounded-xl bg-rose-950/40 border border-rose-800/80 flex items-center gap-2.5 text-rose-300 text-xs">
          <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}
      {successMsg && (
        <div className="p-3.5 rounded-xl bg-emerald-950/40 border border-emerald-800/80 flex items-center gap-2.5 text-emerald-300 text-xs">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-slate-900/60 border border-slate-800 p-3 rounded-xl">
        <form onSubmit={handleSearch} className="flex gap-2 w-full sm:w-80">
          <div className="relative w-full">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search services by name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>
          <Button type="submit" size="sm" variant="secondary">
            Search
          </Button>
        </form>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <span className="text-xs text-slate-400">Environment:</span>
          <select
            value={envFilter}
            onChange={(e) => setEnvFilter(e.target.value)}
            className="px-3 py-1.5 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Environments</option>
            <option value="development">Development</option>
            <option value="staging">Staging</option>
            <option value="production">Production</option>
          </select>
        </div>
      </div>

      {/* Services Grid / List */}
      {isLoading ? (
        <div className="py-20 text-center text-xs text-slate-500">Loading services...</div>
      ) : services.length === 0 ? (
        <Card className="text-center py-16">
          <Server className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-200">No Services Found</h3>
          <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
            {searchQuery || envFilter
              ? "No services match the active search or environment filters."
              : "Register your first service or microservice endpoint to enable health monitoring."}
          </p>
          {canRegister && !searchQuery && !envFilter && (
            <Button size="sm" className="mt-4" onClick={() => setIsModalOpen(true)}>
              <Plus className="w-3.5 h-3.5 mr-1" /> Register Demo Order API
            </Button>
          )}
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {services.map((svc) => (
            <Card key={svc.id} className="flex flex-col justify-between hover:border-slate-700 transition-colors">
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                      <Link
                        href={`/services/${svc.id}`}
                        className="hover:text-emerald-400 transition-colors"
                      >
                        {svc.name}
                      </Link>
                    </h3>
                    <div className="flex items-center gap-1.5 mt-1">
                      <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
                        {svc.environment}
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono">
                        {svc.monitoring_method}
                      </span>
                    </div>
                  </div>
                  <Badge variant={svc.health_status as any}>{svc.health_status}</Badge>
                </div>

                <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 space-y-1 font-mono text-[11px]">
                  <div className="text-slate-400 truncate" title={svc.health_check_url}>
                    <span className="text-slate-400">Endpoint: </span>
                    <span className="text-slate-300">{svc.health_check_url}</span>
                  </div>
                  <div className="text-slate-400">
                    <span className="text-slate-400">Policy: </span>
                    <span className="text-slate-300">{svc.execution_policy}</span>
                  </div>
                  {svc.last_checked_at && (
                    <div className="text-slate-400 text-[10px] flex items-center gap-1">
                      <Clock className="w-2.5 h-2.5" />
                      Checked {new Date(svc.last_checked_at).toLocaleTimeString()}
                    </div>
                  )}
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleEvaluateService(svc.id)}
                  isLoading={evaluatingId === svc.id}
                  title="Run deterministic diagnostic check on health endpoint"
                >
                  <PlayCircle className="w-3.5 h-3.5" />
                  Run Check
                </Button>
                <Link
                  href={`/services/${svc.id}`}
                  className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1 font-medium"
                >
                  Details <ExternalLink className="w-3 h-3" />
                </Link>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Registration Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Register Monitored Service"
        description="Add service endpoint for telemetry collection and deterministic incident detection."
      >
        {formError && (
          <div className="mb-4 p-3 rounded-lg bg-rose-950/50 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{formError}</span>
          </div>
        )}

        <form onSubmit={handleCreateService} className="space-y-4">
          <Input
            label="Service Name"
            placeholder="e.g. Order API"
            value={formName}
            onChange={(e) => setFormName(e.target.value)}
            required
            helper="2–100 characters identifying the service component"
          />

          <div>
            <label className="text-xs font-medium text-slate-300 mb-1.5 block">
              Environment
            </label>
            <select
              value={formEnv}
              onChange={(e) => setFormEnv(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
            >
              <option value="development">Development</option>
              <option value="staging">Staging</option>
              <option value="production">Production</option>
            </select>
          </div>

          <Input
            label="Health-Check URL"
            placeholder="http://127.0.0.1:8001/health"
            value={formUrl}
            onChange={(e) => setFormUrl(e.target.value)}
            required
            helper="Validated format only; does not initiate outbound probe during registration (SSRF protected)"
          />

          <Input
            label="Recovery Endpoint Path (Optional)"
            placeholder="e.g. /demo/restore or /admin/recovery/reset"
            value={formRecoveryPath}
            onChange={(e) => setFormRecoveryPath(e.target.value)}
            helper="Relative endpoint path for automated/approved HTTP recovery actions (POST)"
          />

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-slate-300 mb-1.5 block">
                Monitoring Method
              </label>
              <select
                value={formMethod}
                onChange={(e) => setFormMethod(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
              >
                <option value="prometheus">Prometheus</option>
                <option value="opentelemetry">OpenTelemetry</option>
                <option value="builtin">Built-in Demo</option>
              </select>
            </div>

            <div>
              <label className="text-xs font-medium text-slate-300 mb-1.5 block">
                Execution Policy
              </label>
              <select
                value={formPolicy}
                onChange={(e) => setFormPolicy(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
              >
                <option value="demo">Demo / Isolated</option>
                <option value="approval_required">Approval Required</option>
                <option value="observe_only">Observe Only</option>
              </select>
            </div>
          </div>

          <div className="pt-4 flex justify-end gap-2.5">
            <Button
              type="button"
              variant="secondary"
              size="md"
              onClick={() => setIsModalOpen(false)}
            >
              Cancel
            </Button>
            <Button type="submit" size="md" isLoading={modalLoading}>
              Confirm Registration
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
