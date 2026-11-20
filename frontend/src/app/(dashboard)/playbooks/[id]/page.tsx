"use client";

import React, { useState, useEffect, useCallback, use } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { api, canManagePlaybooks } from "@/lib/api";
import {
  PlaybookDetailResponse,
  Service,
} from "@/lib/types";
import {
  BookOpen,
  ArrowLeft,
  Edit,
  Power,
  Server,
  Plus,
  Trash2,
  Shield,
  ShieldAlert,
  CheckCircle2,
  AlertCircle,
  Clock,
  Activity,
  Lock,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge, BadgeVariant } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default function PlaybookDetailPage({ params }: PageProps) {
  const resolvedParams = use(params);
  const playbookId = resolvedParams.id;

  const { activeWorkspace, token } = useAuth();
  const router = useRouter();
  const isAuthorized = canManagePlaybooks(activeWorkspace?.role);

  const [playbook, setPlaybook] = useState<PlaybookDetailResponse | null>(null);
  const [allServices, setAllServices] = useState<Service[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Expanded version cards in history
  const [expandedVersions, setExpandedVersions] = useState<Record<number, boolean>>({});

  // Activation Toggle Modal
  const [confirmToggleModal, setConfirmToggleModal] = useState(false);
  const [toggleLoading, setToggleLoading] = useState(false);

  // Associate Service Modal
  const [serviceModalOpen, setServiceModalOpen] = useState(false);
  const [selectedServiceId, setSelectedServiceId] = useState("");
  const [servicePriority, setServicePriority] = useState(100);
  const [assocLoading, setAssocLoading] = useState(false);

  // Disassociate Service Modal
  const [disassocModalOpen, setDisassocModalOpen] = useState(false);
  const [serviceToDisassoc, setServiceToDisassoc] = useState<{ id: string; name: string } | null>(null);
  const [disassocLoading, setDisassocLoading] = useState(false);

  const fetchDetail = useCallback(async () => {
    if (!activeWorkspace || !token || !playbookId) return;
    setIsLoading(true);
    setError(null);
    try {
      const [detailData, servicesData] = await Promise.all([
        api.playbooks.getDetail(playbookId, activeWorkspace.workspace_id, token),
        api.services.list(activeWorkspace.workspace_id, token),
      ]);
      setPlaybook(detailData);
      setAllServices(servicesData || []);
    } catch (err: any) {
      setError(err.message || "Failed to load playbook details.");
    } finally {
      setIsLoading(false);
    }
  }, [activeWorkspace, token, playbookId]);

  useEffect(() => {
    fetchDetail();
  }, [fetchDetail]);

  const toggleVersionExpanded = (verNum: number) => {
    setExpandedVersions((prev) => ({
      ...prev,
      [verNum]: !prev[verNum],
    }));
  };

  const handleToggleActivation = async () => {
    if (!playbook || !activeWorkspace || !token) return;
    setToggleLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      if (playbook.is_active) {
        await api.playbooks.deactivate(playbook.id, activeWorkspace.workspace_id, token);
        setSuccessMsg("Playbook deactivated. Policy proposals will fail closed.");
      } else {
        await api.playbooks.activate(playbook.id, activeWorkspace.workspace_id, token);
        setSuccessMsg("Playbook activated and ready for policy evaluation.");
      }
      setConfirmToggleModal(false);
      await fetchDetail();
    } catch (err: any) {
      setError(err.message || "Failed to update activation status.");
    } finally {
      setToggleLoading(false);
    }
  };

  const handleAssociateService = async () => {
    if (!playbook || !activeWorkspace || !token || !selectedServiceId) return;
    setAssocLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      await api.playbooks.associateService(
        playbook.id,
        {
          workspace_id: activeWorkspace.workspace_id,
          service_id: selectedServiceId,
          priority: Number(servicePriority),
        },
        token
      );
      setSuccessMsg("Service successfully associated with this playbook.");
      setServiceModalOpen(false);
      setSelectedServiceId("");
      await fetchDetail();
    } catch (err: any) {
      setError(err.message || "Failed to associate service.");
    } finally {
      setAssocLoading(false);
    }
  };

  const handleDisassociateService = async () => {
    if (!playbook || !activeWorkspace || !token || !serviceToDisassoc) return;
    setDisassocLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      await api.playbooks.disassociateService(
        playbook.id,
        serviceToDisassoc.id,
        activeWorkspace.workspace_id,
        token
      );
      setSuccessMsg(`Service "${serviceToDisassoc.name}" unlinked from this playbook.`);
      setDisassocModalOpen(false);
      setServiceToDisassoc(null);
      await fetchDetail();
    } catch (err: any) {
      setError(err.message || "Failed to disassociate service.");
    } finally {
      setDisassocLoading(false);
    }
  };

  const getRiskBadgeVariant = (risk?: string): BadgeVariant => {
    switch (risk?.toLowerCase()) {
      case "critical":
        return "critical";
      case "high":
        return "high";
      case "medium":
        return "medium";
      case "low":
        return "low";
      default:
        return "neutral";
    }
  };

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center text-slate-500">
        <div className="flex flex-col items-center gap-2">
          <div className="w-5 h-5 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs font-mono">Loading Playbook Specification...</span>
        </div>
      </div>
    );
  }

  if (error || !playbook) {
    return (
      <div className="space-y-4">
        <Link
          href="/playbooks"
          className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Playbooks
        </Link>
        <Card className="p-8 text-center space-y-3">
          <div className="w-10 h-10 rounded-xl bg-rose-950/60 border border-rose-800/80 flex items-center justify-center text-rose-400 mx-auto">
            <AlertCircle className="w-5 h-5" />
          </div>
          <h2 className="text-sm font-semibold text-slate-100">Playbook Unavailable</h2>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            {error || "The requested remediation playbook does not exist or you do not have permission to access it."}
          </p>
          <Link href="/playbooks">
            <Button variant="secondary" size="sm" className="text-xs">
              Return to Catalog
            </Button>
          </Link>
        </Card>
      </div>
    );
  }

  const activeVer = playbook.active_version;
  const boundServiceIds = playbook.associated_services?.map((s) => s.service_id) || [];
  const unassociatedServices = allServices.filter((s) => !boundServiceIds.includes(s.id));

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12">
      {/* Top Breadcrumb & Actions Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="space-y-1">
          <Link
            href="/playbooks"
            className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to Playbooks
          </Link>
          <div className="flex flex-wrap items-center gap-2.5 pt-1">
            <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
              <BookOpen className="w-5 h-5 text-emerald-400" />
              {playbook.name}
            </h1>
            <Badge variant={playbook.is_active ? "healthy" : "closed"}>
              {playbook.is_active ? "Active" : "Inactive"}
            </Badge>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
              v{playbook.current_version}
            </span>
            <Badge variant={getRiskBadgeVariant(activeVer?.risk_level)}>
              Risk: {activeVer?.risk_level.toUpperCase()}
            </Badge>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          {isAuthorized ? (
            <>
              <Link href={`/playbooks/${playbook.id}/edit`}>
                <Button variant="outline" size="sm" className="text-xs gap-1.5">
                  <Edit className="w-3.5 h-3.5" />
                  Edit Playbook
                </Button>
              </Link>

              <Button
                variant={playbook.is_active ? "ghost" : "primary"}
                size="sm"
                onClick={() => setConfirmToggleModal(true)}
                className={`text-xs gap-1.5 ${
                  playbook.is_active
                    ? "text-amber-400 hover:text-amber-300 hover:bg-amber-950/40"
                    : ""
                }`}
              >
                <Power className="w-3.5 h-3.5" />
                {playbook.is_active ? "Deactivate" : "Activate"}
              </Button>
            </>
          ) : (
            <span className="text-[10px] font-mono bg-slate-900 border border-slate-700 text-slate-400 px-2 py-1 rounded">
              Viewer (Read-Only)
            </span>
          )}
        </div>
      </div>

      {/* Notifications */}
      {successMsg && (
        <div className="p-3 bg-emerald-950/50 border border-emerald-800/80 rounded-lg flex items-center justify-between text-xs text-emerald-300">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-emerald-200 ml-4 font-mono">
            ×
          </button>
        </div>
      )}

      {/* Immutability & Audit Guarantee Notice */}
      <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl text-xs text-slate-400 flex items-start gap-3">
        <Lock className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-slate-200">Specification Immutability Guarantee:</span>
          <p className="mt-0.5 text-slate-400">
            Active version <strong>v{playbook.current_version}</strong> parameters and criteria are permanently locked to guarantee audit integrity. Any edits to operational parameters create an immutable new version record without modifying historical executions.
          </p>
        </div>
      </div>

      {/* Main Grid: Left Spec Details, Right Services & Version History */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ================================================================== */}
        {/* LEFT COLUMN: Active Version Operational Spec */}
        {/* ================================================================== */}
        <div className="lg:col-span-2 space-y-5">
          {/* Action Template Card */}
          <Card title="Recovery Action Template" className="p-5">
            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <div className="text-slate-100 font-semibold text-sm">
                    {activeVer?.action_name || activeVer?.action_template_id}
                  </div>
                  <code className="text-emerald-400 font-mono text-[11px]">
                    {activeVer?.action_template_id}
                  </code>
                </div>
                <Badge variant={activeVer?.approval_required ? "awaiting_approval" : "healthy"}>
                  {activeVer?.approval_required ? "Human Approval Required" : "Autonomous Allowed"}
                </Badge>
              </div>

              {playbook.description && (
                <p className="text-slate-400 text-xs border-t border-slate-800/80 pt-2">
                  {playbook.description}
                </p>
              )}

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-2 border-t border-slate-800/80 text-[11px]">
                <div>
                  <span className="text-slate-500">Category: </span>
                  <span className="text-slate-300 font-mono uppercase">{playbook.category}</span>
                </div>
                <div>
                  <span className="text-slate-500">Execution Timeout: </span>
                  <span className="text-slate-300 font-mono">{activeVer?.timeout_seconds}s</span>
                </div>
                <div>
                  <span className="text-slate-500">Version Number: </span>
                  <span className="text-slate-300 font-mono">v{activeVer?.version_number}</span>
                </div>
              </div>
            </div>
          </Card>

          {/* Configured Parameters */}
          <Card title="Active Version Parameters" className="p-5">
            {activeVer?.parameter_schema && Object.keys(activeVer.parameter_schema).length > 0 ? (
              <div className="space-y-2">
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800/90 font-mono text-xs overflow-x-auto">
                  <pre className="text-emerald-300 text-[11px]">
                    {JSON.stringify(activeVer.parameter_schema, null, 2)}
                  </pre>
                </div>
                <p className="text-[11px] text-slate-500">
                  Parameters strictly conform to the allowlisted ActionDefinition Pydantic model.
                </p>
              </div>
            ) : (
              <p className="text-xs text-slate-500">No static parameters configured for this action template.</p>
            )}
          </Card>

          {/* Supported Incident Scenarios */}
          <Card title="Supported Incident Triggers" className="p-5">
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2">
                {activeVer?.supported_scenarios && activeVer.supported_scenarios.length > 0 ? (
                  activeVer.supported_scenarios.map((scen) => (
                    <span
                      key={scen}
                      className="text-xs font-mono px-3 py-1 rounded-full bg-slate-950 border border-slate-800 text-emerald-400"
                    >
                      {scen}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-slate-500">All scenarios supported (*)</span>
                )}
              </div>
              <p className="text-[11px] text-slate-500">
                The Policy Engine only proposes this playbook when an incident trigger matches one of these scenarios.
              </p>
            </div>
          </Card>

          {/* Verification Criteria */}
          <Card title="Synthetic Verification Criteria" className="p-5">
            <div className="space-y-3 text-xs">
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800/90 font-mono overflow-x-auto">
                <pre className="text-cyan-300 text-[11px]">
                  {JSON.stringify(activeVer?.verification_criteria || {}, null, 2)}
                </pre>
              </div>
              <div className="flex items-center gap-2 text-[11px] text-slate-400">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                <span>
                  Post-remediation verification runner probes the service health endpoint to confirm genuine recovery.
                </span>
              </div>
            </div>
          </Card>
        </div>

        {/* ================================================================== */}
        {/* RIGHT COLUMN: Service Bindings & Version History */}
        {/* ================================================================== */}
        <div className="space-y-5">
          {/* Associated Services Card */}
          <Card
            title={
              <div className="flex items-center justify-between w-full">
                <span>Associated Services</span>
                {isAuthorized && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setServiceModalOpen(true)}
                    className="text-xs text-emerald-400 hover:text-emerald-300 p-1 h-auto"
                    title="Bind another service to this playbook"
                  >
                    <Plus className="w-3.5 h-3.5 mr-1" />
                    Bind Service
                  </Button>
                )}
              </div>
            }
            className="p-5"
          >
            <div className="space-y-3 text-xs">
              {playbook.associated_services?.length === 0 ? (
                <p className="text-slate-500 py-2">
                  No services bound to this playbook. Incidents on unassociated services cannot trigger this playbook.
                </p>
              ) : (
                <div className="space-y-2">
                  {playbook.associated_services.map((assoc) => (
                    <div
                      key={assoc.service_id}
                      className="p-2.5 bg-slate-950/70 border border-slate-800 rounded-lg flex items-center justify-between gap-2"
                    >
                      <div className="space-y-0.5 min-w-0">
                        <div className="font-semibold text-slate-200 truncate">
                          {assoc.service_name}
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono">
                          Priority: {assoc.priority} &bull;{" "}
                          {new Date(assoc.associated_at).toLocaleDateString()}
                        </div>
                      </div>

                      {isAuthorized && (
                        <button
                          type="button"
                          onClick={() => {
                            setServiceToDisassoc({ id: assoc.service_id, name: assoc.service_name });
                            setDisassocModalOpen(true);
                          }}
                          className="text-slate-500 hover:text-rose-400 p-1 transition-colors"
                          title="Remove service association"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Card>

          {/* Version History Timeline */}
          <Card title="Version History" className="p-5">
            <div className="space-y-3 text-xs">
              <p className="text-[11px] text-slate-500">
                Audit trail of all specification revisions:
              </p>

              <div className="space-y-2.5 pt-1">
                {playbook.versions.map((ver) => {
                  const isCurrent = ver.version_number === playbook.current_version;
                  const isExpanded = Boolean(expandedVersions[ver.version_number]);

                  return (
                    <div
                      key={ver.id}
                      className={`p-3 rounded-lg border transition-all ${
                        isCurrent
                          ? "bg-slate-900 border-emerald-500/70 shadow-sm"
                          : "bg-slate-950/60 border-slate-800 text-slate-400"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-slate-200">
                            v{ver.version_number}
                          </span>
                          {isCurrent && (
                            <span className="text-[10px] bg-emerald-950/80 text-emerald-400 border border-emerald-800 px-1.5 py-0.2 rounded font-mono">
                              Active
                            </span>
                          )}
                        </div>

                        <button
                          type="button"
                          onClick={() => toggleVersionExpanded(ver.version_number)}
                          className="text-slate-500 hover:text-slate-300 p-1 flex items-center gap-1 text-[11px]"
                        >
                          {isExpanded ? (
                            <ChevronUp className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronDown className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>

                      <div className="text-[11px] text-slate-400 mt-1">
                        {ver.change_summary || "Playbook revision"}
                      </div>

                      <div className="text-[10px] text-slate-500 font-mono mt-1 flex items-center gap-2">
                        <Clock className="w-3 h-3" />
                        <span>{new Date(ver.created_at).toLocaleString()}</span>
                      </div>

                      {/* Expandable Parameters snapshot */}
                      {isExpanded && (
                        <div className="mt-2.5 pt-2 border-t border-slate-800/80 space-y-1.5 font-mono text-[10px]">
                          <div className="text-slate-400">Action: {ver.action_template_id}</div>
                          <div className="text-slate-400">Timeout: {ver.timeout_seconds}s</div>
                          <div className="text-slate-400">Risk: {ver.risk_level}</div>
                          <div className="text-slate-400">
                            Parameters:
                            <pre className="p-1.5 bg-slate-950 rounded border border-slate-800 mt-1 overflow-x-auto text-emerald-300">
                              {JSON.stringify(ver.parameter_schema, null, 2)}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </Card>
        </div>
      </div>

      {/* Activation / Deactivation Confirmation Modal */}
      <Modal
        isOpen={confirmToggleModal}
        onClose={() => {
          if (!toggleLoading) setConfirmToggleModal(false);
        }}
        title={playbook.is_active ? "Deactivate Playbook" : "Activate Playbook"}
        description={
          playbook.is_active
            ? "Disabling this playbook prevents PolicyEngine from proposing or executing its recovery action."
            : "Enabling this playbook authorizes PolicyEngine to evaluate and execute its action."
        }
      >
        <div className="space-y-4 text-xs">
          <p className="text-slate-300">
            Are you sure you want to {playbook.is_active ? "deactivate" : "activate"} &ldquo;
            <strong>{playbook.name}</strong>&rdquo;?
          </p>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setConfirmToggleModal(false)}
              disabled={toggleLoading}
            >
              Cancel
            </Button>
            <Button
              variant={playbook.is_active ? "danger" : "primary"}
              size="sm"
              onClick={handleToggleActivation}
              isLoading={toggleLoading}
            >
              {playbook.is_active ? "Confirm Deactivate" : "Confirm Activate"}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Bind Service Modal */}
      <Modal
        isOpen={serviceModalOpen}
        onClose={() => {
          if (!assocLoading) setServiceModalOpen(false);
        }}
        title="Bind Service to Playbook"
        description="Select a registered service in this workspace to receive remediation proposals from this playbook."
      >
        <div className="space-y-4 text-xs">
          {unassociatedServices.length === 0 ? (
            <p className="text-slate-400 py-2">
              All registered services in this workspace are already bound to this playbook.
            </p>
          ) : (
            <div className="space-y-3">
              <div className="flex flex-col gap-1.5">
                <label className="font-semibold text-slate-300">Select Service *</label>
                <select
                  value={selectedServiceId}
                  onChange={(e) => setSelectedServiceId(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 focus:outline-none focus:border-emerald-500"
                >
                  <option value="">-- Choose a service --</option>
                  {unassociatedServices.map((svc) => (
                    <option key={svc.id} value={svc.id}>
                      {svc.name} ({svc.environment})
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="font-semibold text-slate-300">Priority Ordering</label>
                <input
                  type="number"
                  value={servicePriority}
                  onChange={(e) => setServicePriority(Number(e.target.value))}
                  placeholder="100"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 focus:outline-none focus:border-emerald-500"
                />
                <span className="text-[11px] text-slate-500">
                  Higher priority playbooks take precedence when multiple playbooks match an incident scenario.
                </span>
              </div>
            </div>
          )}

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setServiceModalOpen(false)}
              disabled={assocLoading}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleAssociateService}
              disabled={!selectedServiceId || assocLoading}
              isLoading={assocLoading}
            >
              Bind Service
            </Button>
          </div>
        </div>
      </Modal>

      {/* Disassociate Service Confirmation Modal */}
      <Modal
        isOpen={disassocModalOpen}
        onClose={() => {
          if (!disassocLoading) setDisassocModalOpen(false);
        }}
        title="Remove Service Association"
        description="Unlink this service from the remediation playbook."
      >
        <div className="space-y-4 text-xs">
          <p className="text-slate-300">
            Are you sure you want to remove &ldquo;<strong>{serviceToDisassoc?.name}</strong>&rdquo; from
            this playbook? Incidents occurring on this service will no longer be eligible for this remediation action.
          </p>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setDisassocModalOpen(false)}
              disabled={disassocLoading}
            >
              Cancel
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={handleDisassociateService}
              isLoading={disassocLoading}
            >
              Confirm Removal
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
