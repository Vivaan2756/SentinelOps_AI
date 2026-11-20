"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { api, canManagePlaybooks } from "@/lib/api";
import { PlaybookResponse, Service } from "@/lib/types";
import {
  BookOpen,
  Plus,
  Search,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  Power,
  ChevronRight,
  ShieldAlert,
  Server,
  Clock,
  Edit,
  Shield,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge, BadgeVariant } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";

export default function PlaybooksPage() {
  const { activeWorkspace, token } = useAuth();
  const [playbooks, setPlaybooks] = useState<PlaybookResponse[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [serviceFilter, setServiceFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccessMsg, setActionSuccessMsg] = useState<string | null>(null);

  // Activation / Deactivation Confirmation Modal State
  const [confirmModalOpen, setConfirmModalOpen] = useState(false);
  const [selectedPlaybook, setSelectedPlaybook] = useState<PlaybookResponse | null>(null);
  const [modalLoading, setModalLoading] = useState(false);

  const isAuthorizedManager = canManagePlaybooks(activeWorkspace?.role);

  const fetchServices = useCallback(async () => {
    if (!activeWorkspace || !token) return;
    try {
      const data = await api.services.list(activeWorkspace.workspace_id, token);
      setServices(data || []);
    } catch {
      // Non-fatal, service filter will just show empty list
    }
  }, [activeWorkspace, token]);

  const fetchPlaybooks = useCallback(async () => {
    if (!activeWorkspace || !token) return;
    setIsLoading(true);
    setError(null);
    try {
      const activeParam =
        statusFilter === "active"
          ? true
          : statusFilter === "inactive"
          ? false
          : undefined;

      const data = await api.playbooks.list(activeWorkspace.workspace_id, token, {
        q: searchQuery.trim() || undefined,
        service_id: serviceFilter || undefined,
        is_active: activeParam,
        category: categoryFilter || undefined,
      });
      setPlaybooks(data || []);
    } catch (err: any) {
      setError(err.message || "Failed to load remediation playbooks.");
    } finally {
      setIsLoading(false);
    }
  }, [activeWorkspace, token, searchQuery, serviceFilter, statusFilter, categoryFilter]);

  useEffect(() => {
    fetchServices();
  }, [fetchServices]);

  useEffect(() => {
    fetchPlaybooks();
  }, [fetchPlaybooks]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchPlaybooks();
  };

  const openActivationModal = (pb: PlaybookResponse) => {
    setSelectedPlaybook(pb);
    setConfirmModalOpen(true);
  };

  const handleToggleActivation = async () => {
    if (!selectedPlaybook || !activeWorkspace || !token) return;
    setModalLoading(true);
    setError(null);
    setActionSuccessMsg(null);
    try {
      if (selectedPlaybook.is_active) {
        await api.playbooks.deactivate(selectedPlaybook.id, activeWorkspace.workspace_id, token);
        setActionSuccessMsg(`Playbook "${selectedPlaybook.name}" has been deactivated. Proposals for this playbook will fail closed.`);
      } else {
        await api.playbooks.activate(selectedPlaybook.id, activeWorkspace.workspace_id, token);
        setActionSuccessMsg(`Playbook "${selectedPlaybook.name}" is now active and ready for policy evaluation.`);
      }
      setConfirmModalOpen(false);
      setSelectedPlaybook(null);
      await fetchPlaybooks();
    } catch (err: any) {
      setError(err.message || "Failed to update playbook activation status.");
    } finally {
      setModalLoading(false);
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
              <BookOpen className="w-5 h-5 text-emerald-400" />
              Remediation Playbooks
            </h1>
            {!isAuthorizedManager && (
              <span className="text-[10px] bg-slate-900 border border-slate-700 text-slate-400 px-2 py-0.5 rounded font-mono">
                Viewer (Read-Only)
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Dynamic, user-configurable, versioned remediation procedures with allowlisted execution safeguards.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchPlaybooks}
            disabled={isLoading}
            className="text-xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>

          {isAuthorizedManager ? (
            <Link href="/playbooks/new">
              <Button size="sm" className="text-xs gap-1.5">
                <Plus className="w-3.5 h-3.5" />
                Create Playbook
              </Button>
            </Link>
          ) : (
            <Button
              size="sm"
              disabled
              title="Viewer role has read-only access. Engineer or Admin role required to create playbooks."
              className="text-xs opacity-50 cursor-not-allowed"
            >
              <Plus className="w-3.5 h-3.5" />
              Create Playbook
            </Button>
          )}
        </div>
      </div>

      {/* Success Notification */}
      {actionSuccessMsg && (
        <div className="p-3 bg-emerald-950/50 border border-emerald-800/80 rounded-lg flex items-center justify-between text-xs text-emerald-300">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{actionSuccessMsg}</span>
          </div>
          <button
            onClick={() => setActionSuccessMsg(null)}
            className="text-emerald-400 hover:text-emerald-200 ml-4 font-mono"
          >
            ×
          </button>
        </div>
      )}

      {/* Error Alert */}
      {error && (
        <div className="p-3.5 bg-rose-950/50 border border-rose-800/80 rounded-lg flex items-start gap-2.5 text-xs text-rose-300">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div className="flex-1">
            <div className="font-semibold">Operation Notice</div>
            <div>{error}</div>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={fetchPlaybooks}
            className="text-rose-300 hover:text-rose-100 text-xs py-0.5 px-2 h-auto"
          >
            Retry
          </Button>
        </div>
      )}

      {/* Search & Filters */}
      <Card className="p-4">
        <form onSubmit={handleSearchSubmit} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Search by Name */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-500" />
            <input
              type="text"
              placeholder="Search playbook name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8.5 pr-3 py-1.5 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          {/* Service Filter */}
          <select
            value={serviceFilter}
            onChange={(e) => setServiceFilter(e.target.value)}
            className="w-full px-3 py-1.5 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Associated Services</option>
            {services.map((svc) => (
              <option key={svc.id} value={svc.id}>
                {svc.name} ({svc.environment})
              </option>
            ))}
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full px-3 py-1.5 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Statuses</option>
            <option value="active">Active Only</option>
            <option value="inactive">Inactive Only</option>
          </select>

          {/* Category Filter */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="w-full px-3 py-1.5 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Categories</option>
            <option value="service_recovery">Service Recovery</option>
            <option value="diagnostics">Diagnostics</option>
            <option value="monitoring">Monitoring</option>
          </select>
        </form>
      </Card>

      {/* Playbooks List */}
      {isLoading ? (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="h-28 bg-slate-900/40 border border-slate-800 rounded-xl animate-pulse"
            />
          ))}
        </div>
      ) : playbooks.length === 0 ? (
        <Card className="text-center py-12 px-4">
          <div className="w-12 h-12 rounded-xl bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-slate-400 mx-auto mb-3">
            <BookOpen className="w-6 h-6" />
          </div>
          <h3 className="text-sm font-semibold text-slate-200">No playbooks found</h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1 mb-4">
            {searchQuery || serviceFilter || statusFilter || categoryFilter
              ? "No remediation playbooks match your current filter criteria."
              : "No remediation playbooks have been configured for this workspace yet."}
          </p>
          {isAuthorizedManager && (
            <Link href="/playbooks/new">
              <Button size="sm" className="text-xs gap-1.5">
                <Plus className="w-3.5 h-3.5" />
                Configure First Playbook
              </Button>
            </Link>
          )}
        </Card>
      ) : (
        <div className="space-y-3">
          {playbooks.map((pb) => {
            const activeVer = pb.active_version;
            const riskLevel = activeVer?.risk_level || "medium";

            return (
              <div
                key={pb.id}
                className="bg-slate-900/60 hover:bg-slate-900/90 border border-slate-800 hover:border-slate-700/90 rounded-xl p-4 transition-all"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  {/* Info Column */}
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link
                        href={`/playbooks/${pb.id}`}
                        className="text-sm font-semibold text-slate-100 hover:text-emerald-400 transition-colors truncate"
                      >
                        {pb.name}
                      </Link>

                      {/* Active/Inactive Status */}
                      <Badge variant={pb.is_active ? "healthy" : "closed"}>
                        {pb.is_active ? "Active" : "Inactive"}
                      </Badge>

                      {/* Version Pill */}
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                        v{pb.current_version}
                      </span>

                      {/* Risk Badge */}
                      <Badge variant={getRiskBadgeVariant(riskLevel)}>
                        Risk: {riskLevel.toUpperCase()}
                      </Badge>

                      {/* Category */}
                      <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                        {pb.category.replace(/_/g, " ")}
                      </span>
                    </div>

                    {pb.description && (
                      <p className="text-xs text-slate-400 line-clamp-1">{pb.description}</p>
                    )}

                    {/* Metadata Sub-row */}
                    <div className="flex flex-wrap items-center gap-y-1 gap-x-4 text-[11px] text-slate-500 pt-1">
                      <div className="flex items-center gap-1.5">
                        <Shield className="w-3.5 h-3.5 text-slate-400" />
                        <span>Action: </span>
                        <code className="text-slate-300 font-mono">
                          {activeVer?.action_template_id || "None"}
                        </code>
                      </div>

                      <div className="flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-slate-400" />
                        <span>
                          {pb.associated_services_count}{" "}
                          {pb.associated_services_count === 1 ? "Service" : "Services"} bound
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5 text-slate-400" />
                        <span>
                          Updated: {new Date(pb.updated_at).toLocaleString([], {
                            month: "short",
                            day: "numeric",
                            hour: "2-digit",
                            minute: "2-digit",
                          })}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Actions Column */}
                  <div className="flex items-center gap-2 shrink-0">
                    {/* View Details */}
                    <Link href={`/playbooks/${pb.id}`}>
                      <Button variant="secondary" size="sm" className="text-xs">
                        Details
                        <ChevronRight className="w-3 h-3 ml-1 text-slate-400" />
                      </Button>
                    </Link>

                    {/* Edit Playbook (Manager only) */}
                    {isAuthorizedManager && (
                      <Link href={`/playbooks/${pb.id}/edit`}>
                        <Button
                          variant="outline"
                          size="sm"
                          className="text-xs"
                          title="Edit playbook specification"
                        >
                          <Edit className="w-3 h-3" />
                        </Button>
                      </Link>
                    )}

                    {/* Activation Toggle (Manager only) */}
                    {isAuthorizedManager && (
                      <Button
                        variant={pb.is_active ? "ghost" : "outline"}
                        size="sm"
                        onClick={() => openActivationModal(pb)}
                        className={`text-xs ${
                          pb.is_active
                            ? "text-amber-400 hover:text-amber-300 hover:bg-amber-950/40"
                            : "text-emerald-400 hover:text-emerald-300 hover:bg-emerald-950/40"
                        }`}
                        title={pb.is_active ? "Deactivate playbook" : "Activate playbook"}
                      >
                        <Power className="w-3 h-3 mr-1" />
                        {pb.is_active ? "Deactivate" : "Activate"}
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Activation / Deactivation Confirmation Modal */}
      <Modal
        isOpen={confirmModalOpen}
        onClose={() => {
          if (!modalLoading) {
            setConfirmModalOpen(false);
            setSelectedPlaybook(null);
          }
        }}
        title={
          selectedPlaybook?.is_active
            ? "Deactivate Remediation Playbook"
            : "Activate Remediation Playbook"
        }
        description={
          selectedPlaybook?.is_active
            ? "Disabling this playbook alters policy evaluation immediately."
            : "Enabling this playbook authorizes the Policy Engine to propose and execute its action."
        }
      >
        <div className="space-y-4 text-xs">
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5 font-mono">
            <div className="text-slate-300 font-semibold">{selectedPlaybook?.name}</div>
            <div className="text-slate-500 text-[11px]">
              ID: {selectedPlaybook?.id}
            </div>
            <div className="text-slate-500 text-[11px]">
              Action: {selectedPlaybook?.active_version?.action_template_id}
            </div>
          </div>

          {selectedPlaybook?.is_active ? (
            <div className="p-3 bg-amber-950/40 border border-amber-800/80 rounded-lg text-amber-300 space-y-1">
              <div className="font-semibold flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                Fail-Closed Policy Invariant
              </div>
              <p>
                When deactivated, the Policy Engine will reject any remediation proposals targeting
                this playbook. Associated services without another active playbook will fail closed.
              </p>
            </div>
          ) : (
            <div className="p-3 bg-emerald-950/40 border border-emerald-800/80 rounded-lg text-emerald-300 space-y-1">
              <div className="font-semibold flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                Remediation Policy Integration
              </div>
              <p>
                Activating this playbook allows SentinelOps to evaluate incidents against this playbook&apos;s
                configured scenarios and trigger authorized remediation workflows.
              </p>
            </div>
          )}

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setConfirmModalOpen(false);
                setSelectedPlaybook(null);
              }}
              disabled={modalLoading}
            >
              Cancel
            </Button>
            <Button
              variant={selectedPlaybook?.is_active ? "danger" : "primary"}
              size="sm"
              onClick={handleToggleActivation}
              isLoading={modalLoading}
            >
              {selectedPlaybook?.is_active ? "Confirm Deactivation" : "Confirm Activation"}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
