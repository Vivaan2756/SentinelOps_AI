"use client";

import React, { useState, useEffect } from "react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import {
  User,
  Shield,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Lock,
  Building,
  Sparkles,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

interface HealthState {
  status: string;
  service: string;
  version: string;
  database: {
    connected: boolean;
    message: string;
  };
}

export default function SettingsPage() {
  const { user, activeWorkspace } = useAuth();
  const [health, setHealth] = useState<HealthState | null>(null);
  const [loadingHealth, setLoadingHealth] = useState(true);
  const [healthError, setHealthError] = useState<string | null>(null);

  const checkHealth = async () => {
    setLoadingHealth(true);
    setHealthError(null);
    try {
      const data = await api.system.getHealth();
      setHealth(data);
    } catch (err: any) {
      setHealthError(err.message || "Failed to reach backend health endpoint.");
    } finally {
      setLoadingHealth(false);
    }
  };

  useEffect(() => {
    checkHealth();
  }, []);

  const getRoleDescription = (role?: string) => {
    switch (role?.toLowerCase()) {
      case "admin":
        return {
          title: "Workspace Administrator",
          description:
            "Full administrative access. Can manage workspace settings, invite members, register services, and execute diagnostic checks.",
          permissions: [
            "View all services and incidents",
            "Register new monitored services",
            "Trigger deterministic diagnostic probes",
            "Workspace member management",
          ],
        };
      case "engineer":
        return {
          title: "Site Reliability Engineer",
          description:
            "Operational access. Can register services, trigger health evaluations, and monitor active incidents.",
          permissions: [
            "View all services and incidents",
            "Register new monitored services",
            "Trigger deterministic diagnostic probes",
          ],
        };
      default:
        return {
          title: "Viewer (Read Only)",
          description:
            "Read-only observer access. Can inspect service health, dashboards, and incident event timelines.",
          permissions: [
            "View services, telemetry, and metrics",
            "Inspect incidents and evidence snapshots",
          ],
        };
    }
  };

  const roleInfo = getRoleDescription(activeWorkspace?.role);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Workspace & Account Settings</h1>
        <p className="text-xs text-slate-400 mt-1">
          Active tenant configuration, role authorization boundaries, and system telemetry diagnostics.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Workspace, Account, and Role */}
        <div className="lg:col-span-2 space-y-6">
          {/* Workspace Details */}
          <Card title="Current Workspace Context">
            <div className="space-y-4 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block mb-1">Workspace Name</span>
                  <div className="flex items-center gap-2">
                    <Building className="w-4 h-4 text-cyan-400" />
                    <span className="text-white font-medium text-sm">
                      {activeWorkspace?.workspace_name || "Unknown"}
                    </span>
                  </div>
                </div>

                <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block mb-1">Workspace Slug</span>
                  <div className="font-mono text-slate-300">
                    {activeWorkspace?.workspace_slug || "—"}
                  </div>
                </div>
              </div>

              <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                <span className="text-slate-400 block mb-1">Tenant Workspace ID</span>
                <code className="text-cyan-400/90 font-mono text-[11px] select-all">
                  {activeWorkspace?.workspace_id || "—"}
                </code>
              </div>

              <p className="text-[11px] text-slate-400 leading-relaxed">
                Multi-tenancy isolation is enforced at the database query level on every API request.
                Cross-workspace queries are rejected with HTTP 403 Forbidden.
              </p>
            </div>
          </Card>

          {/* User Account & Role */}
          <Card title="Operator Account & Permissions">
            <div className="space-y-4 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block mb-1">Signed-in User</span>
                  <div className="flex items-center gap-2">
                    <User className="w-4 h-4 text-cyan-400" />
                    <span className="text-white font-medium">
                      {user?.full_name || user?.email || "Unknown"}
                    </span>
                  </div>
                  <span className="text-slate-400 font-mono text-[11px] block mt-1">
                    {user?.email}
                  </span>
                </div>

                <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block mb-1">Assigned Workspace Role</span>
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-emerald-400" />
                    <span className="text-white font-medium capitalize">
                      {activeWorkspace?.role || "Viewer"}
                    </span>
                  </div>
                  <span className="text-slate-400 text-[11px] block mt-1">
                    {roleInfo.title}
                  </span>
                </div>
              </div>

              {/* Permissions list */}
              <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800/80">
                <span className="text-slate-400 block mb-2 font-medium">
                  Authorized Operations:
                </span>
                <ul className="space-y-1.5 text-slate-300">
                  {roleInfo.permissions.map((perm, idx) => (
                    <li key={idx} className="flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>{perm}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </Card>
        </div>

        {/* Right 1 Col: Platform Diagnostics & Phase Boundaries */}
        <div className="space-y-6">
          {/* Backend Diagnostics */}
          <Card title="Platform Diagnostics">
            <div className="space-y-4 text-xs">
              {loadingHealth ? (
                <div className="p-4 text-center text-slate-500 flex items-center justify-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-cyan-500" />
                  <span>Probing backend...</span>
                </div>
              ) : healthError ? (
                <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded text-rose-400 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{healthError}</span>
                </div>
              ) : health ? (
                <div className="space-y-3">
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400">FastAPI Backend</span>
                    <Badge variant={health.status === "healthy" ? "success" : "warning"}>
                      {health.status}
                    </Badge>
                  </div>

                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400">PostgreSQL 18</span>
                    <Badge variant={health.database.connected ? "success" : "error"}>
                      {health.database.connected ? "Connected" : "Disconnected"}
                    </Badge>
                  </div>

                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400">Platform Version</span>
                    <span className="font-mono text-slate-300">v{health.version}</span>
                  </div>
                </div>
              ) : null}

              <Button
                variant="outline"
                size="sm"
                className="w-full"
                onClick={checkHealth}
                disabled={loadingHealth}
              >
                <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${loadingHealth ? "animate-spin" : ""}`} />
                Re-check System Health
              </Button>
            </div>
          </Card>

          {/* Phase Roadmap */}
          <Card title="Phase Roadmap">
            <div className="space-y-3 text-xs">
              <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800/80 space-y-1">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-slate-300 font-medium">
                    <Sparkles className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span>Phase 3: Agentic SRE</span>
                  </div>
                  <Badge variant="success">Active / Complete</Badge>
                </div>
                <p className="text-[11px] text-slate-500">
                  LangGraph multi-agent diagnostic loop, Gemini 2.5 reasoning, and hypothesis generation.
                </p>
              </div>

              <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800/80 space-y-1">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-slate-300 font-medium">
                    <Lock className="w-4 h-4 text-amber-400 shrink-0" />
                    <span>Phase 4: Remediation & Verification</span>
                  </div>
                  <Badge variant="success">Active / Verified</Badge>
                </div>
                <p className="text-[11px] text-slate-500">
                  Human-in-the-loop approval workflow, execution sandbox, and automated recovery verification.
                </p>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
