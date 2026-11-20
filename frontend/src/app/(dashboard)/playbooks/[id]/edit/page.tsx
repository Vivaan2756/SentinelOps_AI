"use client";

import React, { useState, useEffect, useCallback, use } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { api, canManagePlaybooks } from "@/lib/api";
import {
  PlaybookDetailResponse,
  ActionDefinition,
  PlaybookUpdate,
  PlaybookValidationResponse,
} from "@/lib/types";
import {
  BookOpen,
  ArrowLeft,
  Save,
  ShieldCheck,
  ShieldAlert,
  AlertCircle,
  CheckCircle2,
  Lock,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default function EditPlaybookPage({ params }: PageProps) {
  const resolvedParams = use(params);
  const playbookId = resolvedParams.id;

  const { activeWorkspace, token } = useAuth();
  const router = useRouter();
  const isAuthorized = canManagePlaybooks(activeWorkspace?.role);

  const [isLoading, setIsLoading] = useState(true);
  const [playbook, setPlaybook] = useState<PlaybookDetailResponse | null>(null);
  const [actions, setActions] = useState<ActionDefinition[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Form State
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("service_recovery");
  const [isActive, setIsActive] = useState(true);

  // Version Operational Fields
  const [actionTemplateId, setActionTemplateId] = useState("");
  const [parameters, setParameters] = useState<Record<string, any>>({});
  const [selectedScenarios, setSelectedScenarios] = useState<string[]>(["*"]);
  const [riskLevel, setRiskLevel] = useState("medium");
  const [approvalRequired, setApprovalRequired] = useState(true);
  const [timeoutSeconds, setTimeoutSeconds] = useState(30);

  // Verification Criteria
  const [healthPath, setHealthPath] = useState("/health");
  const [expectedStatus, setExpectedStatus] = useState(200);
  const [probesRequired, setProbesRequired] = useState(3);
  const [verificationTimeout, setVerificationTimeout] = useState(15);
  const [expectedState, setExpectedState] = useState("healthy");

  // Audit change summary
  const [changeSummary, setChangeSummary] = useState("");

  // Validation State
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<PlaybookValidationResponse | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const loadData = useCallback(async () => {
    if (!activeWorkspace || !token || !playbookId) return;
    setIsLoading(true);
    setError(null);
    try {
      const [detailData, catalogData] = await Promise.all([
        api.playbooks.getDetail(playbookId, activeWorkspace.workspace_id, token),
        api.remediation.listActions(activeWorkspace.workspace_id, token),
      ]);

      setPlaybook(detailData);
      setActions(catalogData.actions || []);

      // Populate form
      setName(detailData.name);
      setDescription(detailData.description || "");
      setCategory(detailData.category);
      setIsActive(detailData.is_active);

      const activeVer = detailData.active_version;
      if (activeVer) {
        setActionTemplateId(activeVer.action_template_id);
        setParameters(activeVer.parameter_schema || {});
        setSelectedScenarios(activeVer.supported_scenarios || ["*"]);
        setRiskLevel(activeVer.risk_level || "medium");
        setApprovalRequired(activeVer.approval_required);
        setTimeoutSeconds(activeVer.timeout_seconds || 30);

        const vc = activeVer.verification_criteria || {};
        setHealthPath(vc.health_path || "/health");
        setExpectedStatus(vc.expected_status || 200);
        setProbesRequired(vc.probes_required || 3);
        setVerificationTimeout(vc.timeout_seconds || 15);
        setExpectedState(vc.expected_state || "healthy");
      }
    } catch (err: any) {
      setError(err.message || "Failed to load playbook for editing.");
    } finally {
      setIsLoading(false);
    }
  }, [activeWorkspace, token, playbookId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Selected action template definition
  const currentActionDef = actions.find((a) => a.action_id === actionTemplateId);

  const handleValidate = async () => {
    if (!activeWorkspace || !token || !actionTemplateId) return;
    setIsValidating(true);
    setError(null);

    const cleanParams: Record<string, any> = {};
    Object.entries(parameters).forEach(([k, v]) => {
      if (v !== "" && v !== null && v !== undefined) {
        cleanParams[k] = v;
      }
    });

    if (actionTemplateId === "execute_http_recovery") {
      if (typeof cleanParams.expected_status_codes === "string") {
        cleanParams.expected_status_codes = cleanParams.expected_status_codes
          .split(",")
          .map((s: string) => Number(s.trim()))
          .filter((n: number) => !isNaN(n) && n > 0);
      } else if (!cleanParams.expected_status_codes) {
        cleanParams.expected_status_codes = [200];
      }
      if (typeof cleanParams.payload === "string" && cleanParams.payload.trim()) {
        try {
          cleanParams.payload = JSON.parse(cleanParams.payload.trim());
        } catch {
          // let backend validation report
        }
      } else if (cleanParams.payload === "") {
        delete cleanParams.payload;
      }
      if (cleanParams.timeout_seconds !== undefined) {
        cleanParams.timeout_seconds = Number(cleanParams.timeout_seconds);
      }
    }

    const verificationCriteria = {
      health_path: healthPath,
      expected_status: Number(expectedStatus),
      expected_state: expectedState,
      probes_required: Number(probesRequired),
      timeout_seconds: Number(verificationTimeout),
    };

    try {
      const boundServiceIds = playbook?.associated_services?.map((s) => s.service_id) || [];
      const res = await api.playbooks.validate(
        {
          workspace_id: activeWorkspace.workspace_id,
          action_template_id: actionTemplateId,
          service_ids: boundServiceIds,
          parameter_schema: cleanParams,
          verification_criteria: verificationCriteria,
          risk_level: riskLevel,
        },
        token
      );
      setValidationResult(res);
      if (!res.is_valid && res.errors?.length > 0) {
        setError(res.errors.join("; "));
      }
    } catch (err: any) {
      setError(err.message || "Validation failed.");
      setValidationResult(null);
    } finally {
      setIsValidating(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeWorkspace || !token || !playbookId) return;
    setIsSubmitting(true);
    setError(null);

    const cleanParams: Record<string, any> = {};
    Object.entries(parameters).forEach(([k, v]) => {
      if (v !== "" && v !== null && v !== undefined) {
        cleanParams[k] = v;
      }
    });

    if (actionTemplateId === "execute_http_recovery") {
      if (typeof cleanParams.expected_status_codes === "string") {
        cleanParams.expected_status_codes = cleanParams.expected_status_codes
          .split(",")
          .map((s: string) => Number(s.trim()))
          .filter((n: number) => !isNaN(n) && n > 0);
      } else if (!cleanParams.expected_status_codes) {
        cleanParams.expected_status_codes = [200];
      }
      if (typeof cleanParams.payload === "string" && cleanParams.payload.trim()) {
        try {
          cleanParams.payload = JSON.parse(cleanParams.payload.trim());
        } catch {
          // let backend validation report
        }
      } else if (cleanParams.payload === "") {
        delete cleanParams.payload;
      }
      if (cleanParams.timeout_seconds !== undefined) {
        cleanParams.timeout_seconds = Number(cleanParams.timeout_seconds);
      }
    }

    const verificationCriteria = {
      health_path: healthPath,
      expected_status: Number(expectedStatus),
      expected_state: expectedState,
      probes_required: Number(probesRequired),
      timeout_seconds: Number(verificationTimeout),
    };

    const payload: PlaybookUpdate = {
      workspace_id: activeWorkspace.workspace_id,
      name: name.trim(),
      description: description.trim() || undefined,
      category,
      is_active: isActive,
      action_template_id: actionTemplateId,
      supported_scenarios: selectedScenarios,
      parameter_schema: cleanParams,
      verification_criteria: verificationCriteria,
      risk_level: riskLevel,
      approval_required: approvalRequired,
      timeout_seconds: Number(timeoutSeconds),
      change_summary:
        changeSummary.trim() ||
        `Updated playbook specification (Version ${playbook ? playbook.current_version + 1 : 2})`,
    };

    try {
      await api.playbooks.update(playbookId, payload, token);
      router.push(`/playbooks/${playbookId}`);
    } catch (err: any) {
      setError(err.message || "Failed to save playbook changes.");
      setIsSubmitting(false);
    }
  };

  if (!isAuthorized) {
    return (
      <div className="max-w-2xl mx-auto py-12 text-center space-y-4">
        <div className="w-12 h-12 rounded-xl bg-amber-950/60 border border-amber-800/80 flex items-center justify-center text-amber-400 mx-auto">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <h2 className="text-base font-bold text-slate-100">Permission Restricted</h2>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          Your active membership role is <strong>Viewer</strong>. Modifying playbooks requires an{" "}
          <strong>Engineer</strong> or <strong>Admin</strong> role.
        </p>
        <Link href={`/playbooks/${playbookId}`}>
          <Button variant="secondary" size="sm" className="text-xs">
            Return to Playbook Details
          </Button>
        </Link>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center text-slate-500">
        <div className="flex flex-col items-center gap-2">
          <div className="w-5 h-5 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs font-mono">Loading Playbook Configuration...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-12">
      {/* Top Breadcrumb */}
      <div className="space-y-1 border-b border-slate-800/80 pb-4">
        <Link
          href={`/playbooks/${playbookId}`}
          className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Playbook Details
        </Link>
        <div className="flex items-center gap-2.5 pt-1">
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-emerald-400" />
            Edit Playbook: {playbook?.name}
          </h1>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
            Current: v{playbook?.current_version}
          </span>
        </div>
      </div>

      {/* Versioning & Immutability Notice */}
      <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl text-xs text-slate-400 flex items-start gap-3">
        <Lock className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-slate-200">
            Automatic Version Bumping:
          </span>
          <p className="mt-0.5 text-slate-400">
            Modifying operational fields (action template, parameters, verification criteria, risk, or
            timeout) will automatically create <strong>Version {playbook ? playbook.current_version + 1 : 2}</strong>.
            Existing historical executions will continue to reference their original version.
          </p>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-3.5 bg-rose-950/50 border border-rose-800/80 rounded-lg flex items-start gap-2.5 text-xs text-rose-300">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div className="flex-1">{error}</div>
        </div>
      )}

      {/* Edit Form */}
      <form onSubmit={handleSave} className="space-y-6">
        {/* Section 1: Metadata */}
        <Card title="Playbook Metadata" className="p-5 space-y-4">
          <Input
            label="Playbook Name *"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Playbook Name"
          />

          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-slate-300">Description</label>
            <textarea
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-slate-300">Category *</label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
              >
                <option value="service_recovery">Service Recovery</option>
                <option value="diagnostics">Diagnostics</option>
                <option value="monitoring">Monitoring</option>
              </select>
            </div>

            <div className="flex flex-col gap-1.5 justify-center">
              <label className="text-xs font-medium text-slate-300">Activation State</label>
              <div className="flex items-center gap-2 pt-2">
                <input
                  type="checkbox"
                  checked={isActive}
                  onChange={(e) => setIsActive(e.target.checked)}
                  className="rounded border-slate-700 text-emerald-500 focus:ring-0 bg-slate-900 w-4 h-4"
                />
                <span className="text-xs text-slate-300">Playbook is Active</span>
              </div>
            </div>
          </div>
        </Card>

        {/* Section 2: Action Template */}
        <Card title="Recovery Action Template" className="p-5 space-y-4">
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-slate-300">Select Action Template *</label>
            <select
              value={actionTemplateId}
              onChange={(e) => setActionTemplateId(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
            >
              {actions.map((act) => (
                <option key={act.action_id} value={act.action_id}>
                  {act.name} ({act.action_id}) — {act.risk_level.toUpperCase()}
                </option>
              ))}
            </select>
          </div>

          {currentActionDef && (
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800/80 text-xs text-slate-400 space-y-1">
              <div className="text-slate-200 font-semibold">{currentActionDef.name}</div>
              <p>{currentActionDef.description}</p>
              <div className="text-[11px] text-slate-500 font-mono">
                Scope:{" "}
                {currentActionDef.supported_services?.includes("*")
                  ? "Universal (*)"
                  : currentActionDef.supported_services?.join(", ")}
              </div>
            </div>
          )}
        </Card>

        {/* Section 3: Parameters */}
        <Card title="Action Parameters" className="p-5 space-y-4">
          {actionTemplateId === "execute_http_recovery" ? (
            <div className="space-y-4">
              {/* Origin Notice */}
              <div className="p-3 bg-emerald-950/40 border border-emerald-800/70 rounded-lg text-xs text-emerald-300 space-y-1.5">
                <div className="flex items-center gap-2 font-semibold text-emerald-200">
                  <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>HTTP Recovery Adapter Security Contract</span>
                </div>
                <p className="text-emerald-400/90 text-[11px]">
                  Origin is derived strictly from associated service&apos;s registered health check URL. Relative recovery path only; external hosts, query strings, and path traversal are rejected.
                </p>
                <div className="pt-1 text-[11px] font-mono text-slate-300">
                  Configured Path: <span className="text-emerald-300">{parameters.recovery_path || "/admin/recovery/reset"}</span>
                </div>
              </div>

              {/* Service ID */}
              <div className="space-y-1 p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-slate-200 font-mono">service_id *</label>
                  <span className="text-[10px] text-slate-500 uppercase">UUID</span>
                </div>
                <input
                  type="text"
                  value={parameters.service_id || ""}
                  onChange={(e) => setParameters((p) => ({ ...p, service_id: e.target.value }))}
                  className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              {/* Recovery Path */}
              <div className="space-y-1 p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-slate-200 font-mono">recovery_path *</label>
                  <span className="text-[10px] text-slate-500 uppercase">Relative Path</span>
                </div>
                <input
                  type="text"
                  value={parameters.recovery_path || ""}
                  placeholder="/admin/recovery/reset"
                  onChange={(e) => setParameters((p) => ({ ...p, recovery_path: e.target.value }))}
                  className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              {/* Payload */}
              <div className="space-y-1 p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-slate-200 font-mono">payload (Optional JSON)</label>
                  <span className="text-[10px] text-slate-500 uppercase">JSON</span>
                </div>
                <textarea
                  rows={3}
                  value={
                    typeof parameters.payload === "object" && parameters.payload !== null
                      ? JSON.stringify(parameters.payload, null, 2)
                      : parameters.payload || ""
                  }
                  placeholder={`{\n  "action": "reset"\n}`}
                  onChange={(e) => setParameters((p) => ({ ...p, payload: e.target.value }))}
                  className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              {/* Status Codes & Timeout */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-1 p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
                  <label className="text-xs font-semibold text-slate-200 font-mono">expected_status_codes</label>
                  <input
                    type="text"
                    value={
                      Array.isArray(parameters.expected_status_codes)
                        ? parameters.expected_status_codes.join(", ")
                        : parameters.expected_status_codes ?? "200"
                    }
                    onChange={(e) => setParameters((p) => ({ ...p, expected_status_codes: e.target.value }))}
                    className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>

                <div className="space-y-1 p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
                  <label className="text-xs font-semibold text-slate-200 font-mono">timeout_seconds</label>
                  <input
                    type="number"
                    min={1}
                    max={60}
                    value={parameters.timeout_seconds ?? 30}
                    onChange={(e) => setParameters((p) => ({ ...p, timeout_seconds: Number(e.target.value) }))}
                    className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>
              </div>
            </div>
          ) : currentActionDef && Object.keys(currentActionDef.parameter_schema?.properties || {}).length > 0 ? (
            <div className="space-y-3">
              {Object.entries(currentActionDef.parameter_schema.properties).map(
                ([paramKey, propSchema]: [string, any]) => {
                  const val = parameters[paramKey] ?? "";
                  return (
                    <div key={paramKey} className="space-y-1 p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
                      <div className="flex items-center justify-between">
                        <label className="text-xs font-semibold text-slate-200 font-mono">
                          {paramKey}
                        </label>
                        <span className="text-[10px] text-slate-500 uppercase">
                          {propSchema.type || "string"}
                        </span>
                      </div>
                      <input
                        type="text"
                        value={typeof val === "object" ? JSON.stringify(val) : val}
                        onChange={(e) =>
                          setParameters((p) => ({ ...p, [paramKey]: e.target.value }))
                        }
                        className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
                      />
                    </div>
                  );
                }
              )}
            </div>
          ) : (
            <p className="text-xs text-slate-500">No parameters required by this action.</p>
          )}
        </Card>

        {/* Section 4: Safety & Verification */}
        <Card title="Safety and Verification Bounds" className="p-5 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-slate-300">Risk Level *</label>
              <select
                value={riskLevel}
                onChange={(e) => setRiskLevel(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-slate-300">Timeout (seconds) *</label>
              <input
                type="number"
                min={5}
                max={300}
                value={timeoutSeconds}
                onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
                className="w-full px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div className="flex flex-col gap-1.5 justify-center">
              <label className="text-xs font-medium text-slate-300">Approval Requirement</label>
              <div className="flex items-center gap-2 pt-2">
                <input
                  type="checkbox"
                  checked={approvalRequired}
                  disabled={currentActionDef?.approval_required}
                  onChange={(e) => setApprovalRequired(e.target.checked)}
                  className="rounded border-slate-700 text-emerald-500 focus:ring-0 bg-slate-900 w-4 h-4"
                />
                <span className="text-xs text-slate-300">Approval Required</span>
              </div>
            </div>
          </div>

          {/* Verification Probes */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-slate-800">
            <Input
              label="Health Probe Endpoint *"
              value={healthPath}
              onChange={(e) => setHealthPath(e.target.value)}
            />
            <Input
              label="Expected HTTP Status *"
              type="number"
              value={expectedStatus}
              onChange={(e) => setExpectedStatus(Number(e.target.value))}
            />
            <Input
              label="Required Consecutive Probes *"
              type="number"
              min={1}
              max={5}
              value={probesRequired}
              onChange={(e) => setProbesRequired(Number(e.target.value))}
            />
            <Input
              label="Verification Timeout (seconds) *"
              type="number"
              min={5}
              max={60}
              value={verificationTimeout}
              onChange={(e) => setVerificationTimeout(Number(e.target.value))}
            />
          </div>
        </Card>

        {/* Section 5: Change Summary */}
        <Card title="Revision Audit Summary" className="p-5 space-y-3">
          <Input
            label="Summary of Changes"
            placeholder="e.g. Adjusted probe timeout and updated error threshold"
            value={changeSummary}
            onChange={(e) => setChangeSummary(e.target.value)}
            helper="Recorded in immutable version history for compliance auditing"
          />
        </Card>

        {/* Dry-run Validation Section */}
        <div className="flex items-center justify-between">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleValidate}
            isLoading={isValidating}
            className="text-xs"
          >
            <ShieldCheck className="w-3.5 h-3.5 mr-1 text-emerald-400" />
            Dry-Run Validate Specification
          </Button>

          <Button
            type="submit"
            variant="primary"
            size="sm"
            isLoading={isSubmitting}
            className="text-xs gap-1.5"
          >
            <Save className="w-3.5 h-3.5" />
            Save Changes (Bump Version)
          </Button>
        </div>

        {/* Validation Result Display */}
        {validationResult && (
          <div
            className={`p-3.5 rounded-lg border text-xs space-y-1.5 ${
              validationResult.is_valid
                ? "bg-emerald-950/40 border-emerald-800/80 text-emerald-300"
                : "bg-rose-950/40 border-rose-800/80 text-rose-300"
            }`}
          >
            <div className="font-semibold flex items-center gap-1.5">
              {validationResult.is_valid ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              ) : (
                <AlertCircle className="w-4 h-4 text-rose-400" />
              )}
              {validationResult.is_valid
                ? "Dry-Run Passed: Configuration is valid and policy-compliant."
                : "Dry-Run Failed: Issues detected."}
            </div>

            {validationResult.errors?.length > 0 && (
              <ul className="list-disc list-inside space-y-0.5 text-rose-200">
                {validationResult.errors.map((e, idx) => (
                  <li key={idx}>{e}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </form>
    </div>
  );
}
