"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { api, canManagePlaybooks } from "@/lib/api";
import {
  ActionDefinition,
  Service,
  PlaybookValidationResponse,
  PlaybookCreate,
} from "@/lib/types";
import {
  BookOpen,
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Server,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Layers,
  FileCode,
  Sparkles,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";

const TOTAL_STEPS = 8;

const STEPS = [
  { id: 1, label: "Basic Info", icon: BookOpen },
  { id: 2, label: "Services", icon: Server },
  { id: 3, label: "Action Template", icon: Shield },
  { id: 4, label: "Parameters", icon: FileCode },
  { id: 5, label: "Scenarios", icon: Layers },
  { id: 6, label: "Safety & Approvals", icon: ShieldCheck },
  { id: 7, label: "Verification Probes", icon: Activity },
  { id: 8, label: "Validate & Review", icon: CheckCircle2 },
];

const COMMON_SCENARIOS = [
  { id: "*", label: "* (All Incidents)", desc: "Triggers on any incident" },
  { id: "http_5xx_rate_exceeded", label: "Elevated HTTP 5xx Errors", desc: "Excessive 500/502/503 error rates" },
  { id: "demo_failure", label: "Demo Injected Failure", desc: "Simulated in-memory demo error state" },
  { id: "health_check_failure", label: "Health Check Failure", desc: "Continuous probe failures on /health" },
  { id: "worker_process_failure", label: "Worker Process Down", desc: "Background queue consumer unresponsive" },
  { id: "high_latency", label: "High Response Latency", desc: "P99 latency threshold breached" },
];

export default function NewPlaybookPage() {
  const { activeWorkspace, token } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialSvcId = searchParams?.get("service_id");
  const isAuthorized = canManagePlaybooks(activeWorkspace?.role);

  const [currentStep, setCurrentStep] = useState(1);
  const [loadingInitial, setLoadingInitial] = useState(true);
  const [services, setServices] = useState<Service[]>([]);
  const [actions, setActions] = useState<ActionDefinition[]>([]);
  const [globalError, setGlobalError] = useState<string | null>(null);

  // Form State
  // Step 1: Basic Info
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("service_recovery");
  const [targetEnv, setTargetEnv] = useState("development");

  // Step 2: Service Association
  const [selectedServiceIds, setSelectedServiceIds] = useState<string[]>(
    initialSvcId ? [initialSvcId] : []
  );

  // Step 3: Action Template
  const [selectedActionId, setSelectedActionId] = useState("");

  // Step 4: Parameters
  const [parameters, setParameters] = useState<Record<string, any>>({});

  // Step 5: Scenarios
  const [selectedScenarios, setSelectedScenarios] = useState<string[]>(["*"]);
  const [customScenario, setCustomScenario] = useState("");

  // Step 6: Approval & Safety
  const [riskLevel, setRiskLevel] = useState("medium");
  const [approvalRequired, setApprovalRequired] = useState(true);
  const [timeoutSeconds, setTimeoutSeconds] = useState(30);

  // Step 7: Verification Criteria
  const [healthPath, setHealthPath] = useState("/health");
  const [expectedStatus, setExpectedStatus] = useState(200);
  const [probesRequired, setProbesRequired] = useState(3);
  const [verificationTimeout, setVerificationTimeout] = useState(15);
  const [expectedHealthState, setExpectedHealthState] = useState("healthy");

  // Step 8: Validation & Creation
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<PlaybookValidationResponse | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [activateOnCreation, setActivateOnCreation] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Load initial backend dependencies: Services and Allowlisted Actions
  const loadDependencies = useCallback(async () => {
    if (!activeWorkspace || !token) return;
    setLoadingInitial(true);
    setGlobalError(null);
    try {
      const [servicesData, catalogData] = await Promise.all([
        api.services.list(activeWorkspace.workspace_id, token),
        api.remediation.listActions(activeWorkspace.workspace_id, token),
      ]);
      setServices(servicesData || []);
      setActions(catalogData.actions || []);

      if (catalogData.actions?.length > 0 && !selectedActionId) {
        const firstAction = catalogData.actions[0];
        setSelectedActionId(firstAction.action_id);
        setRiskLevel(firstAction.risk_level || "medium");
        setApprovalRequired(firstAction.approval_required);
        setTimeoutSeconds(firstAction.timeout_seconds || 30);
      }
    } catch (err: any) {
      setGlobalError(err.message || "Failed to load services or action catalog.");
    } finally {
      setLoadingInitial(false);
    }
  }, [activeWorkspace, token, selectedActionId]);

  useEffect(() => {
    loadDependencies();
  }, [loadDependencies]);

  // Selected Action Definition object
  const currentActionDef = actions.find((a) => a.action_id === selectedActionId);

  // When action changes, initialize default parameters from schema
  const handleActionSelect = (action: ActionDefinition) => {
    setSelectedActionId(action.action_id);
    setRiskLevel(action.risk_level || "medium");
    setApprovalRequired(action.approval_required);
    setTimeoutSeconds(action.timeout_seconds || 30);

    // Initialize parameters
    const schemaProps = action.parameter_schema?.properties || {};
    const initialParams: Record<string, any> = {};
    Object.entries(schemaProps).forEach(([key, val]: [string, any]) => {
      if (val.default !== undefined) {
        initialParams[key] = val.default;
      } else if (key === "service_id" && selectedServiceIds.length > 0) {
        initialParams[key] = selectedServiceIds[0];
      } else if (val.type === "boolean") {
        initialParams[key] = false;
      } else if (val.type === "integer" || val.type === "number") {
        initialParams[key] = 0;
      } else {
        initialParams[key] = "";
      }
    });

    if (action.action_id === "execute_http_recovery") {
      initialParams["service_id"] = selectedServiceIds[0] || initialParams["service_id"] || "";
      initialParams["recovery_path"] = "/admin/recovery/reset";
      initialParams["expected_status_codes"] = [200];
      initialParams["timeout_seconds"] = 30;
      initialParams["payload"] = null;
      setApprovalRequired(true);
    }

    setParameters(initialParams);
    setValidationResult(null); // invalidate previous validation
  };

  // Toggle service selection in Step 2
  const toggleService = (svcId: string) => {
    setSelectedServiceIds((prev) => {
      const updated = prev.includes(svcId)
        ? prev.filter((id) => id !== svcId)
        : [...prev, svcId];

      // Auto update service_id parameter if needed
      if (updated.length > 0 && parameters.service_id !== undefined) {
        setParameters((p) => ({ ...p, service_id: updated[0] }));
      }
      return updated;
    });
    setValidationResult(null);
  };

  // Toggle scenario selection in Step 5
  const toggleScenario = (scenId: string) => {
    setSelectedScenarios((prev) => {
      if (scenId === "*") {
        return prev.includes("*") ? [] : ["*"];
      }
      const withoutAll = prev.filter((s) => s !== "*");
      return withoutAll.includes(scenId)
        ? withoutAll.filter((s) => s !== scenId)
        : [...withoutAll, scenId];
    });
  };

  const addCustomScenario = () => {
    const trimmed = customScenario.trim();
    if (!trimmed) return;
    if (!selectedScenarios.includes(trimmed)) {
      setSelectedScenarios((prev) => [...prev.filter((s) => s !== "*"), trimmed]);
    }
    setCustomScenario("");
  };

  // Step 8: Validate Configuration via Backend API
  const handleValidateSpec = async () => {
    if (!activeWorkspace || !token || !selectedActionId) return;
    setIsValidating(true);
    setValidationError(null);

    // Filter parameters to only non-empty values matching the schema
    const cleanParams: Record<string, any> = {};
    Object.entries(parameters).forEach(([k, v]) => {
      if (v !== "" && v !== null && v !== undefined) {
        cleanParams[k] = v;
      }
    });

    if (selectedActionId === "execute_http_recovery") {
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
          // let backend handle or fallback
        }
      } else if (cleanParams.payload === "") {
        delete cleanParams.payload;
      }
      if (cleanParams.timeout_seconds !== undefined) {
        cleanParams.timeout_seconds = Number(cleanParams.timeout_seconds);
      }
    }

    if (selectedActionId === "execute_http_recovery") {
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
          // let backend schema report json syntax
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
      expected_state: expectedHealthState,
      probes_required: Number(probesRequired),
      timeout_seconds: Number(verificationTimeout),
    };

    try {
      const res = await api.playbooks.validate(
        {
          workspace_id: activeWorkspace.workspace_id,
          action_template_id: selectedActionId,
          service_ids: selectedServiceIds,
          parameter_schema: cleanParams,
          verification_criteria: verificationCriteria,
          risk_level: riskLevel,
        },
        token
      );
      setValidationResult(res);
      if (!res.is_valid && res.errors?.length > 0) {
        setValidationError(res.errors.join("; "));
      }
    } catch (err: any) {
      setValidationError(err.message || "Backend validation failed.");
      setValidationResult(null);
    } finally {
      setIsValidating(false);
    }
  };

  // Submit Final Creation
  const handleCreatePlaybook = async () => {
    if (!activeWorkspace || !token || !validationResult?.is_valid) return;
    setIsSubmitting(true);
    setGlobalError(null);

    const cleanParams: Record<string, any> = {};
    Object.entries(parameters).forEach(([k, v]) => {
      if (v !== "" && v !== null && v !== undefined) {
        cleanParams[k] = v;
      }
    });

    if (selectedActionId === "execute_http_recovery") {
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
          // let backend handle or fallback
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
      expected_state: expectedHealthState,
      probes_required: Number(probesRequired),
      timeout_seconds: Number(verificationTimeout),
    };

    const payload: PlaybookCreate = {
      workspace_id: activeWorkspace.workspace_id,
      name: name.trim(),
      description: description.trim() || undefined,
      category,
      action_template_id: selectedActionId,
      supported_scenarios: selectedScenarios.length > 0 ? selectedScenarios : ["*"],
      parameter_schema: cleanParams,
      verification_criteria: verificationCriteria,
      risk_level: riskLevel,
      approval_required: approvalRequired,
      timeout_seconds: Number(timeoutSeconds),
      initial_service_ids: selectedServiceIds,
    };

    try {
      const created = await api.playbooks.create(payload, token);

      // If user selected to activate immediately
      if (activateOnCreation) {
        try {
          await api.playbooks.activate(created.id, activeWorkspace.workspace_id, token);
        } catch {
          // Playbook created, activation failure is non-fatal
        }
      }

      router.push(`/playbooks/${created.id}`);
    } catch (err: any) {
      setGlobalError(err.message || "Failed to create remediation playbook.");
      setIsSubmitting(false);
    }
  };

  // Navigation guard
  if (!isAuthorized) {
    return (
      <div className="max-w-2xl mx-auto py-12 text-center space-y-4">
        <div className="w-12 h-12 rounded-xl bg-amber-950/60 border border-amber-800/80 flex items-center justify-center text-amber-400 mx-auto">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <h2 className="text-base font-bold text-slate-100">Permission Restricted</h2>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          Your active membership role in this workspace is <strong>Viewer</strong>. Creating and
          modifying dynamic remediation playbooks requires an <strong>Engineer</strong> or{" "}
          <strong>Admin</strong> role.
        </p>
        <Link href="/playbooks">
          <Button variant="secondary" size="sm" className="text-xs">
            Return to Playbooks
          </Button>
        </Link>
      </div>
    );
  }

  if (loadingInitial) {
    return (
      <div className="flex h-64 items-center justify-center text-slate-500">
        <div className="flex flex-col items-center gap-2">
          <div className="w-5 h-5 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs font-mono">Loading Action Catalog & Service Registry...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-12">
      {/* Top Breadcrumb & Title */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
        <div className="space-y-1">
          <Link
            href="/playbooks"
            className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to Playbooks
          </Link>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-emerald-400" />
            Create Remediation Playbook
          </h1>
        </div>

        <div className="text-right">
          <div className="text-xs font-semibold text-slate-300 font-mono">
            Step {currentStep} of {TOTAL_STEPS}
          </div>
          <div className="text-[10px] text-slate-500">
            {STEPS[currentStep - 1]?.label}
          </div>
        </div>
      </div>

      {/* Global Error Banner */}
      {globalError && (
        <div className="p-3.5 bg-rose-950/50 border border-rose-800/80 rounded-lg flex items-start gap-2.5 text-xs text-rose-300">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div className="flex-1">{globalError}</div>
        </div>
      )}

      {/* Guided Step Progress Bar */}
      <div className="grid grid-cols-4 sm:grid-cols-8 gap-1.5">
        {STEPS.map((step) => {
          const StepIcon = step.icon;
          const isCompleted = currentStep > step.id;
          const isCurrent = currentStep === step.id;

          return (
            <button
              key={step.id}
              onClick={() => {
                if (step.id < currentStep) setCurrentStep(step.id);
              }}
              disabled={step.id > currentStep}
              className={`p-2 rounded-lg border text-left transition-all ${
                isCurrent
                  ? "bg-slate-900 border-emerald-500/80 text-emerald-400 shadow-sm shadow-emerald-950/50"
                  : isCompleted
                  ? "bg-slate-950/80 border-slate-800 text-slate-400 hover:border-slate-700 cursor-pointer"
                  : "bg-slate-950/40 border-slate-800/50 text-slate-600 opacity-60 cursor-not-allowed"
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <StepIcon className="w-3.5 h-3.5" />
                {isCompleted ? (
                  <Check className="w-3 h-3 text-emerald-400" />
                ) : (
                  <span className="text-[10px] font-mono">{step.id}</span>
                )}
              </div>
              <div className="text-[10px] font-medium truncate">{step.label}</div>
            </button>
          );
        })}
      </div>

      {/* Step Content Container */}
      <Card className="p-6">
        {/* ==================================================================== */}
        {/* STEP 1: Basic Information */}
        {/* ==================================================================== */}
        {currentStep === 1 && (
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-emerald-400" />
                Step 1: Basic Information
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Define the identification, scope, and operational category for this playbook.
              </p>
            </div>

            <div className="space-y-4 pt-2">
              <Input
                label="Playbook Name *"
                placeholder="e.g. Order API Service Recovery"
                value={name}
                onChange={(e) => setName(e.target.value)}
                helper="Unique human-readable identifier for this playbook (min 2 characters)"
              />

              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-slate-300">Description</label>
                <textarea
                  rows={3}
                  placeholder="Detail the problem this playbook solves, its expected operational impacts, and recovery goals..."
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
                  <span className="text-[11px] text-slate-500">
                    Defines the high-level operational domain.
                  </span>
                </div>

                <div className="flex flex-col gap-1.5">
                  <label className="text-xs font-medium text-slate-300">Target Environment</label>
                  <select
                    value={targetEnv}
                    onChange={(e) => setTargetEnv(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                  >
                    <option value="development">Development</option>
                    <option value="staging">Staging</option>
                    <option value="production">Production</option>
                    <option value="all">All Environments (*)</option>
                  </select>
                  <span className="text-[11px] text-slate-500">
                    Environment restriction evaluated by PolicyEngine.
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* STEP 2: Service Association */}
        {/* ==================================================================== */}
        {currentStep === 2 && (
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Server className="w-4 h-4 text-emerald-400" />
                Step 2: Service Association
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Select registered services within your workspace that can execute this remediation playbook.
              </p>
            </div>

            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-xs text-slate-400 space-y-1">
              <span className="font-semibold text-slate-200">Workspace Multi-Tenancy Guarantee:</span>
              <p>
                Services shown below belong strictly to <strong>{activeWorkspace?.workspace_name}</strong> (
                <code className="text-slate-400 font-mono">{activeWorkspace?.workspace_id}</code>). Cross-workspace
                service binding is prohibited by database foreign keys.
              </p>
            </div>

            {services.length === 0 ? (
              <div className="text-center py-8 text-xs text-slate-500">
                No services registered in this workspace yet. You can still create the playbook and associate services later.
              </div>
            ) : (
              <div className="space-y-2 pt-1">
                {services.map((svc) => {
                  const isSelected = selectedServiceIds.includes(svc.id);
                  return (
                    <div
                      key={svc.id}
                      onClick={() => toggleService(svc.id)}
                      className={`p-3 rounded-lg border flex items-center justify-between cursor-pointer transition-all ${
                        isSelected
                          ? "bg-emerald-950/20 border-emerald-500/80 text-slate-100"
                          : "bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700"
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}} // handled by parent div
                          className="rounded border-slate-700 text-emerald-500 focus:ring-0 focus:ring-offset-0 bg-slate-900"
                        />
                        <div>
                          <div className="text-xs font-semibold text-slate-200">{svc.name}</div>
                          <div className="text-[11px] text-slate-500 font-mono">
                            {svc.health_check_url} &bull; Env: {svc.environment}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <Badge
                          variant={
                            svc.health_status === "healthy"
                              ? "healthy"
                              : svc.health_status === "degraded"
                              ? "degraded"
                              : "unhealthy"
                          }
                        >
                          {svc.health_status}
                        </Badge>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ==================================================================== */}
        {/* STEP 3: Action Template Selection */}
        {/* ==================================================================== */}
        {currentStep === 3 && (
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                Step 3: Recovery Action Template
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Choose an allowlisted action from the ActionRegistry. Arbitrary commands and scripts are strictly rejected.
              </p>
            </div>

            <div className="p-3 bg-emerald-950/30 border border-emerald-800/60 rounded-lg text-xs text-emerald-300 flex items-start gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong>Security Guarantee:</strong> Playbooks cannot execute raw shell commands,
                arbitrary Python, or unvetted scripts. Every action is strictly pre-registered and isolated
                within Docker remediation containers.
              </div>
            </div>

            <div className="space-y-3 pt-1">
              {actions.map((act) => {
                const isSelected = selectedActionId === act.action_id;
                const isUniversal = !act.supported_services || act.supported_services.includes("*");

                // Check service compatibility warning
                const hasIncompatibleSelection =
                  !isUniversal &&
                  selectedServiceIds.some((sId) => {
                    const svc = services.find((s) => s.id === sId);
                    return svc && !act.supported_services?.includes(svc.name) && !act.supported_services?.includes(svc.id);
                  });

                return (
                  <div
                    key={act.action_id}
                    onClick={() => handleActionSelect(act)}
                    className={`p-4 rounded-xl border cursor-pointer transition-all ${
                      isSelected
                        ? "bg-slate-900 border-emerald-500 shadow-sm shadow-emerald-950/60"
                        : "bg-slate-950/40 border-slate-800 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3 mb-2">
                      <div className="flex items-center gap-2">
                        <div
                          className={`w-4 h-4 rounded-full border flex items-center justify-center ${
                            isSelected
                              ? "border-emerald-500 bg-emerald-500 text-slate-950"
                              : "border-slate-700 bg-slate-900"
                          }`}
                        >
                          {isSelected && <Check className="w-2.5 h-2.5 stroke-[3]" />}
                        </div>
                        <span className="text-xs font-semibold text-slate-100">{act.name}</span>
                        <code className="text-[10px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                          {act.action_id}
                        </code>
                      </div>

                      <div className="flex items-center gap-1.5">
                        {act.status === "requires_adapter" ? (
                          <Badge variant="warning">Requires Adapter</Badge>
                        ) : (
                          <Badge variant="success">Executable</Badge>
                        )}
                        <Badge
                          variant={
                            act.risk_level === "critical"
                              ? "critical"
                              : act.risk_level === "high"
                              ? "high"
                              : "medium"
                          }
                        >
                          {act.risk_level.toUpperCase()} RISK
                        </Badge>
                      </div>
                    </div>

                    <p className="text-xs text-slate-400 mb-2 pl-6">{act.description}</p>

                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-500 pl-6 mb-2">
                      <span>Mechanism: <code className="text-slate-400">{act.execution_mechanism || "http_diagnostic"}</code></span>
                      <span>Target: <code className="text-slate-400">{act.target_resource_type || "http_endpoint"}</code></span>
                      <span>Timeout: {act.timeout_seconds}s</span>
                      <span>Approval: {act.approval_required ? "Mandatory" : "Optional"}</span>
                      <span>
                        Scope:{" "}
                        {isUniversal ? "All Services (*)" : act.supported_services?.join(", ")}
                      </span>
                    </div>

                    {act.status === "requires_adapter" && isSelected && (
                      <div className="mt-2 ml-6 p-2.5 bg-amber-950/40 border border-amber-800/80 rounded text-[11px] text-amber-300 space-y-1">
                        <div className="flex items-center gap-1.5 font-semibold">
                          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                          <span>Infrastructure Integration Prerequisite Required</span>
                        </div>
                        <p className="text-amber-400/90 text-[10px]">
                          This action requires an infrastructure adapter (<code>{act.execution_mechanism}</code>) that is not currently mounted in the runner sandbox. Playbooks can be configured, but execution will require the adapter to be installed.
                        </p>
                      </div>
                    )}

                    {hasIncompatibleSelection && isSelected && (
                      <div className="mt-2 ml-6 p-2 bg-rose-950/50 border border-rose-800/80 rounded text-[11px] text-rose-300 flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                        <span>
                          Notice: One or more selected services are not allowlisted for this action.
                          Validation in Step 8 will verify compatibility and fail if service is incompatible.
                        </span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* STEP 4: Parameters */}
        {/* ==================================================================== */}
        {currentStep === 4 && (
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <FileCode className="w-4 h-4 text-emerald-400" />
                Step 4: Action Parameters
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Configure parameters strictly against the selected action template&apos;s schema (
                <code className="text-slate-300 font-mono">{selectedActionId}</code>).
              </p>
            </div>

            {selectedActionId === "execute_http_recovery" ? (
              <div className="space-y-4 pt-1">
                {/* Authorization & Security Notice */}
                <div className="p-3.5 bg-emerald-950/40 border border-emerald-800/70 rounded-xl text-xs text-emerald-300 space-y-2">
                  <div className="flex items-center gap-2 font-semibold text-emerald-200">
                    <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>HTTP Recovery Adapter Security & Authorization Contract</span>
                  </div>
                  <p className="text-emerald-400/90 leading-relaxed text-[11px]">
                    Configuring this recovery operation authorizes SentinelOps to execute an HTTP POST request to the specified relative path on the target service.
                    The hostname and origin are <strong>strictly derived from the registered service&apos;s health check URL</strong>. External hostnames, query parameters, URL fragments, and path traversal are rejected. Human approval is mandatory.
                  </p>
                  {/* Origin Derivation Preview */}
                  {(() => {
                    const primarySvc = services.find((s) => selectedServiceIds.includes(s.id));
                    let origin = "";
                    if (primarySvc?.health_check_url) {
                      try {
                        const parsed = new URL(primarySvc.health_check_url);
                        origin = `${parsed.protocol}//${parsed.host}`;
                      } catch {}
                    }
                    const recPath = parameters.recovery_path || "/admin/recovery/reset";
                    return (
                      <div className="mt-2 pt-2 border-t border-emerald-800/40 text-[11px] font-mono flex flex-col gap-1">
                        <div>
                          <span className="text-slate-400">Target Origin: </span>
                          <span className="text-cyan-300 font-semibold">{origin || "(Select a service in Step 2)"}</span>
                        </div>
                        <div>
                          <span className="text-slate-400">Derived Full Target URL: </span>
                          <span className="text-emerald-300 font-semibold">{origin ? `${origin}${recPath.startsWith("/") ? recPath : `/${recPath}`}` : `[Derived Origin]${recPath}`}</span>
                        </div>
                      </div>
                    );
                  })()}
                </div>

                {/* Service ID */}
                <div className="space-y-1.5 p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                      <code>service_id</code>
                      <span className="text-rose-400">*</span>
                    </label>
                    <span className="text-[10px] font-mono text-slate-500 uppercase">UUID</span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Target service UUID belonging to the active workspace.
                  </p>
                  {selectedServiceIds.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 pb-1">
                      <span className="text-[10px] text-slate-500">Quick fill:</span>
                      {selectedServiceIds.map((sId) => {
                        const s = services.find((svc) => svc.id === sId);
                        return (
                          <button
                            key={sId}
                            type="button"
                            onClick={() => setParameters((p) => ({ ...p, service_id: sId }))}
                            className={`text-[10px] font-mono px-2 py-0.5 rounded border transition-colors ${
                              parameters.service_id === sId
                                ? "bg-emerald-950/60 border-emerald-500 text-emerald-200"
                                : "bg-slate-900 border-slate-700 text-slate-300 hover:border-emerald-500"
                            }`}
                          >
                            {s?.name || sId}
                          </button>
                        );
                      })}
                    </div>
                  )}
                  <input
                    type="text"
                    value={parameters.service_id || ""}
                    placeholder="e.g. 535f04e0-f1ff-4096-9011-e4e2c7234398"
                    onChange={(e) => setParameters((p) => ({ ...p, service_id: e.target.value }))}
                    className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>

                {/* Recovery Path */}
                <div className="space-y-1.5 p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                      <code>recovery_path</code>
                      <span className="text-rose-400">*</span>
                    </label>
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Relative Path</span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Relative HTTP endpoint invoked via POST (e.g. <code>/admin/recovery/reset</code>). Must start with <code>/</code>. External hostnames, query strings (<code>?</code>), and path traversal (<code>..</code>) are forbidden.
                  </p>
                  <input
                    type="text"
                    value={parameters.recovery_path || ""}
                    placeholder="/admin/recovery/reset"
                    onChange={(e) => setParameters((p) => ({ ...p, recovery_path: e.target.value }))}
                    className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>

                {/* Request Payload (Optional) */}
                <div className="space-y-1.5 p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                      <code>payload</code>
                      <span className="text-[11px] text-slate-500 font-normal">(Optional)</span>
                    </label>
                    <span className="text-[10px] font-mono text-slate-500 uppercase">JSON Object</span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Optional strict JSON request body sent with the recovery POST request. Shell commands, script tags, and Python code patterns are strictly rejected.
                  </p>
                  <textarea
                    rows={4}
                    value={
                      typeof parameters.payload === "object" && parameters.payload !== null
                        ? JSON.stringify(parameters.payload, null, 2)
                        : parameters.payload || ""
                    }
                    placeholder={`{\n  "action": "reset",\n  "force": false\n}`}
                    onChange={(e) => setParameters((p) => ({ ...p, payload: e.target.value }))}
                    className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>

                {/* Expected Status Codes & Timeout */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="space-y-1.5 p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg">
                    <label className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                      <code>expected_status_codes</code>
                    </label>
                    <p className="text-[11px] text-slate-400">
                      Comma-separated 2xx status codes considered successful.
                    </p>
                    <input
                      type="text"
                      value={
                        Array.isArray(parameters.expected_status_codes)
                          ? parameters.expected_status_codes.join(", ")
                          : parameters.expected_status_codes ?? "200"
                      }
                      placeholder="200, 204"
                      onChange={(e) =>
                        setParameters((p) => ({
                          ...p,
                          expected_status_codes: e.target.value,
                        }))
                      }
                      className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
                    />
                  </div>

                  <div className="space-y-1.5 p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg">
                    <label className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                      <code>timeout_seconds</code>
                    </label>
                    <p className="text-[11px] text-slate-400">
                      HTTP connection and response timeout bound (1-60s).
                    </p>
                    <input
                      type="number"
                      min={1}
                      max={60}
                      value={parameters.timeout_seconds ?? 30}
                      onChange={(e) =>
                        setParameters((p) => ({
                          ...p,
                          timeout_seconds: Number(e.target.value),
                        }))
                      }
                      className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
                    />
                  </div>
                </div>
              </div>
            ) : currentActionDef && Object.keys(currentActionDef.parameter_schema?.properties || {}).length === 0 ? (
              <div className="p-4 bg-slate-950/50 border border-slate-800 rounded-lg text-xs text-slate-400 text-center">
                This action template requires no additional parameters. You can proceed to the next step.
              </div>
            ) : (
              <div className="space-y-4 pt-1">
                {Object.entries(currentActionDef?.parameter_schema?.properties || {}).map(
                  ([paramKey, propSchema]: [string, any]) => {
                    const isRequired =
                      currentActionDef?.parameter_schema?.required?.includes(paramKey) || false;
                    const val = parameters[paramKey] ?? "";

                    return (
                      <div key={paramKey} className="space-y-1.5 p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg">
                        <div className="flex items-center justify-between">
                          <label className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                            <code>{paramKey}</code>
                            {isRequired && <span className="text-rose-400">*</span>}
                          </label>
                          <span className="text-[10px] font-mono text-slate-500 uppercase">
                            {propSchema.type || "string"}
                          </span>
                        </div>

                        {propSchema.description && (
                          <p className="text-[11px] text-slate-400">{propSchema.description}</p>
                        )}

                        {/* Special case: service_id selector helper */}
                        {paramKey === "service_id" && selectedServiceIds.length > 0 && (
                          <div className="flex flex-wrap items-center gap-1.5 pb-1">
                            <span className="text-[10px] text-slate-500">Quick fill:</span>
                            {selectedServiceIds.map((sId) => {
                              const s = services.find((svc) => svc.id === sId);
                              return (
                                <button
                                  key={sId}
                                  type="button"
                                  onClick={() => setParameters((p) => ({ ...p, [paramKey]: sId }))}
                                  className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300 hover:border-emerald-500"
                                >
                                  {s?.name || sId}
                                </button>
                              );
                            })}
                          </div>
                        )}

                        {propSchema.type === "boolean" ? (
                          <select
                            value={String(val)}
                            onChange={(e) =>
                              setParameters((p) => ({
                                ...p,
                                [paramKey]: e.target.value === "true",
                              }))
                            }
                            className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
                          >
                            <option value="false">false</option>
                            <option value="true">true</option>
                          </select>
                        ) : propSchema.type === "integer" || propSchema.type === "number" ? (
                          <input
                            type="number"
                            value={val}
                            onChange={(e) =>
                              setParameters((p) => ({
                                ...p,
                                [paramKey]: Number(e.target.value),
                              }))
                            }
                            className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
                          />
                        ) : (
                          <input
                            type="text"
                            value={val}
                            placeholder={propSchema.default || `Enter ${paramKey}...`}
                            onChange={(e) =>
                              setParameters((p) => ({
                                ...p,
                                [paramKey]: e.target.value,
                              }))
                            }
                            className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
                          />
                        )}
                      </div>
                    );
                  }
                )}
              </div>
            )}
          </div>
        )}

        {/* ==================================================================== */}
        {/* STEP 5: Incident Scenarios */}
        {/* ==================================================================== */}
        {currentStep === 5 && (
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Layers className="w-4 h-4 text-emerald-400" />
                Step 5: Incident Scenarios
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Specify which incident types or trigger conditions can evaluate and execute this playbook.
              </p>
            </div>

            <div className="space-y-2 pt-1">
              {COMMON_SCENARIOS.map((scen) => {
                const isSelected = selectedScenarios.includes(scen.id);
                return (
                  <div
                    key={scen.id}
                    onClick={() => toggleScenario(scen.id)}
                    className={`p-3 rounded-lg border flex items-center justify-between cursor-pointer transition-all ${
                      isSelected
                        ? "bg-slate-900 border-emerald-500/80 text-slate-100"
                        : "bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => {}}
                        className="rounded border-slate-700 text-emerald-500 focus:ring-0 bg-slate-900"
                      />
                      <div>
                        <div className="text-xs font-semibold text-slate-200">{scen.label}</div>
                        <div className="text-[11px] text-slate-500 font-mono">{scen.desc}</div>
                      </div>
                    </div>
                    <code className="text-[10px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                      {scen.id}
                    </code>
                  </div>
                );
              })}
            </div>

            {/* Custom Scenario Adder */}
            <div className="pt-2 flex items-center gap-2">
              <input
                type="text"
                placeholder="Add custom incident trigger (e.g. disk_usage_critical)..."
                value={customScenario}
                onChange={(e) => setCustomScenario(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    addCustomScenario();
                  }
                }}
                className="flex-1 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
              />
              <Button type="button" variant="outline" size="sm" onClick={addCustomScenario} className="text-xs">
                Add Tag
              </Button>
            </div>

            {/* Selected Tags Preview */}
            <div className="flex flex-wrap items-center gap-1.5 pt-2">
              <span className="text-[11px] text-slate-500">Configured Triggers:</span>
              {selectedScenarios.map((scen) => (
                <span
                  key={scen}
                  className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-slate-900 border border-slate-700 text-emerald-400 flex items-center gap-1.5"
                >
                  {scen}
                  <button
                    type="button"
                    onClick={() => toggleScenario(scen)}
                    className="hover:text-rose-400 ml-1"
                  >
                    &times;
                  </button>
                </span>
              ))}
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* STEP 6: Safety & Approvals */}
        {/* ==================================================================== */}
        {currentStep === 6 && (
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Step 6: Approval and Safety Bounds
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Set human oversight levels, risk classification, and execution execution timeouts.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
              {/* Risk Level */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-slate-300">Risk Classification *</label>
                <select
                  value={riskLevel}
                  onChange={(e) => setRiskLevel(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                >
                  <option value="low">Low Risk</option>
                  <option value="medium">Medium Risk</option>
                  <option value="high">High Risk</option>
                  <option value="critical">Critical Risk</option>
                </select>
                <span className="text-[11px] text-slate-500">
                  Evaluated by PolicyEngine to determine required approval quorum.
                </span>
              </div>

              {/* Timeout Seconds */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-slate-300">
                  Execution Timeout (seconds) *
                </label>
                <input
                  type="number"
                  min={5}
                  max={300}
                  value={timeoutSeconds}
                  onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
                  className="w-full px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                />
                <span className="text-[11px] text-slate-500">
                  Hard bounds: 5 to 300 seconds enforced by Docker runner.
                </span>
              </div>
            </div>

            {/* Approval Required Toggle */}
            <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg flex items-start justify-between gap-4">
              <div className="space-y-1">
                <div className="text-xs font-semibold text-slate-200">
                  Mandatory Human Approval
                </div>
                <p className="text-[11px] text-slate-400">
                  When enabled, remediation proposals must be explicitly approved by an authorized Engineer or Admin
                  before Docker runner dispatch.
                </p>
              </div>

              <input
                type="checkbox"
                checked={approvalRequired}
                disabled={currentActionDef?.approval_required}
                onChange={(e) => setApprovalRequired(e.target.checked)}
                className="mt-1 rounded border-slate-700 text-emerald-500 focus:ring-0 bg-slate-900 w-4 h-4 cursor-pointer disabled:opacity-50"
              />
            </div>

            {currentActionDef?.approval_required && (
              <p className="text-[11px] text-amber-400/90 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                This action template has an immutable policy requirement: approval is always mandatory.
              </p>
            )}
          </div>
        )}

        {/* ==================================================================== */}
        {/* STEP 7: Verification Criteria */}
        {/* ==================================================================== */}
        {currentStep === 7 && (
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Activity className="w-4 h-4 text-emerald-400" />
                Step 7: Synthetic Verification Criteria
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Configure the post-remediation health probes that prove the service has genuinely recovered.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
              <Input
                label="Health Probe Path *"
                value={healthPath}
                onChange={(e) => setHealthPath(e.target.value)}
                placeholder="/health"
                helper="Endpoint queried by verification runner (e.g. /health)"
              />

              <Input
                label="Expected HTTP Status *"
                type="number"
                value={expectedStatus}
                onChange={(e) => setExpectedStatus(Number(e.target.value))}
                placeholder="200"
                helper="Required HTTP status code for pass probe"
              />

              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-slate-300">
                  Required Consecutive Probes *
                </label>
                <input
                  type="number"
                  min={1}
                  max={5}
                  value={probesRequired}
                  onChange={(e) => setProbesRequired(Number(e.target.value))}
                  className="w-full px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                />
                <span className="text-[11px] text-slate-500">
                  Number of uninterrupted consecutive pass probes required to declare recovery (1-5).
                </span>
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-slate-300">
                  Verification Timeout (seconds) *
                </label>
                <input
                  type="number"
                  min={5}
                  max={60}
                  value={verificationTimeout}
                  onChange={(e) => setVerificationTimeout(Number(e.target.value))}
                  className="w-full px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                />
                <span className="text-[11px] text-slate-500">
                  Maximum window to complete required verification cycles.
                </span>
              </div>
            </div>

            <Input
              label="Expected Health State (Optional)"
              value={expectedHealthState}
              onChange={(e) => setExpectedHealthState(e.target.value)}
              placeholder="healthy"
              helper="Substring or JSON status expected in the probe response body"
            />
          </div>
        )}

        {/* ==================================================================== */}
        {/* STEP 8: Review & Validate */}
        {/* ==================================================================== */}
        {currentStep === 8 && (
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                Step 8: Review & Dry-Run Validation
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Review your playbook specification and run dry-run validation against backend security invariants.
              </p>
            </div>

            {/* Configuration Summary Card */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg space-y-2">
                <div className="text-slate-400 font-semibold border-b border-slate-800 pb-1">
                  General Specification
                </div>
                <div>
                  <span className="text-slate-500">Name: </span>
                  <span className="text-slate-200 font-medium">{name || "Untitled"}</span>
                </div>
                <div>
                  <span className="text-slate-500">Category: </span>
                  <span className="text-slate-200 uppercase font-mono">{category}</span>
                </div>
                <div>
                  <span className="text-slate-500">Action Template: </span>
                  <code className="text-emerald-400 font-mono">{selectedActionId}</code>
                </div>
                <div>
                  <span className="text-slate-500">Associated Services: </span>
                  <span className="text-slate-200">
                    {selectedServiceIds.length > 0
                      ? selectedServiceIds
                          .map((id) => services.find((s) => s.id === id)?.name || id)
                          .join(", ")
                      : "None"}
                  </span>
                </div>
              </div>

              <div className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg space-y-2">
                <div className="text-slate-400 font-semibold border-b border-slate-800 pb-1">
                  Safety & Verification
                </div>
                <div>
                  <span className="text-slate-500">Risk Level: </span>
                  <span className="text-slate-200 uppercase font-mono">{riskLevel}</span>
                </div>
                <div>
                  <span className="text-slate-500">Approval Required: </span>
                  <span className="text-slate-200">{approvalRequired ? "Yes (Mandatory)" : "No"}</span>
                </div>
                <div>
                  <span className="text-slate-500">Timeout: </span>
                  <span className="text-slate-200 font-mono">{timeoutSeconds}s</span>
                </div>
                <div>
                  <span className="text-slate-500">Verification: </span>
                  <span className="text-slate-200 font-mono">
                    {probesRequired} probes on {healthPath} ({verificationTimeout}s timeout)
                  </span>
                </div>
              </div>
            </div>

            {/* Configured Parameters View */}
            <div className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg space-y-1.5 text-xs font-mono">
              <div className="text-slate-400 font-semibold">Configured Parameters:</div>
              <pre className="text-slate-300 text-[11px] overflow-x-auto p-2 bg-slate-950 rounded border border-slate-800/80">
                {JSON.stringify(parameters, null, 2)}
              </pre>
            </div>

            {/* Validation Trigger Button */}
            <div className="pt-2 flex items-center justify-between">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={handleValidateSpec}
                isLoading={isValidating}
                className="text-xs"
              >
                <ShieldCheck className="w-3.5 h-3.5 mr-1 text-emerald-400" />
                Run Backend Validation Check
              </Button>

              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={activateOnCreation}
                  onChange={(e) => setActivateOnCreation(e.target.checked)}
                  className="rounded border-slate-700 text-emerald-500 focus:ring-0 bg-slate-900"
                />
                <span>Activate playbook immediately upon creation</span>
              </label>
            </div>

            {/* Validation Outcome Banner */}
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
                    ? "Validation Succeeded: Specification is authorized and policy-compliant."
                    : "Validation Failed: Issues detected."}
                </div>

                {validationResult.errors?.length > 0 && (
                  <ul className="list-disc list-inside space-y-0.5 text-rose-200">
                    {validationResult.errors.map((e, idx) => (
                      <li key={idx}>{e}</li>
                    ))}
                  </ul>
                )}

                {validationResult.warnings?.length > 0 && (
                  <ul className="list-disc list-inside space-y-0.5 text-amber-300">
                    {validationResult.warnings.map((w, idx) => (
                      <li key={idx}>{w}</li>
                    ))}
                  </ul>
                )}

                {validationResult.incompatible_services?.length > 0 && (
                  <div className="pt-1 text-amber-300">
                    <span className="font-semibold">Incompatible services:</span>
                    <ul className="list-disc list-inside">
                      {validationResult.incompatible_services.map((inc) => (
                        <li key={inc.service_id}>
                          {inc.service_name}: {inc.reason}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {validationError && !validationResult && (
              <div className="p-3 bg-rose-950/50 border border-rose-800 rounded-lg text-xs text-rose-300">
                {validationError}
              </div>
            )}
          </div>
        )}

        {/* Wizard Footer Controls */}
        <div className="flex items-center justify-between pt-6 mt-6 border-t border-slate-800">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => setCurrentStep((prev) => Math.max(1, prev - 1))}
            disabled={currentStep === 1 || isSubmitting}
            className="text-xs"
          >
            <ArrowLeft className="w-3.5 h-3.5 mr-1" />
            Previous
          </Button>

          <div className="flex items-center gap-2">
            {currentStep < TOTAL_STEPS ? (
              <Button
                type="button"
                variant="primary"
                size="sm"
                onClick={() => {
                  // Basic validation before advancing from Step 1
                  if (currentStep === 1 && name.trim().length < 2) {
                    setGlobalError("Playbook name must be at least 2 characters.");
                    return;
                  }
                  setGlobalError(null);
                  setCurrentStep((prev) => Math.min(TOTAL_STEPS, prev + 1));
                }}
                className="text-xs"
              >
                Next
                <ArrowRight className="w-3.5 h-3.5 ml-1" />
              </Button>
            ) : (
              <Button
                type="button"
                variant="primary"
                size="sm"
                onClick={handleCreatePlaybook}
                disabled={!validationResult?.is_valid || isSubmitting}
                isLoading={isSubmitting}
                className="text-xs shadow-md shadow-emerald-950/60"
              >
                <Check className="w-3.5 h-3.5 mr-1" />
                Create Playbook
              </Button>
            )}
          </div>
        </div>
      </Card>
    </div>
  );
}
