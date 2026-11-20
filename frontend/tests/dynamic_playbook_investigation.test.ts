import test from "node:test";
import assert from "node:assert";
import {
  evaluateProposalEligibility,
  executeProposalWorkflow,
  ProposalEligibilityContext,
} from "../src/lib/api";
import {
  PolicyDecisionResponse,
  RemediationRecommendation,
  PolicyEvaluationRequest,
  RemediationApproval,
} from "../src/lib/types";

const mockActionableRecommendation: RemediationRecommendation = {
  outcome: "compatible_found",
  status: "actionable",
  playbook_id: "pb-uuid-1",
  playbook_name: "Inventory Cache Auto-Heal",
  playbook_version: 1,
  action_template_id: "inspect_service_health",
  service_id: "srv-inventory",
  workspace_id: "ws-1111",
  incident_id: "inc-1111",
  investigation_id: "inv-1111",
  risk_level: "low",
  parameters: {
    service_id: "srv-inventory",
    health_path: "/api/v1/health",
  },
  explanation: "Diagnosed service cache degradation; recommended Inventory Cache Auto-Heal.",
  supporting_evidence_ids: ["ev-1", "ev-2"],
  missing_parameters: [],
  compatible_playbooks: [
    {
      playbook_id: "pb-uuid-1",
      playbook_name: "Inventory Cache Auto-Heal",
      version_number: 1,
      action_template_id: "inspect_service_health",
      is_compatible: true,
      rejection_reasons: [],
      matching_scenarios: ["http_5xx_rate_exceeded"],
      matching_evidence_ids: ["ev-1"],
      missing_parameters: [],
      validated_parameters: { service_id: "srv-inventory" },
      risk_level: "low",
      priority: 100,
      compatibility_explanation: "Compatible",
    },
  ],
  rejected_playbooks: [],
  ranked_candidates: [],
  escalation_reason: null,
};

const mockNoPlaybookRecommendation: RemediationRecommendation = {
  outcome: "no_compatible_playbook",
  status: "human_escalation_required",
  playbook_id: null,
  playbook_name: null,
  playbook_version: null,
  action_template_id: null,
  service_id: "srv-inventory",
  workspace_id: "ws-1111",
  incident_id: "inc-1111",
  investigation_id: "inv-1111",
  risk_level: null,
  parameters: {},
  explanation: "No approved, active remediation playbook is configured for service Inventory API.",
  supporting_evidence_ids: [],
  missing_parameters: [],
  compatible_playbooks: [],
  rejected_playbooks: [
    {
      playbook_id: "pb-rejected",
      playbook_name: "Stale Restart",
      version_number: 1,
      action_template_id: "restart_order_api",
      is_compatible: false,
      rejection_reasons: ["Action template does not support service Inventory API."],
      matching_scenarios: [],
      matching_evidence_ids: [],
      missing_parameters: [],
      validated_parameters: {},
      risk_level: "medium",
      priority: 0,
      compatibility_explanation: "Rejected",
    },
  ],
  ranked_candidates: [],
  escalation_reason: "Zero compatible playbooks bound to service.",
};

const mockMissingParamsRecommendation: RemediationRecommendation = {
  outcome: "missing_parameters",
  status: "human_escalation_required",
  playbook_id: "pb-uuid-2",
  playbook_name: "Database Scaler",
  playbook_version: 2,
  action_template_id: "inspect_service_health",
  service_id: "srv-inventory",
  workspace_id: "ws-1111",
  incident_id: "inc-1111",
  investigation_id: "inv-1111",
  risk_level: "medium",
  parameters: {},
  explanation: "Playbook Database Scaler requires parameter 'target_pool_size'.",
  supporting_evidence_ids: ["ev-1"],
  missing_parameters: ["target_pool_size"],
  compatible_playbooks: [],
  rejected_playbooks: [],
  ranked_candidates: [],
  escalation_reason: "Missing required parameter target_pool_size.",
};

const baseContext: ProposalEligibilityContext = {
  role: "engineer",
  investigationStatus: "completed",
  hasTargetService: true,
  serviceName: "Inventory API",
  serviceEnvironment: "development",
  executionPolicy: "demo",
  workspaceId: "ws-1111",
  incidentWorkspaceId: "ws-1111",
  serviceWorkspaceId: "ws-1111",
  investigationWorkspaceId: "ws-1111",
  investigationIncidentId: "inc-1111",
  incidentId: "inc-1111",
};

test("1. Dynamic playbook recommendation: Actionable recommendation enables proposal for Engineer", () => {
  const result = evaluateProposalEligibility({
    ...baseContext,
    role: "engineer",
    recommendation: mockActionableRecommendation,
  });

  assert.strictEqual(result.canInvestigate, true);
  assert.strictEqual(result.hasPlaybook, true);
  assert.strictEqual(result.canPropose, true);
  assert.strictEqual(result.rejectionReason, undefined);
});

test("2. Dynamic playbook recommendation: Actionable recommendation enables proposal for Admin", () => {
  const result = evaluateProposalEligibility({
    ...baseContext,
    role: "admin",
    recommendation: mockActionableRecommendation,
  });

  assert.strictEqual(result.canInvestigate, true);
  assert.strictEqual(result.hasPlaybook, true);
  assert.strictEqual(result.canPropose, true);
});

test("3. Dynamic playbook recommendation: Viewer role cannot propose even with actionable recommendation", () => {
  const result = evaluateProposalEligibility({
    ...baseContext,
    role: "viewer",
    recommendation: mockActionableRecommendation,
  });

  assert.strictEqual(result.canInvestigate, false);
  assert.strictEqual(result.hasPlaybook, true);
  assert.strictEqual(result.canPropose, false);
  assert.match(result.rejectionReason || "", /not authorized/);
});

test("4. Dynamic playbook recommendation: 'no_compatible_playbook' fails closed with escalation notice", () => {
  const result = evaluateProposalEligibility({
    ...baseContext,
    role: "engineer",
    recommendation: mockNoPlaybookRecommendation,
  });

  assert.strictEqual(result.hasPlaybook, false);
  assert.strictEqual(result.canPropose, false);
  assert.match(result.rejectionReason || "", /No compatible remediation playbook/);
});

test("5. Dynamic playbook recommendation: 'missing_parameters' fails closed and reports missing fields", () => {
  const result = evaluateProposalEligibility({
    ...baseContext,
    role: "engineer",
    recommendation: mockMissingParamsRecommendation,
  });

  assert.strictEqual(result.hasPlaybook, false);
  assert.strictEqual(result.canPropose, false);
  assert.match(result.rejectionReason || "", /target_pool_size/);
});

test("6. executeProposalWorkflow: Transmits recommended action, parameters, playbookId, and version", async () => {
  let capturedPolicyRequest: PolicyEvaluationRequest | null = null;
  let capturedApprovalRequest: any = null;

  const mockEvaluatePolicy = async (req: PolicyEvaluationRequest): Promise<PolicyDecisionResponse> => {
    capturedPolicyRequest = req;
    return {
      id: "decision-uuid-2",
      workspace_id: req.workspace_id,
      action_id: req.action_id,
      target_service_id: req.parameters.service_id,
      risk_level: "low",
      decision: "approval_required",
      decision_reason: "Action requires human approval.",
      policy_version: "v1.0",
      approval_required: true,
      validated_parameters: req.parameters,
      evaluated_at: new Date().toISOString(),
    };
  };

  const mockCreateApproval = async (req: any): Promise<RemediationApproval> => {
    capturedApprovalRequest = req;
    return {
      id: "approval-uuid-2",
      workspace_id: req.workspace_id,
      policy_decision_id: req.policy_decision_id,
      incident_id: req.incident_id,
      investigation_id: req.investigation_id,
      action_id: "inspect_service_health",
      target_service_id: "srv-inventory",
      validated_parameters: { service_id: "srv-inventory" },
      risk_level: "low",
      policy_version: "v1.0",
      approval_status: "pending",
      requested_by: "usr-dynamic",
      requested_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 86400000).toISOString(),
      is_expired: false,
      action_name: "Inspect Service Diagnostic Health",
      target_service_name: "Inventory API",
    };
  };

  const result = await executeProposalWorkflow({
    workspaceId: "ws-1111",
    serviceId: "srv-inventory",
    incidentId: "inc-1111",
    investigationId: "inv-1111",
    token: "valid-token",
    actionId: "inspect_service_health",
    parameters: { service_id: "srv-inventory", health_path: "/api/v1/health" },
    environment: "development",
    playbookId: "pb-uuid-1",
    playbookVersion: 1,
    apiClient: {
      evaluatePolicy: mockEvaluatePolicy,
      createApproval: mockCreateApproval,
    },
  });

  assert.strictEqual(result.success, true);
  if (result.success) {
    assert.strictEqual(result.approvalId, "approval-uuid-2");
    assert.match(result.actionName, /Inspect Service Diagnostic Health/);
  }

  assert.deepStrictEqual(capturedPolicyRequest, {
    workspace_id: "ws-1111",
    action_id: "inspect_service_health",
    parameters: { service_id: "srv-inventory", health_path: "/api/v1/health" },
    environment: "development",
    playbook_id: "pb-uuid-1",
    playbook_version: 1,
  });

  assert.deepStrictEqual(capturedApprovalRequest, {
    workspace_id: "ws-1111",
    policy_decision_id: "decision-uuid-2",
    incident_id: "inc-1111",
    investigation_id: "inv-1111",
    expires_in_hours: 24,
  });
});

test("7. executeProposalWorkflow: Policy rejection due to stale playbook version is handled cleanly", async () => {
  const mockEvaluatePolicy = async (req: PolicyEvaluationRequest): Promise<PolicyDecisionResponse> => {
    return {
      id: "decision-rejected",
      workspace_id: req.workspace_id,
      action_id: req.action_id,
      target_service_id: req.parameters.service_id,
      risk_level: "low",
      decision: "rejected",
      decision_reason: "Playbook version mismatch: Playbook is at version v2, but recommendation was v1.",
      policy_version: "v1.0",
      approval_required: true,
      validated_parameters: {},
      evaluated_at: new Date().toISOString(),
    };
  };

  const result = await executeProposalWorkflow({
    workspaceId: "ws-1111",
    serviceId: "srv-inventory",
    incidentId: "inc-1111",
    token: "valid-token",
    actionId: "inspect_service_health",
    playbookId: "pb-uuid-1",
    playbookVersion: 1,
    apiClient: {
      evaluatePolicy: mockEvaluatePolicy,
      createApproval: async () => { throw new Error("Should not be called"); },
    },
  });

  assert.strictEqual(result.success, false);
  if (!result.success) {
    assert.strictEqual(result.errorType, "rejected");
    assert.match(result.message, /Playbook version mismatch/);
  }
});
