import test from "node:test";
import assert from "node:assert";
import {
  evaluateProposalEligibility,
  executeProposalWorkflow,
  ApiError,
  ProposalEligibilityContext,
} from "../src/lib/api";
import { PolicyDecisionResponse, RemediationApproval, PolicyEvaluationRequest } from "../src/lib/types";

// Base valid test fixtures
const validContext: ProposalEligibilityContext = {
  role: "engineer",
  investigationStatus: "completed",
  hasTargetService: true,
  serviceEnvironment: "development",
  executionPolicy: "demo",
  workspaceId: "ws-1111",
  incidentWorkspaceId: "ws-1111",
  serviceWorkspaceId: "ws-1111",
  investigationWorkspaceId: "ws-1111",
  investigationIncidentId: "inc-1111",
  incidentId: "inc-1111",
};

const mockPolicyApprovalRequired: PolicyDecisionResponse = {
  id: "decision-uuid-1",
  workspace_id: "ws-1111",
  action_id: "restore_order_api_demo",
  target_service_id: "srv-1111",
  risk_level: "medium",
  decision: "approval_required",
  decision_reason: "Action 'restore_order_api_demo' requires human approval.",
  policy_version: "2026-03-v1",
  approval_required: true,
  validated_parameters: { service_id: "srv-1111" },
  evaluated_at: new Date().toISOString(),
};

const mockPolicyRejected: PolicyDecisionResponse = {
  id: "decision-uuid-2",
  workspace_id: "ws-1111",
  action_id: "restore_order_api_demo",
  target_service_id: "srv-1111",
  risk_level: "high",
  decision: "rejected",
  decision_reason: "Action rejected: service environment is production",
  policy_version: "2026-03-v1",
  approval_required: false,
  validated_parameters: {},
  evaluated_at: new Date().toISOString(),
};

const mockPolicyAllowed: PolicyDecisionResponse = {
  id: "decision-uuid-3",
  workspace_id: "ws-1111",
  action_id: "restore_order_api_demo",
  target_service_id: "srv-1111",
  risk_level: "low",
  decision: "allowed",
  decision_reason: "Pre-approved safe action without approval",
  policy_version: "2026-03-v1",
  approval_required: false,
  validated_parameters: {},
  evaluated_at: new Date().toISOString(),
};

const mockApprovalCreated: RemediationApproval = {
  id: "approval-uuid-999",
  workspace_id: "ws-1111",
  incident_id: "inc-1111",
  investigation_id: "inv-1111",
  policy_decision_id: "decision-uuid-1",
  action_id: "restore_order_api_demo",
  action_name: "Restore Order API Demo Service",
  action_description: "Restore Order API Demo service container",
  target_service_id: "srv-1111",
  target_service_name: "Order API",
  validated_parameters: { service_id: "srv-1111" },
  risk_level: "medium",
  policy_version: "2026-03-v1",
  approval_status: "pending",
  requested_by: "usr-1111",
  requested_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 86400000).toISOString(),
  is_expired: false,
};

test("1. Engineer can see the action when investigation is completed and service is eligible", () => {
  const result = evaluateProposalEligibility({
    ...validContext,
    role: "engineer",
  });
  assert.strictEqual(result.canInvestigate, true);
  assert.strictEqual(result.canPropose, true);
  assert.strictEqual(result.rejectionReason, undefined);
});

test("2. Admin can see the action", () => {
  const result = evaluateProposalEligibility({
    ...validContext,
    role: "admin",
  });
  assert.strictEqual(result.canInvestigate, true);
  assert.strictEqual(result.canPropose, true);
  assert.strictEqual(result.rejectionReason, undefined);
});

test("3. Viewer cannot see the action", () => {
  const result = evaluateProposalEligibility({
    ...validContext,
    role: "viewer",
  });
  assert.strictEqual(result.canInvestigate, false);
  assert.strictEqual(result.canPropose, false);
  assert.match(result.rejectionReason || "", /not authorized/);
});

test("4. Incomplete investigation prevents proposal creation", () => {
  const runningResult = evaluateProposalEligibility({
    ...validContext,
    investigationStatus: "running",
  });
  assert.strictEqual(runningResult.canPropose, false);
  assert.strictEqual(runningResult.isInvestigationComplete, false);

  const failedResult = evaluateProposalEligibility({
    ...validContext,
    investigationStatus: "failed",
  });
  assert.strictEqual(failedResult.canPropose, false);
  assert.strictEqual(failedResult.isInvestigationComplete, false);

  const missingResult = evaluateProposalEligibility({
    ...validContext,
    investigationStatus: null,
  });
  assert.strictEqual(missingResult.canPropose, false);
  assert.strictEqual(missingResult.isInvestigationComplete, false);
});

test("5. Missing service or workspace prevents proposal creation", () => {
  // Missing target service
  const noService = evaluateProposalEligibility({
    ...validContext,
    hasTargetService: false,
  });
  assert.strictEqual(noService.canPropose, false);
  assert.strictEqual(noService.hasTargetService, false);

  // Missing active workspace
  const noWorkspace = evaluateProposalEligibility({
    ...validContext,
    workspaceId: null,
  });
  assert.strictEqual(noWorkspace.canPropose, false);

  // Cross-tenant service mismatch
  const serviceMismatch = evaluateProposalEligibility({
    ...validContext,
    serviceWorkspaceId: "ws-different",
  });
  assert.strictEqual(serviceMismatch.canPropose, false);
  assert.strictEqual(serviceMismatch.isWorkspaceConsistent, false);

  // Cross-incident investigation mismatch
  const incidentMismatch = evaluateProposalEligibility({
    ...validContext,
    investigationIncidentId: "inc-different",
  });
  assert.strictEqual(incidentMismatch.canPropose, false);
  assert.strictEqual(incidentMismatch.isWorkspaceConsistent, false);
});

test("6. observe_only prevents proposal creation", () => {
  const result = evaluateProposalEligibility({
    ...validContext,
    executionPolicy: "observe_only",
  });
  assert.strictEqual(result.isObserveOnly, true);
  assert.strictEqual(result.canPropose, false);
  assert.match(result.rejectionReason || "", /observe_only/);
});

test("7. Unsupported environment prevents proposal creation", () => {
  const prodResult = evaluateProposalEligibility({
    ...validContext,
    serviceEnvironment: "production",
  });
  assert.strictEqual(prodResult.isSupportedActionEnvironment, false);
  assert.strictEqual(prodResult.canPropose, false);
  assert.match(prodResult.rejectionReason || "", /not supported/);

  const stagingResult = evaluateProposalEligibility({
    ...validContext,
    serviceEnvironment: "staging",
  });
  assert.strictEqual(stagingResult.isSupportedActionEnvironment, false);
  assert.strictEqual(stagingResult.canPropose, false);
});

test("8. Policy evaluation returning approval_required creates an approval", async () => {
  let evaluatedPayload: any = null;
  let createdApprovalPayload: any = null;

  const mockClient = {
    evaluatePolicy: async (data: PolicyEvaluationRequest, _token: string) => {
      evaluatedPayload = data;
      return mockPolicyApprovalRequired;
    },
    createApproval: async (data: any, _token: string) => {
      createdApprovalPayload = data;
      return mockApprovalCreated;
    },
  };

  const result = await executeProposalWorkflow({
    workspaceId: "ws-1111",
    serviceId: "srv-1111",
    incidentId: "inc-1111",
    investigationId: "inv-1111",
    token: "mock-jwt-token",
    apiClient: mockClient as any,
  });

  assert.strictEqual(result.success, true);
  if (result.success) {
    assert.strictEqual(result.approvalId, "approval-uuid-999");
    assert.strictEqual(result.actionName, "Restore Order API Demo Service");
  }

  // Verify evaluate payload was correct
  assert.deepStrictEqual(evaluatedPayload, {
    workspace_id: "ws-1111",
    action_id: "restore_order_api_demo",
    parameters: { service_id: "srv-1111" },
    environment: "development",
  });

  // Verify createApproval payload was correct
  assert.deepStrictEqual(createdApprovalPayload, {
    workspace_id: "ws-1111",
    policy_decision_id: "decision-uuid-1",
    incident_id: "inc-1111",
    investigation_id: "inv-1111",
    expires_in_hours: 24,
  });
});

test("9. Policy evaluation returning rejected does not create an approval", async () => {
  let createApprovalCalled = false;

  const mockClient = {
    evaluatePolicy: async (_data: any, _token: string) => mockPolicyRejected,
    createApproval: async (_data: any, _token: string) => {
      createApprovalCalled = true;
      return mockApprovalCreated;
    },
  };

  const result = await executeProposalWorkflow({
    workspaceId: "ws-1111",
    serviceId: "srv-1111",
    incidentId: "inc-1111",
    token: "mock-jwt-token",
    apiClient: mockClient as any,
  });

  assert.strictEqual(result.success, false);
  assert.strictEqual(createApprovalCalled, false);
  if (!result.success) {
    assert.strictEqual(result.errorType, "rejected");
    assert.match(result.message, /Policy Evaluation Rejected/);
  }
});

test("10. Policy evaluation returning allowed does not create an approval", async () => {
  let createApprovalCalled = false;

  const mockClient = {
    evaluatePolicy: async (_data: any, _token: string) => mockPolicyAllowed,
    createApproval: async (_data: any, _token: string) => {
      createApprovalCalled = true;
      return mockApprovalCreated;
    },
  };

  const result = await executeProposalWorkflow({
    workspaceId: "ws-1111",
    serviceId: "srv-1111",
    incidentId: "inc-1111",
    token: "mock-jwt-token",
    apiClient: mockClient as any,
  });

  assert.strictEqual(result.success, false);
  assert.strictEqual(createApprovalCalled, false);
  if (!result.success) {
    assert.strictEqual(result.errorType, "allowed");
    assert.match(result.message, /workflow expects an approval-required decision/);
  }
});

test("11. Approval creation HTTP 409 is handled gracefully", async () => {
  const mockClient = {
    evaluatePolicy: async (_data: any, _token: string) => mockPolicyApprovalRequired,
    createApproval: async (_data: any, _token: string) => {
      throw new ApiError("A pending proposal already exists for this action", 409, {
        detail: "Active approval request exists",
      });
    },
  };

  const result = await executeProposalWorkflow({
    workspaceId: "ws-1111",
    serviceId: "srv-1111",
    incidentId: "inc-1111",
    token: "mock-jwt-token",
    apiClient: mockClient as any,
  });

  assert.strictEqual(result.success, false);
  if (!result.success) {
    assert.strictEqual(result.errorType, "conflict");
    assert.match(result.message, /pending proposal already exists|pending approval request already exists/);
  }
});

test("12. Repeated clicks do not create duplicate simultaneous requests", async () => {
  let callCount = 0;
  let isProposing = false;

  const mockClient = {
    evaluatePolicy: async (_data: any, _token: string) => {
      callCount++;
      // Simulate network delay
      await new Promise((res) => setTimeout(res, 50));
      return mockPolicyApprovalRequired;
    },
    createApproval: async (_data: any, _token: string) => mockApprovalCreated,
  };

  // Simulate UI concurrency guard:
  const triggerClick = async () => {
    if (isProposing) return null;
    isProposing = true;
    try {
      return await executeProposalWorkflow({
        workspaceId: "ws-1111",
        serviceId: "srv-1111",
        incidentId: "inc-1111",
        token: "mock-jwt-token",
        apiClient: mockClient as any,
      });
    } finally {
      isProposing = false;
    }
  };

  // Dispatch two concurrent clicks simultaneously
  const [firstCall, secondCall] = await Promise.all([triggerClick(), triggerClick()]);

  assert.notStrictEqual(firstCall, null);
  assert.strictEqual(secondCall, null); // Blocked by guard
  assert.strictEqual(callCount, 1); // Only 1 request was dispatched
});

test("13. Successful proposal creation displays a link to the approval queue", async () => {
  const mockClient = {
    evaluatePolicy: async (_data: any, _token: string) => mockPolicyApprovalRequired,
    createApproval: async (_data: any, _token: string) => mockApprovalCreated,
  };

  const result = await executeProposalWorkflow({
    workspaceId: "ws-1111",
    serviceId: "srv-1111",
    incidentId: "inc-1111",
    token: "mock-jwt-token",
    apiClient: mockClient as any,
  });

  assert.strictEqual(result.success, true);
  if (result.success) {
    assert.strictEqual(result.approvalId, "approval-uuid-999");
    assert.strictEqual(result.actionName, "Restore Order API Demo Service");
    // Verify user message indicates creation
    assert.match(result.message, /created successfully/);
  }
});

test("14. Network and validation errors are handled correctly", async () => {
  // Test 401 Unauthorized
  const mockAuthErrorClient = {
    evaluatePolicy: async () => {
      throw new ApiError("Unauthorized", 401);
    },
    createApproval: async () => mockApprovalCreated,
  };
  const authResult = await executeProposalWorkflow({
    workspaceId: "ws-1111",
    serviceId: "srv-1111",
    incidentId: "inc-1111",
    token: "expired-token",
    apiClient: mockAuthErrorClient as any,
  });
  assert.strictEqual(authResult.success, false);
  if (!authResult.success) {
    assert.strictEqual(authResult.errorType, "auth");
    assert.match(authResult.message, /not authorized/);
  }

  // Test 422 Unprocessable Entity
  const mockValidationErrorClient = {
    evaluatePolicy: async () => {
      throw new ApiError("Validation Error", 422, [{ loc: ["body", "action_id"] }]);
    },
    createApproval: async () => mockApprovalCreated,
  };
  const valResult = await executeProposalWorkflow({
    workspaceId: "ws-1111",
    serviceId: "srv-1111",
    incidentId: "inc-1111",
    token: "mock-token",
    apiClient: mockValidationErrorClient as any,
  });
  assert.strictEqual(valResult.success, false);
  if (!valResult.success) {
    assert.strictEqual(valResult.errorType, "validation");
    assert.match(valResult.message, /validation failed/);
  }

  // Test Network Error
  const mockNetworkErrorClient = {
    evaluatePolicy: async () => {
      throw new Error("Failed to fetch: Connection refused");
    },
    createApproval: async () => mockApprovalCreated,
  };
  const netResult = await executeProposalWorkflow({
    workspaceId: "ws-1111",
    serviceId: "srv-1111",
    incidentId: "inc-1111",
    token: "mock-token",
    apiClient: mockNetworkErrorClient as any,
  });
  assert.strictEqual(netResult.success, false);
  if (!netResult.success) {
    assert.strictEqual(netResult.errorType, "network");
    assert.match(netResult.message, /Connection refused/);
  }
});
