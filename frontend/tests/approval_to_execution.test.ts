import test from "node:test";
import assert from "node:assert";
import {
  evaluateExecutionEligibility,
  executeRemediationWorkflow,
  ApiError,
  ExecutionEligibilityContext,
} from "../src/lib/api";
import { ExecutionCreateRequest, RemediationExecution } from "../src/lib/types";

// Base valid test fixtures
const validContext: ExecutionEligibilityContext = {
  role: "engineer",
  approvalStatus: "approved",
  isExpired: false,
  workspaceId: "ws-1111",
  approvalWorkspaceId: "ws-1111",
  isAlreadyExecuted: false,
};

const mockExecutionSuccess: RemediationExecution = {
  id: "exec-uuid-5555",
  workspace_id: "ws-1111",
  approval_id: "approval-uuid-111",
  incident_id: "inc-1111",
  investigation_id: "inv-1111",
  action_id: "restore_order_api_demo",
  target_service_id: "srv-1111",
  approved_parameters: { service_id: "srv-1111" },
  status: "queued",
  idempotency_key: "exec-test-key-1",
  fencing_token: 1,
  triggered_by: "usr-1111",
  triggered_at: new Date().toISOString(),
  timeout_seconds: 30,
  attempt_count: 0,
  max_attempts: 1,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

test("1. Approved proposal displays execution control for an authorized Engineer", () => {
  const result = evaluateExecutionEligibility({
    ...validContext,
    role: "engineer",
  });
  assert.strictEqual(result.canExecute, true);
  assert.strictEqual(result.isAuthorizedRole, true);
  assert.strictEqual(result.isApproved, true);
  assert.strictEqual(result.rejectionReason, undefined);
});

test("2. Approved proposal displays execution control for an authorized Admin", () => {
  const result = evaluateExecutionEligibility({
    ...validContext,
    role: "admin",
  });
  assert.strictEqual(result.canExecute, true);
  assert.strictEqual(result.isAuthorizedRole, true);
  assert.strictEqual(result.isApproved, true);
  assert.strictEqual(result.rejectionReason, undefined);
});

test("3. Viewer cannot execute", () => {
  const result = evaluateExecutionEligibility({
    ...validContext,
    role: "viewer",
  });
  assert.strictEqual(result.canExecute, false);
  assert.strictEqual(result.isAuthorizedRole, false);
  assert.match(result.rejectionReason || "", /not authorized/);
});

test("4. Pending proposal cannot execute", () => {
  const result = evaluateExecutionEligibility({
    ...validContext,
    approvalStatus: "pending",
  });
  assert.strictEqual(result.canExecute, false);
  assert.strictEqual(result.isApproved, false);
  assert.match(result.rejectionReason || "", /requires approved status/);
});

test("5. Rejected proposal cannot execute", () => {
  const result = evaluateExecutionEligibility({
    ...validContext,
    approvalStatus: "rejected",
  });
  assert.strictEqual(result.canExecute, false);
  assert.strictEqual(result.isApproved, false);
  assert.match(result.rejectionReason || "", /requires approved status/);
});

test("6. Cancelled proposal cannot execute", () => {
  const result = evaluateExecutionEligibility({
    ...validContext,
    approvalStatus: "cancelled",
  });
  assert.strictEqual(result.canExecute, false);
  assert.strictEqual(result.isApproved, false);
  assert.match(result.rejectionReason || "", /requires approved status/);
});

test("7. Expired proposal cannot execute", () => {
  const resultExplicit = evaluateExecutionEligibility({
    ...validContext,
    isExpired: true,
  });
  assert.strictEqual(resultExplicit.canExecute, false);
  assert.strictEqual(resultExplicit.isExpired, true);
  assert.match(resultExplicit.rejectionReason || "", /expired/);

  const resultStatus = evaluateExecutionEligibility({
    ...validContext,
    approvalStatus: "expired",
  });
  assert.strictEqual(resultStatus.canExecute, false);
  assert.strictEqual(resultStatus.isExpired, true);
});

test("8. Wrong-workspace proposal cannot execute", () => {
  const result = evaluateExecutionEligibility({
    ...validContext,
    approvalWorkspaceId: "ws-different-tenant",
  });
  assert.strictEqual(result.canExecute, false);
  assert.strictEqual(result.isWorkspaceMatch, false);
  assert.match(result.rejectionReason || "", /active workspace/);
});

test("9. Already-executed proposal cannot execute again", () => {
  const result = evaluateExecutionEligibility({
    ...validContext,
    isAlreadyExecuted: true,
  });
  assert.strictEqual(result.canExecute, false);
  assert.strictEqual(result.isAlreadyExecuted, true);
  assert.match(result.rejectionReason || "", /already been executed/);
});

test("10. Successful mocked execution displays execution ID and status", async () => {
  const mockClient = {
    createExecution: async (data: ExecutionCreateRequest, workspaceId: string, _token: string) => {
      assert.strictEqual(data.approval_id, "approval-uuid-111");
      assert.strictEqual(workspaceId, "ws-1111");
      return mockExecutionSuccess;
    },
  };

  const result = await executeRemediationWorkflow({
    approvalId: "approval-uuid-111",
    workspaceId: "ws-1111",
    token: "jwt-token-123",
    apiClient: mockClient as any,
  });

  assert.strictEqual(result.success, true);
  if (result.success) {
    assert.strictEqual(result.execution.id, "exec-uuid-5555");
    assert.strictEqual(result.execution.status, "queued");
    assert.match(result.message, /exec-uuid-5555/);
    assert.match(result.message, /queued/);
  }
});

test("11. HTTP 409 duplicate execution is handled correctly", async () => {
  const mockClient = {
    createExecution: async () => {
      throw new ApiError(
        "Remediation approval 'approval-uuid-111' has already been executed (execution ID: 'exec-uuid-5555'). Replay is prohibited.",
        409
      );
    },
  };

  const result = await executeRemediationWorkflow({
    approvalId: "approval-uuid-111",
    workspaceId: "ws-1111",
    token: "jwt-token-123",
    apiClient: mockClient as any,
  });

  assert.strictEqual(result.success, false);
  if (!result.success) {
    assert.strictEqual(result.errorType, "conflict");
    assert.match(result.message, /already been executed/);
  }
});

test("12. HTTP 401/403 authorization errors are handled", async () => {
  // Test 403 Forbidden
  const mockForbiddenClient = {
    createExecution: async () => {
      throw new ApiError("Role 'viewer' is not authorized to trigger remediation executions.", 403);
    },
  };

  const forbiddenResult = await executeRemediationWorkflow({
    approvalId: "approval-uuid-111",
    workspaceId: "ws-1111",
    token: "viewer-jwt-token",
    apiClient: mockForbiddenClient as any,
  });

  assert.strictEqual(forbiddenResult.success, false);
  if (!forbiddenResult.success) {
    assert.strictEqual(forbiddenResult.errorType, "auth");
    assert.match(forbiddenResult.message, /not authorized/);
  }

  // Test 401 Unauthorized
  const mockUnauthorizedClient = {
    createExecution: async () => {
      throw new ApiError("Unauthorized", 401);
    },
  };

  const unauthorizedResult = await executeRemediationWorkflow({
    approvalId: "approval-uuid-111",
    workspaceId: "ws-1111",
    token: "expired-jwt-token",
    apiClient: mockUnauthorizedClient as any,
  });

  assert.strictEqual(unauthorizedResult.success, false);
  if (!unauthorizedResult.success) {
    assert.strictEqual(unauthorizedResult.errorType, "auth");
  }
});

test("13. HTTP 422 validation errors are handled", async () => {
  const mockValidationClient = {
    createExecution: async () => {
      throw new ApiError("Validation Error", 422, [
        { loc: ["body", "approval_id"], msg: "Invalid UUID format" },
      ]);
    },
  };

  const result = await executeRemediationWorkflow({
    approvalId: "invalid-uuid",
    workspaceId: "ws-1111",
    token: "jwt-token-123",
    apiClient: mockValidationClient as any,
  });

  assert.strictEqual(result.success, false);
  if (!result.success) {
    assert.strictEqual(result.errorType, "validation");
    assert.match(result.message, /Validation failed/);
  }
});

test("14. Network timeout displays an uncertain state without automatic retry", async () => {
  let callCount = 0;
  const mockTimeoutClient = {
    createExecution: async () => {
      callCount++;
      throw new Error("AbortError: Network connection timed out after 30000ms");
    },
  };

  const result = await executeRemediationWorkflow({
    approvalId: "approval-uuid-111",
    workspaceId: "ws-1111",
    idempotencyKey: "stable-key-timeout-1",
    token: "jwt-token-123",
    apiClient: mockTimeoutClient as any,
  });

  assert.strictEqual(result.success, false);
  assert.strictEqual(callCount, 1); // Exactly 1 call; no automated blind retry
  if (!result.success) {
    assert.strictEqual(result.errorType, "uncertain");
    assert.match(result.message, /uncertain/i);
    assert.match(result.message, /do not retry blindly/i);
    // Verify idempotency key is preserved for any manual retry
    assert.strictEqual(result.idempotencyKey, "stable-key-timeout-1");
  }
});

test("15. Repeated clicks cannot submit concurrent execution requests", async () => {
  let callCount = 0;
  let isExecuting = false;

  const mockClient = {
    createExecution: async () => {
      callCount++;
      // Simulate in-flight backend network delay
      await new Promise((resolve) => setTimeout(resolve, 50));
      return mockExecutionSuccess;
    },
  };

  // Simulate UI concurrency lock
  const submitExecution = async () => {
    if (isExecuting) return null;
    isExecuting = true;
    try {
      return await executeRemediationWorkflow({
        approvalId: "approval-uuid-111",
        workspaceId: "ws-1111",
        token: "jwt-token-123",
        apiClient: mockClient as any,
      });
    } finally {
      isExecuting = false;
    }
  };

  // Dispatch two simultaneous calls
  const [firstCall, secondCall] = await Promise.all([submitExecution(), submitExecution()]);

  assert.notStrictEqual(firstCall, null);
  assert.strictEqual(secondCall, null); // Blocked by concurrency lock
  assert.strictEqual(callCount, 1); // Only 1 network request was created
});

test("16. The frontend never supplies or modifies approved action parameters", async () => {
  let capturedBody: any = null;
  let capturedWorkspaceQuery: string | null = null;

  const mockClient = {
    createExecution: async (data: ExecutionCreateRequest, workspaceId: string, _token: string) => {
      capturedBody = data;
      capturedWorkspaceQuery = workspaceId;
      return mockExecutionSuccess;
    },
  };

  await executeRemediationWorkflow({
    approvalId: "approval-uuid-111",
    workspaceId: "ws-1111",
    idempotencyKey: "key-safe-123",
    token: "jwt-token-123",
    apiClient: mockClient as any,
  });

  // Verify workspace_id is strictly a query parameter and NOT in body
  assert.strictEqual(capturedWorkspaceQuery, "ws-1111");

  // Verify body contains ONLY approved fields and NO action parameters
  const bodyKeys = Object.keys(capturedBody).sort();
  assert.deepStrictEqual(bodyKeys, ["approval_id", "idempotency_key"]);
  assert.strictEqual(capturedBody.approval_id, "approval-uuid-111");
  assert.strictEqual(capturedBody.idempotency_key, "key-safe-123");
  assert.strictEqual((capturedBody as any).parameters, undefined);
  assert.strictEqual((capturedBody as any).approved_parameters, undefined);
  assert.strictEqual((capturedBody as any).action_id, undefined);
});

test("17. Verification navigation is displayed after successful submission", async () => {
  const mockClient = {
    createExecution: async () => mockExecutionSuccess,
  };

  const result = await executeRemediationWorkflow({
    approvalId: "approval-uuid-111",
    workspaceId: "ws-1111",
    token: "jwt-token-123",
    apiClient: mockClient as any,
  });

  assert.strictEqual(result.success, true);
  if (result.success) {
    // Result provides execution ID and status needed for /verification link
    assert.strictEqual(result.execution.id, "exec-uuid-5555");
    assert.strictEqual(result.execution.status, "queued");
    assert.ok(result.message.includes("exec-uuid-5555"));
  }
});
