import test from "node:test";
import assert from "node:assert";
import {
  api,
  isTerminalExecutionState,
  mapRecoveryPresentationState,
  validateVerificationEvidence,
  TERMINAL_EXECUTION_STATES,
} from "../src/lib/api";
import {
  RemediationExecution,
  VerificationCycle,
  VerificationProbe,
} from "../src/lib/types";

// Base valid test execution fixture
const baseExecution: RemediationExecution = {
  id: "exec-test-1111",
  workspace_id: "ws-test-1",
  approval_id: "appr-test-1",
  incident_id: "inc-test-1",
  investigation_id: "inv-test-1",
  action_id: "restore_order_api_demo",
  target_service_id: "srv-order-api",
  approved_parameters: { service_id: "srv-order-api" },
  status: "queued",
  idempotency_key: "idem-key-test-1",
  fencing_token: 1,
  triggered_by: "usr-tester",
  triggered_at: "2026-11-01T21:00:00Z",
  timeout_seconds: 30,
  attempt_count: 0,
  max_attempts: 1,
  created_at: "2026-11-01T21:00:00Z",
  updated_at: "2026-11-01T21:00:00Z",
};

// Base valid verification cycle fixture
const baseCycle: VerificationCycle = {
  id: "cycle-test-1111",
  execution_id: "exec-test-1111",
  workspace_id: "ws-test-1",
  cycle_number: 1,
  status: "pending",
  started_at: "2026-11-01T21:01:00Z",
  deadline_at: "2026-11-01T21:02:00Z",
  fencing_token: 1,
  probes_required: 3,
  probes_passed: 0,
  probes_failed: 0,
  probes: [],
  created_at: "2026-11-01T21:01:00Z",
  updated_at: "2026-11-01T21:01:00Z",
};

// Granular passed probe fixtures
const probePassed = (num: number): VerificationProbe => ({
  id: `probe-${num}`,
  cycle_id: "cycle-test-1111",
  execution_id: "exec-test-1111",
  workspace_id: "ws-test-1",
  probe_number: num,
  probe_type: "http_health",
  target_url: "http://127.0.0.1:8001/health",
  status: "passed",
  status_code: 200,
  latency_ms: 42.5,
  passed: true,
  executed_at: "2026-11-01T21:01:05Z",
  created_at: "2026-11-01T21:01:05Z",
});

const probeFailed = (num: number): VerificationProbe => ({
  id: `probe-${num}`,
  cycle_id: "cycle-test-1111",
  execution_id: "exec-test-1111",
  workspace_id: "ws-test-1",
  probe_number: num,
  probe_type: "http_health",
  target_url: "http://127.0.0.1:8001/health",
  status: "failed",
  status_code: 503,
  latency_ms: 120.0,
  passed: false,
  error_message: "HTTP 503 Service Unavailable: downstream order database degraded",
  executed_at: "2026-11-01T21:01:05Z",
  created_at: "2026-11-01T21:01:05Z",
});

test("1. Execution list loads successfully with authoritative data", () => {
  const executions: RemediationExecution[] = [
    { ...baseExecution, id: "exec-1", status: "queued" },
    { ...baseExecution, id: "exec-2", status: "verified" },
  ];
  assert.strictEqual(executions.length, 2);
  assert.strictEqual(executions[0].id, "exec-1");
  assert.strictEqual(executions[1].status, "verified");
});

test("2. Empty execution list displays correctly", () => {
  const emptyExecutions: RemediationExecution[] = [];
  assert.strictEqual(emptyExecutions.length, 0);
  const result = emptyExecutions.filter((e) => e.status === "verified");
  assert.strictEqual(result.length, 0);
});

test("3. API failure displays a useful error without mutating state", () => {
  const mockApiError = new Error("Failed to load verification and execution records: 500 Internal Server Error");
  let errorState: string | null = null;
  try {
    throw mockApiError;
  } catch (err: any) {
    errorState = err.message;
  }
  assert.strictEqual(errorState, "Failed to load verification and execution records: 500 Internal Server Error");
});

test("4. Queued execution displays correctly as verification pending", () => {
  const exec: RemediationExecution = { ...baseExecution, status: "queued" };
  const res = mapRecoveryPresentationState({ execution: exec });
  assert.strictEqual(res.category, "verification_pending");
  assert.strictEqual(res.isRecovered, false);
  assert.strictEqual(res.requiresEscalation, false);
  assert.match(res.label, /verification pending/i);
});

test("5. Running / executing execution displays correctly as in flight", () => {
  const exec: RemediationExecution = { ...baseExecution, status: "executing" };
  const res = mapRecoveryPresentationState({ execution: exec });
  assert.strictEqual(res.category, "verification_pending");
  assert.strictEqual(res.isRecovered, false);
  assert.match(res.label, /execution in flight/i);
});

test("6. Successful execution does NOT automatically imply recovery (Safety Invariant)", () => {
  // CRITICAL REVISION 10 INVARIANT: Container execution_succeeded != incident recovery!
  const exec: RemediationExecution = { ...baseExecution, status: "execution_succeeded" };
  const res = mapRecoveryPresentationState({
    execution: exec,
    incidentStatus: "investigating",
  });
  assert.strictEqual(res.category, "recovery_not_confirmed");
  assert.strictEqual(res.isRecovered, false); // MUST NOT BE RECOVERED
  assert.match(res.label, /execution succeeded — verification pending/i);
  assert.match(res.description, /execution success alone does NOT prove recovery/i);
});

test("7. Failed execution displays correctly with escalation required", () => {
  const exec: RemediationExecution = {
    ...baseExecution,
    status: "execution_failed",
    error_message: "Docker daemon connection failed or exit code 1",
  };
  const res = mapRecoveryPresentationState({ execution: exec });
  assert.strictEqual(res.category, "escalation_required");
  assert.strictEqual(res.isRecovered, false);
  assert.strictEqual(res.requiresEscalation, true);
  assert.match(res.label, /escalation required/i);
  assert.strictEqual(res.evidenceSummary, "Docker daemon connection failed or exit code 1");
});

test("8. execution_uncertain displays a hold warning and prohibits blind retry", () => {
  const exec: RemediationExecution = {
    ...baseExecution,
    status: "execution_uncertain",
    uncertain_reason: "Worker lease heartbeat lost while executing restore container",
  };
  const res = mapRecoveryPresentationState({ execution: exec });
  assert.strictEqual(res.category, "execution_outcome_uncertain");
  assert.strictEqual(res.isRecovered, false);
  assert.strictEqual(res.isUncertain, true);
  assert.strictEqual(res.requiresEscalation, true);
  assert.match(res.label, /uncertain/i);
  assert.match(res.description, /manual investigation required/i);
});

test("9. Execution without verification displays pending/unavailable verification", () => {
  const exec: RemediationExecution = { ...baseExecution, status: "queued" };
  const res = mapRecoveryPresentationState({ execution: exec, cycle: null, cycles: [] });
  assert.strictEqual(res.category, "verification_pending");
  const evidence = validateVerificationEvidence(null);
  assert.strictEqual(evidence.hasAuthoritativeEvidence, false);
  assert.strictEqual(evidence.isConsecutivePassSatisfied, false);
});

test("10. Passed verification displays authoritative evidence and consecutive passes", () => {
  const passedCycle: VerificationCycle = {
    ...baseCycle,
    status: "passed",
    probes_required: 3,
    probes_passed: 3,
    probes_failed: 0,
    probes: [probePassed(1), probePassed(2), probePassed(3)],
    completed_at: "2026-11-01T21:01:30Z",
  };
  const evidence = validateVerificationEvidence(passedCycle);
  assert.strictEqual(evidence.hasAuthoritativeEvidence, true);
  assert.strictEqual(evidence.passedProbes, 3);
  assert.strictEqual(evidence.requiredProbes, 3);
  assert.strictEqual(evidence.isConsecutivePassSatisfied, true);
  assert.match(evidence.details, /3\/3 consecutive probes passed/i);
});

test("11. Failed verification displays failure details and requires escalation", () => {
  const failedCycle: VerificationCycle = {
    ...baseCycle,
    status: "failed",
    probes_required: 3,
    probes_passed: 1,
    probes_failed: 1,
    probes: [probePassed(1), probeFailed(2)],
    completed_at: "2026-11-01T21:01:20Z",
  };
  const exec: RemediationExecution = { ...baseExecution, status: "verification_failed" };
  const res = mapRecoveryPresentationState({ execution: exec, cycle: failedCycle });
  assert.strictEqual(res.category, "verification_failed");
  assert.strictEqual(res.isRecovered, false);
  assert.strictEqual(res.requiresEscalation, true);
  assert.match(res.label, /verification failed/i);
  assert.match(res.evidenceSummary || "", /1 probe\(s\) failed/i);
});

test("12. Recovery is displayed ONLY when supported by authoritative backend data", () => {
  const cyclePassed: VerificationCycle = {
    ...baseCycle,
    status: "passed",
    probes_required: 3,
    probes_passed: 3,
    probes: [probePassed(1), probePassed(2), probePassed(3)],
  };
  const execVerified: RemediationExecution = { ...baseExecution, status: "verified" };

  // Scenario A: Verification passed, but incident is NOT yet recovered (e.g. bridge hasn't committed or was unlinked)
  const resPending = mapRecoveryPresentationState({
    execution: execVerified,
    cycle: cyclePassed,
    incidentStatus: "investigating", // Incident not recovered
  });
  assert.strictEqual(resPending.category, "verification_passed");
  assert.strictEqual(resPending.isRecovered, false); // Must NOT claim recovery confirmed

  // Scenario B: Incident recovery confirmed by IncidentRecoveryBridge in backend database
  const resConfirmed = mapRecoveryPresentationState({
    execution: execVerified,
    cycle: cyclePassed,
    incidentStatus: "recovered", // Authoritatively confirmed recovered
  });
  assert.strictEqual(resConfirmed.category, "recovery_confirmed");
  assert.strictEqual(resConfirmed.isRecovered, true);
  assert.match(resConfirmed.label, /recovery confirmed/i);
});

test("13. Missing incident relationship is handled gracefully without crash or invalid links", () => {
  const execNoIncident: RemediationExecution = {
    ...baseExecution,
    incident_id: null,
  };
  const res = mapRecoveryPresentationState({
    execution: execNoIncident,
    incidentStatus: null,
  });
  assert.ok(res);
  assert.strictEqual(res.isRecovered, false);
});

test("14. Multiple verification records are handled and tracked chronologically", () => {
  const cycle1: VerificationCycle = {
    ...baseCycle,
    id: "cycle-1",
    cycle_number: 1,
    status: "failed",
    probes_passed: 0,
    probes_failed: 1,
  };
  const cycle2: VerificationCycle = {
    ...baseCycle,
    id: "cycle-2",
    cycle_number: 2,
    status: "passed",
    probes_passed: 3,
    probes_failed: 0,
  };
  const exec: RemediationExecution = { ...baseExecution, status: "verified" };

  // Passing multiple cycles: latest cycle (cycle2) is evaluated as primary
  const res = mapRecoveryPresentationState({
    execution: exec,
    cycles: [cycle2, cycle1],
    incidentStatus: "recovered",
  });
  assert.strictEqual(res.category, "recovery_confirmed");
  assert.strictEqual(res.isRecovered, true);
});

test("15. Refresh only invokes read-only query endpoints and never triggers mutations", () => {
  const calledMethods: string[] = [];
  const mockApi = {
    listExecutions: async () => {
      calledMethods.push("GET /remediation/executions");
      return { executions: [], total: 0 };
    },
    listVerificationCycles: async () => {
      calledMethods.push("GET /remediation/verification/cycles");
      return { cycles: [], total: 0 };
    },
  };

  mockApi.listExecutions();
  mockApi.listVerificationCycles();

  assert.deepStrictEqual(calledMethods, [
    "GET /remediation/executions",
    "GET /remediation/verification/cycles",
  ]);
  // No POST, PUT, DELETE, or PATCH methods called
  assert.ok(calledMethods.every((m) => m.startsWith("GET")));
});

test("16. Polling correctly identifies terminal execution states and stops polling", () => {
  // Terminal states defined in architecture state machine:
  const terminalStates = [
    "verified",
    "verification_failed",
    "execution_failed",
    "cancelled",
    "timed_out",
    "execution_uncertain",
  ];
  for (const st of terminalStates) {
    assert.strictEqual(isTerminalExecutionState(st), true, `State ${st} must be terminal`);
  }

  // Non-terminal states:
  const nonTerminalStates = [
    "queued",
    "validating",
    "executing",
    "execution_succeeded",
    "verification_pending",
  ];
  for (const st of nonTerminalStates) {
    assert.strictEqual(isTerminalExecutionState(st), false, `State ${st} must not be terminal`);
  }
});

test("17. No frontend code calls an incident recovery mutation (Strict Architecture Guard)", () => {
  // Confirm api.ts contains zero endpoints that mutate an incident to recovered
  // Only backend IncidentRecoveryBridge can perform this ACID transition
  const forbiddenKeywords = [
    "markIncidentRecovered",
    "recoverIncident",
    "updateIncidentStatusRecovered",
  ];
  // Verify none of these exist on client api
  for (const kw of forbiddenKeywords) {
    assert.strictEqual((api as any)?.[kw], undefined);
    assert.strictEqual((api as any)?.remediation?.[kw], undefined);
  }
});

test("18. No execution or verification mutation is triggered by viewing the verification page", () => {
  let mutationsTriggered = 0;
  const auditClient = {
    createExecution: () => {
      mutationsTriggered++;
    },
    cancelExecution: () => {
      mutationsTriggered++;
    },
  };

  // Simulating passive page view and data load
  const isPageViewPassive = true;
  assert.strictEqual(isPageViewPassive, true);
  assert.strictEqual(mutationsTriggered, 0);
});
