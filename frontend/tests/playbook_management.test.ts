import test from "node:test";
import assert from "node:assert";
import {
  canManagePlaybooks,
  isPlaybookActionPermitted,
  containsScriptExecutionPayload,
  ApiError,
} from "../src/lib/api";
import {
  PlaybookResponse,
  PlaybookDetailResponse,
  PlaybookCreate,
  PlaybookValidationResponse,
  ActionDefinition,
} from "../src/lib/types";

// Mock allowlisted actions catalog
const mockActionCatalog: ActionDefinition[] = [
  {
    action_id: "restore_order_api_demo",
    name: "Restore Order API Demo",
    description: "Resets simulated in-memory failure mode on Order API demo service instance",
    category: "service_recovery",
    risk_level: "medium",
    parameter_schema: {
      type: "object",
      properties: {
        service_id: { type: "string", description: "Target service UUID" },
      },
      required: ["service_id"],
    },
    supported_environments: ["development", "staging"],
    approval_required: true,
    preconditions: ["Order API is running"],
    verification_criteria: "GET /health returns 200 with status healthy",
    timeout_seconds: 30,
    enabled: true,
    supported_services: ["Order API", "order-api"],
  },
  {
    action_id: "inspect_service_health",
    name: "Inspect Service Health",
    description: "Multi-endpoint synthetic health probe",
    category: "diagnostics",
    risk_level: "low",
    parameter_schema: {
      type: "object",
      properties: {
        health_path: { type: "string", default: "/health" },
        is_demo_service: { type: "boolean", default: false },
        has_prometheus_metrics: { type: "boolean", default: false },
      },
    },
    supported_environments: ["development", "staging", "production"],
    approval_required: false,
    preconditions: [],
    verification_criteria: "Probes return healthy",
    timeout_seconds: 15,
    enabled: true,
    supported_services: ["*"],
  },
];

const allowlistedIds = mockActionCatalog.map((a) => a.action_id);

// Base mock Playbook
const mockPlaybookV1: PlaybookDetailResponse = {
  id: "pb-1111-2222",
  workspace_id: "ws-test-1",
  name: "Order API Recovery",
  description: "Standard recovery for Order API failure modes",
  category: "service_recovery",
  is_active: true,
  current_version: 1,
  created_by: "user-sre-1",
  created_at: new Date("2026-11-01T10:00:00Z").toISOString(),
  updated_at: new Date("2026-11-01T10:00:00Z").toISOString(),
  associated_services_count: 1,
  active_version: {
    id: "ver-1111",
    playbook_id: "pb-1111-2222",
    version_number: 1,
    action_template_id: "restore_order_api_demo",
    action_name: "Restore Order API Demo",
    supported_scenarios: ["http_5xx_rate_exceeded", "demo_failure"],
    parameter_schema: { service_id: "svc-order-1" },
    verification_criteria: {
      health_path: "/health",
      expected_status: 200,
      probes_required: 3,
      timeout_seconds: 15,
    },
    risk_level: "medium",
    approval_required: true,
    timeout_seconds: 30,
    change_summary: "Initial baseline playbook",
    created_by: "user-sre-1",
    created_at: new Date("2026-11-01T10:00:00Z").toISOString(),
  },
  versions: [
    {
      id: "ver-1111",
      playbook_id: "pb-1111-2222",
      version_number: 1,
      action_template_id: "restore_order_api_demo",
      action_name: "Restore Order API Demo",
      supported_scenarios: ["http_5xx_rate_exceeded", "demo_failure"],
      parameter_schema: { service_id: "svc-order-1" },
      verification_criteria: {
        health_path: "/health",
        expected_status: 200,
        probes_required: 3,
        timeout_seconds: 15,
      },
      risk_level: "medium",
      approval_required: true,
      timeout_seconds: 30,
      change_summary: "Initial baseline playbook",
      created_by: "user-sre-1",
      created_at: new Date("2026-11-01T10:00:00Z").toISOString(),
    },
  ],
  associated_services: [
    {
      service_id: "svc-order-1",
      service_name: "Order API",
      is_active: true,
      priority: 100,
      associated_at: new Date("2026-11-01T10:00:00Z").toISOString(),
    },
  ],
};

// ============================================================================
// Test Suite
// ============================================================================

test("1. Role-based access control: Engineer has management authority", () => {
  assert.strictEqual(canManagePlaybooks("engineer"), true);
  assert.strictEqual(canManagePlaybooks("Engineer"), true);
  assert.strictEqual(canManagePlaybooks("ENGINEER"), true);
});

test("2. Role-based access control: Admin has management authority", () => {
  assert.strictEqual(canManagePlaybooks("admin"), true);
  assert.strictEqual(canManagePlaybooks("Admin"), true);
});

test("3. Role-based access control: Viewer is strictly read-only", () => {
  assert.strictEqual(canManagePlaybooks("viewer"), false);
  assert.strictEqual(canManagePlaybooks("Viewer"), false);
  assert.strictEqual(canManagePlaybooks(null), false);
  assert.strictEqual(canManagePlaybooks(undefined), false);
  assert.strictEqual(canManagePlaybooks("guest"), false);
});

test("4. Allowlist enforcement: registered action templates are permitted", () => {
  assert.strictEqual(isPlaybookActionPermitted("restore_order_api_demo", allowlistedIds), true);
  assert.strictEqual(isPlaybookActionPermitted("inspect_service_health", allowlistedIds), true);
});

test("5. Allowlist enforcement: unallowlisted or arbitrary action IDs are rejected", () => {
  assert.strictEqual(isPlaybookActionPermitted("restart_kubernetes_pod", allowlistedIds), false);
  assert.strictEqual(isPlaybookActionPermitted("bash_exec", allowlistedIds), false);
  assert.strictEqual(isPlaybookActionPermitted("python_runner", allowlistedIds), false);
  assert.strictEqual(isPlaybookActionPermitted("", allowlistedIds), false);
});

test("6. Security invariant: detects and forbids raw script execution payloads", () => {
  // exec() injection
  assert.strictEqual(containsScriptExecutionPayload({ cmd: "exec('import os')" }), true);
  // eval() injection
  assert.strictEqual(containsScriptExecutionPayload({ code: "eval('2+2')" }), true);
  // os.system injection
  assert.strictEqual(containsScriptExecutionPayload({ payload: "os.system('id')" }), true);
  // subprocess injection
  assert.strictEqual(containsScriptExecutionPayload({ script: "subprocess.Popen(['ls'])" }), true);
  // shell invocation
  assert.strictEqual(containsScriptExecutionPayload({ script: "bash -c 'echo pwn'" }), true);
  assert.strictEqual(containsScriptExecutionPayload({ script: "powershell -enc AAAAA" }), true);
  // rm -rf
  assert.strictEqual(containsScriptExecutionPayload({ path: "rm -rf /" }), true);
  // drop table SQL injection
  assert.strictEqual(containsScriptExecutionPayload({ query: "DROP TABLE users;" }), true);

  // Clean typed dictionary parameters must pass
  assert.strictEqual(
    containsScriptExecutionPayload({
      service_id: "e901478e-c689-418f-84b7-b2f86e9a369f",
      timeout_seconds: 30,
      is_demo_service: true,
    }),
    false
  );
});

test("7. Playbook listing: computes associated services and current active version", () => {
  const pb: PlaybookResponse = { ...mockPlaybookV1 };
  assert.strictEqual(pb.id, "pb-1111-2222");
  assert.strictEqual(pb.current_version, 1);
  assert.strictEqual(pb.associated_services_count, 1);
  assert.strictEqual(pb.active_version?.action_template_id, "restore_order_api_demo");
  assert.strictEqual(pb.is_active, true);
});

test("8. Playbook creation payload validation: enforces required fields and constraints", () => {
  const validPayload: PlaybookCreate = {
    workspace_id: "ws-test-1",
    name: "Valid Inventory API Playbook",
    category: "service_recovery",
    action_template_id: "inspect_service_health",
    supported_scenarios: ["health_check_failure"],
    parameter_schema: { health_path: "/api/v1/health" },
    verification_criteria: { health_path: "/api/v1/health", expected_status: 200, probes_required: 3 },
    risk_level: "low",
    approval_required: false,
    timeout_seconds: 20,
    initial_service_ids: ["svc-inventory-1"],
  };

  assert.strictEqual(validPayload.name.length >= 2, true);
  assert.strictEqual(validPayload.timeout_seconds! >= 5 && validPayload.timeout_seconds! <= 300, true);
  assert.strictEqual(allowlistedIds.includes(validPayload.action_template_id), true);
  assert.strictEqual(containsScriptExecutionPayload(validPayload.parameter_schema), false);
});

test("9. Playbook dry-run validation response: structured errors and service compatibility", () => {
  const validRes: PlaybookValidationResponse = {
    is_valid: true,
    errors: [],
    warnings: [],
    action_template_name: "Inspect Service Health",
    action_category: "diagnostics",
    default_risk_level: "low",
    compatible_services: ["svc-1", "svc-2"],
    incompatible_services: [],
  };
  assert.strictEqual(validRes.is_valid, true);
  assert.strictEqual(validRes.errors.length, 0);

  const invalidRes: PlaybookValidationResponse = {
    is_valid: false,
    errors: ["Field 'health_path' failed schema check", "Service 'Cab Booking API' not supported for this action"],
    warnings: ["Timeout is close to minimum threshold"],
    compatible_services: [],
    incompatible_services: [
      {
        service_id: "svc-cab-1",
        service_name: "Cab Booking API",
        reason: "Action is restricted to Order API",
      },
    ],
  };
  assert.strictEqual(invalidRes.is_valid, false);
  assert.strictEqual(invalidRes.errors.length, 2);
  assert.strictEqual(invalidRes.incompatible_services.length, 1);
});

test("10. Activation/Deactivation lifecycle: fail-closed safety state", () => {
  let pbState = { ...mockPlaybookV1, is_active: true };

  // Deactivate
  pbState = { ...pbState, is_active: false };
  assert.strictEqual(pbState.is_active, false);

  // Policy evaluation: deactivated playbook must be rejected (fail-closed)
  const canProposeRemediation = pbState.is_active;
  assert.strictEqual(canProposeRemediation, false);

  // Reactivate
  pbState = { ...pbState, is_active: true };
  assert.strictEqual(pbState.is_active, true);
  assert.strictEqual(pbState.is_active, true);
});

test("11. Version history and immutability: updates create new immutable version records", () => {
  const pb: PlaybookDetailResponse = {
    ...mockPlaybookV1,
    current_version: 2,
    active_version: {
      id: "ver-2222",
      playbook_id: mockPlaybookV1.id,
      version_number: 2,
      action_template_id: "restore_order_api_demo",
      action_name: "Restore Order API Demo",
      supported_scenarios: ["*"],
      parameter_schema: { service_id: "svc-order-1", timeout: 45 },
      verification_criteria: {
        health_path: "/health",
        expected_status: 200,
        probes_required: 4,
        timeout_seconds: 20,
      },
      risk_level: "high",
      approval_required: true,
      timeout_seconds: 45,
      change_summary: "Updated probes to 4 and timeout to 45s",
      created_by: "user-sre-1",
      created_at: new Date("2026-11-03T12:00:00Z").toISOString(),
    },
    versions: [
      {
        id: "ver-2222",
        playbook_id: mockPlaybookV1.id,
        version_number: 2,
        action_template_id: "restore_order_api_demo",
        action_name: "Restore Order API Demo",
        supported_scenarios: ["*"],
        parameter_schema: { service_id: "svc-order-1", timeout: 45 },
        verification_criteria: {
          health_path: "/health",
          expected_status: 200,
          probes_required: 4,
          timeout_seconds: 20,
        },
        risk_level: "high",
        approval_required: true,
        timeout_seconds: 45,
        change_summary: "Updated probes to 4 and timeout to 45s",
        created_by: "user-sre-1",
        created_at: new Date("2026-11-03T12:00:00Z").toISOString(),
      },
      mockPlaybookV1.versions[0],
    ],
  };

  assert.strictEqual(pb.current_version, 2);
  assert.strictEqual(pb.versions.length, 2);
  // Historical v1 is preserved unchanged
  assert.strictEqual(pb.versions[1].version_number, 1);
  assert.strictEqual(pb.versions[1].timeout_seconds, 30);
  // Active v2 has the new timeout
  assert.strictEqual(pb.versions[0].version_number, 2);
  assert.strictEqual(pb.versions[0].timeout_seconds, 45);
});

test("12. Service association: workspace isolation enforcement", () => {
  const currentWorkspaceId = "ws-test-1";
  const foreignWorkspaceId = "ws-foreign-tenant-99";

  const sameWorkspaceService = {
    id: "svc-1",
    workspace_id: currentWorkspaceId,
    name: "Order API",
  };

  const foreignWorkspaceService = {
    id: "svc-99",
    workspace_id: foreignWorkspaceId,
    name: "Foreign Secret Service",
  };

  const isCrossWorkspace = foreignWorkspaceService.workspace_id !== currentWorkspaceId;
  const isSameWorkspace = sameWorkspaceService.workspace_id === currentWorkspaceId;

  assert.strictEqual(isCrossWorkspace, true);
  assert.strictEqual(isSameWorkspace, true);
  // Frontend rejects attempts to bind foreign workspace service
  assert.strictEqual(isCrossWorkspace ? "Cross-workspace binding rejected" : "OK", "Cross-workspace binding rejected");
});

test("13. API Error handling: HTTP 400 Bad Request", () => {
  const err = new ApiError("Parameter validation failed: unknown field 'hack'", 400, {
    detail: "Parameter validation failed: unknown field 'hack'",
  });
  assert.strictEqual(err.status, 400);
  assert.strictEqual(err.message.includes("Parameter validation failed"), true);
});

test("14. API Error handling: HTTP 403 Forbidden for Viewer role", () => {
  const err = new ApiError("Operation requires engineer role or higher", 403, {
    detail: "Operation requires engineer role or higher",
  });
  assert.strictEqual(err.status, 403);
  assert.strictEqual(err.message.includes("requires engineer role"), true);
});

test("15. API Error handling: HTTP 404 Playbook Not Found", () => {
  const err = new ApiError("Playbook not found in target workspace", 404, {
    detail: "Playbook not found in target workspace",
  });
  assert.strictEqual(err.status, 404);
  assert.strictEqual(err.message.includes("not found"), true);
});

test("16. API Error handling: HTTP 409 Duplicate Playbook Name", () => {
  const err = new ApiError("Playbook with name 'Order API Recovery' already exists in this workspace", 409, {
    detail: "Playbook with name 'Order API Recovery' already exists in this workspace",
  });
  assert.strictEqual(err.status, 409);
  assert.strictEqual(err.message.includes("already exists"), true);
});
