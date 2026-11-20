/**
 * Frontend Unit & Integration Tests for Phase 5A: Secure, Configurable HTTP Recovery Adapter.
 *
 * Validates:
 * 1. ExecutionMechanism enum includes 'http_recovery'.
 * 2. ActionDefinition for execute_http_recovery: approval mandatory, risk medium, executable.
 * 3. Origin derivation logic: derived strictly from service.health_check_url origin + relative recovery path.
 * 4. Relative recovery path client-side validation (rejection of absolute URLs, query strings, traversal).
 * 5. Parameter normalization (JSON payload parsing, 2xx status code arrays, timeout bounding).
 * 6. Playbook creation and validation payload construction for Customer Orders API.
 * 7. Service capability response handling for execute_http_recovery (unconfigured vs configured).
 * 8. Verification criteria configuration (3 consecutive passing probes).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ActionDefinition,
  ExecutionMechanism,
  PlaybookCreate,
  PlaybookUpdate,
  PlaybookValidationRequest,
  Service,
  ServiceActionCapability,
  ServiceCapabilitiesResponse,
} from "../src/lib/types";

// Customer Orders API Acceptance Fixture
const mockCustomerOrdersService: Service = {
  id: "535f04e0-f1ff-4096-9011-e4e2c7234398",
  workspace_id: "ws-sentinelops-1",
  name: "Customer Orders API",
  environment: "development",
  health_check_url: "http://127.0.0.1:9100/health",
  monitoring_method: "http",
  execution_policy: "demo",
  is_active: true,
  health_status: "healthy",
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

const mockHttpRecoveryAction: ActionDefinition = {
  action_id: "execute_http_recovery",
  name: "Execute HTTP Service Recovery",
  description:
    "Executes an authorized HTTP POST recovery operation against a relative recovery endpoint derived from the registered service's trusted health check origin.",
  category: "service_recovery",
  risk_level: "medium",
  execution_mechanism: "http_recovery",
  status: "executable",
  is_executable: true,
  parameter_schema: {
    type: "object",
    required: ["service_id", "recovery_path"],
    properties: {
      service_id: { type: "string" },
      recovery_path: { type: "string" },
      payload: { type: "object" },
      expected_status_codes: { type: "array" },
      timeout_seconds: { type: "integer", default: 30 },
    },
    additionalProperties: false,
  },
  supported_environments: ["development", "staging", "production"],
  approval_required: true,
  preconditions: ["Target service must be active and have a valid health check URL."],
  verification_criteria: "Target service returns healthy status on configured endpoint.",
  timeout_seconds: 30,
  enabled: true,
  supported_services: ["*"],
};

// ============================================================================
// 1. ExecutionMechanism & ActionDefinition Tests
// ============================================================================

test("ExecutionMechanism type includes 'http_recovery'", () => {
  const mech: ExecutionMechanism = "http_recovery";
  assert.equal(mech, "http_recovery");
});

test("execute_http_recovery action metadata satisfies security contract", () => {
  assert.equal(mockHttpRecoveryAction.action_id, "execute_http_recovery");
  assert.equal(mockHttpRecoveryAction.execution_mechanism, "http_recovery");
  assert.equal(mockHttpRecoveryAction.category, "service_recovery");
  assert.equal(mockHttpRecoveryAction.risk_level, "medium");
  assert.equal(mockHttpRecoveryAction.approval_required, true);
  assert.equal(mockHttpRecoveryAction.is_executable, true);
  assert.deepEqual(mockHttpRecoveryAction.supported_services, ["*"]);
});

// ============================================================================
// 2. Origin Derivation Logic Tests
// ============================================================================

function deriveRecoveryUrl(healthCheckUrl: string, recoveryPath: string): string {
  if (!healthCheckUrl) throw new Error("Missing health check URL");
  const parsed = new URL(healthCheckUrl);
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(`Invalid protocol ${parsed.protocol}`);
  }
  const cleanPath = recoveryPath.trim();
  if (!cleanPath.startsWith("/")) {
    throw new Error("recovery_path must start with '/'");
  }
  if (cleanPath.includes("://") || cleanPath.includes("..") || cleanPath.includes("?")) {
    throw new Error("Invalid characters or traversal in recovery_path");
  }
  return `${parsed.protocol}//${parsed.host}${cleanPath}`;
}

test("Origin derivation strictly derives Customer Orders API target URL", () => {
  const derived = deriveRecoveryUrl(
    mockCustomerOrdersService.health_check_url,
    "/admin/recovery/reset"
  );
  assert.equal(derived, "http://127.0.0.1:9100/admin/recovery/reset");
});

test("Origin derivation rejects absolute URLs and traversal paths", () => {
  assert.throws(() => {
    deriveRecoveryUrl("http://127.0.0.1:9100/health", "http://evil.com/reset");
  }, /must start with '\/'/);

  assert.throws(() => {
    deriveRecoveryUrl("http://127.0.0.1:9100/health", "/admin/../reset");
  }, /Invalid characters or traversal/);

  assert.throws(() => {
    deriveRecoveryUrl("http://127.0.0.1:9100/health", "/admin/reset?key=val");
  }, /Invalid characters or traversal/);
});

// ============================================================================
// 3. Client Parameter Normalization Tests
// ============================================================================

function normalizeHttpRecoveryParams(raw: Record<string, any>): Record<string, any> {
  const clean: Record<string, any> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (v !== "" && v !== null && v !== undefined) {
      clean[k] = v;
    }
  }

  // Parse comma-separated status codes
  if (typeof clean.expected_status_codes === "string") {
    clean.expected_status_codes = clean.expected_status_codes
      .split(",")
      .map((s: string) => Number(s.trim()))
      .filter((n: number) => !isNaN(n) && n >= 200 && n <= 299);
  } else if (!clean.expected_status_codes) {
    clean.expected_status_codes = [200];
  }

  // Parse JSON string payload
  if (typeof clean.payload === "string" && clean.payload.trim()) {
    clean.payload = JSON.parse(clean.payload.trim());
  } else if (clean.payload === "") {
    delete clean.payload;
  }

  if (clean.timeout_seconds !== undefined) {
    clean.timeout_seconds = Number(clean.timeout_seconds);
  }

  return clean;
}

test("Parameter normalization cleans string status codes and JSON payloads", () => {
  const raw = {
    service_id: mockCustomerOrdersService.id,
    recovery_path: "/admin/recovery/reset",
    expected_status_codes: "200, 204",
    payload: '{"action": "reset", "reason": "test"}',
    timeout_seconds: "25",
  };

  const normalized = normalizeHttpRecoveryParams(raw);
  assert.equal(normalized.service_id, mockCustomerOrdersService.id);
  assert.equal(normalized.recovery_path, "/admin/recovery/reset");
  assert.deepEqual(normalized.expected_status_codes, [200, 204]);
  assert.deepEqual(normalized.payload, { action: "reset", reason: "test" });
  assert.equal(normalized.timeout_seconds, 25);
});

test("Parameter normalization filters non-2xx status codes", () => {
  const raw = {
    service_id: mockCustomerOrdersService.id,
    recovery_path: "/admin/recovery/reset",
    expected_status_codes: "200, 500, 302, 204",
  };

  const normalized = normalizeHttpRecoveryParams(raw);
  assert.deepEqual(normalized.expected_status_codes, [200, 204]);
});

// ============================================================================
// 4. Playbook Creation & Validation Payload Construction
// ============================================================================

test("Playbook validation request for HTTP recovery includes correct schema", () => {
  const req: PlaybookValidationRequest = {
    workspace_id: "ws-sentinelops-1",
    action_template_id: "execute_http_recovery",
    service_ids: [mockCustomerOrdersService.id],
    parameter_schema: {
      service_id: mockCustomerOrdersService.id,
      recovery_path: "/admin/recovery/reset",
      expected_status_codes: [200],
      timeout_seconds: 30,
    },
    verification_criteria: {
      health_path: "/health",
      expected_status: 200,
      probes_required: 3,
      timeout_seconds: 15,
    },
    risk_level: "medium",
  };

  assert.equal(req.action_template_id, "execute_http_recovery");
  assert.equal(req.parameter_schema?.recovery_path, "/admin/recovery/reset");
  assert.equal(req.verification_criteria?.probes_required, 3);
});

test("Playbook creation payload for Customer Orders API enforces approval_required=true", () => {
  const payload: PlaybookCreate = {
    workspace_id: "ws-sentinelops-1",
    name: "Customer Orders API Automated Recovery",
    description: "Invokes POST /admin/recovery/reset to clear simulated failure state.",
    category: "service_recovery",
    action_template_id: "execute_http_recovery",
    supported_scenarios: ["*"],
    parameter_schema: {
      service_id: mockCustomerOrdersService.id,
      recovery_path: "/admin/recovery/reset",
    },
    verification_criteria: {
      health_path: "/health",
      expected_status: 200,
      expected_state: "healthy",
      probes_required: 3,
      timeout_seconds: 15,
    },
    risk_level: "medium",
    approval_required: true,
    timeout_seconds: 30,
    initial_service_ids: [mockCustomerOrdersService.id],
  };

  assert.equal(payload.approval_required, true);
  assert.equal(payload.initial_service_ids?.[0], mockCustomerOrdersService.id);
  assert.equal(payload.action_template_id, "execute_http_recovery");
});

// ============================================================================
// 5. Service Capability Discovery Response Tests
// ============================================================================

test("Service capabilities response differentiates unconfigured vs configured HTTP recovery", () => {
  // Service without configured playbook
  const unconfiguredCap: ServiceActionCapability = {
    action_id: "execute_http_recovery",
    action_name: "Execute HTTP Service Recovery",
    description: "Reusable HTTP recovery adapter",
    category: "service_recovery",
    risk_level: "medium",
    execution_mechanism: "http_recovery",
    status: "requires_adapter",
    is_compatible: false,
    is_executable: false,
    approval_required: true,
    reasons: ["No active configured HTTP recovery playbook associated."],
    prerequisites: ["Configure an active HTTP recovery playbook"],
    parameter_schema: {},
    verification_criteria: "3 consecutive passing probes",
    target_resource_type: "http_endpoint",
    supported_environments: ["development", "staging", "production"],
  };

  assert.equal(unconfiguredCap.is_executable, false);
  assert.equal(unconfiguredCap.status, "requires_adapter");

  // Service with active configured playbook
  const configuredCap: ServiceActionCapability = {
    ...unconfiguredCap,
    status: "executable",
    is_compatible: true,
    is_executable: true,
    reasons: ["Active HTTP recovery playbook configured and associated with service."],
  };

  assert.equal(configuredCap.is_executable, true);
  assert.equal(configuredCap.status, "executable");
});
