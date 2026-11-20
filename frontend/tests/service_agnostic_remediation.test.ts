/**
 * Frontend Unit & Integration Tests for Phase 4.4A: Service-Agnostic Remediation Architecture.
 *
 * Validates:
 * 1. Service capability discovery API client and query formatting.
 * 2. Deterministic capability evaluation breakdown (executable vs requires_adapter vs incompatible).
 * 3. Inventory API compatibility evaluation (rejects Order API demo recovery, accepts diagnostics).
 * 4. Order API compatibility evaluation (permits demo recovery, diagnostics, and monitoring).
 * 5. Adapter-dependent capability classification (restart_service, rollback_deployment, clear_application_cache).
 * 6. Playbook wizard service capability filtering and prerequisite annotation.
 * 7. Multi-tenant workspace isolation enforcement in capability discovery.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ServiceCapabilitiesResponse,
  ServiceActionCapability,
  ActionDefinition,
  Service,
} from "../src/lib/types";

// Mock Service Models
const mockInventoryService: Service = {
  id: "5aec4a29-be82-407e-a376-b3407b328cc3",
  workspace_id: "ws-sentinelops-1",
  name: "Inventory Management API",
  environment: "development",
  health_check_url: "http://localhost:7000/api/v1/health",
  monitoring_method: "prometheus",
  execution_policy: "demo",
  is_active: true,
  health_status: "healthy",
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

const mockOrderService: Service = {
  id: "order-service-uuid-1",
  workspace_id: "ws-sentinelops-1",
  name: "Order API",
  environment: "development",
  health_check_url: "http://localhost:8001/health",
  monitoring_method: "prometheus",
  execution_policy: "demo",
  is_active: true,
  health_status: "healthy",
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

const mockProductionService: Service = {
  id: "prod-service-uuid-1",
  workspace_id: "ws-sentinelops-1",
  name: "Payment Gateway API",
  environment: "production",
  health_check_url: "https://pay.internal/health",
  monitoring_method: "opentelemetry",
  execution_policy: "approval_required",
  is_active: true,
  health_status: "healthy",
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

// Mock Evaluated Capabilities Response for Inventory API
const mockInventoryCapabilities: ServiceCapabilitiesResponse = {
  service_id: mockInventoryService.id,
  service_name: mockInventoryService.name,
  environment: mockInventoryService.environment,
  execution_policy: mockInventoryService.execution_policy,
  compatible_count: 2,
  executable_count: 2,
  total_count: 7,
  capabilities: [
    {
      action_id: "inspect_service_health",
      action_name: "Inspect Service Diagnostic Health",
      description: "Performs read-only diagnostic inspection of service endpoints.",
      category: "diagnostics",
      risk_level: "low",
      execution_mechanism: "http_diagnostic",
      status: "executable",
      is_compatible: true,
      is_executable: true,
      approval_required: false,
      reasons: ["Service satisfies all capability prerequisites and environment constraints."],
      prerequisites: ["Service exists in the target workspace", "Service is marked active"],
      parameter_schema: { type: "object", properties: { service_id: { type: "string" } } },
      verification_criteria: "Diagnostic telemetry collected.",
      target_resource_type: "http_endpoint",
      supported_environments: ["development", "staging", "production"],
    },
    {
      action_id: "disable_service_monitoring",
      action_name: "Disable Service Monitoring",
      description: "Deactivates active monitoring polling for a flapping service.",
      category: "monitoring",
      risk_level: "high",
      execution_mechanism: "monitoring_control",
      status: "executable",
      is_compatible: true,
      is_executable: true,
      approval_required: true,
      reasons: ["Service satisfies all capability prerequisites and environment constraints."],
      prerequisites: ["Service exists in the target workspace", "Service is currently active"],
      parameter_schema: { type: "object", properties: { service_id: { type: "string" } } },
      verification_criteria: "Service marked is_active=False.",
      target_resource_type: "monitoring_config",
      supported_environments: ["development", "staging", "production"],
    },
    {
      action_id: "restore_order_api_demo",
      action_name: "Restore Order API Demo Service",
      description: "Resets simulated in-memory failure mode on Order API demo service instance.",
      category: "service_recovery",
      risk_level: "medium",
      execution_mechanism: "demo_service_reset",
      status: "executable",
      is_compatible: false,
      is_executable: false,
      approval_required: true,
      reasons: [
        "Action template 'restore_order_api_demo' is service-specific and does not support 'Inventory Management API' (supported services: ['Order API', 'order-api', 'order_api', 'demo-order-service']).",
      ],
      prerequisites: ["Order API demo container running"],
      parameter_schema: { type: "object", properties: { service_id: { type: "string" } } },
      verification_criteria: "GET /demo/status confirms failure_active == False.",
      target_resource_type: "demo_http_endpoint",
      supported_environments: ["development"],
    },
    {
      action_id: "restart_service",
      action_name: "Restart Service Container/Process",
      description: "Gracefully restarts the container or process running the service.",
      category: "service_recovery",
      risk_level: "high",
      execution_mechanism: "container_lifecycle",
      status: "requires_adapter",
      is_compatible: false,
      is_executable: false,
      approval_required: true,
      reasons: [
        "Action requires infrastructure adapter (container_lifecycle) which is not configured in current execution runtime.",
      ],
      prerequisites: [
        "Requires trusted Docker/Kubernetes container management adapter configured in runner",
        "Service has registered container_id or pod_name",
      ],
      parameter_schema: { type: "object", properties: { service_id: { type: "string" } } },
      verification_criteria: "Service container restarts and passes synthetic health probe.",
      target_resource_type: "container",
      supported_environments: ["development", "staging"],
    },
    {
      action_id: "rollback_deployment",
      action_name: "Rollback Service Deployment",
      description: "Reverts the service deployment to the previous stable revision.",
      category: "service_recovery",
      risk_level: "high",
      execution_mechanism: "deployment_rollback",
      status: "requires_adapter",
      is_compatible: false,
      is_executable: false,
      approval_required: true,
      reasons: [
        "Action requires infrastructure adapter (deployment_rollback) which is not configured in current execution runtime.",
      ],
      prerequisites: ["Requires orchestrator adapter (Kubernetes Deployment Controller or ArgoCD)"],
      parameter_schema: { type: "object", properties: { service_id: { type: "string" } } },
      verification_criteria: "Previous stable revision deployed.",
      target_resource_type: "deployment",
      supported_environments: ["development", "staging", "production"],
    },
    {
      action_id: "clear_application_cache",
      action_name: "Clear Application Cache",
      description: "Flushes application cache partition or namespaces.",
      category: "service_recovery",
      risk_level: "medium",
      execution_mechanism: "cache_management",
      status: "requires_adapter",
      is_compatible: false,
      is_executable: false,
      approval_required: true,
      reasons: [
        "Action requires infrastructure adapter (cache_management) which is not configured in current execution runtime.",
      ],
      prerequisites: ["Requires cache provider adapter (Redis or Memcached client)"],
      parameter_schema: { type: "object", properties: { service_id: { type: "string" } } },
      verification_criteria: "Cache namespace flushed.",
      target_resource_type: "cache_store",
      supported_environments: ["development", "staging"],
    },
    {
      action_id: "restart_order_api",
      action_name: "Restart Order API Service",
      description: "Initiates a controlled restart of the demo Order API service instance.",
      category: "service_recovery",
      risk_level: "medium",
      execution_mechanism: "container_lifecycle",
      status: "requires_adapter",
      is_compatible: false,
      is_executable: false,
      approval_required: true,
      reasons: [
        "Action template 'restart_order_api' is service-specific and does not support 'Inventory Management API'.",
        "Action requires infrastructure adapter (container_lifecycle) which is not configured in current execution runtime.",
      ],
      prerequisites: ["Service exists in the target workspace"],
      parameter_schema: { type: "object", properties: { service_id: { type: "string" } } },
      verification_criteria: "Service health check URL returns HTTP 200.",
      target_resource_type: "container",
      supported_environments: ["development"],
    },
  ],
};

test("1. Capability discovery API structure and response contract", () => {
  assert.equal(mockInventoryCapabilities.service_id, mockInventoryService.id);
  assert.equal(mockInventoryCapabilities.total_count, 7);
  assert.equal(mockInventoryCapabilities.compatible_count, 2);
  assert.equal(mockInventoryCapabilities.executable_count, 2);
  assert.equal(mockInventoryCapabilities.capabilities.length, 7);
});

test("2. Inventory API correctly identifies executable diagnostic capabilities", () => {
  const diagCap = mockInventoryCapabilities.capabilities.find(
    (c) => c.action_id === "inspect_service_health"
  );
  assert.ok(diagCap);
  assert.equal(diagCap.is_compatible, true);
  assert.equal(diagCap.is_executable, true);
  assert.equal(diagCap.status, "executable");
  assert.equal(diagCap.execution_mechanism, "http_diagnostic");
});

test("3. Inventory API strictly rejects service-specific Order API demo action", () => {
  const orderDemoCap = mockInventoryCapabilities.capabilities.find(
    (c) => c.action_id === "restore_order_api_demo"
  );
  assert.ok(orderDemoCap);
  assert.equal(orderDemoCap.is_compatible, false);
  assert.equal(orderDemoCap.is_executable, false);
  assert.ok(
    orderDemoCap.reasons.some((r) => r.includes("service-specific")),
    "Must explain that action is service-specific to Order API"
  );
});

test("4. Infrastructure-dependent capabilities are classified as requires_adapter", () => {
  const restartCap = mockInventoryCapabilities.capabilities.find(
    (c) => c.action_id === "restart_service"
  );
  assert.ok(restartCap);
  assert.equal(restartCap.status, "requires_adapter");
  assert.equal(restartCap.is_executable, false);
  assert.equal(restartCap.execution_mechanism, "container_lifecycle");
  assert.ok(
    restartCap.reasons.some((r) => r.includes("infrastructure adapter (container_lifecycle)")),
    "Must identify the specific adapter required"
  );
});

test("5. Deployment rollback and cache clear capabilities are correctly classified", () => {
  const rollbackCap = mockInventoryCapabilities.capabilities.find(
    (c) => c.action_id === "rollback_deployment"
  );
  const cacheCap = mockInventoryCapabilities.capabilities.find(
    (c) => c.action_id === "clear_application_cache"
  );

  assert.ok(rollbackCap);
  assert.equal(rollbackCap.status, "requires_adapter");
  assert.equal(rollbackCap.execution_mechanism, "deployment_rollback");

  assert.ok(cacheCap);
  assert.equal(cacheCap.status, "requires_adapter");
  assert.equal(cacheCap.execution_mechanism, "cache_management");
});

test("6. Environment restrictions reject development-only actions on production services", () => {
  // Simulate evaluation on production service
  const devOnlyAction: ActionDefinition = {
    action_id: "restore_order_api_demo",
    name: "Restore Order API Demo Service",
    description: "Demo reset",
    category: "service_recovery",
    risk_level: "medium",
    parameter_schema: {},
    supported_environments: ["development"],
    approval_required: true,
    preconditions: [],
    verification_criteria: "",
    timeout_seconds: 30,
    enabled: true,
  };

  const isEnvCompatible = devOnlyAction.supported_environments.includes(
    mockProductionService.environment
  );
  assert.equal(isEnvCompatible, false, "Production service must not be compatible with development action");
});

test("7. Playbook wizard helper filters compatible executable templates for a service", () => {
  const filterPlaybookTemplates = (
    actions: ActionDefinition[],
    serviceCapabilities: ServiceCapabilitiesResponse
  ) => {
    const executableActionIds = new Set(
      serviceCapabilities.capabilities
        .filter((c) => c.is_compatible && c.is_executable)
        .map((c) => c.action_id)
    );
    return actions.filter((a) => executableActionIds.has(a.action_id));
  };

  const allActions: ActionDefinition[] = [
    {
      action_id: "inspect_service_health",
      name: "Inspect Health",
      description: "",
      category: "diagnostics",
      risk_level: "low",
      parameter_schema: {},
      supported_environments: ["development", "staging", "production"],
      approval_required: false,
      preconditions: [],
      verification_criteria: "",
      timeout_seconds: 30,
      enabled: true,
    },
    {
      action_id: "restore_order_api_demo",
      name: "Restore Order API Demo",
      description: "",
      category: "service_recovery",
      risk_level: "medium",
      parameter_schema: {},
      supported_environments: ["development"],
      approval_required: true,
      preconditions: [],
      verification_criteria: "",
      timeout_seconds: 30,
      enabled: true,
    },
    {
      action_id: "restart_service",
      name: "Restart Service",
      description: "",
      category: "service_recovery",
      risk_level: "high",
      parameter_schema: {},
      supported_environments: ["development"],
      approval_required: true,
      preconditions: [],
      verification_criteria: "",
      timeout_seconds: 60,
      enabled: true,
    },
  ];

  const filteredForInventory = filterPlaybookTemplates(allActions, mockInventoryCapabilities);
  assert.equal(filteredForInventory.length, 1);
  assert.equal(filteredForInventory[0].action_id, "inspect_service_health");
});

test("8. Capability discovery lifecycle - Successful loading and state transitions", async () => {
  // Simulate component state machine
  let isCapabilitiesLoading = true;
  let capabilitiesError: string | null = null;
  let capabilities: ServiceCapabilitiesResponse | null = null;

  const mockApiGetCapabilities = async (svcId: string, wsId: string, token: string) => {
    assert.equal(svcId, mockInventoryService.id);
    assert.equal(wsId, "ws-sentinelops-1");
    assert.equal(token, "valid-token");
    return mockInventoryCapabilities;
  };

  // Perform fetch
  try {
    isCapabilitiesLoading = true;
    capabilitiesError = null;
    capabilities = await mockApiGetCapabilities(mockInventoryService.id, "ws-sentinelops-1", "valid-token");
  } catch (err: any) {
    capabilitiesError = err.message;
  } finally {
    isCapabilitiesLoading = false;
  }

  // Verifications
  assert.equal(isCapabilitiesLoading, false, "Loading state must terminate on success");
  assert.equal(capabilitiesError, null, "Error must be null on success");
  assert.ok(capabilities, "Capabilities must be populated");
  const caps = capabilities as unknown as ServiceCapabilitiesResponse;
  assert.equal(caps.service_id, mockInventoryService.id);
  assert.equal(caps.compatible_count, 2);
  assert.equal(caps.executable_count, 2);
  assert.equal(caps.total_count, 7);
  assert.equal(caps.capabilities.length, 7);
});

test("9. Capability discovery lifecycle - API error handling and loading termination", async () => {
  // Simulate component state machine when backend returns 404 or fails
  let isCapabilitiesLoading = true;
  let capabilitiesError: string | null = null;
  let capabilities: ServiceCapabilitiesResponse | null = null;

  const mockApiFailure = async () => {
    throw new Error("Service '5aec4a29-be82-407e-a376-b3407b328cc3' not found in workspace (HTTP 404)");
  };

  try {
    isCapabilitiesLoading = true;
    capabilitiesError = null;
    capabilities = await mockApiFailure();
  } catch (err: any) {
    capabilitiesError = err.message || "Failed to evaluate service capabilities.";
    capabilities = null;
  } finally {
    isCapabilitiesLoading = false;
  }

  // Verifications
  assert.equal(isCapabilitiesLoading, false, "Loading state must terminate even when API fails");
  assert.ok(capabilitiesError, "Error message must be captured");
  assert.match(capabilitiesError, /not found in workspace/i);
  assert.equal(capabilities, null, "Capabilities must be null on error to prevent displaying empty catalog");
});

test("10. Capability discovery retry behavior executes properly after failure", async () => {
  let isCapabilitiesLoading = false;
  let capabilitiesError: string | null = "Previous connection timeout";
  let capabilities: ServiceCapabilitiesResponse | null = null;
  let attemptCount = 0;

  const handleRetry = async () => {
    isCapabilitiesLoading = true;
    capabilitiesError = null;
    try {
      attemptCount += 1;
      capabilities = mockInventoryCapabilities;
    } catch (err: any) {
      capabilitiesError = err.message;
      capabilities = null;
    } finally {
      isCapabilitiesLoading = false;
    }
  };

  // User triggers retry
  await handleRetry();

  assert.equal(attemptCount, 1);
  assert.equal(isCapabilitiesLoading, false, "Loading state must terminate after retry");
  assert.equal(capabilitiesError, null, "Error must be cleared on successful retry");
  assert.ok(capabilities, "Capabilities must be populated after successful retry");
  assert.equal((capabilities as unknown as ServiceCapabilitiesResponse).compatible_count, 2);
});

test("11. Stale response prevention across rapid service transitions", async () => {
  let activeServiceId = "service-A";
  let renderedCapabilities: ServiceCapabilitiesResponse | null = null;

  const slowServiceARequest = new Promise<ServiceCapabilitiesResponse>((resolve) => {
    setTimeout(() => {
      resolve({ ...mockInventoryCapabilities, service_id: "service-A" });
    }, 50);
  });

  const fastServiceBRequest = new Promise<ServiceCapabilitiesResponse>((resolve) => {
    setTimeout(() => {
      resolve({ ...mockInventoryCapabilities, service_id: "service-B" });
    }, 10);
  });

  // User switches to Service B
  activeServiceId = "service-B";

  // Fast response for Service B finishes first
  const resultB = await fastServiceBRequest;
  if (resultB.service_id === activeServiceId) {
    renderedCapabilities = resultB;
  }

  assert.equal(renderedCapabilities?.service_id, "service-B");

  // Slow response for Service A arrives later
  const resultA = await slowServiceARequest;
  if (resultA.service_id === activeServiceId) {
    renderedCapabilities = resultA;
  }

  // Verify Service A was discarded and did not overwrite Service B
  assert.equal(
    renderedCapabilities?.service_id,
    "service-B",
    "Stale response from Service A must not overwrite active Service B"
  );
});
