# SentinelOps AI Documentation Index

Welcome to the internal engineering documentation for **SentinelOps AI**, an enterprise-grade autonomous incident detection, agentic diagnostic investigation, policy-governed human-in-the-loop approval, and container-isolated remediation platform.

---

## Architecture & Specification Guides

| Document | Description | Focus Area |
|---|---|---|
| [**System Architecture**](ARCHITECTURE.md) | Comprehensive system architecture, multi-tenant workspace isolation, detection engine, and database schema. | Core Architecture & Data Models |
| [**Durable Execution Architecture**](PHASE_4_3_EXECUTION_ARCHITECTURE.md) | Technical specification of the Revision 10 container-native execution topology, standalone Docker broker daemon (`SO_PEERCRED`), and crash-durable execution worker. | Execution & Sandbox Isolation |
| [**Verification & Recovery Architecture**](PHASE_4_3_6_ARCHITECTURE.md) | Specification of the `PostExecutionVerificationEngine` (multi-probe synthetic health evaluation) and atomic `IncidentRecoveryBridge`. | Post-Execution Verification & Recovery |
| [**Final Validation Report**](PHASE_4_3_6_FINAL_VALIDATION_REPORT.md) | Authoritative audit report covering test suite execution, security adversarial validations, crash reconciliation, and state machine invariants. | Quality Assurance & Safety Verification |

---

## Test Suite & Validation Status

* **Backend Pytest Suite**: **508 passed, 2 skipped** (100% pass rate across 510 collected items and 38 test suites).
* **Frontend Integration Suite**: **49 passed, 0 failures** (Node/tsx runner across all 3 end-to-end integration test suites).
* **TypeScript & ESLint**: 0 type errors, 0 ESLint errors.
* **Production Build**: Next.js 16.4.3 (Turbopack) successfully compiled all 16 application routes.

---

## Quick Navigation

* **Root Quickstart & Runbook**: See [Root README.md](../README.md) for local installation, Docker Compose orchestrations, testing commands, and the 9-stage end-to-end Order API demonstration.
* **Backend Source Code**: [`backend/app/`](../backend/app/)
* **Frontend Source Code**: [`frontend/src/app/`](../frontend/src/app/)
* **Isolated Executor & Broker**: [`services/broker/`](../services/broker/) and [`services/executor/`](../services/executor/)
* **Monitored Demo Workload**: [`services/order-api/`](../services/order-api/)
