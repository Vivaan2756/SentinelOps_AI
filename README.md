# SentinelOps AI

> **Autonomous Incident Detection, Agentic SRE Diagnostics, Policy-Governed Human-in-the-Loop Remediation, and Container-Isolated Recovery.**

[![Backend Tests](https://img.shields.io/badge/backend%20tests-508%20passed%2C%202%20skipped-emerald.svg)](backend/tests/)
[![Frontend Tests](https://img.shields.io/badge/frontend%20tests-49%20passing-emerald.svg)](frontend/tests/)
[![Python](https://img.shields.io/badge/python-3.13-blue.svg)](backend/)
[![Next.js](https://img.shields.io/badge/next.js-16.4-black.svg)](frontend/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-teal.svg)](backend/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16%20%7C%2018-blue.svg)](backend/alembic/)
[![Docker](https://img.shields.io/badge/Docker-Broker%20%2B%20Worker-blue.svg)](docker-compose.yml)

---

## Table of Contents

1. [Project Overview & Objectives](#1-project-overview--objectives)
2. [Key Features & Capabilities](#2-key-features--capabilities)
3. [Technology Stack](#3-technology-stack)
4. [System Architecture](#4-system-architecture)
5. [Mermaid Architecture Diagram](#5-mermaid-architecture-diagram)
6. [Complete Incident-to-Recovery Workflow](#6-complete-incident-to-recovery-workflow)
7. [Directory Structure](#7-directory-structure)
8. [Prerequisites](#8-prerequisites)
9. [Environment Configuration](#9-environment-configuration)
10. [Database Setup & Alembic Migrations](#10-database-setup--alembic-migrations)
11. [Docker Topology & Service Startup](#11-docker-topology--service-startup)
12. [Local Development Commands](#12-local-development-commands)
13. [Testing Commands](#13-testing-commands)
14. [Security Architecture & Defense-in-Depth](#14-security-architecture--defense-in-depth)
15. [Step-by-Step 9-Stage Order API Demonstration](#15-step-by-step-9-stage-order-api-demonstration)
16. [Troubleshooting & Diagnostics](#16-troubleshooting--diagnostics)
17. [Current Limitations & Future Roadmap](#17-current-limitations--future-roadmap)

---

## 1. Project Overview & Objectives

**SentinelOps AI** is an enterprise site reliability engineering (SRE) platform designed to eliminate blind, unverified automated remediation while drastically reducing Mean Time to Detect (MTTD) and Mean Time to Recover (MTTR).

### Core Objectives
* **Autonomous Telemetry & Probing**: Continuous health and Prometheus metric evaluation without external polling daemons.
* **Agentic Diagnostic Reasoning**: Multi-agent incident investigation using LangGraph and Google Gemini 2.5 Flash, equipped with deterministic heuristic fallbacks for disconnected environments.
* **Deterministic Policy Enforcement**: Strict Pydantic parameter schemas (`extra="forbid"`), action allowlists, and risk classification preventing hallucinated actions or parameter injection.
* **Two-Person Integrity (Human-in-the-Loop)**: Strict four-eyes approval workflow for all high-risk operational changes with RBAC workspace enforcement.
* **Sandboxed Container-Isolated Execution**: Linux container-native execution topology separating Docker daemon privileges (`SO_PEERCRED` broker) from durable worker processes.
* **Mandatory Multi-Probe Post-Execution Verification**: Automated recovery verification requiring baseline plus 3 consecutive successful health probe cycles before closing an incident.

---

## 2. Key Features & Capabilities

* **Autonomous Detection Engine**: Built-in async poller evaluating service health, HTTP latency, and 5xx error rates every 10 seconds.
* **LangGraph Diagnostic Agent**: 6-node state graph gathering context, querying diagnostic telemetry, generating hypotheses, and computing confidence levels.
* **Strict Action Registry**: Only registered, pre-audited action IDs (`restore_order_api_demo`, `restart_order_api`, `inspect_service_health`) can ever be proposed or executed.
* **Durable PostgreSQL Job Queue**: Concurrency-safe execution claiming using PostgreSQL `SELECT ... FOR UPDATE SKIP LOCKED`, fencing tokens, and lease heartbeats.
* **Standalone Docker Broker Daemon**: Runs in an isolated Linux container (`network_mode: none`) holding exclusive access to `/var/run/docker.sock` and validating worker requests over a shared Unix socket with peer credential verification (`SO_PEERCRED`).
* **Connection-Time IP Pinning & SSRF Mitigation**: Ephemeral executor container resolves host addresses prior to connection and validates Docker host gateways, strictly rejecting unauthorized loopback or metadata endpoints.
* **Three-Way Crash Durability**: Synchronous write-ahead operation journal (`SOJ1`), local SQLite operation registry, and PostgreSQL state synchronization.
* **Transactional Recovery Bridge**: Single ACID database transaction atomically updating incident status to `recovered`, execution status to `completed`, and writing tamper-evident audit records.

---

## 3. Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Frontend** | Next.js 16 (App Router), React 19, TypeScript 5, Tailwind CSS | Operator cockpit, live telemetry charts, approval queues, and verification monitoring. |
| **Backend API** | FastAPI 0.115, Python 3.13, Pydantic v2, Pydantic-Settings | Control plane REST API, JWT auth, RBAC enforcement, and background polling. |
| **Agentic AI** | LangGraph 0.2, LangChain Google GenAI, Gemini 2.5 Flash | Root-cause hypothesis generation, log evidence correlation, and diagnosis synthesis. |
| **Authoritative DB** | PostgreSQL 16 / 18, SQLAlchemy 2.0, Alembic, psycopg v3 | Multi-tenant schema, state persistence, job queue, and immutable audit logs. |
| **Worker Engine** | Python AsyncIO, SQLite3, Custom Append-Only Journal (`SOJ1`) | Distributed durable background execution, lease acquisition, and crash recovery. |
| **Broker Daemon** | Python AsyncIO, Unix Domain Sockets, Docker Engine API | Privilege isolation, peer UID/GID credential checking (`SO_PEERCRED`). |
| **Remediation Sandbox** | Docker Engine, Alpine Linux, Custom Pinned HTTP Client | Disposable container executing allowlisted HTTP remediation actions. |
| **Monitored Workload** | FastAPI, Prometheus Client (`services/order-api`) | Demo microservice with in-memory deterministic failure injection and metrics. |

---

## 4. System Architecture

The architecture enforces a strict boundary between the control plane, execution engines, and the host environment:

1. **Host Control Plane**: The FastAPI backend, Next.js frontend, and monitored Order API run on the development host or standard container bridges.
2. **Authoritative State**: PostgreSQL stores all tenants, workspaces, services, incidents, investigations, approvals, executions, verification records, and audit events.
3. **Execution Worker (`sentinelops-worker`)**: Runs as unprivileged user `1000:1000`. It has **ZERO** access to the Docker daemon socket (`/var/run/docker.sock`). It claims executions from PostgreSQL and delegates execution requests over a shared Unix socket (`/var/run/sentinelops/broker.sock`).
4. **Restricted Broker (`sentinelops-broker`)**: The **ONLY** component with access to `/var/run/docker.sock`. It runs with `network_mode: none` (completely offline) and verifies that connecting processes possess UID `1000`.
5. **Disposable Executor Container**: Launched on-demand by the broker with a read-only root filesystem, dropped Linux capabilities (`cap_drop: ALL`), and strictly pinned IP connectivity back to the monitored service.

---

## 5. Mermaid Architecture Diagram

```mermaid
flowchart TD
    subgraph Client ["Operator UI (Next.js :3000)"]
        UI_Incidents["Incidents Cockpit"]
        UI_Investigate["LangGraph AI Insights"]
        UI_Approvals["Two-Person Approval Queue"]
        UI_Verification["Authoritative Verification View"]
    end

    subgraph ControlPlane ["FastAPI Backend Control Plane (:8000)"]
        Auth["JWT / RBAC Enforcement"]
        Poller["Background Service Poller (10s)"]
        LangGraph["LangGraph Diagnostic Engine (Gemini 2.5)"]
        Policy["Strict Policy Engine (extra=forbid)"]
        Bridge["Transactional Incident Recovery Bridge"]
    end

    subgraph Database ["Authoritative PostgreSQL (:5432)"]
        DB_State[("Services, Incidents & Audits")]
        DB_Queue[("Executions Queue (FOR UPDATE SKIP LOCKED)")]
        DB_Verification[("Verification Cycles & Probes")]
    end

    subgraph MonitoredWorkload ["Monitored Workload (:8001)"]
        OrderAPI["Order API Demo Service"]
        Prometheus["/metrics & /health"]
    end

    subgraph IsolationBoundary ["Container Execution Isolation Boundary"]
        subgraph WorkerContainer ["sentinelops-worker (UID 1000:1000)"]
            Worker["DurableExecutionWorker"]
            Registry[("SQLite Operation Registry")]
            Journal[("Append-Only SOJ1 Journal")]
            Engine["PostExecutionVerificationEngine"]
        end

        subgraph BrokerContainer ["sentinelops-broker (network_mode: none)"]
            Broker["RestrictedDockerBroker"]
            UnixSocket["/var/run/sentinelops/broker.sock (SO_PEERCRED)"]
        end

        subgraph ExecutorContainer ["Disposable Ephemeral Container"]
            Runner["Executor Runner (PinnedSyncBackend)"]
        end
    end

    Client -->|REST API + JWT| ControlPlane
    Poller -->|Synthetic HTTP Probes| OrderAPI
    Poller -->|Create Incident| DB_State
    LangGraph -->|Read Telemetry & Logs| OrderAPI
    LangGraph -->|Persist Diagnostic Evidence| DB_State
    Policy -->|Propose Allowlisted Action| DB_State
    Client -->|Approve Action| Policy
    Policy -->|Enqueue Execution| DB_Queue

    Worker -->|Claim Job (FOR UPDATE)| DB_Queue
    Worker -->|Sync State| Registry
    Worker -->|Append SOJ1 Entry| Journal
    Worker -->|Unix IPC Request| UnixSocket
    UnixSocket -->|Peer Credential Check| Broker
    Broker -->|Launch Container| ExecutorContainer

    ExecutorContainer -->|Pinned HTTP POST /demo/restore| OrderAPI
    Worker -->|Post-Execution 3x Health Probes| OrderAPI
    Worker -->|Persist Cycle Records| DB_Verification
    Worker -->|Atomic Recovery Transaction| Bridge
    Bridge -->|Update Status: recovered| DB_State
```

---

## 6. Complete Incident-to-Recovery Workflow

```mermaid
sequenceDiagram
    autonumber
    participant Monitored as Monitored Workload (Order API)
    participant Poller as Background Poller
    participant DB as PostgreSQL
    participant Operator as Operator / SRE
    participant AI as LangGraph Agent
    participant Policy as Policy Engine
    participant Worker as Durable Worker
    participant Broker as Docker Broker
    participant Executor as Ephemeral Container
    participant Verifier as Verification Engine

    Note over Monitored: Failure Injected (DB Timeout 500s)
    Poller->>Monitored: Synthetic health check (GET /health)
    Monitored-->>Poller: HTTP 500 Database Timeout
    Poller->>DB: Create Incident (status: detected)

    Operator->>AI: Trigger Investigation (POST /investigate)
    AI->>Monitored: Collect telemetry & log metrics
    AI->>DB: Persist Root-Cause Hypotheses & Confidence

    AI->>Policy: Propose allowlisted action (restore_order_api_demo)
    Policy->>Policy: Validate parameter schema (extra=forbid)
    Policy->>DB: Create Remediation Approval (status: pending)

    Operator->>Policy: Human Review & Authorize (POST /approve)
    Policy->>DB: Enqueue Execution (status: queued, token: 0)

    Worker->>DB: Claim Execution (FOR UPDATE SKIP LOCKED)
    DB-->>Worker: Lock acquired, token incremented to 1
    Worker->>Broker: IPC execution dispatch over Unix Socket
    Broker->>Broker: Check peer UID == 1000 (SO_PEERCRED)
    Broker->>Executor: Launch isolated container (sentinelops/remediation-executor)
    Executor->>Monitored: Pinned HTTP POST /demo/restore
    Monitored-->>Executor: HTTP 200 Restored
    Executor-->>Broker: Exit code 0
    Broker-->>Worker: Execution dispatched successfully

    Worker->>Verifier: Run PostExecutionVerificationEngine
    Verifier->>Monitored: Baseline probe + 3 consecutive passing health probes (15s)
    Monitored-->>Verifier: 3x HTTP 200 Healthy
    Verifier->>DB: Record verification cycles and probe evidence

    Worker->>DB: Transactional IncidentRecoveryBridge (ACID)
    Note over DB: Atomically sets Execution=completed, Incident=recovered
    DB-->>Operator: Live UI updates to "Recovered"
```

---

## 7. Directory Structure

```
D:\Sentinal_AI
├── .env.example                     # Root container environment template
├── docker-compose.yml               # Topology orchestration (broker, worker, order-api, backend, postgres)
├── docs/                            # Deep architectural specifications & ADRs
│   ├── ARCHITECTURE.md
│   ├── PHASE_4_3_EXECUTION_ARCHITECTURE.md
│   ├── PHASE_4_3_6_ARCHITECTURE.md
│   ├── PHASE_4_3_6_FINAL_VALIDATION_REPORT.md
│   └── README.md
├── backend/                         # FastAPI Control Plane & Worker Engine
│   ├── .env.example                 # Backend environment template
│   ├── Dockerfile                   # Worker & backend production Docker image
│   ├── alembic.ini                  # Alembic database migration config
│   ├── requirements.txt             # Python dependencies
│   ├── pytest.ini                   # Pytest test suite configuration
│   ├── alembic/versions/            # 8 applied Alembic schema migrations
│   ├── scripts/                     # Seed utilities (create_test_users.py)
│   ├── app/
│   │   ├── main.py                  # FastAPI application entrypoint
│   │   ├── core/                    # Pydantic settings, security, and logging
│   │   ├── db/                      # SQLAlchemy session and connection lifecycle
│   │   ├── models/                  # Declarative SQLAlchemy models
│   │   ├── schemas/                 # Pydantic request & response schemas
│   │   ├── api/v1/                  # REST API endpoints (incidents, remediation, etc.)
│   │   ├── detector/                # Background async health poller and rules
│   │   ├── agents/                  # LangGraph multi-agent diagnostic graph
│   │   ├── remediation/             # Policy engine, registry, and approval service
│   │   ├── execution/               # DurableExecutionWorker, queue manager, watchdog
│   │   └── verification/            # Verification engine and transactional recovery bridge
│   └── tests/                       # 38 test suites (508 passed, 2 skipped across 510 items)
├── frontend/                        # Next.js 16 Web Cockpit
│   ├── package.json                 # Node dependencies and scripts
│   ├── tsconfig.json                # TypeScript compiler config
│   ├── src/
│   │   ├── app/                     # Next.js App Router pages (incidents, approvals, etc.)
│   │   ├── components/              # UI design system components (Card, Badge, Button, etc.)
│   │   └── lib/                     # Typed API client, authentication, and utilities
│   └── tests/                       # Node/tsx integration test suites (49 tests)
└── services/                        # Isolated Services and Microservices
    ├── broker/                      # Standalone Unix socket Docker broker daemon
    │   ├── Dockerfile
    │   └── server.py
    ├── executor/                    # Pinned disposable remediation runner
    │   ├── Dockerfile
    │   └── runner.py
    └── order-api/                   # Monitored demo microservice with failure injection
        ├── Dockerfile
        └── service/main.py
```

---

## 8. Prerequisites

* **Operating System**: Windows 10/11 with WSL2 enabled, or Linux (Ubuntu 22.04+).
* **Docker Desktop**: Docker 26.0+ with WSL2 backend active.
* **Python**: Python 3.13 (or 3.11+).
* **Node.js**: Node.js 20+ and npm 10+.
* **PostgreSQL**: Local PostgreSQL 16 or 18 instance running on `127.0.0.1:5432` (or the Docker Compose PostgreSQL container).

---

## 9. Environment Configuration

### Root Container Environment
Copy `.env.example` to `.env` in the project root:

```powershell
Copy-Item .env.example .env
```

Contents of `.env`:
```ini
DATABASE_URL_CONTAINER=postgresql+psycopg://postgres:your_password@host.docker.internal:5432/sentinelops_dev
SENTINELOPS_TRUSTED_GATEWAY_IP=192.168.65.254
ENVIRONMENT=development
```

> [!NOTE]
> **Docker Host-Gateway Configuration**: `192.168.65.254` is the verified gateway IP for the local Docker Desktop (WSL2) development environment on Windows. It is **not** a universal default for all Docker installations.
> * On native Linux Docker engines, the default bridge gateway is typically `172.17.0.1`.
> * On macOS Docker Desktop or custom bridge subnets, it may differ within `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16`.
> * **How to discover the host-gateway IP in your environment**:
>   ```powershell
>   docker run --rm --add-host host.docker.internal:host-gateway alpine sh -c "grep host.docker.internal /etc/hosts | head -n 1 | cut -f 1"
>   ```
>   Set `SENTINELOPS_TRUSTED_GATEWAY_IP=<discovered_ip>` in your `.env` and `docker-compose.yml`.

### Backend Host Environment
Copy `backend/.env.example` to `backend/.env`:

```powershell
Copy-Item backend/.env.example backend/.env
```

Configure `backend/.env`:
```ini
ENVIRONMENT=development
DEBUG=True
DATABASE_URL=postgresql+psycopg://postgres:your_password@127.0.0.1:5432/sentinelops_dev
LOG_LEVEL=INFO
# Optional: Set your Gemini API key for live LLM diagnosis (falls back to deterministic heuristics if unset)
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```

### Frontend Environment
Ensure `frontend/.env.local` contains:
```ini
NEXT_PUBLIC_API_URL=http://127.0.0.1:8000/api/v1
```

---

## 10. Database Setup & Alembic Migrations

1. Ensure PostgreSQL is running on port 5432 and the `sentinelops_dev` database exists:
   ```sql
   CREATE DATABASE sentinelops_dev;
   ```

2. Run Alembic migrations from the `backend/` directory:
   ```powershell
   Set-Location -Path backend
   & .venv\Scripts\python.exe -m alembic upgrade head
   ```

3. Seed standard test user credentials:
   ```powershell
   & .venv\Scripts\python.exe scripts/create_test_users.py
   ```

   > [!WARNING]
   > **DEVELOPMENT-ONLY CREDENTIALS**: The seeded accounts listed below are strictly intended for local development testing and automated integration test suites. **NEVER** deploy, reuse, or expose these default credentials in staging, production, or internet-accessible environments. In production, provision unique credentials using enterprise identity providers (IdP), SAML/OIDC SSO, or strong randomly generated passwords.

   *Seeded Accounts (Development Only)*:
   * **Admin**: `admin@sentinelops.local` / `AdminPass123!`
   * **Engineer**: `engineer@sentinelops.local` / `EngineerPass123!`
   * **Viewer**: `viewer@sentinelops.local` / `ViewerPass123!`

---

## 11. Docker Topology & Service Startup

SentinelOps uses a dual-topology model: the backend, database, and monitored services run locally on the host for rapid development, while the broker daemon and worker run inside Linux containers to enforce container isolation.

### Build the Disposable Executor Image
The broker launches this image on-demand to run remediation actions:

```powershell
docker build -t sentinelops/remediation-executor:dev-local -f services/executor/Dockerfile .
```

### Start the Restricted Broker Container
```powershell
docker compose up -d broker
```

Verify that the broker is running with `network_mode: none`:
```powershell
docker ps --filter "name=sentinelops-broker"
```

---

## 12. Local Development Commands

### 1. Start the Monitored Order API Workload (Port 8001)
In a dedicated PowerShell terminal:
```powershell
Set-Location -Path "D:\Sentinal_AI\services\order-api"
& "..\..\backend\.venv\Scripts\python.exe" -m uvicorn service.main:app --host 0.0.0.0 --port 8001
```

### 2. Start the Backend Control Plane (Port 8000)
In a dedicated PowerShell terminal:
```powershell
Set-Location -Path "D:\Sentinal_AI\backend"
& .venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 3. Start the Next.js Frontend Cockpit (Port 3000)
In a dedicated PowerShell terminal:
```powershell
Set-Location -Path "D:\Sentinal_AI\frontend"
npm run dev
```

The web dashboard is now accessible at `http://localhost:3000`.

---

## 13. Testing Commands

### Backend Test Suite (Pytest)
Executes all unit, integration, and security adversarial test suites:
```powershell
Set-Location -Path "D:\Sentinal_AI\backend"
& .venv\Scripts\python.exe -m pytest -v
```
*Expected Result*: **508 passed, 2 skipped**, 0 failures (100% pass rate).

### Frontend Integration Test Suites (tsx)
Executes the full browser-level flow tests (Incident $\rightarrow$ Investigation $\rightarrow$ Approval $\rightarrow$ Execution $\rightarrow$ Verification):
```powershell
Set-Location -Path "D:\Sentinal_AI"
npx tsx --test frontend/tests/incident_to_approval.test.ts frontend/tests/approval_to_execution.test.ts frontend/tests/execution_to_verification.test.ts
```
*Expected Result*: **49 passed tests**, 0 failures.

### Frontend TypeScript Verification & Production Build
```powershell
Set-Location -Path "D:\Sentinal_AI\frontend"
npm run lint
npm run build
```

---

## 14. Security Architecture & Defense-in-Depth

| Security Guard | Implementation Location | Security Invariant Enforced |
|---|---|---|
| **Multi-Tenant Isolation** | [`backend/app/db/session.py`](backend/app/db/session.py) | Every query strictly filters by `workspace_id`. Cross-workspace data access is structurally impossible. |
| **RBAC & Four-Eyes Principle** | [`backend/app/remediation/approval_service.py`](backend/app/remediation/approval_service.py) | Viewers cannot execute; Engineers/Admins require independent peer approval (`allow_self_approval=False`). |
| **Parameter Allowlisting** | [`backend/app/remediation/registry.py`](backend/app/remediation/registry.py) | Pydantic models configure `extra="forbid"`. AI agents cannot inject arbitrary shell commands or custom URLs. |
| **Durable Execution & Fencing** | [`backend/app/execution/manager.py`](backend/app/execution/manager.py) | PostgreSQL `FOR UPDATE SKIP LOCKED` prevents concurrent workers from double-claiming. Monotonic fencing tokens prevent zombie writes. |
| **Broker Peer Credential Check** | [`services/broker/server.py`](services/broker/server.py) | Linux kernel `SO_PEERCRED` authenticates worker UID/GID `1000:1000`. Unauthorized processes cannot dispatch containers. |
| **Broker Network Isolation** | [`docker-compose.yml`](docker-compose.yml) | Broker runs with `network_mode: none`. It cannot transmit telemetry or egress data anywhere. |
| **Connection-Time IP Pinning** | [`services/executor/runner.py`](services/executor/runner.py) | DNS resolution occurs upfront. Connections connect directly to the pinned IP, mitigating Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding SSRF. |
| **Dual-Stack Gateway Verification** | [`services/executor/runner.py`](services/executor/runner.py) | In development mode, resolves `host.docker.internal` and matches strictly against trusted gateway (`192.168.65.254` in local Docker Desktop, or configured `SENTINELOPS_TRUSTED_GATEWAY_IP`). Production completely forbids `host.docker.internal`. |
| **Immutable Audit Logging** | [`backend/app/models/`](backend/app/models/) | All state transitions write append-only records to `incident_events`, `policy_decisions`, and `execution_events`. |

---

## 15. Step-by-Step 9-Stage Order API Demonstration

This end-to-end walkthrough demonstrates the entire autonomous detection, AI diagnostic, human approval, containerized remediation, and verification lifecycle.

### Stage 1: Verify Baseline Service Health
Confirm the Order API is healthy:
```powershell
curl -s http://127.0.0.1:8001/health
```
*Expected Response*: `{"status":"healthy","service":"order-api","version":"1.0.0",...}`

### Stage 2: Inject Simulated Failure
Trigger an in-memory database connection pool exhaustion failure:
```powershell
curl -s -X POST http://127.0.0.1:8001/demo/simulate-failure
```
*Expected Response*: `{"status":"failure_injected","failure_active":true,...}`

Verify that `/health` now fails:
```powershell
curl -s -w "\nHTTP Status: %{http_code}\n" http://127.0.0.1:8001/health
```
*Expected Response*: HTTP 500 `{"status":"unhealthy",...}`

### Stage 3: Autonomous Incident Detection
Wait ~10 seconds for the autonomous background poller to detect the 500 error threshold breach. In the Next.js Cockpit (`http://localhost:3000/incidents`), a new incident appears with:
* **Status**: `detected`
* **Severity**: `high`
* **Title**: `Service order-api health check failed`

### Stage 4: Trigger LangGraph AI Investigation
1. In the Incident Cockpit, click **"Run AI Investigation"** (or call `POST /api/v1/incidents/{incident_id}/investigate`).
2. LangGraph queries recent telemetry, inspects error codes, and synthesizes root-cause hypotheses.
3. The UI presents the top diagnosis (e.g., `Database connection pool exhaustion`) with confidence rating and log excerpts.

### Stage 5: Policy Evaluation & Remediation Proposal
1. On the investigation page, click **"Propose Remediation"**.
2. The Policy Engine validates the action `restore_order_api_demo` against the registry schema.
3. Because this is a `medium` risk action, the policy engine marks it as `approval_required` and creates an approval request.

### Stage 6: Human Authorization & Queueing
1. Navigate to **Remediation $\rightarrow$ Approvals** (`http://localhost:3000/remediation/approvals`).
2. Log in as an authorized Engineer or Admin (`engineer@sentinelops.local`).
3. Click **"Approve"**.
4. Click **"Enqueue Execution"**.
5. The execution job is now safely stored in PostgreSQL with status `queued` and `fencing_token: 0`. Copy the generated **Execution ID**.

### Stage 7: Targeted Isolated Execution

#### Prerequisites:
Confirm the standalone restricted broker daemon container is running:
```powershell
docker ps --filter "name=sentinelops-broker"
```
*(If stopped, start it via `docker compose up -d broker`).*

#### Execute the Targeted One-Shot Worker:
Execute the one-shot worker via Docker Compose targeting the exact generated Execution ID.

**Option A (Explicit CLI arguments — Recommended)**:
```powershell
docker compose run --rm worker python -m app.execution.worker --execution-id "<EXECUTION_ID>" --one-shot
```

**Option B (Environment variable configuration)**:
```powershell
docker compose run --rm -e TARGET_EXECUTION_ID="<EXECUTION_ID>" -e ONE_SHOT=true worker
```

#### What occurs behind the scenes:
1. **Container Environment & Least Privilege**:
   * The worker container starts as unprivileged user `1000:1000` with **zero** access to `/var/run/docker.sock`.
   * Inherits mounts from `docker-compose.yml`:
     - Shared IPC volume `broker_ipc_socket` at `/var/run/sentinelops` (directory `0750`, socket `0660`, GID 1000).
     - Persistent storage volumes `sentinelops_registry_data` (SQLite `operation_registry.db`) and `sentinelops_journal_data` (`operation.soj1`).
   * Routes `host.docker.internal` to Docker host-gateway (`--add-host host.docker.internal:host-gateway`).
   * Connects to host PostgreSQL via `sentinelops-bridge` network (`DATABASE_URL_CONTAINER`).
2. **Authoritative Targeted Claim Invariant**:
   * Worker queries PostgreSQL using `SELECT ... FOR UPDATE SKIP LOCKED` with explicit filter: `WHERE remediation_executions.id == target_execution_id`.
   * **Strict Guarantee**: It claims exclusively `<EXECUTION_ID>`. Any other queued execution (such as `aec136fc-759b-4d6a-95a1-753a5042ebd8`) is completely ignored and untouched.
3. **Fencing & Lease Acquisition**:
   * Worker atomically increments the execution's fencing token from `0` to `1` and starts lease heartbeats.
4. **Peer-Authenticated Broker Dispatch**:
   * Worker submits an IPC execution request over `/var/run/sentinelops/broker.sock`.
   * Broker inspects socket credentials via Linux `SO_PEERCRED`, verifying the peer is UID `1000`.
5. **Disposable Executor Sandbox**:
   * Broker launches an ephemeral container (`sentinelops/remediation-executor:dev-local`) with dropped capabilities (`cap_drop: ALL`).
   * Executor validates the host-gateway IP (`192.168.65.254` or configured `SENTINELOPS_TRUSTED_GATEWAY_IP`) and executes `POST http://host.docker.internal:8001/demo/restore`.
   * Monitored Order API resets failure mode to healthy (HTTP 200).
   * Ephemeral container terminates and is automatically cleaned up.
6. **Clean Termination Invariant**:
   * Because `--one-shot` / `ONE_SHOT=true` is set, the worker exits with code `0` immediately after processing the single execution. It does **not** enter continuous background polling.

### Stage 8: Multi-Probe Post-Execution Verification
The worker automatically initiates `PostExecutionVerificationEngine`:
1. Executes a baseline health probe against `http://127.0.0.1:8001/health`.
2. Executes 3 consecutive health probes across a 15-second window.
3. All 3 probes return HTTP 200 `healthy`.
4. Verification engine records the verification cycle as `passed`.

### Stage 9: Transactional Incident Recovery
1. The `IncidentRecoveryBridge` executes a single ACID transaction in PostgreSQL:
   * Execution status transitions to `completed`.
   * Incident status transitions to `recovered`.
   * Audit log entries are written with exact timestamps and probe evidence.
2. In the web cockpit (`http://localhost:3000/incidents`), the incident status changes to **Recovered**.
3. Navigating to the Verification Cockpit (`http://localhost:3000/verification`) confirms all 3 successful probe cycles and recovery evidence.

---

## 16. Troubleshooting & Diagnostics

### 1. Docker Host-Gateway Connection Issues
* **Symptom**: `[Errno 111] Connection refused` when the executor container calls `http://host.docker.internal:8001`.
* **Root Cause & Resolution**:
  1. **Gateway IP Configuration**: `192.168.65.254` is the gateway verified for Docker Desktop on Windows. In other environments (native Linux or custom subnets), the host-gateway IP may differ (e.g., `172.17.0.1` on Linux standard bridge).
     * Discover the environment's host-gateway IP:
       ```powershell
       docker run --rm --add-host host.docker.internal:host-gateway alpine sh -c "grep host.docker.internal /etc/hosts | head -n 1 | cut -f 1"
       ```
     * Configure `SENTINELOPS_TRUSTED_GATEWAY_IP=<discovered_ip>` in root `.env` and `docker-compose.yml`.
  2. **Service Interface Binding**: The monitored Order API on the host must be bound to `0.0.0.0:8001` (all interfaces), not `127.0.0.1:8001`, so Docker bridge traffic can reach it.

### 2. Broker Socket Permission Denied
* **Symptom**: `PermissionError: [Errno 13] Permission denied: '/var/run/sentinelops/broker.sock'`.
* **Resolution**: The worker container must run as user `1000:1000`. Verify that the named volume `broker_ipc_socket` has permissions `0750` with group ownership `1000`.

### 3. PostgreSQL Migrations Out of Sync
* **Symptom**: `UndefinedTable: relation "verification_cycles" does not exist`.
* **Resolution**: Run `alembic upgrade head` from `backend/` to apply all 8 migrations.

### 4. Gemini API Key Quota or Network Restrictions
* **Symptom**: Investigation times out or reports LLM API error.
* **Resolution**: SentinelOps AI features an automatic deterministic fallback. If `GEMINI_API_KEY` is omitted or invalid, the engine falls back to heuristic diagnostic parsing without failing the investigation.

---

## 17. Current Limitations & Future Roadmap

### Current Scope & Boundaries
* **Supported Environments**: Tested and optimized for local development and Docker Desktop environments.
* **Workload Scope**: Action registry is currently scoped to demo recovery actions (`restore_order_api_demo`, `restart_order_api`).

### Future Production Roadmap
* **External Notification Gateways**: Production dispatchers for Slack webhook and PagerDuty alert triggers on incident state transitions.
* **Kubernetes Operator**: Native CRD-based operator replacing the Docker broker for orchestrated clusters.
* **Dynamic Action Sandboxing**: WebAssembly (WASM) micro-sandboxes for millisecond-latency ephemeral diagnostic execution.
* **Federated Multi-Cluster Support**: Multi-region workspace management with cross-cluster lease coordination.
