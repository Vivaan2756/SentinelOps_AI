# SentinelOps — Operational Security, Generic Verification & Network Isolation Architecture

## Document Purpose & Context
This document formalizes the architectural contracts, limitations, and operational guarantees established during **SentinelOps Option C Stage 3A**, directly addressing findings from the Stage 2.1 Independent Security Audit:
- **FINDING-2.1-01:** Operator Uncertainty Resolution Mechanism
- **FINDING-2.1-02:** Dedicated Worker Database Role & Least Privilege
- **FINDING-2.1-03:** Worker Manifest Signing Key Isolation
- **FINDING-2.1-04:** Generic Service Verification vs Demo-Specific Probes
- **FINDING-2.1-05:** Application-Layer Transport Pinning vs Kernel-Level Network Enforcement

---

## 1. Generic Service Verification vs Demo-Specific Invariants (FINDING-2.1-04)

### 1.1 Non-Negotiable Platform Invariant: Service-Agnostic Design
SentinelOps is a generic, service-agnostic AI SRE platform. A customer must be able to register any arbitrary external microservice (e.g. Payment API, Inventory API, Authentication Service), provide its registered HTTP health check endpoint, and configure an authorized recovery playbook.

### 1.2 Verification Capabilities Breakdown

| Check Type | Target Endpoint / Mechanism | Service Scope | Guarantees Provided | Limitations |
|---|---|---|---|---|
| **Generic Health Probe** | `GET {service.health_check_url}` | **All Registered Services** | Verifies transport reachability, socket connection, HTTP 200 response, and nominal latency (< 5.0s). Evaluates 1 baseline probe followed by 3 consecutive passing evaluation probes with randomized jitter. | Proves basic process liveness and nominal HTTP responsiveness; **cannot** attest to complex downstream transactional integrity without domain-specific probes. |
| **Demo Status Probe** | `GET /demo/status` | **Order API Demo Workload Only** | Validates `failure_injected == False` and internal mock component state for SentinelOps development/validation harnesses. | **Strictly disabled** for non-demo services. Generic microservices are NEVER evaluated against demo status endpoints. |
| **Prometheus 5xx Invariance** | Prometheus scraper delta evaluation | **Services with Prometheus Monitoring Enabled** | Validates that HTTP 5xx error counters (`order_api_http_5xx_errors_total` for demo, or configured counter) did not increase between baseline and evaluation cycles ($\Delta \le 0$). | Requires a configured Prometheus monitoring endpoint. If Prometheus is not configured for a registered service, metric checks are skipped cleanly. |

### 1.3 What SentinelOps Can and Cannot Claim
1. **When a service exposes only a standard health endpoint (`/health`):**
   - **SentinelOps CAN claim:** The service has resumed network listening, accepted TCP connections, returned nominal HTTP 200 responses across 3 consecutive independent probes over a minimum observation window, and resolved the initial availability outage.
   - **SentinelOps CANNOT claim:** End-to-end database consistency, internal queue clearing, or business logic correctness that is not exposed through the service's health endpoint.
2. **Incident Closure Invariant:**
   - A passing verification cycle transitions the incident from `investigating` to `recovered` via `IncidentRecoveryBridge.mark_incident_recovered`.
   - **An incident is NEVER automatically closed.** Final incident closure strictly requires explicit human operator sign-off and closure notes.
3. **External Service Registration Requirements:**
   To configure an external service for automated recovery and independent verification, an operator must supply:
   - `name`: Human-readable service identifier.
   - `environment`: Deployment tier (`development`, `staging`, `production`).
   - `health_check_url`: Authoritative HTTP/HTTPS health endpoint returning HTTP 200 when nominal.
   - `recovery_playbook`: An explicitly allowlisted action definition specifying target path and authorized parameter boundaries.

---

## 2. Network Isolation & SSRF Security Guarantees (FINDING-2.1-05)

### 2.1 Architecture Scope
Option C implements direct unprivileged HTTP recovery via `IsolatedHttpRecoveryRunner` and `PinnedIPTransport`.

### 2.2 Security Controls Enforced (Application-Layer)
1. **Connection-Time DNS Pinning (`PinnedIPTransport`):**
   - The target URL's hostname is resolved to an IP address exactly once during pre-flight validation.
   - HTTP TCP connections are opened directly to the resolved pinned IP address, while preserving the original `Host` HTTP header and TLS Server Name Indication (SNI).
   - This prevents **DNS Time-of-Check to Time-of-Use (TOCTOU) Rebinding Attacks**, ensuring that a malicious DNS server cannot switch host resolution to internal infrastructure between authorization and dispatch.
2. **Prohibited Address Space & Cloud Metadata Blocking:**
   - The target IP is authoritatively validated against forbidden IP ranges before any TCP socket is opened:
     - `169.254.169.254` (AWS, GCP, Azure, OpenStack instance metadata)
     - `169.254.170.2` (AWS ECS container metadata)
     - `100.100.100.200` (Alibaba Cloud metadata)
     - `fd00:ec2::254` (AWS IPv6 metadata)
     - Standard multicast (`224.0.0.0/4`), broadcast (`255.255.255.255`), and link-local (`169.254.0.0/16`)
3. **Strict HTTP Redirect Blocking:**
   - `follow_redirects=False` is strictly enforced on all recovery actions and verification probes.
   - Any HTTP 301, 302, 307, or 308 redirect response raises `BrokerSecurityViolation`, completely preventing redirect-based SSRF bounce attacks.

### 2.3 Explicitly Stated Limitation
- Option C provides **application-level** transport pinning and URL filtering.
- Option C does **NOT** provide kernel-level packet filtering (iptables / nftables), host network namespace isolation (veth pairs), or eBPF socket enforcement.
- This design decision was explicitly accepted in Option C to avoid host virtualization and kernel module compatibility blockers on WSL2/Windows while maintaining cryptographic manifest binding and robust application-layer SSRF defenses.

---

## 3. Operator Uncertainty Resolution Workflow (FINDING-2.1-01)

### 3.1 Context & Fail-Closed Guarantee
When an in-flight network timeout, connection reset, or ambiguous socket termination occurs during recovery execution, SentinelOps enforces `HOLD:EXECUTION_UNCERTAIN` locked until year 9999 (`HOLD_EXPIRATION_TIMESTAMP`). Automated retries, replays, and queue sweeps are permanently blocked.

### 3.2 Resolution API Contract
- **Endpoint:** `POST /api/v1/remediation/executions/{execution_id}/resolve-uncertain?workspace_id={workspace_id}`
- **Authorization:** Requires authenticated user with `engineer` or `admin` role in the execution's workspace. Viewers and cross-workspace callers are denied.
- **Mandatory Justification:** Minimum 5 characters explaining out-of-band investigation evidence.
- **Decisions:**
  - `ABORT_FAILURE`: Transitions execution to `EXECUTION_FAILED` with `attempt_count = max_attempts` to permanently prevent automated retry. Uncertainty evidence is preserved. The incident remains active in `investigating` status.
  - `CONFIRM_SUCCESS`: Transitions execution to `VERIFICATION_PENDING` and triggers `PostExecutionVerificationEngine`. The incident is ONLY transitioned to `recovered` if all independent verification probes pass. If verification fails, execution transitions to `VERIFICATION_FAILED` and the incident remains open.

---

## 4. Dedicated Worker Role & Secret Separation (FINDING-2.1-02 & FINDING-2.1-03)

1. **Database Least Privilege:** The execution worker operates under the dedicated `sentinelops_worker` PostgreSQL role, which has zero access to user authentication data, passwords, API tokens, or playbook definitions.
2. **Private Signing Key Isolation:** The Ed25519 manifest signing private key (`SENTINELOPS_MANIFEST_PRIVATE_KEY`) is strictly confined to the FastAPI control plane process. The worker process scrubs any signing key environment variables upon startup (defense-in-depth) and verifies manifests using only public keys from `BrokerPublicKeyRegistry`.
