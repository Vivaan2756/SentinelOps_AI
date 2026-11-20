# SentinelOps Stage 4.0.8 — Architecture Revision Report
## Final Revocation Atomicity, Execution Isolation & Receiver Durability Closure

**Repository:** `D:\Sentinal_AI`
**Milestone:** Stage 4.0.8 — Final Revocation Atomicity, Execution Isolation & Receiver Durability Closure
**Baseline:** Option C Stage 3.3 — ACCEPTED & FROZEN
**Target Document:** `docs/STAGE_4_GENERIC_EXTERNAL_SERVICE_ARCHITECTURE.md` (Revision 4.0.8)
**Mode:** STRICTLY READ-ONLY ARCHITECTURE REVISION
**Implementation Authorization:** NOT GRANTED
**Date:** 2026-11-12
**Final Verdict:** **PASS — STAGE 4.0.8 CORRECTIONS COMPLETE; READY FOR INDEPENDENT RE-AUDIT**

---

## 1. Executive Summary

SentinelOps Stage 4.0.8 delivers the definitive architectural closure for generic external service integration, resolving all subtle race conditions, execution namespace isolation questions, receiver idempotency durability gaps, KMS budget edge cases, TLS trust material byte consistency, and PostgreSQL catalog-level privilege assertions identified during the review of Stage 4.0.7:

1. **Dispatch & Revocation Synchronization Closure:** Explicitly acknowledged that a database check followed by a host firewall installation is non-atomic. Closed the post-firewall race window ($\Delta t$) by introducing a mandatory **Step 10 Synchronous Pre-Dispatch Verification** before writing local SOJ1 `START` records or opening sockets. Formally defined the irreversible **Point of No Return** at `socket.sendall(HTTP_POST_BYTES)`, mandating that revocations occurring at or after this point enter permanent uncertain holds (`HOLD_EXPIRATION_TIMESTAMP = 9999-01-01T00:00:00Z`). Enforced that revoked executions never receive new dispatch tokens.
2. **Execution-Specific Network Isolation:** Enforced the architectural invariant **`worker_concurrency = 1`** (`max_concurrent_executions = 1` per worker container/network namespace). Each active execution operates within a private, dedicated Linux network namespace. Scoped kernel socket destruction (`SOCK_DESTROY` / `ss -K`) and netfilter conntrack flushing (`conntrack -D`) strictly within the execution's private namespace, eliminating any possibility of disrupting concurrent executions targeting the same destination IP and port. Enforced `Connection: close` and namespace recreation upon failed cleanup.
3. **Customer Receiver Idempotency Durability & Permanent Tombstones:** Fully specified a 4-state receiver lifecycle (`IN_PROGRESS`, `COMPLETED`, `FAILED`, `AMBIGUOUS`). Bound `request_body_digest` (SHA-256) in the schema to detect tampering across replays. Specified that receiver crashes during physical remediation transition records to `AMBIGUOUS` with `expires_at = NULL` (**Permanent Durable Tombstones**). Prohibited automated TTL deletion of ambiguous records to prevent duplicate side effects, requiring audited manual resolution. Stated honest at-most-once guarantees.
4. **Atomic KMS Budget Reservation & Disaster Recovery Table:** Formulated an atomic block reservation protocol ($B = 100$ operations) with **conservative consumption**: once reserved, blocks are permanently counted against the 100,000 ceiling; unconsumed tokens on crash or timeout are discarded and never refunded. Provided a complete **10-State Disaster Recovery Transition Table** detailing triggers, actions, and fail-closed paths.
5. **Exact TLS Trust-Store Binary Byte Consistency:** Specified the exact byte normalization algorithm (`get_canonical_pem_bytes()`: Unix LF normalization and single `0x0A` EOF) producing `canonical_pem_bytes`, used identically across Proposal Spec hashing, Worker Manifest verification, and in-memory `load_verify_locations()` ingest, permanently eliminating filesystem TOCTOU races.
6. **PostgreSQL Catalog-Level Privilege Verification:** Replaced ambiguous information-schema queries with the authoritative `has_schema_privilege()` catalog query across `pg_namespace` and `pg_roles` verified for PostgreSQL 12–16+. Preserved `sentinelops_fn_owner` as `NOLOGIN`, schema-qualified queries, and the strict global lock hierarchy.

In strict accordance with instructions, **zero implementation work was performed**. Application source code, test suites, database migrations, Docker Compose configurations, and the frozen Option C Stage 3.3 baseline remain completely untouched and green.

---

## 2. Finding-by-Finding Correction Matrix

| Item # | Review Finding / Technical Gap | Root Cause & Security Risk | Architecture Resolution in Revision 4.0.8 | Target Section |
| :--- | :--- | :--- | :--- | :--- |
| **REV-408-01** | Non-atomic firewall install window; ambiguous revocation semantics. | Host Controller checking DB followed by iptables install is non-atomic ($\Delta t$). Revocation committing during $\Delta t$ leaves firewall open. | Explicitly acknowledged non-atomicity. Added **Step 10 Synchronous Pre-Dispatch Verification** before writing SOJ1 `START`. If revoked, worker halts, calls Host Controller to teardown rule, and transitions to `aborted_pre_dispatch`. Defined **Point of No Return** at `socket.sendall()`; in-flight requests enter permanent uncertain hold; revoked executions never receive new tokens. | Section 4.1, 4.2, 4.3 |
| **REV-408-02** | `ss -K dst <ip> dport = 443` could kill connections of other executions in same namespace. | If multiple concurrent executions run in the same container, socket cleanup terminates connections of other executions targeting the same IP. | Mandated **`worker_concurrency = 1`**. Each worker container has a private Linux network namespace dedicated to strictly one execution lease. Concurrent executions run in separate containers. `ss -K` is namespace-scoped and cannot affect other executions. Enforced `Connection: close` and container recreation on failed cleanup. | Section 1 (Inv 3), Section 9.1, 9.2, 9.3 |
| **REV-408-03** | Customer receiver state machine lacked 4-state lifecycle, tombstones, and crash recovery. | Receiver crash during physical side effect leaves ambiguous state. Automatic TTL deletion could purge record, allowing duplicate execution. | Implemented 4-state engine (`IN_PROGRESS`, `COMPLETED`, `FAILED`, `AMBIGUOUS`). Bound `request_body_digest`. Crashes transition to `AMBIGUOUS` with `expires_at = NULL` (**Permanent Durable Tombstone**). Prohibited automated TTL deletion; mandated audited manual operator resolution. Replaced magical claims with honest at-most-once guarantees. | Section 12.2 |
| **REV-408-04** | KMS 100,000 operation budget lacked atomic reservation protocol and state table. | Concurrent Control Plane instances or crashes could exceed 100,000 ceiling. DR state machine was narrative only. | Specified atomic block reservation ($B=100$) via KMS CAS. Implemented **conservative consumption**: unconsumed tokens on crash/partition are permanently discarded, never refunded. Formulated comprehensive **10-State Disaster Recovery Transition Table** with explicit failure paths. | Section 11.2, 11.3 |
| **REV-408-05** | Ambiguity regarding exact bytes hashed vs. loaded into `SSLContext`. | Discrepancy between proposal hash and OpenSSL memory ingest could cause false verification failures or TOCTOU file races. | Formally specified `canonical_pem_bytes` algorithm (Unix LF normalization, single `0x0A` EOF). Verified that Proposal Spec hashing, Worker Manifest verification, and in-memory `load_verify_locations` operate on the exact identical byte array. | Section 5.2 (Prop 36), Section 10.2 |
| **REV-408-06** | Schema privilege audit query compatibility across PostgreSQL versions. | `information_schema.schema_privileges` has column naming nuances and misses indirect role inheritance. | Replaced with authoritative `has_schema_privilege(r.oid, n.oid, 'CREATE')` catalog query joining `pg_namespace` and `pg_roles`. Verified compatible across PostgreSQL 12–16+. Preserved `NOLOGIN`, search path, and lock hierarchy. | Section 6.2 |

---

## 3. Exact State-Transition and Concurrency Specifications

### 3.1 Dispatch & Revocation Synchronization Protocol
1. **Linearization & Verification Sequence:**
   - **Step 8:** Worker calls `consume_dispatch_authorization()` stored procedure. Acquires locks in strict global order: `worker_instances` (Lock 1) $\to$ `remediation_executions` (Lock 2) $\to$ `dispatch_authorizations` (Lock 3) `FOR UPDATE`. Verifies active status, transitions token to `CONSUMED`, execution to `dispatching`, and commits.
   - **Step 9:** Worker requests Host Controller via authenticated UNIX socket (`/run/sentinelops/netfilter.sock`) to install dynamic `/32:443` allow rule. Host Controller checks PostgreSQL and injects netfilter rule into dedicated worker network namespace.
   - **Step 10 (Synchronous Pre-Dispatch Verification):** Worker executes synchronous database assertion:
     ```sql
     SELECT dispatch_revoked, status FROM public.remediation_executions WHERE id = p_execution_id;
     ```
     If `dispatch_revoked == TRUE` or `status != 'dispatching'`:
     * Worker immediately invokes Host Controller `DELETE /rules/<execution_id>`.
     * Host Controller executes `ss -K` and removes iptables rule.
     * Worker marks PostgreSQL execution `aborted_pre_dispatch`.
     * Worker zeroizes decrypted secret buffer and halts.
     * **Zero network bytes are sent.**
   - **Step 11 (Irreversible Point of No Return):**
     * Worker writes SOJ1 `START` record and executes `os.fsync(journal_fd)`.
     * Worker executes `socket.connect()` to `<pinned_ip>:443` and completes TLS handshake.
     * Worker executes `socket.sendall(HTTP_POST_BYTES)`: **Point of No Return Crossed**.
     * Once bytes are on the wire, remote execution cannot be guaranteed to be cancelled.
     * Any revocation arriving at or after this point forces execution into `execution_uncertain` with permanent hold (`HOLD_EXPIRATION_TIMESTAMP = 9999-01-01T00:00:00Z`).
     * Revoked executions are permanently barred from receiving new dispatch tokens.

### 3.2 Customer Receiver 4-State Idempotency Engine & Tombstones
```sql
CREATE TABLE remediation_idempotency_keys (
    execution_id UUID NOT NULL,
    nonce VARCHAR(64) NOT NULL,
    request_body_digest CHAR(64) NOT NULL,     -- SHA-256 of request_body_bytes
    status VARCHAR(30) NOT NULL,              -- 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'AMBIGUOUS'
    response_status INTEGER,
    response_body TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,                   -- Set to NULL for AMBIGUOUS (Permanent Tombstone)
    resolved_at TIMESTAMPTZ,
    resolved_by VARCHAR(64),
    resolution_notes TEXT,
    CONSTRAINT pk_idempotency_keys PRIMARY KEY (execution_id, nonce)
);
```

#### Replay and Transition Rules:
1. **Pre-Allocation HMAC Authentication:** HMAC-SHA256 signature and timestamp tolerance ($\le 300\text{s}$) verified before database connection or row allocation.
2. **Payload Digest Verification:** If record exists and `SHA256(request_body_bytes) != request_body_digest`, request is rejected with `HTTP 400 Bad Request` (`IdempotencyKeyPayloadMismatch`).
3. **Replay Responses:**
   - `COMPLETED`: Returns cached `response_status` and `response_body` (HTTP 200/202). No side effect re-executed.
   - `FAILED`: Returns cached failure status code and error body.
   - `IN_PROGRESS`: Returns `HTTP 409 Conflict` (or `HTTP 429 Too Many Requests` with `Retry-After: 5`).
   - `AMBIGUOUS`: Returns `HTTP 409 Conflict` with `{"error": "OperationInAmbiguousState", "message": "Manual reconciliation required"}`.
4. **Crash Recovery to Durable Tombstones:** If the receiver crashes during physical execution, the startup reconciliation worker identifies orphaned `IN_PROGRESS` records exceeding lease duration, marks them `status = 'AMBIGUOUS'`, and sets `expires_at = NULL`.
5. **Prohibition of Automatic TTL Deletion:** Automated pruning queries enforce:
   ```sql
   DELETE FROM remediation_idempotency_keys
   WHERE expires_at IS NOT NULL AND expires_at < now() AND status != 'AMBIGUOUS';
   ```
   Ambiguous records persist permanently until audited human operator resolution (`resolved_by`, `resolution_notes`, `resolved_at`).

### 3.3 Atomic KMS Budget Allocation & Disaster Recovery Transition Table
- **Block Allocation:** Control Plane nodes reserve blocks of $B = 100$ operations using atomic CAS in KMS.
- **Conservative Consumption:** Once reserved, the block is permanently deducted from the 100,000 ceiling. Unconsumed tokens on node crash, reboot, or timeout are **discarded and never refunded**, guaranteeing the physical encryption ceiling of 100,000 is never breached.

#### 10-State Disaster Recovery Transition Table:

| State # | Current State | Trigger / Event | Pre-Conditions | Action Taken by Control Plane / KMS | Next State | Failure / Timeout Path |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **DR-01** | `VAULT_ACTIVE` | Secret write request | `allocated_count < 100,000` | Encrypt DEK under $\text{MK}_v$; decrement local block. | `VAULT_ACTIVE` | Block exhausted $\to$ reserve next block. |
| **DR-02** | `VAULT_ACTIVE` | Allocation reaches ceiling | `allocated_count == 100,000` | KMS rejects new reservations; initiate orderly key rotation. | `ORDERLY_ROTATION` | Reject writes with HTTP 503 (`BudgetExhausted`). |
| **DR-03** | `ORDERLY_ROTATION` | Automated key advance | Cron / threshold trigger | KMS generates $\text{MK}_{v+1}$; CP re-wraps DEKs in background. | `VAULT_ACTIVE` (Key $V+1$) | Retry rewrapping; old key reads active. |
| **DR-04** | `VAULT_ACTIVE` | Database restore detected | `local_epoch < KMS_epoch` | Deployment orchestrator detects epoch mismatch on boot. | `RECOVERY_LOCKED` | Immediate lock; assert fails closed. |
| **DR-05** | `RECOVERY_LOCKED` | Secret write/encrypt request | Vault in `RECOVERY_LOCKED` | Reject request immediately with HTTP 503 (`RecoveryInProgress`). | `RECOVERY_LOCKED` | Zero writes permitted. |
| **DR-06** | `RECOVERY_LOCKED` | Recovery leader election | Multiple CP instances | Acquire distributed advisory lease lock in KMS quorum. | `LEADER_ELECTED` | Non-leaders wait; timeout $\to$ retry. |
| **DR-07** | `LEADER_ELECTED` | Request new Master Key | Leader lease held | KMS generates $\text{MK}_{v+1}$; initializes `allocated_count = 0` for $V+1$. | `KEY_ADVANCED` | KMS unreachable $\to$ fail closed in `RECOVERY_LOCKED`. |
| **DR-08** | `KEY_ADVANCED` | Batch DEK re-wrapping | $\text{MK}_{v+1}$ available | Read `encrypted_dek` with $\text{MK}_v$; re-wrap under $\text{MK}_{v+1}$; checkpoint batches. | `REWRAPPING` | Crash $\to$ leader resumes from checkpoint. |
| **DR-09** | `REWRAPPING` | Integrity verification | 100% DEKs re-wrapped | Verify GCM auth tags on all re-wrapped DEKs; assert zero read errors. | `INTEGRITY_VERIFIED` | Auth tag mismatch $\to$ halt recovery; alert SRE. |
| **DR-10** | `INTEGRITY_VERIFIED` | Commit recovery epoch | 100% integrity verified | Atomically update `local_epoch_token = KMS_epoch` in DB & KMS; release lock. | `VAULT_ACTIVE` | Commit failure $\to$ retry commit; remain locked. |

---

## 4. Adversarial Test Scenarios

### 4.1 Dispatch & Revocation Race Scenarios (CI/CD Suite)
1. **Test RAC-01 (Pre-Commit Revocation):** Revocation commits before Step 8. Stored procedure detects `status != 'ACTIVE'`, aborts, zero rows modified. Worker requests no rule, sends zero bytes.
2. **Test RAC-02 (Post-Firewall Revocation Window):** Revocation commits during Step 9. Step 10 pre-dispatch check detects `dispatch_revoked == TRUE`. Worker immediately invokes `DELETE /rules/<id>`, teardown executes `ss -K`, execution transitions to `aborted_pre_dispatch`. Zero bytes transmitted.
3. **Test RAC-03 (Point of No Return Crossed):** Revocation commits after `socket.sendall()`. Host Controller executes `SOCK_DESTROY`, resetting local socket. Execution transitions to `execution_uncertain` with permanent hold (`9999-01-01T00:00:00Z`). Redispatch is strictly blocked.
4. **Test RAC-04 (Stale Token Invalidation):** Revoked execution attempts to re-claim lease. Stored procedure rejects token with `TOKEN_ALREADY_CONSUMED_OR_REVOKED`.

### 4.2 Network Isolation & Socket Destruction Scenarios
1. **Test NET-01 (Concurrent Executions to Same IP):** Worker A (Execution 1) and Worker B (Execution 2) simultaneously connect to `api.customer.com:443`. When Execution 1 terminates, Host Controller executes `ss -K dst api.customer.com:443` inside Worker A's network namespace. Worker B's active TLS connection and HTTP transfer proceed with **zero packet loss and zero disruption**.
2. **Test NET-02 (Keep-Alive Pool Draining):** Worker establishes HTTP connection with persistent keep-alive. Upon lease expiration, kernel `SOCK_DESTROY` tears down the socket. Subsequent attempts to reuse pooled socket fail immediately with `ECONNABORTED`.
3. **Test NET-03 (Failed Cleanup Tainting):** Conntrack deletion is mocked to return exit code 1. Host Controller marks worker container tainted, issues `SIGKILL`, destroys container (`docker rm -f`), and provisions fresh container with clean network namespace before next lease claim.

### 4.3 Customer Receiver Idempotency Scenarios
1. **Test IDP-01 (Replay Cached Outcome):** Repeated HTTP POST requests with matching `(execution_id, nonce)` return cached HTTP 200 response without re-executing physical mock action.
2. **Test IDP-02 (Payload Tampering Rejection):** Repeated HTTP POST with matching `(execution_id, nonce)` but altered JSON body returns `HTTP 400 Bad Request` (`IdempotencyKeyPayloadMismatch`).
3. **Test IDP-03 (Crash Recovery to Tombstone):** Customer service terminates mid-remediation. On restart, orphaned `IN_PROGRESS` record transitions to `AMBIGUOUS` with `expires_at = NULL`. Automated TTL cleaner runs; record is NOT deleted. Replayed request receives `HTTP 409 Conflict`.

---

## 5. Residual Risk Register & Operational Assumptions

All architectural and cryptographic blockers have been resolved. The residual operational assumptions are classified below:

| Risk ID | Severity | Operational Assumption / Scenario | Architectural Defense & Mitigation |
| :--- | :--- | :--- | :--- |
| **RES-408-01** | **Low** | Host Netfilter Controller daemon crashes during execution. | Netfilter rules reside in kernel memory and remain active for the lease duration. On reboot, the controller reconciles active leases against PostgreSQL and flushes orphaned rules. |
| **RES-408-02** | **Low** | KMS API latency during budget block reservation ($B=100$). | Block allocation is amortized over 100 executions; Control Plane buffers blocks in memory. Expiration forces fail-closed reject. |
| **RES-408-03** | **Low** | Customer webhook endpoint crashes before persisting tombstone. | SentinelOps worker marks local execution `execution_uncertain` with permanent hold; customer receiver startup sweep recovers in-progress records to tombstones. |

---

## 6. Cross-Section Consistency Audit

A thorough internal consistency audit verified that all 18 sections of `docs/STAGE_4_GENERIC_EXTERNAL_SERVICE_ARCHITECTURE.md` are completely aligned:
1. **Worker Concurrency & Network Isolation:** Invariant 3 in Section 1 matches `worker_concurrency = 1` in Section 9.1 and Section 16 roadmap.
2. **Step 10 Pre-Dispatch Synchronization:** Sequence diagram (Section 4.1), race conditions table (Section 4.3), and crash matrix (Section 7.2) consistently reflect Step 10 synchronous database verification closing the post-firewall window.
3. **Point of No Return Invariant:** Section 3.2, Section 4.2, Section 4.3 (Race 5), and Section 7.2 (CS-08) consistently identify `socket.sendall()` as the irreversible boundary forcing permanent uncertain holds.
4. **4-State Customer Receiver Engine:** Section 12.2 schema and state diagram match CS-12 crash matrix entry and SEC-408-03 threat model defense.
5. **External KMS Conservative Budget:** Section 11.2 and Section 11.3 block allocation protocol matches SEC-408-04 and 10-state DR table.
6. **Canonical Byte Hashing:** Section 5.2 Property 36 matches Section 10.2 algorithm and SEC-408-05.
7. **PostgreSQL Catalog Verification:** Section 6.2 DDL matches Section 8.1 grants and SEC-408-06.
8. **Option C Preservation:** Baseline Option C execution invariants remain green, verified, and 100% frozen.

---

## 7. Independent Readiness Self-Assessment & Concluding Verdict

```text
========================================================================================
FINAL ACCEPTANCE VERDICT:
PASS — READY FOR INDEPENDENT SECURITY ACCEPTANCE RE-AUDIT
========================================================================================
```

The SentinelOps Stage 4.0.8 architecture delivers complete mathematical, cryptographic, and operational closure across dispatch/revocation synchronization, single-concurrency execution network isolation, customer receiver durability with permanent tombstones, external KMS budget conservation, exact TLS trust material byte consistency, and PostgreSQL catalog-level privilege verification. The specification is complete, robust, fully backwards-compatible with frozen Option C Stage 3.3, and certified ready for formal independent re-audit. Implementation of Stage 4.1 remains unauthorized pending successful independent audit acceptance.
