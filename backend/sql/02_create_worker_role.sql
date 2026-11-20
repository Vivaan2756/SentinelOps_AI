-- =============================================================================
-- SentinelOps Phase 3A / Stage 3.1: Dedicated Worker Role (FINDING-2.1-02)
-- Minimum Necessary Permissions for Asynchronous Execution Worker
-- Requires deployment-provided secret via WORKER_DB_PASSWORD.
-- Committed static default passwords are strictly prohibited.
-- =============================================================================

\getenv worker_pwd WORKER_DB_PASSWORD

DO $$
DECLARE
    pwd text := NULLIF(:'worker_pwd', '');
BEGIN
    IF pwd IS NULL OR pwd = 'sentinelops_worker_password' OR pwd = 'change_me' OR pwd = 'password' THEN
        RAISE EXCEPTION 'A secure deployment-provided WORKER_DB_PASSWORD must be configured for sentinelops_worker.';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinelops_worker') THEN
        EXECUTE format('CREATE ROLE sentinelops_worker WITH LOGIN PASSWORD %L', pwd);
    ELSE
        EXECUTE format('ALTER ROLE sentinelops_worker WITH PASSWORD %L', pwd);
    END IF;
END
$$;

-- Schema usage
GRANT USAGE ON SCHEMA public TO sentinelops_worker;

-- 1. Execution coordination and durable state (SELECT, UPDATE)
GRANT SELECT, UPDATE ON remediation_executions TO sentinelops_worker;
GRANT SELECT, INSERT, UPDATE ON execution_attempts TO sentinelops_worker;
GRANT SELECT, INSERT ON execution_events TO sentinelops_worker;

-- 2. Human approval reference (SELECT only - read-only parameters)
GRANT SELECT ON remediation_approvals TO sentinelops_worker;

-- 3. Incident tracking & recovery bridge (SELECT, UPDATE on incidents; SELECT, INSERT on incident_events)
GRANT SELECT, UPDATE ON incidents TO sentinelops_worker;
GRANT SELECT, INSERT ON incident_events TO sentinelops_worker;

-- 4. Monitored target service resolution (SELECT only)
GRANT SELECT ON services TO sentinelops_worker;

-- 5. AI investigation reference (SELECT only)
GRANT SELECT ON investigations TO sentinelops_worker;

-- 6. Independent verification cycles and probes (SELECT, INSERT, UPDATE)
GRANT SELECT, INSERT, UPDATE ON verification_cycles TO sentinelops_worker;
GRANT SELECT, INSERT, UPDATE ON verification_probe_results TO sentinelops_worker;

-- 7. Workspace tenant isolation (SELECT only)
GRANT SELECT ON workspaces TO sentinelops_worker;

-- Sequences for auto-increment / serials if any
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinelops_worker;

-- =============================================================================
-- Explicitly RESTRICTED tables (ZERO permissions granted to worker):
-- - users (passwords, tokens, personal data)
-- - workspace_memberships (user-workspace roles)
-- - playbooks (playbook definitions and scripts)
-- - playbook_versions (version history)
-- - service_playbook_associations (playbook mappings)
-- - policy_decisions (policy evaluation rules and decisions)
-- =============================================================================
