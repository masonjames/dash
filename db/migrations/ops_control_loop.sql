-- Canonical operational control-loop ledger.
-- Dockhand is the only writer/executor. Dash receives a read-only role.

CREATE SCHEMA IF NOT EXISTS ops;

-- Durable replay protection for Portal-signed mutation requests. Verification
-- consumes the request ID exactly once before the handler mutates state;
-- bounded pruning is allowed after the replay window has safely elapsed.
CREATE TABLE IF NOT EXISTS ops.ops_portal_request_nonces (
    request_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    body_hash TEXT NOT NULL CHECK (body_hash ~ '^[a-f0-9]{64}$'),
    sent_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ops_portal_request_nonces_consumed_idx
    ON ops.ops_portal_request_nonces (consumed_at);

ALTER TABLE IF EXISTS state_snapshots
    ADD COLUMN IF NOT EXISTS docker_root TEXT,
    ADD COLUMN IF NOT EXISTS docker_disk_usage_pct NUMERIC,
    ADD COLUMN IF NOT EXISTS cpu_pressure_pct NUMERIC;

ALTER TABLE IF EXISTS desired_services
    ADD COLUMN IF NOT EXISTS source_commit TEXT,
    ADD COLUMN IF NOT EXISTS source_content_hash TEXT,
    ADD COLUMN IF NOT EXISTS logical_service_name TEXT,
    ADD COLUMN IF NOT EXISTS inventory_project_id TEXT,
    ADD COLUMN IF NOT EXISTS runtime_project_name TEXT,
    ADD COLUMN IF NOT EXISTS host TEXT,
    ADD COLUMN IF NOT EXISTS current_memory_limit_bytes BIGINT;
UPDATE desired_services
SET source_commit = COALESCE(source_commit, 'legacy-unknown'),
    source_content_hash = COALESCE(source_content_hash, md5(source_file || COALESCE(image, ''))),
    logical_service_name = COALESCE(NULLIF(logical_service_name, ''), service_name),
    host = COALESCE(NULLIF(host, ''), NULLIF(environment, ''), 'legacy-unknown')
WHERE source_commit IS NULL OR source_content_hash IS NULL
   OR logical_service_name IS NULL OR logical_service_name = ''
   OR host IS NULL OR host = '';
ALTER TABLE IF EXISTS desired_services
    ALTER COLUMN source_commit SET NOT NULL,
    ALTER COLUMN source_content_hash SET NOT NULL,
    ALTER COLUMN logical_service_name SET NOT NULL,
    ALTER COLUMN host SET NOT NULL;
ALTER TABLE IF EXISTS desired_services
    DROP CONSTRAINT IF EXISTS desired_services_current_memory_limit_bytes_check;
ALTER TABLE IF EXISTS desired_services
    ADD CONSTRAINT desired_services_current_memory_limit_bytes_check CHECK (
        current_memory_limit_bytes IS NULL OR current_memory_limit_bytes > 0
    );

-- Drift is partitioned by observed environment and host. A service name is
-- not globally unique, and incomplete hosts must never resolve one another.
ALTER TABLE IF EXISTS drift_observations
    ADD COLUMN IF NOT EXISTS host TEXT,
    ADD COLUMN IF NOT EXISTS environment TEXT;
UPDATE drift_observations
SET host = COALESCE(NULLIF(host, ''), 'legacy-unknown'),
    environment = COALESCE(
        NULLIF(environment, ''), NULLIF(host, ''), 'legacy-unknown'
    )
WHERE host IS NULL OR host = '' OR environment IS NULL OR environment = '';
ALTER TABLE IF EXISTS drift_observations
    ALTER COLUMN host SET NOT NULL,
    ALTER COLUMN environment SET NOT NULL;
DROP INDEX IF EXISTS idx_drift_observations_upsert;
CREATE UNIQUE INDEX idx_drift_observations_upsert
    ON drift_observations (environment, host, service_name, category)
    WHERE resolved_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_drift_observations_partition
    ON drift_observations (environment, host, observed_at DESC);

ALTER TABLE IF EXISTS deploy_events
    ADD COLUMN IF NOT EXISTS external_event_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS deploy_events_external_event_idx
    ON deploy_events (external_event_id) WHERE external_event_id IS NOT NULL;

ALTER TABLE IF EXISTS docker_events
    ADD COLUMN IF NOT EXISTS external_event_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS docker_events_external_event_idx
    ON docker_events (external_event_id) WHERE external_event_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ops.event_projection_cursors (
    source TEXT PRIMARY KEY,
    last_rowid BIGINT NOT NULL DEFAULT 0,
    last_error TEXT,
    classifier_version TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE ops.event_projection_cursors
    ADD COLUMN IF NOT EXISTS last_error TEXT,
    ADD COLUMN IF NOT EXISTS classifier_version TEXT;

CREATE TABLE IF NOT EXISTS ops.ops_raw_events (
    external_event_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    local_rowid BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    host TEXT,
    severity TEXT,
    raw_payload TEXT NOT NULL,
    raw_payload_length INTEGER NOT NULL DEFAULT 0,
    payload JSONB,
    related_job_ids JSONB,
    parse_error TEXT,
    redaction_version TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE ops.ops_raw_events
    ADD COLUMN IF NOT EXISTS raw_payload_length INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS ops_raw_events_occurred_idx
    ON ops.ops_raw_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS ops_raw_events_source_idx
    ON ops.ops_raw_events (source, local_rowid);

CREATE TABLE IF NOT EXISTS ops.event_projection_status (
    projector TEXT NOT NULL,
    external_event_id TEXT NOT NULL REFERENCES ops.ops_raw_events(external_event_id),
    classifier_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('classified','unclassified','dead_letter')),
    target_table TEXT,
    error TEXT,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (projector, external_event_id)
);
CREATE INDEX IF NOT EXISTS event_projection_status_retry_idx
    ON ops.event_projection_status (projector, status, classifier_version);

CREATE TABLE IF NOT EXISTS ops.ops_investigations (
    id TEXT PRIMARY KEY,
    request_id TEXT UNIQUE,
    request_hash TEXT,
    prompt TEXT NOT NULL,
    environment TEXT,
    service TEXT,
    incident_id TEXT,
    state TEXT NOT NULL CHECK (state IN (
        'queued','collecting','reasoning','proposed','executing',
        'verifying','recovery_required','resolved','failed'
    )),
    requested_by TEXT,
    job_id TEXT,
    model_version TEXT,
    confidence NUMERIC CHECK (confidence BETWEEN 0 AND 1),
    summary TEXT,
    reasoning_result JSONB,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE ops.ops_investigations
    DROP CONSTRAINT IF EXISTS ops_investigations_state_check;
ALTER TABLE ops.ops_investigations
    ADD CONSTRAINT ops_investigations_state_check CHECK (state IN (
        'queued','collecting','reasoning','proposed','executing',
        'verifying','recovery_required','resolved','failed'
    ));

ALTER TABLE ops.ops_investigations
    ADD COLUMN IF NOT EXISTS request_id TEXT,
    ADD COLUMN IF NOT EXISTS request_hash TEXT;
UPDATE ops.ops_investigations
SET request_id = COALESCE(request_id, 'legacy-' || id),
    request_hash = COALESCE(
        request_hash,
        md5(id || prompt || COALESCE(requested_by, ''))
    )
WHERE request_id IS NULL OR request_hash IS NULL;
ALTER TABLE ops.ops_investigations
    ALTER COLUMN request_id SET NOT NULL,
    ALTER COLUMN request_hash SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ops_investigations_request_idx
    ON ops.ops_investigations (request_id);

-- Transactional outbox bridging the canonical Postgres command ledger to the
-- local replay-safe Dockhand queue. The deterministic idempotency key prevents
-- a crash between SQLite enqueue and Postgres acknowledgement from duplicating
-- an investigation job.
CREATE TABLE IF NOT EXISTS ops.ops_commands (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    investigation_id TEXT NOT NULL REFERENCES ops.ops_investigations(id) ON DELETE CASCADE,
    proposal_id TEXT,
    command_type TEXT NOT NULL CHECK (command_type IN ('investigate','execute_proposal')),
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending','dispatching','dispatched','dead')
    ),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    job_id TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_id TEXT,
    lease_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dispatched_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE ops.ops_commands
    ADD COLUMN IF NOT EXISTS proposal_id TEXT,
    ADD COLUMN IF NOT EXISTS lease_id TEXT;
ALTER TABLE ops.ops_commands DROP CONSTRAINT IF EXISTS ops_commands_command_type_check;
ALTER TABLE ops.ops_commands ADD CONSTRAINT ops_commands_command_type_check
    CHECK (command_type IN ('investigate','execute_proposal'));
CREATE INDEX IF NOT EXISTS ops_commands_dispatch_idx
    ON ops.ops_commands (status, next_attempt_at, created_at);

CREATE TABLE IF NOT EXISTS ops.ops_evidence (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES ops.ops_investigations(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    query_version TEXT NOT NULL DEFAULT 'legacy-v0',
    scope JSONB NOT NULL DEFAULT '{}'::JSONB,
    redaction_version TEXT NOT NULL DEFAULT 'legacy-v0',
    summary TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    observation_started_at TIMESTAMPTZ,
    observation_ended_at TIMESTAMPTZ,
    captured_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    content_hash TEXT NOT NULL,
    redacted BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (investigation_id, content_hash)
);

ALTER TABLE ops.ops_evidence
    ADD COLUMN IF NOT EXISTS query_version TEXT NOT NULL DEFAULT 'legacy-v0',
    ADD COLUMN IF NOT EXISTS scope JSONB NOT NULL DEFAULT '{}'::JSONB,
    ADD COLUMN IF NOT EXISTS redaction_version TEXT NOT NULL DEFAULT 'legacy-v0',
    ADD COLUMN IF NOT EXISTS observation_started_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS observation_ended_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS ops.ops_remediation_proposals (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES ops.ops_investigations(id) ON DELETE CASCADE,
    proposal_type TEXT NOT NULL CHECK (proposal_type IN ('job','playbook','desired_state_pr')),
    job_kind TEXT,
    playbook_id TEXT,
    playbook_version TEXT NOT NULL,
    registry_version TEXT NOT NULL DEFAULT 'legacy-v0',
    definition_digest TEXT NOT NULL DEFAULT 'legacy-v0',
    stabilization_seconds INTEGER NOT NULL DEFAULT 0 CHECK (stabilization_seconds >= 0),
    risk_class TEXT NOT NULL CHECK (risk_class IN ('R0','R1','R2','R3')),
    target_environment TEXT NOT NULL,
    arguments JSONB NOT NULL DEFAULT '{}'::JSONB,
    preconditions JSONB NOT NULL,
    evidence_ids JSONB NOT NULL,
    evidence_max_age_seconds INTEGER NOT NULL CHECK (evidence_max_age_seconds > 0),
    rollback_steps JSONB NOT NULL,
    postconditions JSONB NOT NULL,
    plan_hash TEXT NOT NULL UNIQUE,
    approval_id TEXT,
    job_id TEXT,
    state TEXT NOT NULL DEFAULT 'proposed',
    execution_requested_by TEXT,
    execution_requested_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE ops.ops_remediation_proposals
    ADD COLUMN IF NOT EXISTS registry_version TEXT NOT NULL DEFAULT 'legacy-v0',
    ADD COLUMN IF NOT EXISTS definition_digest TEXT NOT NULL DEFAULT 'legacy-v0',
    ADD COLUMN IF NOT EXISTS stabilization_seconds INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS execution_requested_by TEXT,
    ADD COLUMN IF NOT EXISTS execution_requested_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ops_commands_proposal_fk'
          AND conrelid = 'ops.ops_commands'::regclass
    ) THEN
        ALTER TABLE ops.ops_commands
            ADD CONSTRAINT ops_commands_proposal_fk
            FOREIGN KEY (proposal_id) REFERENCES ops.ops_remediation_proposals(id);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS ops.ops_verification_runs (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES ops.ops_investigations(id),
    proposal_id TEXT NOT NULL REFERENCES ops.ops_remediation_proposals(id),
    success BOOLEAN,
    rollback_executed BOOLEAN NOT NULL DEFAULT FALSE,
    postcondition_results JSONB NOT NULL DEFAULT '[]'::JSONB,
    evidence_ids JSONB NOT NULL DEFAULT '[]'::JSONB,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS ops.ops_learning_candidates (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES ops.ops_investigations(id),
    playbook_id TEXT NOT NULL,
    playbook_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'legacy','candidate','verified','promoted','rejected','superseded'
    )),
    confidence NUMERIC NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    evidence_ids JSONB NOT NULL,
    successful_outcomes INTEGER NOT NULL DEFAULT 0,
    distinct_incidents INTEGER NOT NULL DEFAULT 0,
    failures_90d INTEGER NOT NULL DEFAULT 0,
    rollbacks_90d INTEGER NOT NULL DEFAULT 0,
    rollback_tested BOOLEAN NOT NULL DEFAULT FALSE,
    automatic_eligibility BOOLEAN NOT NULL DEFAULT FALSE,
    decision_reason TEXT,
    decided_by TEXT,
    decided_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (investigation_id, playbook_id, playbook_version)
);

CREATE TABLE IF NOT EXISTS ops.ops_playbook_outcomes (
    id TEXT PRIMARY KEY,
    learning_candidate_id TEXT REFERENCES ops.ops_learning_candidates(id),
    investigation_id TEXT NOT NULL REFERENCES ops.ops_investigations(id),
    proposal_id TEXT REFERENCES ops.ops_remediation_proposals(id),
    verification_run_id TEXT REFERENCES ops.ops_verification_runs(id),
    incident_id TEXT,
    playbook_id TEXT NOT NULL,
    playbook_version TEXT NOT NULL,
    outcome_kind TEXT NOT NULL DEFAULT 'execution' CHECK (
        outcome_kind IN ('execution','rollback_drill')
    ),
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    source TEXT NOT NULL DEFAULT 'dockhand-verifier',
    success BOOLEAN NOT NULL,
    rollback_executed BOOLEAN NOT NULL DEFAULT FALSE,
    confidence NUMERIC NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    evidence_ids JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE ops.ops_playbook_outcomes
    ADD COLUMN IF NOT EXISTS proposal_id TEXT REFERENCES ops.ops_remediation_proposals(id),
    ADD COLUMN IF NOT EXISTS verification_run_id TEXT REFERENCES ops.ops_verification_runs(id),
    ADD COLUMN IF NOT EXISTS outcome_kind TEXT NOT NULL DEFAULT 'execution',
    ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'dockhand-verifier';

CREATE TABLE IF NOT EXISTS ops.ops_health_score_snapshots (
    id TEXT PRIMARY KEY,
    score_version TEXT NOT NULL,
    score NUMERIC CHECK (score BETWEEN 0 AND 100),
    coverage NUMERIC NOT NULL CHECK (coverage BETWEEN 0 AND 1),
    components JSONB NOT NULL,
    deductions JSONB NOT NULL DEFAULT '{}'::JSONB,
    source_freshness JSONB NOT NULL,
    unavailable_reasons JSONB NOT NULL DEFAULT '[]'::JSONB,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE ops.ops_health_score_snapshots
    ADD COLUMN IF NOT EXISTS deductions JSONB NOT NULL DEFAULT '{}'::JSONB;

CREATE INDEX IF NOT EXISTS ops_investigations_state_idx
    ON ops.ops_investigations (state, updated_at DESC);
CREATE INDEX IF NOT EXISTS ops_evidence_investigation_idx
    ON ops.ops_evidence (investigation_id, captured_at DESC);
CREATE INDEX IF NOT EXISTS ops_learning_status_idx
    ON ops.ops_learning_candidates (status, created_at DESC);
CREATE INDEX IF NOT EXISTS ops_outcomes_playbook_idx
    ON ops.ops_playbook_outcomes (playbook_id, playbook_version, occurred_at DESC);

-- Evidence and outcomes are append-only facts. Proposal safety plans are also
-- immutable; only lifecycle linkage/state may change after an operator acts.
CREATE OR REPLACE FUNCTION ops.reject_append_only_mutation()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;

DROP TRIGGER IF EXISTS ops_evidence_append_only ON ops.ops_evidence;
CREATE TRIGGER ops_evidence_append_only
    BEFORE UPDATE OR DELETE ON ops.ops_evidence
    FOR EACH ROW EXECUTE FUNCTION ops.reject_append_only_mutation();

DROP TRIGGER IF EXISTS ops_raw_events_append_only ON ops.ops_raw_events;
CREATE TRIGGER ops_raw_events_append_only
    BEFORE UPDATE OR DELETE ON ops.ops_raw_events
    FOR EACH ROW EXECUTE FUNCTION ops.reject_append_only_mutation();

DROP TRIGGER IF EXISTS ops_outcomes_append_only ON ops.ops_playbook_outcomes;
CREATE TRIGGER ops_outcomes_append_only
    BEFORE UPDATE OR DELETE ON ops.ops_playbook_outcomes
    FOR EACH ROW EXECUTE FUNCTION ops.reject_append_only_mutation();

CREATE OR REPLACE FUNCTION ops.reject_proposal_plan_mutation()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.proposal_type, NEW.job_kind, NEW.playbook_id, NEW.playbook_version,
        NEW.registry_version, NEW.definition_digest, NEW.stabilization_seconds,
        NEW.risk_class, NEW.target_environment, NEW.arguments, NEW.preconditions,
        NEW.evidence_ids, NEW.evidence_max_age_seconds, NEW.rollback_steps,
        NEW.postconditions, NEW.plan_hash)
       IS DISTINCT FROM
       (OLD.proposal_type, OLD.job_kind, OLD.playbook_id, OLD.playbook_version,
        OLD.registry_version, OLD.definition_digest, OLD.stabilization_seconds,
        OLD.risk_class, OLD.target_environment, OLD.arguments, OLD.preconditions,
        OLD.evidence_ids, OLD.evidence_max_age_seconds, OLD.rollback_steps,
        OLD.postconditions, OLD.plan_hash) THEN
        RAISE EXCEPTION 'remediation proposal safety plan is immutable';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS ops_proposal_plan_immutable ON ops.ops_remediation_proposals;
CREATE TRIGGER ops_proposal_plan_immutable
    BEFORE UPDATE ON ops.ops_remediation_proposals
    FOR EACH ROW EXECUTE FUNCTION ops.reject_proposal_plan_mutation();

-- Deployment should replace these sample principals with secret-managed roles.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dash_ops_reader') THEN
        GRANT USAGE ON SCHEMA ops TO dash_ops_reader;
        GRANT SELECT ON ALL TABLES IN SCHEMA ops TO dash_ops_reader;
        ALTER DEFAULT PRIVILEGES IN SCHEMA ops GRANT SELECT ON TABLES TO dash_ops_reader;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dockhand_ops_writer') THEN
        GRANT USAGE ON SCHEMA public, ops TO dockhand_ops_writer;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public, ops
            TO dockhand_ops_writer;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public, ops
            TO dockhand_ops_writer;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public, ops
            GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO dockhand_ops_writer;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public, ops
            GRANT USAGE, SELECT ON SEQUENCES TO dockhand_ops_writer;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dash_api_runtime') THEN
        EXECUTE 'CREATE SCHEMA IF NOT EXISTS ai AUTHORIZATION dash_api_runtime';
        EXECUTE 'CREATE SCHEMA IF NOT EXISTS dash AUTHORIZATION dash_api_runtime';
        GRANT USAGE, CREATE ON SCHEMA ai, dash TO dash_api_runtime;
        GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA ai, dash TO dash_api_runtime;
        GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ai, dash TO dash_api_runtime;
        ALTER DEFAULT PRIVILEGES IN SCHEMA ai, dash
            GRANT ALL PRIVILEGES ON TABLES TO dash_api_runtime;
        ALTER DEFAULT PRIVILEGES IN SCHEMA ai, dash
            GRANT ALL PRIVILEGES ON SEQUENCES TO dash_api_runtime;
        GRANT USAGE ON SCHEMA public TO dash_api_runtime;
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO dash_api_runtime;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
            GRANT SELECT ON TABLES TO dash_api_runtime;
        REVOKE ALL ON SCHEMA ops FROM dash_api_runtime;
        REVOKE ALL ON ALL TABLES IN SCHEMA ops FROM dash_api_runtime;
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA ops FROM dash_api_runtime;
        ALTER ROLE dash_api_runtime SET search_path = ai, dash, public;
    END IF;
END $$;

-- Conservative legacy backfill: searchable, never automatically eligible.
INSERT INTO ops.ops_investigations (
    id, request_id, request_hash, prompt, incident_id, state, requested_by, confidence, summary,
    created_at, updated_at
)
SELECT
    'legacy_incident_' || id,
    'legacy-incident-' || id,
    md5(id::TEXT || 'legacy-sanitized-migration'),
    'Legacy incident ' || id,
    id::TEXT,
    'resolved',
    'migration',
    0.5,
    'Legacy conclusion withheld pending explicit redaction review',
    started_at,
    COALESCE(resolved_at, started_at)
FROM incident_markers
ON CONFLICT (id) DO NOTHING;

INSERT INTO ops.ops_evidence (
    id, investigation_id, kind, source, query_version, redaction_version,
    summary, payload, captured_at, content_hash, redacted
)
SELECT
    'legacy_evidence_incident_' || id,
    'legacy_incident_' || id,
    'legacy_incident',
    'incident_markers',
    'legacy-v0',
    'migration-sanitized-v1',
    'Legacy incident metadata; narrative payload omitted pending redaction review',
    jsonb_build_object(
        'severity', severity,
        'affected_services', affected_services,
        'narrative_omitted', TRUE
    ),
    started_at,
    md5(
        id::TEXT || COALESCE(severity, '') || 'legacy-sanitized'
    ),
    TRUE
FROM incident_markers
ON CONFLICT (id) DO NOTHING;

INSERT INTO ops.ops_learning_candidates (
    id, investigation_id, playbook_id, playbook_version, status, confidence,
    evidence_ids, decision_reason
)
SELECT
    'legacy_learning_incident_' || id,
    'legacy_incident_' || id,
    'legacy.incident.' || id,
    '0',
    'legacy',
    0.5,
    jsonb_build_array('legacy_evidence_incident_' || id),
    'Imported for retrieval only; requires new verified outcomes before promotion'
FROM incident_markers
WHERE resolved_at IS NOT NULL
ON CONFLICT (id) DO NOTHING;
