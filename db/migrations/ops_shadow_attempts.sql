-- Full-path shadow telemetry and fail-closed seven-day readiness.
--
-- A Dash response is only one part of a governed investigation. Dockhand owns
-- this attempt record so evidence-collection, registry, transport, and
-- persistence failures cannot remain invisible to the promotion gate.

CREATE TABLE IF NOT EXISTS ops.ops_shadow_attempts (
    investigation_id TEXT PRIMARY KEY REFERENCES ops.ops_investigations(id),
    status TEXT NOT NULL CHECK (status IN ('started', 'succeeded', 'failed')),
    stage TEXT NOT NULL,
    error_code TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CHECK (
        (status = 'started' AND completed_at IS NULL)
        OR (status IN ('succeeded', 'failed') AND completed_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS ops_shadow_attempts_gate_idx
    ON ops.ops_shadow_attempts (started_at DESC, status);

CREATE OR REPLACE VIEW ops.ops_shadow_readiness AS
WITH evaluation_window AS (
    SELECT *
    FROM ops.ops_shadow_evaluations
    WHERE evaluated_at >= date_trunc('day', NOW()) - INTERVAL '6 days'
), attempt_window AS (
    SELECT *
    FROM ops.ops_shadow_attempts
    WHERE started_at >= date_trunc('day', NOW()) - INTERVAL '6 days'
), evaluation_totals AS (
    SELECT
        COUNT(*) AS evaluation_count,
        COUNT(*) FILTER (WHERE NOT citation_valid) AS citation_failures,
        COUNT(*) FILTER (WHERE NOT proposal_schema_valid) AS proposal_schema_failures,
        COALESCE(SUM(policy_violations), 0) AS policy_violations
    FROM evaluation_window
), attempt_totals AS (
    SELECT
        COUNT(*) AS attempt_count,
        COUNT(*) FILTER (WHERE status = 'succeeded') AS successful_attempts,
        COUNT(*) FILTER (WHERE status = 'failed') AS failed_attempts,
        COUNT(*) FILTER (WHERE status = 'started') AS incomplete_attempts,
        COUNT(DISTINCT started_at::DATE) FILTER (
            WHERE status = 'succeeded'
        ) AS covered_days
    FROM attempt_window
)
SELECT
    -- Preserve the original view columns and order. PostgreSQL permits
    -- CREATE OR REPLACE VIEW to append columns, but not to reorder them.
    evaluation.evaluation_count,
    attempt.covered_days,
    evaluation.citation_failures,
    evaluation.proposal_schema_failures,
    evaluation.policy_violations,
    (
        attempt.covered_days = 7
        AND attempt.successful_attempts >= 7
        AND attempt.failed_attempts = 0
        AND attempt.incomplete_attempts = 0
        AND evaluation.evaluation_count > 0
        AND evaluation.citation_failures = 0
        AND evaluation.proposal_schema_failures = 0
        AND evaluation.policy_violations = 0
    ) AS recommendation_mode_eligible,
    attempt.attempt_count,
    attempt.successful_attempts,
    attempt.failed_attempts,
    attempt.incomplete_attempts
FROM evaluation_totals evaluation
CROSS JOIN attempt_totals attempt;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dash_ops_reader') THEN
        GRANT SELECT ON ops.ops_shadow_attempts, ops.ops_shadow_readiness
            TO dash_ops_reader;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dockhand_ops_writer') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON ops.ops_shadow_attempts
            TO dockhand_ops_writer;
        GRANT SELECT ON ops.ops_shadow_readiness TO dockhand_ops_writer;
    END IF;
END $$;
