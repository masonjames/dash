-- Advisory telemetry never authorizes recommendation mode or automation.
CREATE TABLE IF NOT EXISTS ops.ops_advisory_decisions (
    id TEXT PRIMARY KEY,
    decision_kind TEXT NOT NULL CHECK (decision_kind IN (
        'residue_target','signal_scope','alert_job','cause_code',
        'postcondition_forecast','prompt_injection','failure_pattern')),
    subject_type TEXT NOT NULL CHECK (subject_type IN (
        'raw_event','investigation','proposal','job')),
    subject_id TEXT NOT NULL,
    detector_version TEXT NOT NULL, -- question-schema version
    model_version TEXT NOT NULL, -- '<response.model>+<fingerprint12>'
    request_id TEXT,
    state_hash TEXT NOT NULL CHECK (state_hash ~ '^[a-f0-9]{64}$'),
    answers JSONB NOT NULL,
    top_answer TEXT NOT NULL,
    confidence NUMERIC NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    rules_answer TEXT,
    agrees_with_rules BOOLEAN,
    latency_ms INTEGER NOT NULL CHECK (latency_ms >= 0),
    advised_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((rules_answer IS NULL) = (agrees_with_rules IS NULL)),
    UNIQUE (decision_kind, subject_id, detector_version)
);

CREATE INDEX IF NOT EXISTS ops_advisory_decisions_kind_advised_idx
    ON ops.ops_advisory_decisions (decision_kind, advised_at DESC);
CREATE INDEX IF NOT EXISTS ops_advisory_decisions_subject_idx
    ON ops.ops_advisory_decisions (subject_type, subject_id);

DROP TRIGGER IF EXISTS ops_advisory_decisions_append_only ON ops.ops_advisory_decisions;
CREATE TRIGGER ops_advisory_decisions_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON ops.ops_advisory_decisions
    FOR EACH STATEMENT EXECUTE FUNCTION ops.reject_append_only_mutation();

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
), advisory_window AS (
    SELECT *
    FROM ops.ops_advisory_decisions
    WHERE advised_at >= date_trunc('day', NOW()) - INTERVAL '6 days'
), advisory_totals AS (
    SELECT
        COUNT(*) FILTER (WHERE decision_kind = 'cause_code') AS advisory_cause_decisions,
        COUNT(*) FILTER (
            WHERE decision_kind = 'cause_code' AND agrees_with_rules
        ) AS advisory_cause_agreements,
        COUNT(*) FILTER (
            WHERE decision_kind = 'cause_code' AND agrees_with_rules IS NOT NULL
        ) AS advisory_cause_comparable,
        COUNT(DISTINCT model_version) AS advisory_model_versions
    FROM advisory_window
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
    attempt.incomplete_attempts,
    advisory.advisory_cause_decisions,
    advisory.advisory_cause_agreements,
    advisory.advisory_cause_comparable,
    advisory.advisory_model_versions
FROM evaluation_totals evaluation
CROSS JOIN attempt_totals attempt
CROSS JOIN advisory_totals advisory;

CREATE OR REPLACE VIEW ops.ops_playbook_automation_readiness AS
SELECT
    candidate.id AS learning_candidate_id,
    candidate.playbook_id,
    candidate.playbook_version,
    candidate.status,
    candidate.confidence,
    candidate.automatic_eligibility,
    COUNT(*) FILTER (
        WHERE outcome.outcome_kind = 'execution'
          AND outcome.verified AND outcome.success AND NOT outcome.rollback_executed
    ) AS verified_successes,
    COUNT(DISTINCT outcome.incident_id) FILTER (
        WHERE outcome.outcome_kind = 'execution'
          AND outcome.verified AND outcome.success AND NOT outcome.rollback_executed
    ) AS distinct_incidents,
    COUNT(*) FILTER (
        WHERE outcome.outcome_kind = 'execution'
          AND outcome.verified AND (NOT outcome.success OR outcome.rollback_executed)
          AND outcome.occurred_at >= NOW() - INTERVAL '90 days'
    ) AS failures_or_rollbacks_90d,
    COALESCE(BOOL_OR(
        outcome.outcome_kind = 'rollback_drill'
        AND outcome.verified AND outcome.success
    ), FALSE) AS rollback_tested,
    (
        candidate.status = 'promoted'
        AND candidate.automatic_eligibility
        AND COUNT(*) FILTER (
            WHERE outcome.outcome_kind = 'execution'
              AND outcome.verified AND outcome.success AND NOT outcome.rollback_executed
        ) >= 3
        AND COUNT(DISTINCT outcome.incident_id) FILTER (
            WHERE outcome.outcome_kind = 'execution'
              AND outcome.verified AND outcome.success AND NOT outcome.rollback_executed
        ) >= 2
        AND COUNT(*) FILTER (
            WHERE outcome.outcome_kind = 'execution'
              AND outcome.verified AND (NOT outcome.success OR outcome.rollback_executed)
              AND outcome.occurred_at >= NOW() - INTERVAL '90 days'
        ) = 0
        AND COALESCE(BOOL_OR(
            outcome.outcome_kind = 'rollback_drill'
            AND outcome.verified AND outcome.success
        ), FALSE)
    ) AS outcome_gate_eligible
FROM ops.ops_learning_candidates candidate
LEFT JOIN ops.ops_playbook_outcomes outcome
  ON outcome.playbook_id = candidate.playbook_id
 AND outcome.playbook_version = candidate.playbook_version
GROUP BY candidate.id;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dash_ops_reader') THEN
        GRANT SELECT ON ops.ops_advisory_decisions TO dash_ops_reader;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dockhand_ops_writer') THEN
        GRANT SELECT, INSERT ON ops.ops_advisory_decisions TO dockhand_ops_writer;
    END IF;
END $$;
