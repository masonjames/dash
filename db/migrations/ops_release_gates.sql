-- Durable evidence for shadow-mode and per-playbook automation gates.
-- Dockhand records these facts because it owns policy validation. Dash remains
-- read-only and cannot self-certify its own promotion.

CREATE TABLE IF NOT EXISTS ops.ops_shadow_evaluations (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES ops.ops_investigations(id),
    model_version TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    registry_version TEXT NOT NULL,
    response_hash TEXT NOT NULL,
    latency_ms INTEGER NOT NULL CHECK (latency_ms >= 0),
    citation_valid BOOLEAN NOT NULL,
    citation_count INTEGER NOT NULL CHECK (citation_count >= 0),
    proposal_schema_valid BOOLEAN NOT NULL,
    policy_violations INTEGER NOT NULL CHECK (policy_violations >= 0),
    policy_rejections JSONB NOT NULL DEFAULT '[]'::JSONB,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (investigation_id, response_hash)
);

CREATE INDEX IF NOT EXISTS ops_shadow_evaluations_gate_idx
    ON ops.ops_shadow_evaluations (evaluated_at DESC, policy_violations);

CREATE OR REPLACE VIEW ops.ops_shadow_readiness AS
WITH windowed AS (
    SELECT *
    FROM ops.ops_shadow_evaluations
    WHERE evaluated_at >= date_trunc('day', NOW()) - INTERVAL '6 days'
), daily AS (
    SELECT evaluated_at::DATE AS evaluation_day, COUNT(*) AS evaluations
    FROM windowed
    GROUP BY evaluated_at::DATE
)
SELECT
    COUNT(*) AS evaluation_count,
    (SELECT COUNT(*) FROM daily) AS covered_days,
    COUNT(*) FILTER (WHERE NOT citation_valid) AS citation_failures,
    COUNT(*) FILTER (WHERE NOT proposal_schema_valid) AS proposal_schema_failures,
    COALESCE(SUM(policy_violations), 0) AS policy_violations,
    (
        (SELECT COUNT(*) FROM daily) = 7
        AND COUNT(*) > 0
        AND COUNT(*) FILTER (WHERE NOT citation_valid) = 0
        AND COUNT(*) FILTER (WHERE NOT proposal_schema_valid) = 0
        AND COALESCE(SUM(policy_violations), 0) = 0
    ) AS recommendation_mode_eligible
FROM windowed;

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
        AND candidate.confidence >= 0.85
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
        GRANT SELECT ON ops.ops_shadow_evaluations,
            ops.ops_shadow_readiness, ops.ops_playbook_automation_readiness
            TO dash_ops_reader;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dockhand_ops_writer') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON ops.ops_shadow_evaluations
            TO dockhand_ops_writer;
        GRANT SELECT ON ops.ops_shadow_readiness,
            ops.ops_playbook_automation_readiness TO dockhand_ops_writer;
    END IF;
END $$;
