-- Human-reviewable desired-state suggestions. These records are inert data:
-- no command, shell, commit, push, pull-request, merge, or deployment action is
-- derived from them automatically.

CREATE TABLE IF NOT EXISTS ops.ops_desired_state_suggestions (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES ops.ops_investigations(id),
    proposal_id TEXT NOT NULL UNIQUE REFERENCES ops.ops_remediation_proposals(id),
    artifact_version TEXT NOT NULL,
    source_file TEXT NOT NULL CHECK (source_file !~ '(^/|(^|/)\.\.(/|$))'),
    source_commit TEXT NOT NULL CHECK (source_commit ~ '^[a-f0-9]{40}$'),
    operations JSONB NOT NULL CHECK (
        jsonb_typeof(operations) = 'array' AND jsonb_array_length(operations) > 0
    ),
    content_hash TEXT NOT NULL CHECK (content_hash ~ '^[a-f0-9]{64}$'),
    state TEXT NOT NULL DEFAULT 'draft' CHECK (
        state IN ('draft','accepted_for_review','rejected','superseded')
    ),
    decision_reason TEXT,
    decided_by TEXT,
    decided_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION ops.enforce_suggestion_artifact_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(
        NEW.investigation_id, NEW.proposal_id, NEW.artifact_version,
        NEW.source_file, NEW.source_commit, NEW.operations, NEW.content_hash,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.investigation_id, OLD.proposal_id, OLD.artifact_version,
        OLD.source_file, OLD.source_commit, OLD.operations, OLD.content_hash,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'desired-state suggestion artifact is immutable';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS ops_desired_state_suggestion_immutable
    ON ops.ops_desired_state_suggestions;
CREATE TRIGGER ops_desired_state_suggestion_immutable
    BEFORE UPDATE ON ops.ops_desired_state_suggestions
    FOR EACH ROW EXECUTE FUNCTION ops.enforce_suggestion_artifact_immutable();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dash_ops_reader') THEN
        GRANT SELECT ON ops.ops_desired_state_suggestions TO dash_ops_reader;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dockhand_ops_writer') THEN
        GRANT SELECT, INSERT, UPDATE ON ops.ops_desired_state_suggestions
            TO dockhand_ops_writer;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dash_ops_indexer') THEN
        GRANT SELECT ON ops.ops_desired_state_suggestions TO dash_ops_indexer;
    END IF;
END $$;
