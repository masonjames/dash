-- Canonical learning records and derived retrieval pointers.
--
-- Operational facts stay in the ledger. Retrieval documents contain only a
-- canonical record pointer plus a disposable search representation; deleting
-- and rebuilding this table cannot delete source evidence or outcomes.

CREATE SCHEMA IF NOT EXISTS dash;

CREATE TABLE IF NOT EXISTS ops.ops_learnings (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    tags JSONB NOT NULL DEFAULT '[]'::JSONB,
    job_kind TEXT,
    source TEXT,
    actor_id TEXT,
    source_job_ids JSONB NOT NULL DEFAULT '[]'::JSONB,
    source_tool_sig TEXT,
    confidence NUMERIC NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    lifecycle_status TEXT NOT NULL DEFAULT 'legacy' CHECK (
        lifecycle_status IN (
            'legacy','candidate','verified','promoted','rejected','superseded'
        )
    ),
    use_count INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    upvotes INTEGER NOT NULL DEFAULT 0 CHECK (upvotes >= 0),
    downvotes INTEGER NOT NULL DEFAULT 0 CHECK (downvotes >= 0),
    migrated_from TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ops_learnings_lifecycle_idx
    ON ops.ops_learnings (lifecycle_status, updated_at DESC);
CREATE INDEX IF NOT EXISTS ops_learnings_job_kind_idx
    ON ops.ops_learnings (job_kind, updated_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS ops_learnings_source_tool_sig_idx
    ON ops.ops_learnings (source_tool_sig)
    WHERE source_tool_sig IS NOT NULL;

ALTER TABLE ops.ops_learning_candidates
    ADD COLUMN IF NOT EXISTS learning_id TEXT REFERENCES ops.ops_learnings(id);
CREATE INDEX IF NOT EXISTS ops_learning_candidates_learning_idx
    ON ops.ops_learning_candidates (learning_id)
    WHERE learning_id IS NOT NULL;

CREATE OR REPLACE FUNCTION ops.sync_governed_learning_lifecycle()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.learning_id IS NOT NULL THEN
        UPDATE ops.ops_learnings
        SET lifecycle_status = NEW.status,
            updated_at = GREATEST(updated_at, NOW())
        WHERE id = NEW.learning_id;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS ops_learning_candidate_lifecycle_sync
    ON ops.ops_learning_candidates;
CREATE TRIGGER ops_learning_candidate_lifecycle_sync
    AFTER INSERT OR UPDATE OF status, learning_id
    ON ops.ops_learning_candidates
    FOR EACH ROW EXECUTE FUNCTION ops.sync_governed_learning_lifecycle();

CREATE TABLE IF NOT EXISTS ops.ops_retrieval_documents (
    id TEXT PRIMARY KEY,
    canonical_type TEXT NOT NULL CHECK (
        canonical_type IN (
            'evidence','investigation','outcome','learning','validated_query'
        )
    ),
    canonical_id TEXT NOT NULL,
    environment TEXT,
    service TEXT,
    incident_type TEXT,
    outcome_status TEXT,
    detector_version TEXT,
    source_updated_at TIMESTAMPTZ NOT NULL,
    fresh_until TIMESTAMPTZ,
    content_hash TEXT NOT NULL,
    search_text TEXT NOT NULL,
    search_vector TSVECTOR GENERATED ALWAYS AS (
        to_tsvector('english'::regconfig, search_text)
    ) STORED,
    embedding VECTOR(1536),
    embedding_model TEXT,
    indexed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (canonical_type, canonical_id, content_hash)
);

CREATE INDEX IF NOT EXISTS ops_retrieval_documents_lexical_idx
    ON ops.ops_retrieval_documents USING GIN (search_vector);
CREATE INDEX IF NOT EXISTS ops_retrieval_documents_scope_idx
    ON ops.ops_retrieval_documents (
        environment, service, incident_type, outcome_status, source_updated_at DESC
    );
CREATE INDEX IF NOT EXISTS ops_retrieval_documents_vector_idx
    ON ops.ops_retrieval_documents
    USING hnsw (embedding vector_cosine_ops)
    WHERE embedding IS NOT NULL;

CREATE TABLE IF NOT EXISTS ops.ops_retrieval_index_status (
    indexer TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('building','ready','stale','failed')),
    model TEXT NOT NULL,
    source_high_water_at TIMESTAMPTZ,
    indexed_at TIMESTAMPTZ,
    document_count INTEGER NOT NULL DEFAULT 0 CHECK (document_count >= 0),
    embedded_count INTEGER NOT NULL DEFAULT 0 CHECK (embedded_count >= 0),
    error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (embedded_count <= document_count),
    CHECK (
        status <> 'ready'
        OR (
            indexed_at IS NOT NULL
            AND embedded_count = document_count
            AND error IS NULL
        )
    )
);

-- Validated queries have an explicit lifecycle. Only a successful execution
-- whose observed result shape matches the declared shape may become reusable.
CREATE TABLE IF NOT EXISTS dash.validated_queries (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    sql_text TEXT NOT NULL,
    query_fingerprint TEXT NOT NULL UNIQUE,
    schema_fingerprint TEXT NOT NULL,
    expected_shape JSONB NOT NULL,
    observed_shape JSONB,
    validation_status TEXT NOT NULL CHECK (
        validation_status IN ('pending','valid','invalid','stale')
    ),
    validation_error TEXT,
    validated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        validation_status <> 'valid'
        OR (
            observed_shape IS NOT NULL
            AND validated_at IS NOT NULL
            AND validation_error IS NULL
        )
    )
);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dash_ops_reader') THEN
        GRANT USAGE ON SCHEMA dash TO dash_ops_reader;
        GRANT SELECT ON ops.ops_learnings, ops.ops_retrieval_documents,
            ops.ops_retrieval_index_status
            TO dash_ops_reader;
        GRANT SELECT ON dash.validated_queries TO dash_ops_reader;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dockhand_ops_writer') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON ops.ops_learnings, ops.ops_retrieval_documents
            TO dockhand_ops_writer;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dash_ops_indexer') THEN
        GRANT USAGE ON SCHEMA ops, dash TO dash_ops_indexer;
        GRANT SELECT ON ops.ops_investigations, ops.ops_evidence,
            ops.ops_remediation_proposals, ops.ops_verification_runs,
            ops.ops_playbook_outcomes, ops.ops_learning_candidates,
            ops.ops_learnings TO dash_ops_indexer;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ops.ops_retrieval_documents
            TO dash_ops_indexer;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ops.ops_retrieval_index_status
            TO dash_ops_indexer;
        GRANT SELECT ON dash.validated_queries TO dash_ops_indexer;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dash_api_runtime') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON dash.validated_queries
            TO dash_api_runtime;
    END IF;
END $$;

COMMENT ON TABLE ops.ops_retrieval_documents IS
    'Disposable hybrid-search index containing canonical IDs, never source-of-truth records';
COMMENT ON TABLE dash.validated_queries IS
    'Reusable SQL admitted only after read-only execution and result-shape validation';
