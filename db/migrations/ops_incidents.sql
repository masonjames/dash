-- Canonical incident lifecycle. Legacy public.incident_markers remains a
-- migration/read-compatibility surface; new control-loop writes target these
-- ops-schema records and append-only transitions.

CREATE TABLE IF NOT EXISTS ops.ops_incidents (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    environment TEXT,
    service TEXT,
    incident_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open','resolved','suppressed')),
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    source TEXT NOT NULL,
    source_event_ids JSONB NOT NULL DEFAULT '[]'::JSONB,
    evidence_ids JSONB NOT NULL DEFAULT '[]'::JSONB,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (last_seen_at >= first_seen_at),
    CHECK ((status = 'resolved') = (resolved_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS ops_incidents_open_fingerprint_idx
    ON ops.ops_incidents (fingerprint) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS ops_incidents_scope_time_idx
    ON ops.ops_incidents (environment, service, status, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS ops.ops_incident_transitions (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES ops.ops_incidents(id),
    from_status TEXT,
    to_status TEXT NOT NULL CHECK (to_status IN ('open','resolved','suppressed')),
    reason TEXT NOT NULL,
    evidence_ids JSONB NOT NULL DEFAULT '[]'::JSONB,
    source TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS ops_incident_transitions_append_only
    ON ops.ops_incident_transitions;
CREATE TRIGGER ops_incident_transitions_append_only
    BEFORE UPDATE OR DELETE ON ops.ops_incident_transitions
    FOR EACH ROW EXECUTE FUNCTION ops.reject_append_only_mutation();

-- Source freshness is independent per producer. In particular, an event
-- projector heartbeat cannot certify incident ingestion and vice versa.
CREATE TABLE IF NOT EXISTS ops.ops_source_checkpoints (
    source TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('healthy','degraded','failed')),
    observed_at TIMESTAMPTZ NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO ops.ops_incidents (
    id, fingerprint, incident_type, severity, status, title, summary, source,
    first_seen_at, last_seen_at, resolved_at
)
SELECT
    marker.id::TEXT,
    'legacy:' || marker.id::TEXT,
    'legacy',
    marker.severity,
    CASE WHEN marker.resolved_at IS NULL THEN 'open' ELSE 'resolved' END,
    marker.title,
    'Legacy narrative withheld pending explicit redaction review',
    'legacy-incident-markers',
    marker.started_at,
    COALESCE(marker.resolved_at, marker.started_at),
    marker.resolved_at
FROM public.incident_markers marker
ON CONFLICT (id) DO NOTHING;

INSERT INTO ops.ops_incident_transitions (
    id, incident_id, from_status, to_status, reason, evidence_ids, source,
    occurred_at
)
SELECT
    'legacy_transition_' || marker.id::TEXT,
    marker.id::TEXT,
    NULL,
    CASE WHEN marker.resolved_at IS NULL THEN 'open' ELSE 'resolved' END,
    'Imported from legacy incident marker',
    jsonb_build_array('legacy_evidence_incident_' || marker.id::TEXT),
    'migration',
    COALESCE(marker.resolved_at, marker.started_at)
FROM public.incident_markers marker
ON CONFLICT (id) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dash_ops_reader') THEN
        GRANT SELECT ON ops.ops_incidents, ops.ops_incident_transitions,
            ops.ops_source_checkpoints TO dash_ops_reader;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dockhand_ops_writer') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON ops.ops_incidents,
            ops.ops_source_checkpoints TO dockhand_ops_writer;
        GRANT SELECT, INSERT ON ops.ops_incident_transitions TO dockhand_ops_writer;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dash_ops_indexer') THEN
        GRANT SELECT ON ops.ops_incidents, ops.ops_incident_transitions
            TO dash_ops_indexer;
    END IF;
END $$;
