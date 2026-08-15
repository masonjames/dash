-- Runtime privileges are intentionally reconciled outside the checksummed
-- schema migrations. Plain pg_dump backups use --no-owner/--no-privileges,
-- and a restored ops.schema_migrations table causes schema migrations to be
-- skipped. This contract therefore runs after every migration invocation,
-- including no-op and post-restore runs.

-- Start from a deny-by-default object matrix so stale grants from an older
-- release cannot survive reconciliation.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public, ops, ai, dash
    FROM dash_ops_reader, dash_ops_indexer, dockhand_ops_writer, dash_api_runtime;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public, ops, ai, dash
    FROM dash_ops_reader, dash_ops_indexer, dockhand_ops_writer, dash_api_runtime;
REVOKE ALL PRIVILEGES ON SCHEMA public, ops, ai, dash
    FROM dash_ops_reader, dash_ops_indexer, dockhand_ops_writer, dash_api_runtime;

-- Cancel broad defaults installed by early control-loop migrations. New
-- canonical objects are exposed only when this reconciliation runs after the
-- migration that creates them.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL PRIVILEGES ON TABLES FROM dash_ops_reader, dash_ops_indexer,
        dockhand_ops_writer, dash_api_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM dash_ops_reader, dash_ops_indexer,
        dockhand_ops_writer, dash_api_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA ops
    REVOKE ALL PRIVILEGES ON TABLES FROM dash_ops_reader, dash_ops_indexer,
        dockhand_ops_writer, dash_api_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA ops
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM dash_ops_reader, dash_ops_indexer,
        dockhand_ops_writer, dash_api_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA dash
    REVOKE ALL PRIVILEGES ON TABLES FROM dash_ops_reader, dash_ops_indexer,
        dockhand_ops_writer, dash_api_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA ai
    REVOKE ALL PRIVILEGES ON TABLES FROM dash_ops_reader, dash_ops_indexer,
        dockhand_ops_writer, dash_api_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA ai
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM dash_ops_reader, dash_ops_indexer,
        dockhand_ops_writer, dash_api_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA dash
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM dash_ops_reader, dash_ops_indexer,
        dockhand_ops_writer, dash_api_runtime;

-- Dash reasoning: evidence-only. It can read every canonical Ops relation,
-- the public warehouse, and validated queries, but cannot create or mutate
-- database state. Public grants are deliberately limited to the canonical
-- warehouse instead of exposing unrelated company tables.
GRANT USAGE ON SCHEMA ops, public, dash TO dash_ops_reader;
DO $runtime_reader_privileges$
DECLARE
    relation RECORD;
BEGIN
    FOR relation IN
        SELECT class.relname AS relation_name
        FROM pg_class AS class
        JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
        WHERE namespace.nspname = 'ops'
          AND class.relkind IN ('r', 'p', 'v', 'm')
          AND class.relname NOT LIKE 'chronicle\_%' ESCAPE '\'
          AND class.relname <> 'ops_portal_request_nonces'
    LOOP
        EXECUTE format(
            'GRANT SELECT ON ops.%I TO dash_ops_reader',
            relation.relation_name
        );
    END LOOP;
END
$runtime_reader_privileges$;
GRANT SELECT ON public.desired_services, public.actual_services,
    public.drift_observations, public.deploy_events, public.docker_events,
    public.incident_markers, public.update_status, public.state_snapshots,
    public.ops_unified_timeline TO dash_ops_reader;
GRANT SELECT ON dash.validated_queries TO dash_ops_reader;

-- Dash indexer: the sole runtime writer of the disposable retrieval index.
-- Its source reads are deliberately explicit rather than schema-wide.
GRANT USAGE ON SCHEMA ops, dash TO dash_ops_indexer;
GRANT SELECT ON ops.ops_playbook_outcomes, ops.ops_investigations,
    ops.ops_remediation_proposals, ops.ops_learnings
    TO dash_ops_indexer;
GRANT SELECT, INSERT, UPDATE, DELETE ON ops.ops_retrieval_documents,
    ops.ops_retrieval_index_status TO dash_ops_indexer;
GRANT SELECT ON dash.validated_queries TO dash_ops_indexer;

-- Dockhand owns canonical observations and governed lifecycle records, not
-- migration truth or derived search indexes. Grant current base tables
-- dynamically so future migrations are admitted only after reconciliation.
-- The unregistered Chronicle candidate is a reserved exception: every
-- ops.chronicle_* relation is excluded and receives only the explicit
-- test-only function/view grants reconciled below.
GRANT USAGE ON SCHEMA public, ops TO dockhand_ops_writer;
-- Preserve the pre-Chronicle health read used by Dockhand. The generic CRUD
-- loop below intentionally covers base tables only, so this view stays an
-- exact, auditable exception instead of restoring schema-wide view access.
GRANT SELECT ON ops.ops_shadow_readiness TO dockhand_ops_writer;
DO $runtime_privileges$
DECLARE
    relation RECORD;
BEGIN
    FOR relation IN
        SELECT namespace.nspname AS schema_name, class.relname AS relation_name
        FROM pg_class AS class
        JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
        WHERE namespace.nspname IN ('public', 'ops')
          AND class.relkind IN ('r', 'p')
          AND class.relname NOT LIKE 'chronicle\_%' ESCAPE '\'
          AND NOT (
              namespace.nspname = 'ops'
              AND class.relname IN (
                  'schema_migrations',
                  'ops_portal_request_nonces',
                  'ops_retrieval_documents',
                  'ops_retrieval_index_status'
              )
          )
    LOOP
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON %I.%I TO dockhand_ops_writer',
            relation.schema_name,
            relation.relation_name
        );
    END LOOP;
END
$runtime_privileges$;

-- Agent Chronicle is unregistered and default-disabled. Keep all runtime roles
-- off every candidate relation, then expose only the owner-gated SECURITY
-- DEFINER append/replay/rejection functions to Dockhand and the approved
-- projection view to the two read identities. This block is safe before the
-- candidate exists and is required after a no-ACL restore.
DO $chronicle_runtime_boundary$
DECLARE
    relation RECORD;
BEGIN
    FOR relation IN
        SELECT
            namespace.nspname AS schema_name,
            class.relname AS relation_name
        FROM pg_class AS class
        JOIN pg_namespace AS namespace
            ON namespace.oid = class.relnamespace
        WHERE namespace.nspname = 'ops'
          AND class.relname LIKE 'chronicle\_%' ESCAPE '\'
          AND class.relkind IN ('r', 'p', 'v', 'm', 'S')
    LOOP
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON %I.%I '
            'FROM dash_ops_reader, dash_ops_indexer, '
            'dockhand_ops_writer, dash_api_runtime',
            relation.schema_name,
            relation.relation_name
        );
    END LOOP;

    IF to_regprocedure(
        'ops.chronicle_test_append_v1(jsonb,text[],text[],text[],bytea[],bytea)'
    ) IS NOT NULL THEN
        EXECUTE
            'REVOKE ALL PRIVILEGES ON FUNCTION '
            'ops.chronicle_test_append_v1('
            'JSONB, TEXT[], TEXT[], TEXT[], BYTEA[], BYTEA'
            ') FROM PUBLIC, dash_ops_reader, dash_ops_indexer, '
            'dockhand_ops_writer, dash_api_runtime';
        EXECUTE
            'GRANT EXECUTE ON FUNCTION '
            'ops.chronicle_test_append_v1('
            'JSONB, TEXT[], TEXT[], TEXT[], BYTEA[], BYTEA'
            ') TO dockhand_ops_writer';
    END IF;

    IF to_regprocedure(
        'ops.chronicle_test_resolve_request_v1(text,text,text,uuid,uuid)'
    ) IS NOT NULL THEN
        EXECUTE
            'REVOKE ALL PRIVILEGES ON FUNCTION '
            'ops.chronicle_test_resolve_request_v1('
            'TEXT, TEXT, TEXT, UUID, UUID'
            ') FROM PUBLIC, dash_ops_reader, dash_ops_indexer, '
            'dockhand_ops_writer, dash_api_runtime';
        EXECUTE
            'GRANT EXECUTE ON FUNCTION '
            'ops.chronicle_test_resolve_request_v1('
            'TEXT, TEXT, TEXT, UUID, UUID'
            ') TO dockhand_ops_writer';
    END IF;

    IF to_regprocedure(
        'ops.chronicle_test_record_rejection_v1('
        'text,text,text,uuid,uuid,text,text,timestamp with time zone,boolean)'
    ) IS NOT NULL THEN
        EXECUTE
            'REVOKE ALL PRIVILEGES ON FUNCTION '
            'ops.chronicle_test_record_rejection_v1('
            'TEXT, TEXT, TEXT, UUID, UUID, TEXT, TEXT, TIMESTAMPTZ, BOOLEAN'
            ') FROM PUBLIC, dash_ops_reader, dash_ops_indexer, '
            'dockhand_ops_writer, dash_api_runtime';
        EXECUTE
            'GRANT EXECUTE ON FUNCTION '
            'ops.chronicle_test_record_rejection_v1('
            'TEXT, TEXT, TEXT, UUID, UUID, TEXT, TEXT, TIMESTAMPTZ, BOOLEAN'
            ') TO dockhand_ops_writer';
    END IF;

    IF to_regprocedure(
        'ops.chronicle_canonical_json_text_v1(jsonb)'
    ) IS NOT NULL THEN
        EXECUTE
            'REVOKE ALL PRIVILEGES ON FUNCTION '
            'ops.chronicle_canonical_json_text_v1(JSONB) '
            'FROM PUBLIC, dash_ops_reader, dash_ops_indexer, '
            'dockhand_ops_writer, dash_api_runtime';
    END IF;

    IF to_regclass('ops.chronicle_audit_projection_v1') IS NOT NULL THEN
        GRANT SELECT ON ops.chronicle_audit_projection_v1
            TO dockhand_ops_writer, dash_ops_reader;
    END IF;
END
$chronicle_runtime_boundary$;

GRANT SELECT, INSERT, DELETE ON ops.ops_portal_request_nonces
    TO dockhand_ops_writer;
DO $runtime_sequence_privileges$
DECLARE
    sequence RECORD;
BEGIN
    FOR sequence IN
        SELECT namespace.nspname AS schema_name, class.relname AS sequence_name
        FROM pg_class AS class
        JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
        WHERE namespace.nspname IN ('public', 'ops')
          AND class.relkind = 'S'
          AND class.relname NOT LIKE 'chronicle\_%' ESCAPE '\'
    LOOP
        EXECUTE format(
            'GRANT USAGE, SELECT ON SEQUENCE %I.%I TO dockhand_ops_writer',
            sequence.schema_name,
            sequence.sequence_name
        );
    END LOOP;
END
$runtime_sequence_privileges$;

-- Public AgentOS runtime: agent-managed ai/dash state and read-only company
-- data. It has no visibility into the private Ops schema.
GRANT USAGE, CREATE ON SCHEMA ai, dash TO dash_api_runtime;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA ai, dash TO dash_api_runtime;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ai, dash TO dash_api_runtime;
GRANT USAGE ON SCHEMA public TO dash_api_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO dash_api_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA ai
    GRANT ALL PRIVILEGES ON TABLES TO dash_api_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA ai
    GRANT ALL PRIVILEGES ON SEQUENCES TO dash_api_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA dash
    GRANT ALL PRIVILEGES ON TABLES TO dash_api_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA dash
    GRANT ALL PRIVILEGES ON SEQUENCES TO dash_api_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO dash_api_runtime;

-- The original single-user deployment created an empty warehouse in ``ai``
-- because PostgreSQL's default search path begins with ``"$user"``. Preserve
-- those relations for old-image rollback, but never let the least-privileged
-- runtime resolve or mutate them. Public is canonical; AgentOS still receives
-- its required access to every other object in ``ai``. Owned serial sequences
-- are denied with their shadow tables so a stale default cannot be exercised.
DO $legacy_ai_warehouse_denials$
DECLARE
    relation_name TEXT;
    relation_oid REGCLASS;
    sequence_name TEXT;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY[
        'desired_services',
        'actual_services',
        'drift_observations',
        'deploy_events',
        'docker_events',
        'incident_markers',
        'update_status',
        'state_snapshots',
        'ops_unified_timeline'
    ]
    LOOP
        relation_oid := to_regclass(format('%I.%I', 'ai', relation_name));
        CONTINUE WHEN relation_oid IS NULL;

        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON TABLE ai.%I FROM dash_api_runtime',
            relation_name
        );
        FOR sequence_name IN
            SELECT sequence.relname
            FROM pg_depend AS dependency
            JOIN pg_class AS sequence
              ON sequence.oid = dependency.objid
             AND sequence.relkind = 'S'
            JOIN pg_namespace AS namespace
              ON namespace.oid = sequence.relnamespace
            WHERE dependency.classid = 'pg_class'::regclass
              AND dependency.refclassid = 'pg_class'::regclass
              AND dependency.refobjid = relation_oid
              AND dependency.deptype IN ('a', 'i')
              AND namespace.nspname = 'ai'
        LOOP
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON SEQUENCE ai.%I FROM dash_api_runtime',
                sequence_name
            );
        END LOOP;
    END LOOP;
END
$legacy_ai_warehouse_denials$;

-- These denials are repeated explicitly as auditable invariants.
REVOKE ALL PRIVILEGES ON ops.schema_migrations,
    ops.ops_retrieval_documents, ops.ops_retrieval_index_status
    FROM dockhand_ops_writer;
REVOKE ALL PRIVILEGES ON ops.ops_portal_request_nonces
    FROM dash_ops_reader, dash_ops_indexer, dash_api_runtime;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ops FROM dash_api_runtime;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ops FROM dash_api_runtime;

ALTER ROLE dash_ops_reader SET search_path = ops, public, dash;
ALTER ROLE dash_ops_indexer SET search_path = ops, public, dash;
ALTER ROLE dockhand_ops_writer SET search_path = ops, public;
-- Canonical company data must precede both agent-managed ``dash`` objects and
-- rollback-only ``ai`` warehouse shadows. Dash views and AgentOS objects are
-- schema-qualified by the application and remain available in dash/ai.
ALTER ROLE dash_api_runtime SET search_path = public, dash, ai;
