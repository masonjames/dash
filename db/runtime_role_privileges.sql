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

-- Dash reasoning: evidence-only. It can read every canonical Ops relation and
-- validated query, but cannot create or mutate database state.
GRANT USAGE ON SCHEMA ops, dash TO dash_ops_reader;
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
          AND class.relname <> 'ops_portal_request_nonces'
    LOOP
        EXECUTE format(
            'GRANT SELECT ON ops.%I TO dash_ops_reader',
            relation.relation_name
        );
    END LOOP;
END
$runtime_reader_privileges$;
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
GRANT USAGE ON SCHEMA public, ops TO dockhand_ops_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA ops TO dockhand_ops_writer;
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
GRANT SELECT, INSERT, DELETE ON ops.ops_portal_request_nonces
    TO dockhand_ops_writer;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public, ops TO dockhand_ops_writer;

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

-- These denials are repeated explicitly as auditable invariants.
REVOKE ALL PRIVILEGES ON ops.schema_migrations,
    ops.ops_retrieval_documents, ops.ops_retrieval_index_status
    FROM dockhand_ops_writer;
REVOKE ALL PRIVILEGES ON ops.ops_portal_request_nonces
    FROM dash_ops_reader, dash_ops_indexer, dash_api_runtime;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ops FROM dash_api_runtime;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ops FROM dash_api_runtime;

ALTER ROLE dash_ops_reader SET search_path = ops, dash, public;
ALTER ROLE dash_ops_indexer SET search_path = ops, dash, public;
ALTER ROLE dockhand_ops_writer SET search_path = ops, public;
ALTER ROLE dash_api_runtime SET search_path = ai, dash, public;
