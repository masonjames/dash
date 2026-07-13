from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_privileged_migration_installs_pgvector_before_runtime() -> None:
    runner = (ROOT / "scripts/migrate_ops.py").read_text()
    migration_name = "ops_runtime_prerequisites.sql"
    assert migration_name in runner

    migration = (ROOT / "db/migrations" / migration_name).read_text()
    assert "CREATE EXTENSION IF NOT EXISTS vector" in migration


def test_runtime_privileges_are_reconciled_after_skipped_migrations() -> None:
    runner = (ROOT / "scripts/migrate_ops.py").read_text()
    reconciliation = (ROOT / "db/runtime_role_privileges.sql").read_text()

    assert runner.index("for migration in migrations:") < runner.index('root / "db" / "runtime_role_privileges.sql"')
    assert 'print(f"already applied {migration.name}")' in runner
    assert "reconciled runtime role privileges" in runner
    assert "REVOKE ALL PRIVILEGES ON ops.schema_migrations" in reconciliation
    assert "ops.ops_retrieval_documents, ops.ops_retrieval_index_status" in reconciliation
    assert "FROM dockhand_ops_writer" in reconciliation
    assert "TO dash_ops_indexer" in reconciliation
    assert "ops_portal_request_nonces" in reconciliation
    assert "FROM dash_ops_reader, dash_ops_indexer, dash_api_runtime" in reconciliation


def test_runtime_role_contract_denies_database_scratch_space() -> None:
    runner = (ROOT / "scripts/migrate_ops.py").read_text()

    assert "REVOKE CREATE, TEMPORARY ON DATABASE" in runner
    assert "if read_only:" not in runner


def test_migrations_and_runtime_ignore_user_schema_shadow_tables() -> None:
    runner = (ROOT / "scripts/migrate_ops.py").read_text()
    reconciliation = (ROOT / "db/runtime_role_privileges.sql").read_text()
    shadow_relations = (
        "desired_services",
        "actual_services",
        "drift_observations",
        "deploy_events",
        "docker_events",
        "incident_markers",
        "update_status",
        "state_snapshots",
        "ops_unified_timeline",
    )

    pin = 'connection.execute("SET LOCAL search_path = public")'
    assert pin in runner
    assert runner.index(pin) < runner.index('connection.execute("CREATE SCHEMA IF NOT EXISTS ops")')
    assert runner.index(pin) < runner.index("for migration in migrations:")
    assert "SET LOCAL search_path = public, pg_catalog" not in runner

    for relation in shadow_relations:
        assert f"'{relation}'" in reconciliation
    assert "REVOKE ALL PRIVILEGES ON TABLE ai.%I FROM dash_api_runtime" in reconciliation
    assert "REVOKE ALL PRIVILEGES ON SEQUENCE ai.%I FROM dash_api_runtime" in reconciliation
    assert "GRANT USAGE ON SCHEMA ops, public, dash TO dash_ops_reader" in reconciliation
    assert "public.ops_unified_timeline TO dash_ops_reader" in reconciliation
    assert "ALTER ROLE dash_ops_reader SET search_path = ops, public, dash" in reconciliation
    assert "ALTER ROLE dash_ops_indexer SET search_path = ops, public, dash" in reconciliation
    assert "SET search_path = ops, dash, public" not in reconciliation
    assert "ALTER ROLE dash_api_runtime SET search_path = public, dash, ai" in reconciliation
    assert "ALTER ROLE dash_api_runtime SET search_path = dash, public, ai" not in reconciliation
    assert "ALTER ROLE dash_api_runtime SET search_path = ai, dash, public" not in reconciliation
