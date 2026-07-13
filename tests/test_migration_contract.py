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

    assert runner.index("for migration in migrations:") < runner.index(
        'root / "db" / "runtime_role_privileges.sql"'
    )
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
