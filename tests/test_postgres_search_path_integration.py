"""Behavioral proof for the production PostgreSQL search-path boundary."""

from __future__ import annotations

import os

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict

from scripts import migrate_ops

_DSN_ENV = "DASH_TEST_POSTGRES_DSN"
_EXPECTED_DATABASE = "dash_search_path_ci"
_ROLE_SECRETS = {
    "DASH_OPS_READER_PASSWORD": "dash_ops_reader-integration-only",
    "DASH_OPS_INDEXER_PASSWORD": "dash_ops_indexer-integration-only",
    "DOCKHAND_OPS_WRITER_PASSWORD": "dockhand_ops_writer-integration-only",
    "DASH_API_RUNTIME_PASSWORD": "dash_api_runtime-integration-only",
}


@pytest.mark.skipif(not os.getenv(_DSN_ENV), reason="explicit PostgreSQL integration DSN is required")
def test_live_owner_collision_resolves_only_canonical_warehouse(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reproduce the live ai/public collision and prove migration/runtime resolution."""

    dsn = os.environ[_DSN_ENV]
    connection_settings = conninfo_to_dict(dsn)
    assert connection_settings.get("dbname") == _EXPECTED_DATABASE

    with psycopg.connect(dsn, autocommit=True) as connection:
        pristine = connection.execute(
            """
            SELECT to_regnamespace('ops') IS NULL
               AND NOT EXISTS (
                   SELECT 1 FROM pg_roles
                   WHERE rolname IN (
                       'dash_ops_reader', 'dash_ops_indexer',
                       'dockhand_ops_writer', 'dash_api_runtime'
                   )
               )
            """
        ).fetchone()
        assert pristine == (True,), "integration database must be disposable and pristine"

        connection.execute("CREATE SCHEMA ai")
        connection.execute("CREATE SCHEMA dash")
        for schema in ("ai", "dash"):
            connection.execute(f"CREATE TABLE {schema}.desired_services (id SERIAL PRIMARY KEY, marker TEXT NOT NULL)")
            connection.execute(
                f"INSERT INTO {schema}.desired_services (marker) VALUES (%s)",
                (f"{schema}-sentinel",),
            )
        connection.execute(
            """
            CREATE FUNCTION public.md5(TEXT) RETURNS TEXT
            LANGUAGE SQL IMMUTABLE
            RETURN 'poisoned-public-md5'
            """
        )

    for key, value in _ROLE_SECRETS.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("DB_DRIVER", "postgresql+psycopg")
    monkeypatch.setenv("DB_HOST", connection_settings.get("host", "127.0.0.1"))
    monkeypatch.setenv("DB_PORT", connection_settings.get("port", "5432"))
    monkeypatch.setenv("DB_USER", connection_settings.get("user", "ai"))
    monkeypatch.setenv("DB_PASS", connection_settings.get("password", ""))
    monkeypatch.setenv("DB_DATABASE", _EXPECTED_DATABASE)

    migrate_ops.main()
    migrate_ops.main()  # Reconciliation must remain safe after a no-op migration pass.

    with psycopg.connect(dsn, autocommit=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ops.schema_migrations").fetchone() == (8,)
        assert connection.execute("SELECT marker FROM ai.desired_services").fetchone() == ("ai-sentinel",)
        assert connection.execute("SELECT marker FROM dash.desired_services").fetchone() == ("dash-sentinel",)
        assert connection.execute("SELECT last_value, is_called FROM ai.desired_services_id_seq").fetchone() == (
            1,
            True,
        )
        assert (
            connection.execute("SELECT environment IS NOT NULL FROM public.desired_services LIMIT 0").description
            is not None
        )

        connection.execute("SET search_path = public")
        resolved_md5 = connection.execute(
            "SELECT md5('canonical'), public.md5('canonical'), pg_catalog.md5('canonical')"
        ).fetchone()
        assert resolved_md5 is not None
        assert resolved_md5[0] == resolved_md5[2]
        assert resolved_md5[1] == "poisoned-public-md5"

    role_paths = {
        "dash_api_runtime": "public, dash, ai",
        "dash_ops_reader": "ops, public, dash",
    }
    base_settings = {
        "host": connection_settings.get("host", "127.0.0.1"),
        "port": connection_settings.get("port", "5432"),
        "dbname": _EXPECTED_DATABASE,
    }
    for role, expected_path in role_paths.items():
        secret_key = {
            "dash_api_runtime": "DASH_API_RUNTIME_PASSWORD",
            "dash_ops_reader": "DASH_OPS_READER_PASSWORD",
        }[role]
        with psycopg.connect(
            **base_settings,
            user=role,
            password=_ROLE_SECRETS[secret_key],
            autocommit=True,
        ) as connection:
            assert connection.execute("SHOW search_path").fetchone() == (expected_path,)
            assert connection.execute(
                """
                SELECT namespace.nspname
                FROM pg_class AS class
                JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
                WHERE class.oid = to_regclass('desired_services')
                """
            ).fetchone() == ("public",)
            connection.execute("SELECT COUNT(*) FROM desired_services").fetchone()

            if role == "dash_api_runtime":
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("SELECT marker FROM ai.desired_services").fetchone()
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("SELECT nextval('ai.desired_services_id_seq')").fetchone()
