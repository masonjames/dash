"""Apply Ops migrations once, under a database lock, and provision runtime roles."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import psycopg
from psycopg import sql

from db.url import build_db_url

_LOCK_NAME = "dash.ops.schema-migrations.v1"
_RUNTIME_ROLES = (
    ("dash_ops_reader", "DASH_OPS_READER_PASSWORD", True),
    ("dash_ops_indexer", "DASH_OPS_INDEXER_PASSWORD", False),
    ("dockhand_ops_writer", "DOCKHAND_OPS_WRITER_PASSWORD", False),
    ("dash_api_runtime", "DASH_API_RUNTIME_PASSWORD", False),
)


def _required_secret(name: str) -> str:
    value = os.getenv(name, "")
    if len(value) < 16:
        raise RuntimeError(f"{name} must be a secret-managed value of at least 16 characters")
    return value


def _provision_role(
    connection: psycopg.Connection[object],
    role: str,
    password: str,
    *,
    read_only: bool,
) -> None:
    exists = connection.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
    if not exists:
        connection.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(password))
        )
    connection.execute(
        sql.SQL(
            "ALTER ROLE {} WITH LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
        ).format(sql.Identifier(role), sql.Literal(password))
    )
    connection.execute(
        sql.SQL("ALTER ROLE {} SET default_transaction_read_only = {}").format(
            sql.Identifier(role), sql.Literal("on" if read_only else "off")
        )
    )
    # Runtime processes do not need database creation or temporary tables.
    # Applying this to every runtime role makes the role matrix deterministic
    # after a no-ACL restore and prevents a stale privilege from surviving.
    connection.execute(
        sql.SQL("REVOKE CREATE, TEMPORARY ON DATABASE {} FROM {}").format(
            sql.Identifier(str(connection.info.dbname)), sql.Identifier(role)
        )
    )
    connection.execute(sql.SQL("REVOKE CREATE ON SCHEMA public FROM {}").format(sql.Identifier(role)))


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    migrations = [
        root / "db" / "migrations" / "ops_warehouse.sql",
        root / "db" / "migrations" / "ops_control_loop.sql",
        root / "db" / "migrations" / "ops_runtime_prerequisites.sql",
        root / "db" / "migrations" / "ops_learning_retrieval.sql",
        root / "db" / "migrations" / "ops_release_gates.sql",
        root / "db" / "migrations" / "ops_desired_state_suggestions.sql",
        root / "db" / "migrations" / "ops_incidents.sql",
    ]
    db_url = build_db_url().replace("postgresql+psycopg://", "postgresql://", 1)
    role_secrets = [(role, _required_secret(env_name), read_only) for role, env_name, read_only in _RUNTIME_ROLES]

    with psycopg.connect(db_url) as connection, connection.transaction():
        connection.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (_LOCK_NAME,))
        connection.execute(
            sql.SQL("REVOKE CREATE, TEMPORARY ON DATABASE {} FROM PUBLIC").format(
                sql.Identifier(str(connection.info.dbname))
            )
        )
        connection.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        connection.execute("CREATE SCHEMA IF NOT EXISTS ops")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ops.schema_migrations (
                name TEXT PRIMARY KEY,
                checksum TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        for role, password, read_only in role_secrets:
            _provision_role(connection, role, password, read_only=read_only)

        for migration in migrations:
            migration_sql = migration.read_text(encoding="utf-8")
            checksum = hashlib.sha256(migration_sql.encode()).hexdigest()
            existing = connection.execute(
                "SELECT checksum FROM ops.schema_migrations WHERE name = %s",
                (migration.name,),
            ).fetchone()
            if existing:
                if existing[0] != checksum:
                    raise RuntimeError(f"applied migration {migration.name} has changed; add a new migration")
                print(f"already applied {migration.name}")
                continue
            connection.execute(migration_sql)
            connection.execute(
                "INSERT INTO ops.schema_migrations (name, checksum) VALUES (%s, %s)",
                (migration.name, checksum),
            )
            print(f"applied {migration.name}")

        # Deliberately not tracked in ops.schema_migrations: pg_dump backups
        # omit ACLs while restoring the migration ledger. This idempotent
        # contract must run even when every schema migration says "already
        # applied" so post-restore runtimes are neither broken nor overbroad.
        privilege_sql = (root / "db" / "runtime_role_privileges.sql").read_text(
            encoding="utf-8"
        )
        connection.execute(privilege_sql)
        print("reconciled runtime role privileges")


if __name__ == "__main__":
    main()
