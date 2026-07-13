"""
Database Session
================

PostgreSQL database connection for AgentOS.

Two schemas:
- ``public``: Company data (loaded externally). Read-only for agents.
- ``dash``: Agent-managed data (views, summary tables). Owned by Engineer.
"""

import re
from functools import lru_cache

from agno.db.postgres import PostgresDb
from agno.knowledge import Knowledge
from agno.knowledge.embedder.openai import OpenAIEmbedder
from agno.vectordb.pgvector import PgVector, SearchType
from sqlalchemy import Engine, create_engine, event

from db.url import db_url

DB_ID = "dash-db"

# PostgreSQL schema for agent-managed tables (views, summaries, computed data).
# Company data stays in "public". Agno framework tables use the default schema.
DASH_SCHEMA = "dash"
AGNO_SCHEMA = "ai"

# Cached engines — one per access pattern, created on first use.
_dash_engine: Engine | None = None
_readonly_engine: Engine | None = None

# ---------------------------------------------------------------------------
# Public-schema write guard (Engineer connection)
# ---------------------------------------------------------------------------
# Matches DDL/DML that explicitly targets the public schema.
# Allows reads (SELECT FROM public.*) but blocks writes (CREATE TABLE public.x,
# DROP VIEW public.y, INSERT INTO public.z, etc.).
_PUBLIC_WRITE_RE = re.compile(
    r"""(?ix)
    # DDL targeting public schema
    (?:create|alter|drop)\s+
    (?:or\s+replace\s+)?
    (?:(?:temp|temporary|unlogged|materialized)\s+)?
    (?:table|view|index|sequence|function|procedure|trigger|type)\s+
    (?:if\s+(?:not\s+)?exists\s+)?
    "?public"?\s*\.
    |
    # DML targeting public schema
    insert\s+into\s+"?public"?\s*\.
    |
    update\s+"?public"?\s*\.
    |
    delete\s+from\s+"?public"?\s*\.
    |
    truncate\s+(?:table\s+)?"?public"?\s*\.
    """,
)


def _guard_public_schema(conn, cursor, statement, parameters, context, executemany):
    """Block DDL/DML targeting the public schema on the Engineer's connection."""
    if _PUBLIC_WRITE_RE.search(statement):
        raise RuntimeError(
            "Cannot write to the public schema. "
            "Use the dash schema for all CREATE, ALTER, DROP, INSERT, UPDATE, and DELETE operations."
        )


def get_sql_engine() -> Engine:
    """SQLAlchemy engine scoped to the dash schema (cached).

    The privileged migration service owns schema and extension creation.
    Runtime startup must not require database-level CREATE privileges. This
    engine therefore assumes the checksummed migration gate has provisioned
    ``dash`` and returns a search_path-scoped connection that can read company
    data in public and write only to agent-owned tables.
    """
    global _dash_engine
    if _dash_engine is not None:
        return _dash_engine
    _dash_engine = create_engine(
        db_url,
        connect_args={"options": f"-c search_path={DASH_SCHEMA},public"},
        pool_size=10,
        max_overflow=20,
    )
    event.listen(_dash_engine, "before_cursor_execute", _guard_public_schema)
    return _dash_engine


def get_readonly_engine() -> Engine:
    """SQLAlchemy engine with read-only transactions (cached).

    Uses PostgreSQL's ``default_transaction_read_only`` so any INSERT,
    UPDATE, DELETE, CREATE, DROP, or ALTER is rejected at the database level.
    """
    global _readonly_engine
    if _readonly_engine is not None:
        return _readonly_engine
    _readonly_engine = create_engine(
        db_url,
        connect_args={"options": "-c default_transaction_read_only=on -c search_path=public,dash,ai"},
        pool_size=10,
        max_overflow=20,
    )
    return _readonly_engine


@lru_cache(maxsize=None)
def get_postgres_db(contents_table: str | None = None) -> PostgresDb:
    """Create a PostgresDb instance.

    Args:
        contents_table: Optional table name for storing knowledge contents.

    Returns:
        Configured PostgresDb instance.
    """
    if contents_table is not None:
        return PostgresDb(
            id=f"{DB_ID}-{contents_table}",
            db_url=db_url,
            db_schema=AGNO_SCHEMA,
            knowledge_table=contents_table,
            create_schema=False,
        )
    return PostgresDb(
        id=DB_ID,
        db_url=db_url,
        db_schema=AGNO_SCHEMA,
        create_schema=False,
    )


def create_knowledge(name: str, table_name: str) -> Knowledge:
    """Create a Knowledge instance with PgVector hybrid search.

    Args:
        name: Display name for the knowledge base.
        table_name: PostgreSQL table name for vector storage.

    Returns:
        Configured Knowledge instance.
    """
    return Knowledge(
        name=name,
        vector_db=PgVector(
            db_url=db_url,
            table_name=table_name,
            schema=AGNO_SCHEMA,
            search_type=SearchType.hybrid,
            embedder=OpenAIEmbedder(id="text-embedding-3-small"),
            create_schema=False,
        ),
        contents_db=get_postgres_db(contents_table=f"{table_name}_contents"),
    )
