"""Narrowly privileged canonical Ops hybrid-index projector.

This process is separate from both the public AgentOS and the private read-only
reasoning service. It reads canonical records, writes only disposable retrieval
documents and its heartbeat, and never copies evidence payloads, prompts, SQL, or
free-form learning bodies into the index.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from os import getenv
from typing import Any, Iterable

import psycopg
from openai import AsyncOpenAI, OpenAIError
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row


logger = logging.getLogger(__name__)
INDEXER_NAME = "dash-canonical-hybrid-v1"
EMBEDDING_MODEL = "text-embedding-3-small"
EMBEDDING_DIMENSIONS = 1536
_SOURCE_TABLES = (
    "ops.ops_playbook_outcomes",
    "ops.ops_investigations",
    "ops.ops_remediation_proposals",
    "ops.ops_learnings",
    "dash.validated_queries",
)
_TARGET_TABLES = (
    "ops.ops_retrieval_documents",
    "ops.ops_retrieval_index_status",
)
_REQUIRED_ENV = (
    "OPS_INDEXER_DB_HOST",
    "OPS_INDEXER_DB_PORT",
    "OPS_INDEXER_DB_USER",
    "OPS_INDEXER_DB_PASS",
    "OPS_INDEXER_DB_DATABASE",
)


class IndexerConfigurationError(RuntimeError):
    """The standalone indexer lacks an explicit least-privilege configuration."""


class IndexerPrivilegeError(RuntimeError):
    """The configured database role violates the indexer privilege contract."""


class IndexerEmbeddingError(RuntimeError):
    """The embedding pass failed; lexical-only index publication is forbidden."""


@dataclass(frozen=True)
class IndexDocument:
    canonical_type: str
    canonical_id: str
    environment: str | None
    service: str | None
    incident_type: str | None
    outcome_status: str | None
    detector_version: str | None
    source_updated_at: datetime
    fresh_until: datetime | None
    search_text: str
    content_hash: str
    embedding: tuple[float, ...] | None = None

    @property
    def id(self) -> str:
        identity = f"{self.canonical_type}:{self.canonical_id}:{self.content_hash}"
        return f"idx_{hashlib.sha256(identity.encode()).hexdigest()[:32]}"


def _config() -> dict[str, str]:
    values = {name: getenv(name, "").strip() for name in _REQUIRED_ENV}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise IndexerConfigurationError(f"missing explicit Ops indexer settings: {', '.join(missing)}")
    try:
        port = int(values["OPS_INDEXER_DB_PORT"])
    except ValueError as exc:
        raise IndexerConfigurationError("OPS_INDEXER_DB_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise IndexerConfigurationError("OPS_INDEXER_DB_PORT is outside the valid range")
    if not getenv("OPENAI_API_KEY", "").strip():
        raise IndexerConfigurationError("OPENAI_API_KEY is required for non-degenerate hybrid indexing")
    return values


def _conninfo() -> str:
    values = _config()
    return make_conninfo(
        host=values["OPS_INDEXER_DB_HOST"],
        port=values["OPS_INDEXER_DB_PORT"],
        user=values["OPS_INDEXER_DB_USER"],
        password=values["OPS_INDEXER_DB_PASS"],
        dbname=values["OPS_INDEXER_DB_DATABASE"],
        connect_timeout="5",
        application_name=INDEXER_NAME,
        options="-c statement_timeout=30000 -c lock_timeout=2000",
    )


def _hash_document(values: dict[str, Any]) -> str:
    canonical = json.dumps(values, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _outcome_status(success: bool, rollback_executed: bool) -> str:
    if rollback_executed:
        return "rollback"
    return "success" if success else "failed"


def build_outcome_document(row: dict[str, Any]) -> IndexDocument:
    """Build a minimal search representation without copying canonical payloads."""

    occurred_at = row["occurred_at"].astimezone(UTC)
    status = _outcome_status(bool(row["success"]), bool(row["rollback_executed"]))
    structured = {
        "canonical_type": "outcome",
        "canonical_id": str(row["id"]),
        "environment": row.get("environment"),
        "service": row.get("service"),
        "incident_type": row.get("incident_type"),
        "outcome_status": status,
        "detector_version": row.get("detector_version"),
        "playbook_id": row.get("playbook_id"),
        "playbook_version": row.get("playbook_version"),
        "outcome_kind": row.get("outcome_kind"),
        "source_updated_at": occurred_at.isoformat(),
    }
    search_text = " ".join(str(value) for value in structured.values() if value not in {None, ""})
    return IndexDocument(
        canonical_type="outcome",
        canonical_id=str(row["id"]),
        environment=str(row["environment"]) if row.get("environment") else None,
        service=str(row["service"]) if row.get("service") else None,
        incident_type=str(row["incident_type"]) if row.get("incident_type") else None,
        outcome_status=status,
        detector_version=str(row["detector_version"]) if row.get("detector_version") else None,
        source_updated_at=occurred_at,
        fresh_until=occurred_at + timedelta(days=90),
        search_text=search_text,
        content_hash=_hash_document(structured),
    )


def build_learning_document(row: dict[str, Any]) -> IndexDocument:
    updated_at = row["updated_at"].astimezone(UTC)
    # Deliberately index only controlled categorical metadata. The canonical
    # learning body remains in Postgres and is fetched only after authorization.
    structured = {
        "canonical_type": "learning",
        "canonical_id": str(row["id"]),
        "kind": row.get("kind"),
        "job_kind": row.get("job_kind"),
        "lifecycle_status": row.get("lifecycle_status"),
        "source_updated_at": updated_at.isoformat(),
    }
    return IndexDocument(
        canonical_type="learning",
        canonical_id=str(row["id"]),
        environment=None,
        service=None,
        incident_type=str(row["kind"]) if row.get("kind") else None,
        outcome_status=str(row["lifecycle_status"]) if row.get("lifecycle_status") else None,
        detector_version=None,
        source_updated_at=updated_at,
        fresh_until=None,
        search_text=" ".join(str(value) for value in structured.values() if value not in {None, ""}),
        content_hash=_hash_document(structured),
    )


def build_validated_query_document(row: dict[str, Any]) -> IndexDocument:
    updated_at = row["updated_at"].astimezone(UTC)
    # SQL and free-form descriptions stay canonical; the index stores identity
    # and lifecycle metadata only.
    structured = {
        "canonical_type": "validated_query",
        "canonical_id": str(row["id"]),
        "name": row.get("name"),
        "validation_status": row.get("validation_status"),
        "source_updated_at": updated_at.isoformat(),
    }
    return IndexDocument(
        canonical_type="validated_query",
        canonical_id=str(row["id"]),
        environment=None,
        service=None,
        incident_type=None,
        outcome_status=str(row["validation_status"]),
        detector_version=None,
        source_updated_at=updated_at,
        fresh_until=None,
        search_text=" ".join(str(value) for value in structured.values() if value not in {None, ""}),
        content_hash=_hash_document(structured),
    )


async def _verify_privileges(conn: psycopg.AsyncConnection[Any], expected_user: str) -> None:
    cursor = await conn.execute("SELECT current_user")
    row = await cursor.fetchone()
    if row is None or str(row["current_user"]) != expected_user:
        raise IndexerPrivilegeError("database current_user does not match OPS_INDEXER_DB_USER")
    cursor = await conn.execute(
        """
        SELECT required.name,
               has_table_privilege(current_user, required.name, 'SELECT') AS can_select,
               has_table_privilege(current_user, required.name, 'INSERT')
                 OR has_table_privilege(current_user, required.name, 'UPDATE')
                 OR has_table_privilege(current_user, required.name, 'DELETE')
                 OR has_table_privilege(current_user, required.name, 'TRUNCATE') AS can_write
        FROM unnest(%s::text[]) AS required(name)
        """,
        (list((*_SOURCE_TABLES, *_TARGET_TABLES)),),
    )
    privileges = {
        str(item["name"]): (bool(item["can_select"]), bool(item["can_write"])) for item in await cursor.fetchall()
    }
    unreadable = [name for name in (*_SOURCE_TABLES, *_TARGET_TABLES) if not privileges.get(name, (False, False))[0]]
    writable_sources = [name for name in _SOURCE_TABLES if privileges.get(name, (False, False))[1]]
    unwritable_targets = [name for name in _TARGET_TABLES if not privileges.get(name, (False, False))[1]]
    if unreadable or writable_sources or unwritable_targets:
        raise IndexerPrivilegeError(
            f"invalid indexer privileges unreadable={unreadable} writable_sources={writable_sources} "
            f"unwritable_targets={unwritable_targets}"
        )


async def _load_documents(conn: psycopg.AsyncConnection[Any]) -> list[IndexDocument]:
    cursor = await conn.execute(
        """
        SELECT o.id, o.success, o.rollback_executed, o.playbook_id,
               o.playbook_version, o.outcome_kind, o.occurred_at,
               i.environment, i.service,
               i.reasoning_result #>> '{hypotheses,0,cause_code}' AS incident_type,
               i.reasoning_result #>> '{hypotheses,0,detector_version}' AS detector_version
        FROM ops.ops_playbook_outcomes o
        JOIN ops.ops_investigations i ON i.id = o.investigation_id
        WHERE o.verified IS TRUE
          AND o.occurred_at >= NOW() - INTERVAL '90 days'
        ORDER BY o.occurred_at, o.id
        """
    )
    documents = [build_outcome_document(row) for row in await cursor.fetchall()]
    cursor = await conn.execute(
        """
        SELECT id, kind, job_kind, lifecycle_status, updated_at
        FROM ops.ops_learnings
        WHERE lifecycle_status IN ('verified', 'promoted')
        ORDER BY updated_at, id
        """
    )
    documents.extend(build_learning_document(row) for row in await cursor.fetchall())
    cursor = await conn.execute(
        """
        SELECT id, name, validation_status, updated_at
        FROM dash.validated_queries
        WHERE validation_status = 'valid'
        ORDER BY updated_at, id
        """
    )
    documents.extend(build_validated_query_document(row) for row in await cursor.fetchall())
    return documents


async def embed_documents(
    documents: Iterable[IndexDocument],
    *,
    client: AsyncOpenAI | None = None,
) -> list[IndexDocument]:
    pending = list(documents)
    if not pending:
        return []
    api_key = getenv("OPENAI_API_KEY", "").strip()
    if not api_key and client is None:
        raise IndexerConfigurationError("OPENAI_API_KEY is required for non-degenerate hybrid indexing")
    embedding_client = client or AsyncOpenAI(api_key=api_key, timeout=20.0, max_retries=2)
    embedded: list[IndexDocument] = []
    try:
        for start in range(0, len(pending), 100):
            batch = pending[start : start + 100]
            response = await embedding_client.embeddings.create(
                model=EMBEDDING_MODEL,
                input=[item.search_text for item in batch],
            )
            vectors = [tuple(item.embedding) for item in sorted(response.data, key=lambda item: item.index)]
            if len(vectors) != len(batch) or any(len(vector) != EMBEDDING_DIMENSIONS for vector in vectors):
                raise IndexerEmbeddingError("embedding response shape does not match the index batch")
            embedded.extend(
                replace(document, embedding=vector) for document, vector in zip(batch, vectors, strict=True)
            )
    except (OpenAIError, TimeoutError, ValueError) as exc:
        raise IndexerEmbeddingError("embedding provider failed; index publication was aborted") from exc
    return embedded


def _vector_literal(values: tuple[float, ...]) -> str:
    return f"[{','.join(str(value) for value in values)}]"


async def _replace_index(conn: psycopg.AsyncConnection[Any], documents: list[IndexDocument]) -> None:
    if any(item.embedding is None for item in documents):
        raise IndexerEmbeddingError("refusing to publish a lexical-only retrieval document")
    await conn.execute(
        "DELETE FROM ops.ops_retrieval_documents WHERE canonical_type = ANY(%s)",
        (["outcome", "learning", "validated_query"],),
    )
    for item in documents:
        assert item.embedding is not None
        await conn.execute(
            """
            INSERT INTO ops.ops_retrieval_documents (
                id, canonical_type, canonical_id, environment, service,
                incident_type, outcome_status, detector_version,
                source_updated_at, fresh_until, content_hash, search_text,
                embedding, embedding_model, indexed_at
            ) VALUES (
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::vector,%s,NOW()
            )
            """,
            (
                item.id,
                item.canonical_type,
                item.canonical_id,
                item.environment,
                item.service,
                item.incident_type,
                item.outcome_status,
                item.detector_version,
                item.source_updated_at,
                item.fresh_until,
                item.content_hash,
                item.search_text,
                _vector_literal(item.embedding),
                EMBEDDING_MODEL,
            ),
        )
    high_water = max((item.source_updated_at for item in documents), default=datetime.now(UTC))
    await conn.execute(
        """
        INSERT INTO ops.ops_retrieval_index_status (
            indexer, status, model, source_high_water_at,
            indexed_at, document_count, embedded_count, error
        ) VALUES (%s,'ready',%s,%s,NOW(),%s,%s,NULL)
        ON CONFLICT (indexer) DO UPDATE SET
            status = EXCLUDED.status,
            model = EXCLUDED.model,
            source_high_water_at = EXCLUDED.source_high_water_at,
            indexed_at = EXCLUDED.indexed_at,
            document_count = EXCLUDED.document_count,
            embedded_count = EXCLUDED.embedded_count,
            error = NULL
        """,
        (INDEXER_NAME, EMBEDDING_MODEL, high_water, len(documents), len(documents)),
    )


async def run_indexer() -> int:
    values = _config()
    try:
        async with await psycopg.AsyncConnection.connect(_conninfo(), row_factory=dict_row) as conn:
            await _verify_privileges(conn, values["OPS_INDEXER_DB_USER"])
            documents = await _load_documents(conn)
            embedded = await embed_documents(documents)
            await _replace_index(conn, embedded)
        logger.info("Published %s fully embedded canonical retrieval documents", len(embedded))
        return len(embedded)
    except Exception as exc:
        logger.error("Canonical retrieval indexing failed: %s", type(exc).__name__)
        # Best-effort failure heartbeat. It contains no exception message because
        # database/provider errors can include credentials or URLs.
        try:
            async with await psycopg.AsyncConnection.connect(_conninfo(), row_factory=dict_row) as conn:
                await conn.execute(
                    """
                    INSERT INTO ops.ops_retrieval_index_status (
                        indexer, status, model, indexed_at,
                        document_count, embedded_count, error
                    ) VALUES (%s,'failed',%s,NOW(),0,0,%s)
                    ON CONFLICT (indexer) DO UPDATE SET
                        status = 'failed', indexed_at = NOW(),
                        document_count = 0, embedded_count = 0, error = EXCLUDED.error
                    """,
                    (INDEXER_NAME, EMBEDDING_MODEL, type(exc).__name__),
                )
        except Exception:
            logger.exception("Unable to persist retrieval index failure heartbeat")
        raise
