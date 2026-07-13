"""Least-privilege canonical hybrid-index projector tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from dash import ops_indexer


def test_outcome_document_contains_only_canonical_pointer_and_structured_metadata() -> None:
    document = ops_indexer.build_outcome_document(
        {
            "id": "outcome_1",
            "success": True,
            "rollback_executed": False,
            "playbook_id": "diagnose.service-health",
            "playbook_version": "1.0.0",
            "outcome_kind": "execution",
            "occurred_at": datetime(2026, 7, 12, tzinfo=UTC),
            "environment": "production",
            "service": "web",
            "incident_type": "container_oom",
            "detector_version": "ops-shadow-rules-v2",
            "prompt": "SECRET PROMPT MUST NOT BE COPIED",
            "payload": {"Authorization": "Bearer secret"},
        }
    )

    assert document.canonical_type == "outcome"
    assert document.canonical_id == "outcome_1"
    assert document.outcome_status == "success"
    assert document.incident_type == "container_oom"
    assert "diagnose.service-health" in document.search_text
    assert "SECRET" not in document.search_text
    assert "Authorization" not in document.search_text
    assert document.embedding is None


def test_learning_and_validated_query_documents_exclude_free_form_body_and_sql() -> None:
    now = datetime.now(UTC)
    learning = ops_indexer.build_learning_document(
        {
            "id": "learning_1",
            "kind": "container_oom",
            "job_kind": "service.healthcheck",
            "lifecycle_status": "promoted",
            "updated_at": now,
            "body": "secret-bearing free-form body",
        }
    )
    query = ops_indexer.build_validated_query_document(
        {
            "id": "vq_1",
            "name": "service_health",
            "validation_status": "valid",
            "updated_at": now,
            "sql_text": "SELECT secret FROM credentials",
        }
    )

    assert "secret-bearing" not in learning.search_text
    assert "SELECT" not in query.search_text
    assert "service_health" in query.search_text


class FakeEmbeddings:
    def __init__(self, dimensions: int = 1536) -> None:
        self.dimensions = dimensions

    async def create(self, *, model: str, input: list[str]):  # type: ignore[no-untyped-def]
        assert model == ops_indexer.EMBEDDING_MODEL
        return SimpleNamespace(
            data=[
                SimpleNamespace(index=index, embedding=[float(index)] * self.dimensions)
                for index, _ in enumerate(input)
            ]
        )


def test_indexer_requires_complete_embeddings_before_publication() -> None:
    source = ops_indexer.build_outcome_document(
        {
            "id": "outcome_1",
            "success": True,
            "rollback_executed": False,
            "playbook_id": "diagnose.service-health",
            "playbook_version": "1.0.0",
            "outcome_kind": "execution",
            "occurred_at": datetime.now(UTC),
            "environment": "production",
            "service": "web",
            "incident_type": "container_oom",
            "detector_version": "v2",
        }
    )

    embedded = asyncio.run(
        ops_indexer.embed_documents(
            [source],
            client=SimpleNamespace(embeddings=FakeEmbeddings()),  # type: ignore[arg-type]
        )
    )
    assert len(embedded[0].embedding or ()) == 1536

    with pytest.raises(ops_indexer.IndexerEmbeddingError, match="shape"):
        asyncio.run(
            ops_indexer.embed_documents(
                [source],
                client=SimpleNamespace(embeddings=FakeEmbeddings(12)),  # type: ignore[arg-type]
            )
        )


def test_indexer_configuration_has_no_general_database_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ops_indexer._REQUIRED_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DB_USER", "writer")
    monkeypatch.setenv("OPS_DB_USER", "dash_ops_reader")

    with pytest.raises(ops_indexer.IndexerConfigurationError, match="explicit Ops indexer"):
        ops_indexer._config()


def test_indexer_source_writes_only_derived_index_and_status_tables() -> None:
    source = (Path(ops_indexer.__file__) if ops_indexer.__file__ else Path()).read_text(encoding="utf-8")

    assert "INSERT INTO ops.ops_retrieval_documents" in source
    assert "INSERT INTO ops.ops_retrieval_index_status" in source
    for canonical_table in (
        "ops.ops_playbook_outcomes",
        "ops.ops_investigations",
        "ops.ops_learnings",
        "dash.validated_queries",
    ):
        assert f"INSERT INTO {canonical_table}" not in source
        assert f"UPDATE {canonical_table}" not in source
        assert f"DELETE FROM {canonical_table}" not in source
