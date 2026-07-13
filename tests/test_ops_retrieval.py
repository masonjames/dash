"""Canonical hybrid-retrieval contract tests."""

from __future__ import annotations

import asyncio
from typing import Any

from dash.ops_retrieval import search_canonical_documents


class FakeCursor:
    async def fetchall(self) -> list[tuple[Any, ...]]:
        return [
            (
                "outcome",
                "outcome_123",
                "production",
                "web",
                "container_oom",
                "success",
                0.88,
                1.7,
                0.91,
            )
        ]


class FakeConnection:
    def __init__(self) -> None:
        self.query = ""
        self.params: tuple[Any, ...] = ()

    async def __aenter__(self) -> "FakeConnection":
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    async def execute(self, query: str, params: tuple[Any, ...]) -> FakeCursor:
        self.query = query
        self.params = params
        return FakeCursor()


def test_hybrid_retrieval_filters_fresh_canonical_scope_and_returns_real_scores() -> None:
    connection = FakeConnection()

    async def connect() -> FakeConnection:
        return connection

    hits = asyncio.run(
        search_canonical_documents(
            connect,
            query_text="container oom after deploy",
            environment="production",
            service="web",
            incident_type="container_oom",
            outcome_status="success",
            query_embedding=[0.0] * 1536,
        )
    )

    assert [hit.canonical_id for hit in hits] == ["outcome_123"]
    assert hits[0].score == 0.88
    assert hits[0].lexical_relevance == 1.7
    assert hits[0].semantic_similarity == 0.91
    assert "DISTINCT ON (canonical_type, canonical_id)" in connection.query
    assert "websearch_to_tsquery" in connection.query
    assert "embedding <=>" in connection.query
    assert "source_updated_at >=" in connection.query
    assert connection.params[1:9] == (
        "production",
        "production",
        "web",
        "web",
        "container_oom",
        "container_oom",
        "success",
        "success",
    )


def test_hybrid_retrieval_rejects_wrong_embedding_dimension_without_database_access() -> None:
    async def unexpected_connect() -> FakeConnection:
        raise AssertionError("invalid retrieval input must fail before database access")

    hits = asyncio.run(
        search_canonical_documents(
            unexpected_connect,
            query_text="oom",
            environment=None,
            service=None,
            incident_type=None,
            outcome_status=None,
            query_embedding=[0.0, 1.0],
        )
    )

    assert hits == []


def test_hybrid_retrieval_never_claims_lexical_only_results(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    async def unexpected_connect() -> FakeConnection:
        raise AssertionError("missing query embedding must fail before database access")

    hits = asyncio.run(
        search_canonical_documents(
            unexpected_connect,
            query_text="oom",
            environment="production",
            service="web",
            incident_type="container_oom",
            outcome_status="success",
        )
    )

    assert hits == []
