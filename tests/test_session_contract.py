from typing import Any

import db.session as session


def test_agno_database_never_bootstraps_schema_at_runtime(monkeypatch) -> None:
    captured: list[dict[str, Any]] = []

    def fake_postgres_db(**kwargs: Any) -> dict[str, Any]:
        captured.append(kwargs)
        return kwargs

    monkeypatch.setattr(session, "PostgresDb", fake_postgres_db)
    session.get_postgres_db.cache_clear()

    base = session.get_postgres_db()
    assert session.get_postgres_db() is base
    contents = session.get_postgres_db(contents_table="knowledge_contents")
    assert session.get_postgres_db(contents_table="knowledge_contents") is contents

    assert len(captured) == 2
    assert all(item["create_schema"] is False for item in captured)
    assert captured[0]["id"] == session.DB_ID
    assert captured[1]["id"] == f"{session.DB_ID}-knowledge_contents"
    session.get_postgres_db.cache_clear()


def test_pgvector_never_bootstraps_schema_at_runtime(monkeypatch) -> None:
    vector_args: dict[str, Any] = {}

    def fake_pgvector(**kwargs: Any) -> dict[str, Any]:
        vector_args.update(kwargs)
        return kwargs

    monkeypatch.setattr(session, "PgVector", fake_pgvector)
    monkeypatch.setattr(session, "Knowledge", lambda **kwargs: kwargs)
    monkeypatch.setattr(session, "get_postgres_db", lambda **kwargs: kwargs)

    session.create_knowledge("Ops", "ops_knowledge")

    assert vector_args["schema"] == session.AGNO_SCHEMA
    assert vector_args["create_schema"] is False
