"""Execution-backed validated-query admission tests."""

from __future__ import annotations

from unittest.mock import MagicMock

from sqlalchemy import create_engine, text

from dash.tools.save_query import create_save_validated_query_tool, execute_query_validation


def _validation_engine():  # type: ignore[no-untyped-def]
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE metrics (name TEXT NOT NULL, value INTEGER NOT NULL)"))
        connection.execute(text("INSERT INTO metrics VALUES ('healthy', 1), ('degraded', 2)"))
    return engine


def test_query_is_admitted_only_after_execution_and_exact_shape_validation() -> None:
    clean, observed, error = execute_query_validation(
        _validation_engine(),
        "SELECT name, value FROM metrics ORDER BY value",
        ["name", "value"],
        {"name": "string", "value": "integer"},
        min_rows=2,
        max_rows=2,
    )

    assert clean.startswith("SELECT")
    assert error is None
    assert observed == {
        "columns": [{"name": "name", "type": "str"}, {"name": "value", "type": "int"}],
        "sample_rows": 2,
        "sample_truncated": False,
    }


def test_query_admission_rejects_execution_shape_type_and_cardinality_failures() -> None:
    engine = _validation_engine()

    assert execute_query_validation(engine, "SELECT missing FROM metrics", ["missing"])[2] is not None
    assert execute_query_validation(engine, "SELECT name FROM metrics", ["wrong"])[2] is not None
    assert execute_query_validation(engine, "SELECT value FROM metrics", ["value"], {"value": "string"})[2] is not None
    assert execute_query_validation(engine, "SELECT name FROM metrics", ["name"], max_rows=1)[2] is not None
    assert (
        execute_query_validation(
            engine,
            "SELECT 1 AS value UNION ALL SELECT 'two' AS value",
            ["value"],
        )[2]
        is not None
    )
    assert execute_query_validation(engine, "DELETE FROM metrics", ["name"])[2] is not None


class RegistryConnection:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def __enter__(self) -> "RegistryConnection":
        return self

    def __exit__(self, *_args) -> None:  # type: ignore[no-untyped-def]
        return None

    def execute(self, statement, parameters: dict) -> None:  # type: ignore[no-untyped-def]
        self.calls.append((str(statement), parameters))


class RegistryEngine:
    def __init__(self) -> None:
        self.connection = RegistryConnection()

    def begin(self) -> RegistryConnection:
        return self.connection


def test_validated_query_tool_persists_canonical_record_before_disposable_index() -> None:
    knowledge = MagicMock()
    registry = RegistryEngine()
    function = create_save_validated_query_tool(
        knowledge,
        validation_engine=_validation_engine(),
        registry_engine=registry,  # type: ignore[arg-type]
    )

    message = function.entrypoint(
        name="service_health",
        question="Which service states exist?",
        query="SELECT name, value FROM metrics ORDER BY value",
        expected_columns=["name", "value"],
        expected_types={"name": "str", "value": "int"},
        min_rows=1,
        max_rows=10,
    )

    assert "Validated and saved query" in message
    assert len(registry.connection.calls) == 1
    sql, parameters = registry.connection.calls[0]
    assert "INSERT INTO dash.validated_queries" in sql
    assert parameters["observed_shape"]
    knowledge.insert.assert_called_once()


def test_disposable_index_failure_does_not_erase_canonical_query_admission() -> None:
    knowledge = MagicMock()
    knowledge.insert.side_effect = OSError("index unavailable")
    registry = RegistryEngine()
    function = create_save_validated_query_tool(
        knowledge,
        validation_engine=_validation_engine(),
        registry_engine=registry,  # type: ignore[arg-type]
    )

    message = function.entrypoint(
        name="service_health",
        question="Which service states exist?",
        query="SELECT name, value FROM metrics",
        expected_columns=["name", "value"],
    )

    assert "canonical record" in message
    assert "indexing is pending" in message
    assert len(registry.connection.calls) == 1
