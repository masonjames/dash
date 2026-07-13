"""Execute, shape-check, and persist reusable SQL queries."""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from agno.knowledge import Knowledge
from agno.knowledge.reader.text_reader import TextReader
from agno.tools import tool
from agno.utils.log import logger
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError


def _value_type(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, Decimal):
        return "decimal"
    if isinstance(value, datetime):
        return "datetime"
    if isinstance(value, date):
        return "date"
    if isinstance(value, str):
        return "str"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, (list, tuple)):
        return "array"
    return type(value).__name__.casefold()


def _observed_shape(columns: list[str], rows: list[Any]) -> dict[str, Any]:
    observed_columns: list[dict[str, str]] = []
    for column in columns:
        concrete = [row._mapping[column] for row in rows if row._mapping[column] is not None]
        concrete_types = {_value_type(value) for value in concrete}
        observed_columns.append(
            {
                "name": column,
                "type": next(iter(concrete_types))
                if len(concrete_types) == 1
                else ("unknown" if not concrete else "mixed"),
            }
        )
    return {
        "columns": observed_columns,
        "sample_rows": min(len(rows), 50),
        "sample_truncated": len(rows) > 50,
    }


def _validate_shape(
    observed: dict[str, Any],
    expected_columns: list[str],
    expected_types: dict[str, str],
    *,
    min_rows: int,
    max_rows: int | None,
) -> str | None:
    if not expected_columns or len(expected_columns) != len(set(expected_columns)):
        return "expected_columns must be a non-empty unique ordered list"
    if set(expected_types) - set(expected_columns):
        return "expected_types contains columns absent from expected_columns"
    observed_columns = [str(item["name"]) for item in observed["columns"]]
    if observed_columns != expected_columns:
        return f"result columns {observed_columns} do not match expected columns {expected_columns}"
    sample_rows = int(observed["sample_rows"])
    if sample_rows < min_rows and not observed["sample_truncated"]:
        return f"result returned {sample_rows} rows, fewer than the required {min_rows}"
    if max_rows is not None and (sample_rows > max_rows or observed["sample_truncated"]):
        return f"result exceeds the allowed maximum of {max_rows} rows"
    observed_types = {str(item["name"]): str(item["type"]) for item in observed["columns"]}
    if mixed := [column for column, value_type in observed_types.items() if value_type == "mixed"]:
        return f"result types are inconsistent across the sample for columns {mixed}"
    for column, expected in expected_types.items():
        actual = observed_types[column]
        if actual == "unknown":
            return f"result type for {column} cannot be verified from an all-null/empty sample"
        normalised = {
            "boolean": "bool",
            "integer": "int",
            "number": "number",
            "string": "str",
        }.get(expected.casefold(), expected.casefold())
        if normalised == "number":
            matches = actual in {"int", "float", "decimal"}
        else:
            matches = actual == normalised
        if not matches:
            return f"result type for {column} is {actual}, expected {normalised}"
    return None


def execute_query_validation(
    validation_engine: Engine,
    query: str,
    expected_columns: list[str],
    expected_types: dict[str, str] | None = None,
    *,
    min_rows: int = 0,
    max_rows: int | None = None,
) -> tuple[str, dict[str, Any] | None, str | None]:
    """Execute one bounded SELECT and validate its declared result contract.

    Returns ``(clean_sql, observed_shape, error)``. The caller must not persist a
    query when ``error`` is non-null.
    """

    clean = query.strip()
    if clean.endswith(";"):
        clean = clean[:-1].strip()
    if not clean.casefold().startswith(("select", "with")):
        return clean, None, "Only SELECT queries can be validated"
    if ";" in clean:
        return clean, None, "Multi-statement queries are not allowed"
    if not 0 <= min_rows <= 50:
        return clean, None, "min_rows must be between 0 and 50"
    if max_rows is not None and (not 0 <= max_rows <= 50 or max_rows < min_rows):
        return clean, None, "max_rows must be between min_rows and 50"

    expected_type_map = expected_types or {}
    empty_shape = {
        "columns": [{"name": value, "type": "unknown"} for value in expected_columns],
        "sample_rows": 0,
        "sample_truncated": False,
    }
    if shape_error := _validate_shape(
        empty_shape,
        expected_columns,
        {},
        min_rows=0,
        max_rows=None,
    ):
        return clean, None, shape_error
    allowed_types = {
        "array",
        "bool",
        "boolean",
        "date",
        "datetime",
        "decimal",
        "float",
        "int",
        "integer",
        "number",
        "object",
        "str",
        "string",
    }
    if unsupported := {value.casefold() for value in expected_type_map.values()} - allowed_types:
        return clean, None, f"Unsupported expected result types: {sorted(unsupported)}"

    try:
        with validation_engine.connect() as conn:
            if validation_engine.dialect.name == "postgresql":
                conn.execute(text("SET LOCAL statement_timeout = '5000ms'"))
                conn.execute(text("SET LOCAL lock_timeout = '1000ms'"))
            result = conn.execute(text(f"SELECT * FROM ({clean}) AS dash_validated_query LIMIT 51"))
            columns = [str(value) for value in result.keys()]
            rows = list(result.fetchmany(51))
    except SQLAlchemyError as exc:
        logger.warning("Validated-query execution failed: %s", type(exc).__name__)
        return clean, None, "Query did not execute successfully under the read-only validation role"

    observed = _observed_shape(columns, rows)
    if shape_error := _validate_shape(
        observed,
        expected_columns,
        expected_type_map,
        min_rows=min_rows,
        max_rows=max_rows,
    ):
        return clean, observed, f"Result shape validation failed: {shape_error}"
    return clean, observed, None


def create_save_validated_query_tool(
    knowledge: Knowledge,
    *,
    validation_engine: Engine,
    registry_engine: Engine,
):
    """Create a tool that admits queries only after real read-only execution."""

    @tool
    def save_validated_query(
        name: str,
        question: str,
        query: str,
        expected_columns: list[str],
        expected_types: dict[str, str] | None = None,
        min_rows: int = 0,
        max_rows: int | None = None,
        summary: str | None = None,
        tables_used: list[str] | None = None,
        data_quality_notes: str | None = None,
    ) -> str:
        """Execute a SELECT and save it only when its observed result shape matches.

        ``expected_columns`` is ordered. ``expected_types`` may constrain any or all
        columns using: bool, int, number, float, decimal, str, date, datetime,
        object, array. ``min_rows`` and ``max_rows`` admit an explicit cardinality
        contract (bounded to 50 rows).
        Validation runs through the database-enforced read-only engine with a bounded
        sample before the canonical record and disposable knowledge index are written.
        """

        if not name or not name.strip():
            return "Error: Name required."
        if not question or not question.strip():
            return "Error: Question required."
        if not query or not query.strip():
            return "Error: Query required."

        clean, observed, validation_error = execute_query_validation(
            validation_engine,
            query,
            expected_columns,
            expected_types,
            min_rows=min_rows,
            max_rows=max_rows,
        )
        if validation_error is not None or observed is None:
            return f"Error: {validation_error}."

        expected_type_map = expected_types or {}

        expected_shape: dict[str, Any] = {
            "columns": [
                {"name": column, "type": expected_type_map.get(column, "any").casefold()} for column in expected_columns
            ],
            "min_rows": min_rows,
            "max_rows": max_rows,
        }
        query_fingerprint = hashlib.sha256(clean.encode()).hexdigest()
        schema_fingerprint = hashlib.sha256(
            json.dumps(observed["columns"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        query_id = f"vq_{query_fingerprint[:24]}"
        payload = {
            "type": "validated_query",
            "canonical_id": query_id,
            "name": name.strip(),
            "question": question.strip(),
            "query": clean,
            "expected_shape": expected_shape,
            "observed_shape": observed,
            "summary": summary.strip() if summary else None,
            "tables_used": tables_used or [],
            "data_quality_notes": data_quality_notes.strip() if data_quality_notes else None,
        }
        payload = {key: value for key, value in payload.items() if value is not None}

        try:
            with registry_engine.begin() as conn:
                conn.execute(
                    text(
                        """
                        INSERT INTO dash.validated_queries (
                            id, name, description, sql_text, query_fingerprint,
                            schema_fingerprint, expected_shape, observed_shape,
                            validation_status, validated_at, updated_at
                        ) VALUES (
                            :id, :name, :description, :sql_text, :query_fingerprint,
                            :schema_fingerprint, CAST(:expected_shape AS JSONB),
                            CAST(:observed_shape AS JSONB), 'valid', NOW(), NOW()
                        )
                        ON CONFLICT (query_fingerprint) DO UPDATE SET
                            name = EXCLUDED.name,
                            description = EXCLUDED.description,
                            sql_text = EXCLUDED.sql_text,
                            schema_fingerprint = EXCLUDED.schema_fingerprint,
                            expected_shape = EXCLUDED.expected_shape,
                            observed_shape = EXCLUDED.observed_shape,
                            validation_status = 'valid',
                            validation_error = NULL,
                            validated_at = NOW(),
                            updated_at = NOW()
                        """
                    ),
                    {
                        "id": query_id,
                        "name": name.strip(),
                        "description": (summary or question).strip(),
                        "sql_text": clean,
                        "query_fingerprint": query_fingerprint,
                        "schema_fingerprint": schema_fingerprint,
                        "expected_shape": json.dumps(expected_shape, sort_keys=True),
                        "observed_shape": json.dumps(observed, sort_keys=True),
                    },
                )
        except (TypeError, ValueError, SQLAlchemyError) as exc:
            logger.error("Failed to persist canonical validated query: %s", type(exc).__name__)
            return "Error: Query passed validation but its canonical record could not be persisted."

        try:
            knowledge.insert(
                name=name.strip(),
                text_content=json.dumps(payload, ensure_ascii=False, indent=2),
                reader=TextReader(),
                skip_if_exists=False,
            )
        except (AttributeError, TypeError, ValueError, OSError, SQLAlchemyError) as exc:
            # The vector knowledge record is a disposable index. Canonical query
            # admission succeeded and must not be misreported as a failed write.
            logger.warning("Canonical query saved but knowledge indexing failed: %s", type(exc).__name__)
            return f"Validated and saved query '{name}' as canonical record {query_id}; indexing is pending."
        return f"Validated and saved query '{name}' as canonical record {query_id}."

    return save_validated_query
