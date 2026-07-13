"""Deterministic, no-model shadow diagnosis and comparable tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from dash import internal_ops
from dash.ops_contract import CauseCode, EvidenceReference, OpsInvestigationRequest
from dash.ops_shadow_reasoning import DETECTOR_VERSION, build_catalog_backed_proposals, diagnose_evidence
from evals.cases.control_loop import _proposal_catalog


class FakeCursor:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

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


def _evidence(
    evidence_id: str,
    *,
    kind: str = "live_runtime_snapshot",
    payload: dict[str, Any],
) -> EvidenceReference:
    now = datetime.now(UTC)
    return EvidenceReference(
        id=evidence_id,
        kind=kind,
        captured_at=now - timedelta(seconds=30),
        observation_started_at=now - timedelta(seconds=30),
        observation_ended_at=now - timedelta(seconds=30),
        expires_at=now + timedelta(minutes=5),
        source="dockhand.collect_state",
        query_version="live-collect-state-v1",
        scope={"environment": "production", "service": "client-portal"},
        redaction_version="dockhand-redaction-v1",
        summary="canonical replay evidence",
        freshness_seconds=30,
        content_hash=internal_ops._payload_hash(payload),
        redacted=True,
        payload=payload,
    )


def _live_state(**probes: dict[str, Any]) -> dict[str, Any]:
    state = {
        name: {"ok": True, "output": ""}
        for name in (
            "services",
            "containers",
            "volumes",
            "networks",
            "images",
            "disk",
            "docker_disk",
            "memory",
            "cpu_pressure",
        )
    }
    state.update(probes)
    return {"query_version": "live-collect-state-v1", "state": state}


def _historical_evidence_row(
    evidence_id: str,
    investigation_id: str,
    *,
    query_version: str = "historical-runtime-v1",
) -> tuple[Any, ...]:
    payload = {"signal": "verified historical outcome", "evidence_id": evidence_id}
    captured_at = datetime.now(UTC) - timedelta(days=2)
    return (
        evidence_id,
        "verification" if "verify" in evidence_id else "runtime_snapshot",
        captured_at,
        captured_at + timedelta(minutes=5),
        "dockhand.verifier",
        query_version,
        {"environment": "production", "service": "client-portal"},
        "dockhand-redaction-v1",
        "historical evidence",
        payload,
        captured_at,
        captured_at,
        172_800,
        internal_ops._payload_hash(payload),
        True,
        "production",
        "client-portal",
        investigation_id,
    )


def test_diagnoses_structured_oom_and_cites_only_its_evidence() -> None:
    evidence = _evidence(
        "ev_oom",
        payload={"event": {"event_type": "container.oom", "exit_code": 137}},
    )

    result = diagnose_evidence([evidence])

    assert result.root_cause == "container_oom"
    assert result.confidence == 0.98
    assert result.summary_evidence_ids == ["ev_oom"]
    assert result.hypotheses[0].evidence_ids == ["ev_oom"]
    assert result.hypotheses[0].cause_code is CauseCode.CONTAINER_OOM
    assert result.hypotheses[0].detector_version == DETECTOR_VERSION
    assert len(result.hypotheses[0].signal_fingerprint) == 64


def _service_health_catalog() -> dict[str, Any]:
    return {
        "registry_version": "test-v1",
        "playbooks": [
            {
                "id": "diagnose.service-health",
                "version": "1.0.0",
                "enabled": True,
                "proposal_type": "job",
                "job_kind": "service.healthcheck",
                "risk_class": "R0",
                "allowed_environments": ["production"],
                "required_arguments": ["service_name", "host"],
                "optional_arguments": ["container"],
                "argument_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["service_name", "host"],
                    "properties": {
                        "service_name": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 160,
                            "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
                        },
                        "host": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 253,
                            "pattern": r"^[A-Za-z0-9][A-Za-z0-9.-]*$",
                        },
                        "container": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 255,
                            "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
                        },
                    },
                },
                "evidence_max_age_seconds": 300,
                "preconditions": ["target resolves"],
                "rollback_steps": ["no mutation"],
                "postconditions": ["health evidence stored"],
            }
        ],
    }


def test_catalog_only_r0_diagnostic_proposal_is_schema_validated() -> None:
    evidence = _evidence("ev_oom", payload={"oom_killed": True})
    evidence = evidence.model_copy(update={"scope": {**evidence.scope, "host": "prod-1"}})
    diagnosis = diagnose_evidence([evidence])
    request = OpsInvestigationRequest.model_validate(
        {
            "investigation_id": "inv_oom",
            "prompt": "Investigate the OOM",
            "environment": "production",
            "service": "client-portal",
            "evidence_ids": [evidence.id],
            "proposal_catalog": _service_health_catalog(),
        }
    )

    proposals = build_catalog_backed_proposals(request, [evidence], diagnosis)

    assert len(proposals) == 1
    assert proposals[0].playbook_id == "diagnose.service-health"
    assert proposals[0].job_kind == "service.healthcheck"
    assert proposals[0].risk_class.value == "R0"
    assert proposals[0].arguments == {"service_name": "client-portal", "host": "prod-1"}


def test_catalog_argument_schema_rejects_unknown_or_wrong_typed_arguments() -> None:
    request = OpsInvestigationRequest.model_validate(
        {
            "investigation_id": "inv_schema",
            "prompt": "Validate the catalog",
            "proposal_catalog": _service_health_catalog(),
        }
    )
    schema = request.proposal_catalog.playbooks[0].argument_schema

    assert schema.accepts({"service_name": "web", "host": "prod-1"})
    assert not schema.accepts({"service_name": "web", "host": "prod-1", "force": True})
    assert not schema.accepts({"service_name": "web", "host": 123})
    assert not schema.accepts({"service_name": "bad service", "host": "prod-1"})


def _scoped_evidence(
    evidence_id: str,
    *,
    payload: dict[str, Any],
    environment: str,
    service: str,
    host: str,
    kind: str,
) -> EvidenceReference:
    evidence = _evidence(evidence_id, kind=kind, payload=payload)
    return evidence.model_copy(update={"scope": {"environment": environment, "service": service, "host": host}})


def test_production_compiler_emits_only_explicit_nonprod_immutable_redeploy() -> None:
    payload = {
        "service": "web",
        "inventory_registered": True,
        "inventory_project": "compose-preview-42",
        "runtime_project_name": "preview-42-runtime",
        "inventory_service": "preview-42-runtime_web",
        "inventory_environment": "staging",
        "catalog_compose_id": "compose-preview-42",
        "catalog_discovery_status": "complete",
        "catalog_source_commit": "c" * 40,
        "catalog_manifest_path": "infra/dokploy/apps/staging/preview/docker-compose.yml",
        "desired_digest": f"sha256:{'a' * 64}",
        "actual_digest": f"sha256:{'b' * 64}",
        "health": "unhealthy",
    }
    evidence = _scoped_evidence(
        "ev_deploy",
        payload=payload,
        environment="staging",
        service="web",
        host="staging-1",
        kind="deployment",
    )
    request = OpsInvestigationRequest.model_validate(
        {
            "investigation_id": "inv_deploy",
            "prompt": "Investigate immutable deployment failure",
            "environment": "staging",
            "service": "web",
            "evidence_ids": [evidence.id],
            "proposal_catalog": _proposal_catalog(include_redeploy=True),
        }
    )

    proposals = build_catalog_backed_proposals(
        request,
        [evidence],
        diagnose_evidence([evidence]),
    )

    assert len(proposals) == 1
    proposal = proposals[0]
    assert proposal.playbook_id == "recover.nonprod-redeploy"
    assert proposal.risk_class.value == "R1"
    assert proposal.target_environment == "staging"
    assert proposal.arguments == {"project": "compose-preview-42", "host": "staging-1"}

    production_request = request.model_copy(update={"environment": "production"})
    assert (
        build_catalog_backed_proposals(
            production_request,
            [evidence],
            diagnose_evidence([evidence]),
        )
        == []
    )


@pytest.mark.parametrize(
    "inventory_update",
    [
        {"inventory_registered": False},
        {"inventory_project": "another-project"},
        {"runtime_project_name": "another-runtime"},
        {"inventory_service": "another-runtime_web"},
        {"inventory_environment": "production"},
        {"catalog_compose_id": "another-project"},
        {"catalog_discovery_status": "partial"},
        {"catalog_source_commit": "main"},
        {"catalog_manifest_path": "../../untracked.yml"},
        {"desired_digest": "latest"},
    ],
)
def test_nonprod_redeploy_requires_canonical_project_environment_inventory_identity(
    inventory_update: dict[str, Any],
) -> None:
    payload = {
        "service": "web",
        "inventory_registered": True,
        "inventory_project": "compose-preview-42",
        "runtime_project_name": "preview-42-runtime",
        "inventory_service": "preview-42-runtime_web",
        "inventory_environment": "staging",
        "catalog_compose_id": "compose-preview-42",
        "catalog_discovery_status": "complete",
        "catalog_source_commit": "c" * 40,
        "catalog_manifest_path": "infra/dokploy/apps/staging/preview/docker-compose.yml",
        "desired_digest": f"sha256:{'a' * 64}",
        "actual_digest": f"sha256:{'b' * 64}",
        "health": "unhealthy",
    }
    payload.update(inventory_update)
    evidence = _scoped_evidence(
        "ev_deploy_invalid",
        payload=payload,
        environment="staging",
        service="web",
        host="staging-1",
        kind="deployment",
    )
    request = OpsInvestigationRequest.model_validate(
        {
            "investigation_id": "inv_deploy_invalid",
            "prompt": "Investigate unproven inventory deployment",
            "environment": "staging",
            "service": "web",
            "evidence_ids": [evidence.id],
            "proposal_catalog": _proposal_catalog(include_redeploy=True),
        }
    )

    assert (
        build_catalog_backed_proposals(
            request,
            [evidence],
            diagnose_evidence([evidence]),
        )
        == []
    )


def test_production_compiler_emits_bounded_immutable_memory_pr_suggestion() -> None:
    payload = {
        "oom_killed": True,
        "service": "client-portal",
        "desired_state_tracked": True,
        "source_file": "compose/client-portal.yml",
        "source_commit": "c" * 40,
        "current_memory_limit_bytes": 512 * 1024 * 1024,
        "observed_peak_bytes": 530_000_000,
    }
    evidence = _scoped_evidence(
        "ev_memory",
        payload=payload,
        environment="production",
        service="client-portal",
        host="prod",
        kind="docker_oom_event",
    )
    request = OpsInvestigationRequest.model_validate(
        {
            "investigation_id": "inv_memory",
            "prompt": "Investigate OOM and suggest desired state",
            "environment": "production",
            "service": "client-portal",
            "evidence_ids": [evidence.id],
            "proposal_catalog": _proposal_catalog(include_memory=True),
        }
    )

    proposals = build_catalog_backed_proposals(
        request,
        [evidence],
        diagnose_evidence([evidence]),
    )

    assert len(proposals) == 1
    proposal = proposals[0]
    assert proposal.proposal_type == "desired_state_pr"
    assert proposal.job_kind is None
    assert proposal.playbook_id == "suggest.memory-limit"
    assert proposal.arguments == {
        "service": "client-portal",
        "source_file": "compose/client-portal.yml",
        "source_commit": "c" * 40,
        "proposed_memory_limit": "1024Mi",
        "observed_peak_bytes": 530_000_000,
    }
    assert not set(proposal.arguments) & {"cmd", "command", "code", "script", "shell"}


@pytest.mark.parametrize(
    "payload_update",
    [
        {"source_commit": "not-a-commit"},
        {"desired_state_tracked": False},
        {"observed_peak_bytes": 10 * 1024 * 1024 * 1024},
        {"source_file": "../../secrets"},
    ],
)
def test_memory_pr_suggestion_fails_closed_without_bounded_tracked_inputs(
    payload_update: dict[str, Any],
) -> None:
    payload = {
        "oom_killed": True,
        "service": "client-portal",
        "desired_state_tracked": True,
        "source_file": "compose/client-portal.yml",
        "source_commit": "c" * 40,
        "current_memory_limit_bytes": 512 * 1024 * 1024,
        "observed_peak_bytes": 530_000_000,
    }
    payload.update(payload_update)
    evidence = _scoped_evidence(
        "ev_memory_invalid",
        payload=payload,
        environment="production",
        service="client-portal",
        host="prod",
        kind="docker_oom_event",
    )
    request = OpsInvestigationRequest.model_validate(
        {
            "investigation_id": "inv_memory_invalid",
            "prompt": "Investigate invalid OOM desired state evidence",
            "environment": "production",
            "service": "client-portal",
            "evidence_ids": [evidence.id],
            "proposal_catalog": _proposal_catalog(include_memory=True),
        }
    )

    assert (
        build_catalog_backed_proposals(
            request,
            [evidence],
            diagnose_evidence([evidence]),
        )
        == []
    )


def test_current_platform_registry_shape_matches_dash_proposal_contract() -> None:
    registry_path = Path(__file__).resolve().parents[2] / "platform-infra" / "ops" / "remediation-playbooks.yaml"
    if not registry_path.is_file():
        pytest.skip("platform-infra sibling is unavailable in this checkout")
    raw = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    fields = {
        "id",
        "version",
        "enabled",
        "proposal_type",
        "job_kind",
        "risk_class",
        "allowed_environments",
        "required_arguments",
        "optional_arguments",
        "argument_schema",
        "evidence_max_age_seconds",
        "preconditions",
        "rollback_steps",
        "postconditions",
    }
    selected = []
    for definition in raw["playbooks"]:
        if definition["id"] in {"recover.nonprod-redeploy", "suggest.memory-limit"}:
            selected.append({key: definition[key] for key in fields if key in definition})

    request = OpsInvestigationRequest.model_validate(
        {
            "investigation_id": "inv_cross_contract",
            "prompt": "Validate current platform proposal contract",
            "proposal_catalog": {
                "registry_version": raw["registry_version"],
                "playbooks": selected,
            },
        }
    )

    assert {item.id for item in request.proposal_catalog.playbooks} == {
        "recover.nonprod-redeploy",
        "suggest.memory-limit",
    }
    memory = next(item for item in request.proposal_catalog.playbooks if item.id == "suggest.memory-limit")
    assert "source_commit" in memory.argument_schema.required


def test_diagnoses_docker_data_pressure_when_root_is_healthy() -> None:
    payload = _live_state(
        disk={
            "ok": True,
            "output": "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/sda 100 20 80 20% /\n",
        },
        docker_disk={
            "ok": True,
            "output": "/var/lib/docker\nFilesystem 1K-blocks Used Available Use% Mounted on\n"
            "/dev/sdb 100 91 9 91% /var/lib/docker\n",
        },
    )
    result = diagnose_evidence([_evidence("ev_disk", payload=payload)])

    assert result.root_cause == "docker_volume_pressure"
    assert result.hypotheses[0].evidence_ids == ["ev_disk"]


def test_diagnoses_unresolved_configuration_drift() -> None:
    payload = {
        "records": [
            {
                "category": "image",
                "desired_value": "app@sha256:new",
                "actual_value": "app@sha256:old",
                "resolved_at": None,
            }
        ]
    }
    result = diagnose_evidence([_evidence("ev_drift", kind="configuration_drift", payload=payload)])

    assert result.root_cause == "configuration_drift"
    assert result.hypotheses[0].evidence_ids == ["ev_drift"]


def test_diagnoses_unhealthy_service_replicas() -> None:
    payload = _live_state(
        services={
            "ok": True,
            "output": '{"Name":"client-portal","Replicas":"0/1","Image":"app@sha256:abc"}\n',
        }
    )
    result = diagnose_evidence([_evidence("ev_service", payload=payload)])

    assert result.root_cause == "service_unhealthy"
    assert result.hypotheses[0].evidence_ids == ["ev_service"]


def test_unknown_or_ambiguous_text_fails_closed() -> None:
    evidence = _evidence(
        "ev_unknown",
        payload={"message": "operator wondered whether this might be an OOM or disk problem"},
    )

    result = diagnose_evidence([evidence])

    assert result.root_cause is None
    assert result.confidence == 0.0
    assert result.hypotheses == []
    assert result.summary_evidence_ids == ["ev_unknown"]


def test_exit_137_without_explicit_oom_signal_fails_closed() -> None:
    result = diagnose_evidence(
        [_evidence("ev_sigkill", payload={"event": {"event_type": "container.die", "exit_code": 137}})]
    )

    assert result.root_cause is None
    assert result.hypotheses == []


def test_unhealthy_unrelated_service_is_not_attributed_to_scoped_target() -> None:
    payload = _live_state(
        services={
            "ok": True,
            "output": '{"Name":"unrelated-worker","Replicas":"0/1"}\n',
        }
    )

    result = diagnose_evidence([_evidence("ev_unrelated", payload=payload)])

    assert result.root_cause is None
    assert result.hypotheses == []


def test_ranked_signals_are_deterministic_and_citation_grounded() -> None:
    oom = _evidence("ev_oom", payload={"container": {"OOMKilled": True}})
    disk = _evidence(
        "ev_disk",
        payload=_live_state(
            disk={"ok": True, "output": "/dev/sda 100 20 80 20% /\n"},
            docker_disk={
                "ok": True,
                "output": "/var/lib/docker\n/dev/sdb 100 90 10 90% /var/lib/docker\n",
            },
        ),
    )

    result = diagnose_evidence([disk, oom])

    assert [item.rank for item in result.hypotheses] == [1, 2]
    assert "root_cause=container_oom" in result.hypotheses[0].statement
    assert "root_cause=docker_volume_pressure" in result.hypotheses[1].statement
    assert set(result.summary_evidence_ids) == {"ev_oom", "ev_disk"}


def test_historical_comparable_requires_verified_same_scope_nonlegacy_outcome(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    historical_id = "inv_historical"
    candidate = (
        historical_id,
        "incident_123",
        {
            "hypotheses": [
                {
                    "rank": 1,
                    "statement": "root_cause=container_oom; structured lifecycle evidence",
                    "evidence_ids": ["ev_hypothesis"],
                }
            ]
        },
        ["ev_verify"],
        datetime.now(UTC) - timedelta(days=2),
        0.92,
        "outcome_123",
    )
    connection = FakeConnection(
        [
            FakeCursor([candidate]),
            FakeCursor(
                [
                    _historical_evidence_row("ev_hypothesis", historical_id),
                    _historical_evidence_row("ev_verify", historical_id),
                ]
            ),
        ]
    )

    async def fake_connect() -> FakeConnection:
        return connection

    monkeypatch.setattr(internal_ops, "_connect", fake_connect)
    comparables, evidence = asyncio.run(
        internal_ops._load_historical_comparables(
            "inv_current",
            environment="production",
            service="client-portal",
            root_cause=CauseCode.CONTAINER_OOM,
            outcome_scores={"outcome_123": 0.77},
        )
    )

    assert [item.incident_id for item in comparables] == ["incident_123"]
    assert comparables[0].similarity == 0.77
    assert set(comparables[0].evidence_ids) == {"ev_hypothesis", "ev_verify"}
    assert {item.id for item in evidence} == {"ev_hypothesis", "ev_verify"}
    candidate_query, candidate_params = connection.calls[0]
    assert candidate_params == (
        "inv_current",
        "production",
        "client-portal",
        ["outcome_123"],
        ["outcome_123"],
    )
    assert "i.environment = %s" in candidate_query
    assert "i.service = %s" in candidate_query
    assert "INTERVAL '90 days'" in candidate_query
    assert "i.request_id NOT LIKE 'legacy-%%'" in candidate_query
    assert "o.verified IS TRUE" in candidate_query
    assert "o.success IS TRUE" in candidate_query
    assert "o.rollback_executed IS FALSE" in candidate_query
    assert "o.confidence >= 0.85" in candidate_query
    evidence_query, _ = connection.calls[1]
    assert "e.query_version NOT LIKE 'legacy-%%'" in evidence_query
    assert "e.redaction_version NOT LIKE 'legacy-%%'" in evidence_query
    assert "e.captured_at >= NOW() - INTERVAL '90 days'" in evidence_query


def test_comparable_wrong_root_or_missing_outcome_evidence_is_filtered(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    wrong_root = (
        "inv_wrong",
        "incident_wrong",
        {
            "hypotheses": [
                {
                    "rank": 1,
                    "statement": "root_cause=service_unhealthy; different signature",
                    "evidence_ids": ["ev_wrong"],
                }
            ]
        },
        ["ev_wrong_verify"],
        datetime.now(UTC),
        0.99,
        "outcome_wrong",
    )
    missing_outcome_evidence = (
        "inv_missing",
        "incident_missing",
        {
            "hypotheses": [
                {
                    "rank": 1,
                    "statement": "root_cause=container_oom; matching signature",
                    "evidence_ids": ["ev_missing"],
                }
            ]
        },
        [],
        datetime.now(UTC),
        0.99,
        "outcome_missing",
    )
    connection = FakeConnection([FakeCursor([wrong_root, missing_outcome_evidence])])

    async def fake_connect() -> FakeConnection:
        return connection

    monkeypatch.setattr(internal_ops, "_connect", fake_connect)
    comparables, evidence = asyncio.run(
        internal_ops._load_historical_comparables(
            "inv_current",
            environment="production",
            service="client-portal",
            root_cause=CauseCode.CONTAINER_OOM,
        )
    )

    assert comparables == []
    assert evidence == []
    assert len(connection.calls) == 1


def test_comparable_is_skipped_when_canonical_evidence_is_legacy(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    historical_id = "inv_historical"
    candidate = (
        historical_id,
        "incident_123",
        {
            "hypotheses": [
                {
                    "rank": 1,
                    "statement": "root_cause=container_oom; structured lifecycle evidence",
                    "evidence_ids": ["ev_hypothesis"],
                }
            ]
        },
        ["ev_verify"],
        datetime.now(UTC),
        0.95,
        "outcome_legacy",
    )
    connection = FakeConnection(
        [
            FakeCursor([candidate]),
            FakeCursor(
                [
                    _historical_evidence_row("ev_hypothesis", historical_id, query_version="legacy-v0"),
                    _historical_evidence_row("ev_verify", historical_id),
                ]
            ),
        ]
    )

    async def fake_connect() -> FakeConnection:
        return connection

    monkeypatch.setattr(internal_ops, "_connect", fake_connect)
    comparables, evidence = asyncio.run(
        internal_ops._load_historical_comparables(
            "inv_current",
            environment="production",
            service="client-portal",
            root_cause=CauseCode.CONTAINER_OOM,
        )
    )

    assert comparables == []
    assert evidence == []


def test_comparable_lookup_requires_explicit_environment_and_service(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    async def unexpected_connect() -> FakeConnection:
        raise AssertionError("database lookup should not run without complete scope")

    monkeypatch.setattr(internal_ops, "_connect", unexpected_connect)
    comparables, evidence = asyncio.run(
        internal_ops._load_historical_comparables(
            "inv_current",
            environment=None,
            service="client-portal",
            root_cause=CauseCode.CONTAINER_OOM,
        )
    )

    assert comparables == []
    assert evidence == []
