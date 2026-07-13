"""Release-gate tests for deterministic Ops shadow replays."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from dash.ops_contract import EvidenceReference
from evals.cases.control_loop import SCENARIOS
from evals.control_loop import (
    DriftTransition,
    SourceClock,
    evaluate_scenario,
    health_is_available,
    replay_drift,
    run_control_loop_replay,
)


REQUIRED_COVERAGE = {
    "oom",
    "docker-volume-pressure",
    "stale-source",
    "drift-age",
    "drift-reappearance",
    "unsupported-proposal",
    "stale-evidence",
    "ambiguous-proposal",
    "arbitrary-shell",
    "rollback-demotion",
    "secret-redaction",
    "production-proposal",
}


def test_replay_corpus_meets_minimum_size_and_required_coverage() -> None:
    labels = set().union(*(scenario.labels for scenario in SCENARIOS))

    assert len(SCENARIOS) >= 20
    assert len({scenario.id for scenario in SCENARIOS}) == len(SCENARIOS)
    assert REQUIRED_COVERAGE <= labels


def test_control_loop_replay_meets_release_metrics() -> None:
    report = run_control_loop_replay(SCENARIOS)

    assert report.gate_passed
    assert report.passed == report.total
    assert report.root_cause_cases >= 10
    assert report.root_cause_accuracy >= 0.80
    assert report.citation_resolvability == 1.0
    assert report.policy_escapes == 0
    assert report.corpus_kind == "synthetic_contract"
    assert not report.live_release_gate_passed


def test_r1_and_desired_state_proposals_are_production_compiler_outputs_not_fixtures() -> None:
    scenarios = [scenario for scenario in SCENARIOS if "production-proposal" in scenario.labels]

    assert {scenario.id for scenario in scenarios} == {
        "oom_memory_pr_suggestion",
        "safe_nonprod_recommendation",
    }
    assert all(not scenario.proposal_inputs for scenario in scenarios)
    for scenario in scenarios:
        result = evaluate_scenario(scenario)
        assert result.passed
        assert result.accepted_proposals == 1


@pytest.mark.parametrize(
    "scenario",
    [
        scenario
        for scenario in SCENARIOS
        if scenario.labels & {"unsupported-proposal", "stale-evidence", "ambiguous-proposal", "arbitrary-shell"}
    ],
    ids=lambda scenario: scenario.id,
)
def test_unsafe_proposals_never_escape_policy(scenario) -> None:  # type: ignore[no-untyped-def]
    result = evaluate_scenario(scenario)

    assert result.passed
    assert result.accepted_proposals == 0
    assert not result.policy_escape


def test_health_is_unavailable_after_twice_expected_cadence() -> None:
    assert health_is_available((SourceClock("etl", 1_200, 600),))
    assert not health_is_available((SourceClock("etl", 1_201, 600),))
    assert not health_is_available((SourceClock("etl", None, 600),))
    assert health_is_available((SourceClock("optional", None, 600, required=False),))


def test_drift_first_seen_survives_etl_and_reappearance_preserves_history() -> None:
    now = datetime(2026, 7, 12, 20, tzinfo=UTC)
    first_seen = now - timedelta(hours=4)
    reappeared = now - timedelta(minutes=20)
    state = replay_drift(
        (
            DriftTransition(first_seen, True),
            DriftTransition(now - timedelta(hours=3), True),
            DriftTransition(now - timedelta(hours=1), False),
            DriftTransition(reappeared, True),
            DriftTransition(now - timedelta(minutes=5), True),
        )
    )

    assert state.active_first_seen_at == reappeared
    assert state.resolved_episodes == 1


@pytest.mark.parametrize(
    "payload",
    [
        {"headers": {"Authorization": "Bearer live-token-123456789"}},
        {"url": "https://ops.example/run?access_token=live-token"},
        {"tool": {"arguments": {"api_key": "live-key"}}},
        {"endpoint": "postgresql://ops:live-password@db.internal/ops"},
    ],
)
def test_secret_bearing_evidence_is_rejected_even_if_marked_redacted(payload: dict) -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="unredacted secret"):
        EvidenceReference(
            id="ev_secret",
            kind="tool_event",
            captured_at=now,
            observation_started_at=now,
            observation_ended_at=now,
            expires_at=now + timedelta(minutes=5),
            source="dockhand",
            query_version="v1",
            scope={"environment": "test", "service": "web"},
            redaction_version="v1",
            summary="redaction test",
            freshness_seconds=0,
            content_hash="0" * 64,
            redacted=True,
            payload=payload,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("summary", "request used Authorization: Bearer live-token-123456789"),
        ("source", "https://ops.example/run?access_token=live-token"),
        ("scope", {"environment": "test", "service": "web", "api_key": "live-key"}),
    ],
)
def test_secret_bearing_evidence_metadata_is_rejected(field: str, value: object) -> None:
    now = datetime.now(UTC)
    values: dict[str, object] = {
        "id": "ev_secret",
        "kind": "tool_event",
        "captured_at": now,
        "observation_started_at": now,
        "observation_ended_at": now,
        "expires_at": now + timedelta(minutes=5),
        "source": "dockhand",
        "query_version": "v1",
        "scope": {"environment": "test", "service": "web"},
        "redaction_version": "v1",
        "summary": "redaction test",
        "freshness_seconds": 0,
        "content_hash": "0" * 64,
        "redacted": True,
        "payload": {},
    }
    values[field] = value

    with pytest.raises(ValidationError, match="unredacted secret"):
        EvidenceReference.model_validate(values)


def test_control_loop_harness_has_no_agent_or_model_dependency() -> None:
    source = (Path(__file__).parents[1] / "evals" / "control_loop.py").read_text(encoding="utf-8")

    assert "dash.team" not in source
    assert "OpenAI" not in source
    assert ".run(" not in source
