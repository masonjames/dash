"""Outcome-backed learning admission tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from dash.internal_ops import CanonicalOutcome, _payload_hash, evaluate_canonical_outcome
from dash.ops_contract import EvidenceReference


def _canonical(*, success: bool = True, rollback: bool = False, confidence: float = 0.95) -> CanonicalOutcome:
    now = datetime.now(UTC)
    ids = ("ev_post", "ev_rollback") if rollback else ("ev_post",)
    return CanonicalOutcome(
        success=success,
        rollback_executed=rollback,
        confidence=confidence,
        evidence_ids=ids,
        verified=True,
        verifier_source="dockhand-independent-verifier",
        verification_started_at=now - timedelta(minutes=2),
        verification_completed_at=now - timedelta(minutes=1),
        outcome_occurred_at=now,
    )


def _evidence(
    evidence_id: str,
    *,
    kind: str,
    success: bool,
    source: str = "dockhand-independent-verifier",
) -> EvidenceReference:
    now = datetime.now(UTC)
    payload = {"phase": kind, "success": success, "job_id": f"job_{evidence_id}"}
    observed = now - timedelta(seconds=90 if kind == "postcondition_verification" else 30)
    return EvidenceReference(
        id=evidence_id,
        kind=kind,
        captured_at=observed,
        observation_started_at=observed,
        observation_ended_at=observed,
        expires_at=now + timedelta(minutes=5),
        source=source,
        query_version="dockhand-verifier-v1",
        scope={"environment": "production", "service": "web"},
        redaction_version="dockhand-redaction-v1",
        summary="independent governed phase verification",
        freshness_seconds=90,
        content_hash=_payload_hash(payload),
        redacted=True,
        payload=payload,
    )


def test_verified_success_with_post_action_evidence_becomes_candidate_only() -> None:
    result = evaluate_canonical_outcome(
        _canonical(),
        [_evidence("ev_post", kind="postcondition_verification", success=True)],
    )

    assert result.disposition == "candidate"
    assert result.eligible_candidate
    assert result.evidence_ids == ["ev_post"]
    assert result.automatic_eligibility_disabled


def test_pre_action_or_wrong_source_evidence_cannot_back_a_learning() -> None:
    result = evaluate_canonical_outcome(
        _canonical(),
        [_evidence("ev_post", kind="runtime_snapshot", success=True)],
    )

    assert result.disposition == "insufficient_evidence"
    assert not result.eligible_candidate
    assert result.evidence_ids == []


def test_failure_and_rollback_are_cited_and_never_automatically_eligible() -> None:
    result = evaluate_canonical_outcome(
        _canonical(success=False, rollback=True),
        [
            _evidence("ev_post", kind="postcondition_verification", success=False),
            _evidence("ev_rollback", kind="rollback_verification", success=True),
        ],
    )

    assert result.disposition == "rollback"
    assert not result.eligible_candidate
    assert set(result.evidence_ids) == {"ev_post", "ev_rollback"}
    assert result.automatic_eligibility_disabled


def test_missing_rollback_proof_fails_closed_even_when_row_claims_rollback() -> None:
    result = evaluate_canonical_outcome(
        _canonical(success=False, rollback=True),
        [_evidence("ev_post", kind="postcondition_verification", success=False)],
    )

    assert result.disposition == "insufficient_evidence"
    assert not result.eligible_candidate


def test_failed_rollback_attempt_is_a_cited_failure_not_a_successful_rollback() -> None:
    canonical = replace(
        _canonical(success=False, rollback=False),
        evidence_ids=("ev_post", "ev_rollback"),
    )
    result = evaluate_canonical_outcome(
        canonical,
        [
            _evidence("ev_post", kind="postcondition_verification", success=False),
            _evidence("ev_rollback", kind="rollback_verification", success=False),
        ],
    )

    assert result.disposition == "failed"
    assert set(result.evidence_ids) == {"ev_post", "ev_rollback"}
    assert not result.eligible_candidate
