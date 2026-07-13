"""Private, HMAC-authenticated, read-only Ops API.

This module deliberately contains no model or AgentOS imports. It validates
canonical evidence and returns fail-closed shadow responses until the governed
reasoning pipeline is ready.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from os import getenv
from time import time
from typing import Any

import psycopg
from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError
from psycopg.conninfo import make_conninfo

from dash.ops_contract import (
    CauseCode,
    EvidenceReference,
    HistoricalComparable,
    OpsInvestigationRequest,
    OpsInvestigationResult,
    OutcomeEvaluation,
    VerificationOutcome,
)
from dash.ops_shadow_reasoning import DETECTOR_VERSION, build_catalog_backed_proposals, diagnose_evidence
from dash.ops_retrieval import search_canonical_documents

router = APIRouter(prefix="/internal")
logger = logging.getLogger(__name__)

_MAX_CLOCK_SKEW_SECONDS = 300
_MAX_BODY_BYTES = 1_048_576
_MAX_NONCES = 50_000
_MODEL_VERSION = getenv("DASH_OPS_MODEL_VERSION", DETECTOR_VERSION)
_MAX_HISTORICAL_COMPARABLES = 3
_REQUIRED_ENV = (
    "OPS_DB_HOST",
    "OPS_DB_PORT",
    "OPS_DB_USER",
    "OPS_DB_PASS",
    "OPS_DB_DATABASE",
)
_REQUIRED_TABLES = (
    "ops.event_projection_cursors",
    "ops.event_projection_status",
    "ops.ops_raw_events",
    "ops.ops_investigations",
    "ops.ops_commands",
    "ops.ops_evidence",
    "ops.ops_remediation_proposals",
    "ops.ops_verification_runs",
    "ops.ops_learning_candidates",
    "ops.ops_playbook_outcomes",
    "ops.ops_health_score_snapshots",
    "ops.ops_learnings",
    "ops.ops_retrieval_documents",
    "ops.ops_retrieval_index_status",
    "ops.ops_shadow_evaluations",
    "ops.ops_desired_state_suggestions",
    "ops.ops_incidents",
    "ops.ops_incident_transitions",
    "ops.ops_source_checkpoints",
    "dash.validated_queries",
)
_RETRIEVAL_INDEXER = "dash-canonical-hybrid-v1"
_RETRIEVAL_EMBEDDING_MODEL = "text-embedding-3-small"


class OpsConfigurationError(RuntimeError):
    """Private Ops service configuration is absent or unsafe."""


class OpsReadinessError(RuntimeError):
    """Configured database identity does not satisfy the reader contract."""


class EvidenceValidationError(ValueError):
    """Canonical evidence failed its scope, freshness, or integrity checks."""


class NonceCacheFullError(RuntimeError):
    """Replay cache cannot safely accept more signed requests."""


@dataclass(frozen=True)
class CanonicalOutcome:
    success: bool
    rollback_executed: bool
    confidence: float
    evidence_ids: tuple[str, ...]
    verified: bool
    verifier_source: str
    verification_started_at: datetime
    verification_completed_at: datetime
    outcome_occurred_at: datetime


class NonceReplayCache:
    """Single-process replay protection for the one-replica private service."""

    def __init__(self, ttl_seconds: int = _MAX_CLOCK_SKEW_SECONDS, max_entries: int = _MAX_NONCES) -> None:
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._entries: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def consume(self, nonce: str, now: float) -> bool:
        async with self._lock:
            self._entries = {value: expires_at for value, expires_at in self._entries.items() if expires_at > now}
            if nonce in self._entries:
                return False
            if len(self._entries) >= self._max_entries:
                raise NonceCacheFullError("nonce replay cache capacity reached")
            self._entries[nonce] = now + self._ttl_seconds
            return True


_nonce_cache = NonceReplayCache()


def _reader_config() -> dict[str, str]:
    values = {name: getenv(name, "").strip() for name in _REQUIRED_ENV}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise OpsConfigurationError(f"missing explicit Ops reader settings: {', '.join(missing)}")
    try:
        port = int(values["OPS_DB_PORT"])
    except ValueError as exc:
        raise OpsConfigurationError("OPS_DB_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise OpsConfigurationError("OPS_DB_PORT is outside the valid range")
    return values


def _psycopg_conninfo() -> str:
    config = _reader_config()
    return make_conninfo(
        host=config["OPS_DB_HOST"],
        port=config["OPS_DB_PORT"],
        user=config["OPS_DB_USER"],
        password=config["OPS_DB_PASS"],
        dbname=config["OPS_DB_DATABASE"],
        connect_timeout="5",
        application_name="dash-private-ops-reader",
        options="-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000",
    )


async def _connect() -> psycopg.AsyncConnection[Any]:
    return await psycopg.AsyncConnection.connect(_psycopg_conninfo())


async def _authenticate(request: Request, body: bytes) -> None:
    if len(body) > _MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="request body is too large")

    secret = getenv("DASH_INTERNAL_API_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(status_code=503, detail="internal Ops authentication is not configured securely")

    timestamp = request.headers.get("x-dash-timestamp", "")
    nonce = request.headers.get("x-dash-nonce", "")
    supplied = request.headers.get("x-dash-signature", "")
    try:
        sent_at = int(timestamp)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid signature timestamp") from exc

    now = time()
    if (
        not 16 <= len(nonce) <= 128
        or not re.fullmatch(r"[A-Za-z0-9_-]+", nonce)
        or abs(int(now) - sent_at) > _MAX_CLOCK_SKEW_SECONDS
    ):
        raise HTTPException(status_code=401, detail="expired or incomplete signature")
    if not re.fullmatch(r"[a-f0-9]{64}", supplied):
        raise HTTPException(status_code=401, detail="invalid signature")

    canonical = b"\n".join(
        [
            timestamp.encode(),
            nonce.encode(),
            request.method.upper().encode(),
            request.url.path.encode(),
            body,
        ]
    )
    expected = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=401, detail="invalid signature")

    try:
        accepted = await _nonce_cache.consume(nonce, now)
    except NonceCacheFullError as exc:
        logger.error("Dash private Ops nonce cache is full")
        raise HTTPException(status_code=503, detail="replay protection is unavailable") from exc
    if not accepted:
        raise HTTPException(status_code=409, detail="signed request replay detected")


def _payload_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _aware_utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None:
        raise EvidenceValidationError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _evidence_from_row(
    row: tuple[Any, ...],
    *,
    now: datetime,
    expected_scope: tuple[str | None, str | None] | None = None,
    require_unexpired: bool = True,
) -> EvidenceReference:
    (
        evidence_id,
        kind,
        captured_at,
        expires_at,
        source,
        query_version,
        scope,
        redaction_version,
        summary,
        payload,
        observation_started_at,
        observation_ended_at,
        freshness_seconds,
        content_hash,
        redacted,
        canonical_environment,
        canonical_service,
    ) = row
    if redacted is not True:
        raise EvidenceValidationError(f"evidence {evidence_id} has not passed redaction")
    if not isinstance(payload, dict):
        raise EvidenceValidationError(f"evidence {evidence_id} payload is not an object")
    if not isinstance(scope, dict):
        raise EvidenceValidationError(f"evidence {evidence_id} scope is not an object")
    if str(query_version).startswith("legacy-") or str(redaction_version).startswith("legacy-"):
        raise EvidenceValidationError(f"evidence {evidence_id} lacks a current provenance contract")
    if scope.get("environment") != canonical_environment or scope.get("service") != canonical_service:
        raise EvidenceValidationError(f"evidence {evidence_id} scope does not match its investigation")
    if expected_scope is not None and expected_scope != (
        canonical_environment,
        canonical_service,
    ):
        raise EvidenceValidationError("request scope does not match the canonical investigation")

    captured_at = _aware_utc(captured_at, "captured_at")
    if observation_started_at is None or observation_ended_at is None or expires_at is None:
        raise EvidenceValidationError(f"evidence {evidence_id} lacks a bounded observation window")
    observation_started_at = _aware_utc(observation_started_at, "observation_started_at")
    observation_ended_at = _aware_utc(observation_ended_at, "observation_ended_at")
    expires_at = _aware_utc(expires_at, "expires_at")
    if observation_started_at > observation_ended_at:
        raise EvidenceValidationError(f"evidence {evidence_id} has an invalid observation window")
    if require_unexpired and expires_at <= now:
        raise EvidenceValidationError(f"evidence {evidence_id} is expired")
    if captured_at > now:
        raise EvidenceValidationError(f"evidence {evidence_id} was captured in the future")
    if observation_ended_at > now:
        raise EvidenceValidationError(f"evidence {evidence_id} observation ends in the future")

    calculated_hash = _payload_hash(payload)
    if not isinstance(content_hash, str) or not hmac.compare_digest(calculated_hash, content_hash):
        raise EvidenceValidationError(f"evidence {evidence_id} failed its content hash")

    try:
        return EvidenceReference(
            id=str(evidence_id),
            kind=str(kind),
            captured_at=captured_at,
            observation_started_at=observation_started_at,
            observation_ended_at=observation_ended_at,
            expires_at=expires_at,
            source=str(source),
            query_version=str(query_version),
            scope=scope,
            redaction_version=str(redaction_version),
            summary=str(summary),
            payload=payload,
            freshness_seconds=int(freshness_seconds),
            content_hash=content_hash,
            redacted=True,
        )
    except ValidationError as exc:
        raise EvidenceValidationError(f"evidence {evidence_id} failed its typed contract") from exc


async def _load_evidence(
    investigation_id: str,
    ids: list[str],
    *,
    expected_scope: tuple[str | None, str | None] | None = None,
    require_unexpired: bool = True,
) -> list[EvidenceReference]:
    if not ids:
        return []

    query = """
        SELECT e.id, e.kind, e.captured_at, e.expires_at, e.source,
               e.query_version, e.scope, e.redaction_version, e.summary, e.payload,
               e.observation_started_at, e.observation_ended_at,
               GREATEST(
                   0,
                   EXTRACT(EPOCH FROM (NOW() - COALESCE(e.observation_started_at, e.captured_at)))
               )::INTEGER,
               e.content_hash, e.redacted, i.environment, i.service
        FROM ops.ops_evidence e
        JOIN ops.ops_investigations i ON i.id = e.investigation_id
        WHERE e.investigation_id = %s AND e.id = ANY(%s)
        ORDER BY e.captured_at DESC
    """
    try:
        async with await _connect() as conn:
            cursor = await conn.execute(query, (investigation_id, ids))
            rows = await cursor.fetchall()
    except OpsConfigurationError:
        raise
    except psycopg.Error as exc:
        raise OpsReadinessError("canonical evidence store is unavailable") from exc

    requested = set(ids)
    returned = {str(row[0]) for row in rows}
    missing = requested - returned
    if missing:
        raise EvidenceValidationError(f"missing evidence in investigation scope: {sorted(missing)}")

    now = datetime.now(UTC)
    return [
        _evidence_from_row(
            row,
            now=now,
            expected_scope=expected_scope,
            require_unexpired=require_unexpired,
        )
        for row in rows
    ]


def _string_ids(value: Any, *, limit: int = 2) -> list[str]:
    if not isinstance(value, list):
        return []
    return list(dict.fromkeys(str(item) for item in value if isinstance(item, str) and item.strip()))[:limit]


def _matching_hypothesis_evidence(reasoning_result: Any, root_cause: CauseCode) -> list[str]:
    if not isinstance(reasoning_result, dict):
        return []
    hypotheses = reasoning_result.get("hypotheses")
    if not isinstance(hypotheses, list):
        return []

    def rank(item: dict[str, Any]) -> int:
        value = item.get("rank")
        return value if isinstance(value, int) else 10_000

    ranked = sorted(
        (item for item in hypotheses if isinstance(item, dict)),
        key=rank,
    )[:3]
    marker = re.compile(
        rf"(?:^|[;\s])root_cause={re.escape(root_cause.value)}(?:;|\s|$)",
        re.IGNORECASE,
    )
    for hypothesis in ranked:
        if hypothesis.get("cause_code") == root_cause.value:
            return _string_ids(hypothesis.get("evidence_ids"))
        if marker.search(str(hypothesis.get("statement", ""))):
            return _string_ids(hypothesis.get("evidence_ids"))
    return []


async def _load_historical_comparables(
    investigation_id: str,
    *,
    environment: str | None,
    service: str | None,
    root_cause: CauseCode | None,
    outcome_scores: dict[str, float] | None = None,
    evidence_budget: int = 12,
) -> tuple[list[HistoricalComparable], list[EvidenceReference]]:
    """Load verified same-scope outcomes for an exact deterministic diagnosis.

    Historical evidence may be expired for action purposes, but must retain a
    current provenance/redaction contract and pass content-integrity validation.
    It is included only to support the historical comparison claim; proposals are
    always empty in this shadow service.
    """

    if not environment or not service or not root_cause or evidence_budget <= 0:
        return [], []

    candidate_query = """
        SELECT i.id,
               COALESCE(NULLIF(i.incident_id, ''), i.id) AS incident_id,
               i.reasoning_result,
               o.evidence_ids,
               o.occurred_at,
               o.confidence,
               o.id
        FROM ops.ops_investigations i
        JOIN ops.ops_playbook_outcomes o ON o.investigation_id = i.id
        WHERE i.id <> %s
          AND i.environment = %s
          AND i.service = %s
          AND i.state = 'resolved'
          AND i.updated_at >= NOW() - INTERVAL '90 days'
          AND i.request_id NOT LIKE 'legacy-%%'
          AND i.model_version IS NOT NULL
          AND i.model_version NOT LIKE 'legacy-%%'
          AND o.occurred_at >= NOW() - INTERVAL '90 days'
          AND o.outcome_kind = 'execution'
          AND o.verified IS TRUE
          AND o.success IS TRUE
          AND o.rollback_executed IS FALSE
          AND o.confidence >= 0.85
          AND (%s::text[] IS NULL OR o.id = ANY(%s))
        ORDER BY o.occurred_at DESC
        LIMIT 20
    """
    try:
        async with await _connect() as conn:
            cursor = await conn.execute(
                candidate_query,
                (
                    investigation_id,
                    environment,
                    service,
                    list(outcome_scores) if outcome_scores else None,
                    list(outcome_scores) if outcome_scores else None,
                ),
            )
            rows = await cursor.fetchall()
    except OpsConfigurationError:
        raise
    except psycopg.Error as exc:
        raise OpsReadinessError("historical comparable lookup failed") from exc

    candidates: list[tuple[str, str, list[str], float]] = []
    seen_investigations: set[str] = set()
    selected_evidence_ids: set[str] = set()
    for row in rows:
        historical_id = str(row[0])
        if historical_id in seen_investigations:
            continue
        hypothesis_evidence = _matching_hypothesis_evidence(row[2], root_cause)
        outcome_evidence = _string_ids(row[3])
        if not hypothesis_evidence or not outcome_evidence:
            continue
        cited_ids = list(dict.fromkeys((*hypothesis_evidence, *outcome_evidence)))
        new_evidence_ids = set(cited_ids) - selected_evidence_ids
        if len(selected_evidence_ids) + len(new_evidence_ids) > evidence_budget:
            continue
        outcome_id = str(row[6])
        # An exact typed cause + environment + service match is categorical
        # similarity 1.0. When the hybrid index selected the candidate, expose
        # its actual fused retrieval score instead of deriving a fake value from
        # verification confidence.
        similarity = outcome_scores.get(outcome_id, 1.0) if outcome_scores else 1.0
        candidates.append((historical_id, str(row[1]), cited_ids, max(0.0, min(1.0, similarity))))
        seen_investigations.add(historical_id)
        selected_evidence_ids.update(new_evidence_ids)
        if len(candidates) >= _MAX_HISTORICAL_COMPARABLES:
            break

    if not candidates:
        return [], []

    investigation_ids = [item[0] for item in candidates]
    evidence_ids = list(dict.fromkeys(value for item in candidates for value in item[2]))
    evidence_query = """
        SELECT e.id, e.kind, e.captured_at, e.expires_at, e.source,
               e.query_version, e.scope, e.redaction_version, e.summary, e.payload,
               e.observation_started_at, e.observation_ended_at,
               GREATEST(
                   0,
                   EXTRACT(EPOCH FROM (NOW() - COALESCE(e.observation_started_at, e.captured_at)))
               )::INTEGER,
               e.content_hash, e.redacted, i.environment, i.service,
               e.investigation_id
        FROM ops.ops_evidence e
        JOIN ops.ops_investigations i ON i.id = e.investigation_id
        WHERE e.investigation_id = ANY(%s)
          AND e.id = ANY(%s)
          AND i.environment = %s
          AND i.service = %s
          AND e.redacted IS TRUE
          AND e.query_version NOT LIKE 'legacy-%%'
          AND e.redaction_version NOT LIKE 'legacy-%%'
          AND e.captured_at >= NOW() - INTERVAL '90 days'
        ORDER BY e.captured_at DESC
    """
    try:
        async with await _connect() as conn:
            cursor = await conn.execute(
                evidence_query,
                (investigation_ids, evidence_ids, environment, service),
            )
            evidence_rows = await cursor.fetchall()
    except OpsConfigurationError:
        raise
    except psycopg.Error as exc:
        raise OpsReadinessError("historical comparable evidence lookup failed") from exc

    now = datetime.now(UTC)
    by_investigation_and_id: dict[tuple[str, str], EvidenceReference] = {}
    for row in evidence_rows:
        historical_id = str(row[17])
        try:
            reference = _evidence_from_row(
                row[:17],
                now=now,
                expected_scope=(environment, service),
                require_unexpired=False,
            )
        except EvidenceValidationError:
            continue
        by_investigation_and_id[(historical_id, reference.id)] = reference

    comparables: list[HistoricalComparable] = []
    comparable_evidence: list[EvidenceReference] = []
    returned_evidence: set[str] = set()
    for historical_id, incident_id, cited_ids, similarity in candidates:
        references = [by_investigation_and_id.get((historical_id, evidence_id)) for evidence_id in cited_ids]
        if any(reference is None for reference in references):
            continue
        concrete = [reference for reference in references if reference is not None]
        comparables.append(
            HistoricalComparable(
                incident_id=incident_id,
                similarity=similarity,
                reason=(
                    "Verified successful historical outcome selected by typed scope and canonical hybrid retrieval."
                ),
                evidence_ids=[reference.id for reference in concrete],
            )
        )
        for reference in concrete:
            if reference.id not in returned_evidence:
                comparable_evidence.append(reference)
                returned_evidence.add(reference.id)

    return comparables, comparable_evidence


def _validation_detail(exc: ValidationError) -> list[dict[str, Any]]:
    return [
        {
            "loc": list(error["loc"]),
            "msg": error["msg"],
            "type": error["type"],
        }
        for error in exc.errors(include_input=False)
    ]


async def _load_canonical_outcome(outcome: VerificationOutcome) -> CanonicalOutcome | None:
    """Resolve an outcome only through Dockhand's persisted independent verifier facts."""

    query = """
        SELECT v.id, v.investigation_id, v.proposal_id, v.success,
               v.rollback_executed, v.evidence_ids, v.started_at, v.completed_at,
               p.playbook_id, p.playbook_version, i.incident_id,
               o.verified, o.source, o.success, o.rollback_executed,
               o.confidence, o.evidence_ids, o.occurred_at
        FROM ops.ops_verification_runs v
        JOIN ops.ops_remediation_proposals p ON p.id = v.proposal_id
        JOIN ops.ops_investigations i ON i.id = v.investigation_id
        LEFT JOIN ops.ops_playbook_outcomes o
          ON o.verification_run_id = v.id
         AND o.outcome_kind = 'execution'
        WHERE v.id = %s
        ORDER BY o.occurred_at DESC NULLS LAST
        LIMIT 2
    """
    try:
        async with await _connect() as conn:
            cursor = await conn.execute(query, (outcome.verification_run_id,))
            rows = await cursor.fetchall()
    except OpsConfigurationError:
        raise
    except psycopg.Error as exc:
        raise OpsReadinessError("canonical verification lookup failed") from exc

    if not rows:
        return None
    if len(rows) != 1:
        raise EvidenceValidationError("verification run has ambiguous canonical outcomes")
    row = rows[0]
    (
        verification_run_id,
        investigation_id,
        proposal_id,
        verification_success,
        verification_rollback,
        verification_evidence_ids,
        started_at,
        completed_at,
        playbook_id,
        playbook_version,
        incident_id,
        verified,
        verifier_source,
        canonical_success,
        canonical_rollback,
        confidence,
        canonical_evidence_ids,
        occurred_at,
    ) = row

    expected_identity = (
        outcome.verification_run_id,
        outcome.investigation_id,
        outcome.proposal_id,
        outcome.playbook_id,
        outcome.playbook_version,
    )
    canonical_identity = (
        str(verification_run_id),
        str(investigation_id),
        str(proposal_id),
        str(playbook_id),
        str(playbook_version),
    )
    if canonical_identity != expected_identity:
        raise EvidenceValidationError("reported outcome identity does not match the canonical verifier record")
    if outcome.incident_id is not None and str(incident_id) != outcome.incident_id:
        raise EvidenceValidationError("reported incident does not match the canonical investigation")
    if started_at is None or completed_at is None:
        return None
    if verified is not True or verifier_source != "dockhand-independent-verifier" or occurred_at is None:
        return None
    if canonical_success is None or verification_success is None:
        return None
    if bool(canonical_success) != bool(verification_success) or bool(canonical_rollback) != bool(verification_rollback):
        raise EvidenceValidationError("verifier run and append-only outcome disagree")
    if bool(canonical_success) != outcome.success or bool(canonical_rollback) != outcome.rollback_executed:
        raise EvidenceValidationError("reported outcome does not match canonical verification")
    verification_started_at = _aware_utc(started_at, "verification.started_at")
    verification_completed_at = _aware_utc(completed_at, "verification.completed_at")
    outcome_occurred_at = _aware_utc(occurred_at, "outcome.occurred_at")
    if verification_completed_at < verification_started_at:
        raise EvidenceValidationError("canonical verification completed before it started")
    if outcome_occurred_at < verification_completed_at:
        raise EvidenceValidationError("canonical outcome predates verification completion")

    evidence_ids = tuple(
        dict.fromkeys(
            [
                *_string_ids(verification_evidence_ids, limit=100),
                *_string_ids(canonical_evidence_ids, limit=100),
            ]
        )
    )
    if set(evidence_ids) != set(outcome.evidence_ids):
        raise EvidenceValidationError("reported evidence does not match canonical verifier evidence")
    return CanonicalOutcome(
        success=bool(canonical_success),
        rollback_executed=bool(canonical_rollback),
        confidence=float(confidence),
        evidence_ids=evidence_ids,
        verified=True,
        verifier_source=str(verifier_source),
        verification_started_at=verification_started_at,
        verification_completed_at=verification_completed_at,
        outcome_occurred_at=outcome_occurred_at,
    )


def _phase_evidence(
    canonical: CanonicalOutcome,
    evidence: list[EvidenceReference],
) -> tuple[list[EvidenceReference], list[EvidenceReference]]:
    """Return independently recorded postcondition and rollback evidence.

    An outcome row is only a pointer. Learning admission requires the pointed-to
    evidence to prove that an independent verifier ran after execution and before
    the immutable outcome was appended.
    """

    postconditions: list[EvidenceReference] = []
    rollbacks: list[EvidenceReference] = []
    for item in evidence:
        if item.source != canonical.verifier_source:
            continue
        if item.observation_ended_at < canonical.verification_started_at:
            continue
        if item.observation_ended_at > canonical.outcome_occurred_at:
            continue
        marker = item.payload.get("success", item.payload.get("passed"))
        if not isinstance(marker, bool):
            continue
        if item.kind == "postcondition_verification" and marker is canonical.success:
            postconditions.append(item)
        if item.kind == "rollback_verification":
            rollbacks.append(item)
    return postconditions, rollbacks


def evaluate_canonical_outcome(
    canonical: CanonicalOutcome | None,
    evidence: list[EvidenceReference],
) -> OutcomeEvaluation:
    """Evaluate only canonical, independently verified, post-action evidence."""

    if canonical is None:
        disposition = "insufficient_evidence"
        summary = "No completed independent canonical verification outcome is available."
        confidence = 0.0
        eligible_candidate = False
        cited: list[str] = []
    else:
        known = {item.id for item in evidence}
        if known != set(canonical.evidence_ids):
            disposition = "insufficient_evidence"
            summary = "Canonical verification evidence is incomplete or contains an unbound record."
            confidence = 0.0
            eligible_candidate = False
            cited = []
        else:
            postconditions, rollbacks = _phase_evidence(canonical, evidence)
            cited = [item.id for item in [*postconditions, *rollbacks]]
            phase_evidence_complete = len(cited) == len(evidence)
            successful_rollback = any(
                item.payload.get("success", item.payload.get("passed")) is True for item in rollbacks
            )
            if (
                not phase_evidence_complete
                or not postconditions
                or (canonical.rollback_executed and not successful_rollback)
                or (canonical.success and bool(rollbacks))
            ):
                disposition = "insufficient_evidence"
                summary = "Canonical outcome lacks independent post-action verification evidence."
                confidence = 0.0
                eligible_candidate = False
            elif canonical.rollback_executed:
                disposition = "rollback"
                summary = "Independent canonical verification records a rollback; automatic eligibility is disabled."
                confidence = canonical.confidence
                eligible_candidate = False
            elif not canonical.success:
                disposition = "failed"
                summary = "Independent canonical verification records a failure; automatic eligibility is disabled."
                confidence = canonical.confidence
                eligible_candidate = False
            elif canonical.confidence < 0.85:
                disposition = "insufficient_evidence"
                summary = "Canonical verification confidence is below the learning-candidate threshold."
                confidence = canonical.confidence
                eligible_candidate = False
            else:
                disposition = "candidate"
                summary = (
                    "Independent canonical verification supports a learning candidate; promotion and automatic "
                    "eligibility remain separate Dockhand decisions."
                )
                confidence = canonical.confidence
                eligible_candidate = True

    return OutcomeEvaluation(
        eligible_candidate=eligible_candidate,
        disposition=disposition,
        learning_summary=summary,
        confidence=confidence,
        evidence_ids=cited,
        automatic_eligibility_disabled=True,
    )


async def _check_readiness() -> str:
    config = _reader_config()
    if not getenv("OPENAI_API_KEY", "").strip():
        raise OpsReadinessError("OPENAI_API_KEY is required for canonical hybrid retrieval")
    try:
        async with await _connect() as conn:
            cursor = await conn.execute(
                """
                SELECT current_user,
                       current_setting('transaction_read_only'),
                       to_regnamespace('ops') IS NOT NULL
                """
            )
            identity = await cursor.fetchone()
            if identity is None:
                raise OpsReadinessError("database identity check returned no result")

            current_user, transaction_read_only, schema_exists = identity
            if str(current_user) != config["OPS_DB_USER"]:
                raise OpsReadinessError("database current_user does not match OPS_DB_USER")
            if transaction_read_only != "on":
                raise OpsReadinessError("database transaction is not read-only")
            if schema_exists is not True:
                raise OpsReadinessError("required ops schema is absent")

            cursor = await conn.execute(
                """
                SELECT required.name, to_regclass(required.name)::text
                FROM unnest(%s::text[]) AS required(name)
                """,
                (list(_REQUIRED_TABLES),),
            )
            registrations = await cursor.fetchall()
            missing = [name for name, registered in registrations if registered is None]
            if missing:
                raise OpsReadinessError(f"required Ops tables are absent: {missing}")

            cursor = await conn.execute(
                """
                SELECT required.name,
                       has_table_privilege(current_user, required.name, 'SELECT'),
                       has_table_privilege(current_user, required.name, 'INSERT')
                        OR has_table_privilege(current_user, required.name, 'UPDATE')
                        OR has_table_privilege(current_user, required.name, 'DELETE')
                        OR has_table_privilege(current_user, required.name, 'TRUNCATE')
                FROM unnest(%s::text[]) AS required(name)
                """,
                (list(_REQUIRED_TABLES),),
            )
            privileges = await cursor.fetchall()
            unreadable = [name for name, can_select, _ in privileges if not can_select]
            writable = [name for name, _, can_write in privileges if can_write]
            if unreadable:
                raise OpsReadinessError(f"reader cannot select required Ops tables: {unreadable}")
            if writable:
                raise OpsReadinessError(f"reader has forbidden write privileges: {writable}")

            try:
                max_index_age = int(getenv("DASH_OPS_INDEX_MAX_AGE_SECONDS", "7200"))
            except ValueError as exc:
                raise OpsReadinessError("DASH_OPS_INDEX_MAX_AGE_SECONDS must be an integer") from exc
            if not 60 <= max_index_age <= 86_400:
                raise OpsReadinessError("retrieval index freshness limit is outside the safe range")
            cursor = await conn.execute(
                """
                SELECT status, model, indexed_at, document_count, embedded_count, error,
                       EXTRACT(EPOCH FROM (NOW() - indexed_at))::INTEGER AS age_seconds
                FROM ops.ops_retrieval_index_status
                WHERE indexer = %s
                """,
                (_RETRIEVAL_INDEXER,),
            )
            index_status = await cursor.fetchone()
            if index_status is None:
                raise OpsReadinessError("canonical hybrid retrieval index has no heartbeat")
            status, model, indexed_at, document_count, embedded_count, error, age_seconds = index_status
            if (
                status != "ready"
                or model != _RETRIEVAL_EMBEDDING_MODEL
                or indexed_at is None
                or error is not None
                or int(document_count) != int(embedded_count)
                or int(age_seconds) > max_index_age
            ):
                raise OpsReadinessError("canonical hybrid retrieval index is stale or incomplete")

            cursor = await conn.execute(
                """
                WITH canonical AS (
                    SELECT 'outcome'::text AS canonical_type, id, occurred_at AS source_updated_at
                    FROM ops.ops_playbook_outcomes
                    WHERE verified IS TRUE
                      AND occurred_at >= NOW() - INTERVAL '90 days'
                    UNION ALL
                    SELECT 'learning', id, updated_at
                    FROM ops.ops_learnings
                    WHERE lifecycle_status IN ('verified', 'promoted')
                    UNION ALL
                    SELECT 'validated_query', id, updated_at
                    FROM dash.validated_queries
                    WHERE validation_status = 'valid'
                )
                SELECT COUNT(*) AS canonical_count,
                       COUNT(*) FILTER (
                           WHERE EXISTS (
                               SELECT 1 FROM ops.ops_retrieval_documents document
                               WHERE document.canonical_type = canonical.canonical_type
                                 AND document.canonical_id = canonical.id
                                 AND document.embedding IS NOT NULL
                                 AND document.embedding_model = %s
                                 AND document.source_updated_at >= canonical.source_updated_at
                                 AND (document.fresh_until IS NULL OR document.fresh_until > NOW())
                           )
                       ) AS embedded_count
                FROM canonical
                """,
                (_RETRIEVAL_EMBEDDING_MODEL,),
            )
            coverage = await cursor.fetchone()
            if coverage is None or int(coverage[0]) != int(coverage[1]):
                raise OpsReadinessError("canonical hybrid retrieval index coverage is incomplete")
            if int(document_count) != int(coverage[0]):
                raise OpsReadinessError("retrieval heartbeat document count disagrees with canonical coverage")
    except (OpsConfigurationError, OpsReadinessError):
        raise
    except psycopg.Error as exc:
        raise OpsReadinessError("Ops reader database check failed") from exc

    return config["OPS_DB_USER"]


@router.get("/health/ready")
async def ready(request: Request) -> dict[str, str]:
    await _authenticate(request, b"")
    try:
        db_user = await _check_readiness()
    except (OpsConfigurationError, OpsReadinessError) as exc:
        logger.warning("Dash private Ops readiness failed: %s", exc)
        raise HTTPException(status_code=503, detail="Ops reader is not ready") from exc
    return {
        "status": "ready",
        "mode": "read-only-shadow",
        "model_version": _MODEL_VERSION,
        "db_user": db_user,
    }


@router.post("/ops/investigate", response_model=OpsInvestigationResult)
async def investigate(request: Request) -> OpsInvestigationResult:
    body = await request.body()
    await _authenticate(request, body)
    try:
        investigation = OpsInvestigationRequest.model_validate_json(body)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=_validation_detail(exc)) from exc

    try:
        evidence = await _load_evidence(
            investigation.investigation_id,
            investigation.evidence_ids,
            expected_scope=(investigation.environment, investigation.service),
        )
    except EvidenceValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (OpsConfigurationError, OpsReadinessError) as exc:
        logger.warning("Dash private Ops evidence lookup failed: %s", exc)
        raise HTTPException(status_code=503, detail="canonical evidence is unavailable") from exc

    diagnosis = diagnose_evidence(evidence)
    historical_comparables: list[HistoricalComparable] = []
    comparable_evidence: list[EvidenceReference] = []
    if diagnosis.root_cause:
        outcome_scores: dict[str, float] = {}
        try:
            retrieval_hits = await search_canonical_documents(
                _connect,
                query_text=f"{investigation.prompt} root cause {diagnosis.root_cause.value}",
                environment=investigation.environment,
                service=investigation.service,
                incident_type=diagnosis.root_cause.value,
                outcome_status="success",
            )
            outcome_scores = {item.canonical_id: item.score for item in retrieval_hits}
        except (OpsConfigurationError, psycopg.Error) as exc:
            logger.warning("Dash canonical hybrid retrieval failed closed: %s", type(exc).__name__)
        if outcome_scores:
            try:
                historical_comparables, comparable_evidence = await _load_historical_comparables(
                    investigation.investigation_id,
                    environment=investigation.environment,
                    service=investigation.service,
                    root_cause=diagnosis.root_cause,
                    outcome_scores=outcome_scores,
                    evidence_budget=100 - len(evidence),
                )
            except (OpsConfigurationError, OpsReadinessError) as exc:
                # Comparables are optional supporting context. The current diagnosis
                # remains fully grounded in already validated current evidence.
                logger.warning("Dash historical comparable lookup failed closed: %s", exc)

    return OpsInvestigationResult(
        investigation_id=investigation.investigation_id,
        summary=diagnosis.summary,
        summary_evidence_ids=diagnosis.summary_evidence_ids,
        evidence=[*evidence, *comparable_evidence],
        hypotheses=diagnosis.hypotheses,
        confidence=diagnosis.confidence,
        historical_comparables=historical_comparables,
        remediation_proposals=build_catalog_backed_proposals(investigation, evidence, diagnosis),
        model_version=_MODEL_VERSION,
        generated_at=datetime.now(UTC),
    )


@router.post("/ops/evaluate-outcome", response_model=OutcomeEvaluation)
async def evaluate_outcome(request: Request) -> OutcomeEvaluation:
    body = await request.body()
    await _authenticate(request, body)
    try:
        outcome = VerificationOutcome.model_validate_json(body)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=_validation_detail(exc)) from exc

    try:
        canonical = await _load_canonical_outcome(outcome)
        evidence = (
            await _load_evidence(
                outcome.investigation_id,
                list(canonical.evidence_ids),
                require_unexpired=False,
            )
            if canonical is not None
            else []
        )
    except EvidenceValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (OpsConfigurationError, OpsReadinessError) as exc:
        logger.warning("Dash private Ops outcome lookup failed: %s", exc)
        raise HTTPException(status_code=503, detail="canonical verification is unavailable") from exc

    return evaluate_canonical_outcome(canonical, evidence)
