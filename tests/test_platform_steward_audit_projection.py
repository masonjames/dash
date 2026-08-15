"""Adversarial tests for Dash's read-only steward audit consumer."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from dash.platform_steward_audit_projection import (
    API_VERSION,
    CLAIM_SUPPORT_STATES,
    RECORD_HASH_DOMAIN,
    PINNED_AUDIT_VECTOR_SHA256,
    PINNED_CANONICAL_COMMIT,
    PINNED_CHRONICLE_BOUNDARY_VECTOR_SHA256,
    PINNED_SOURCE_FILES,
    PINNED_SOURCE_LOCK,
    PINNED_SOURCE_LOCK_SHA256,
    PROJECTION_FIELDS,
    WARNING_CATEGORIES,
    AuditProjectionError,
    canonical_digest,
    canonical_json_bytes,
    _derive_expected_projection,
    load_json_strict,
    load_pinned_audit_projection,
    normalize_expected_projection,
    validate_audit_projection_document,
)

ROOT = Path(__file__).parents[1]
CONTRACT_ROOT = ROOT / "contracts" / "platform-steward"
VECTOR_PATH = CONTRACT_ROOT / "v1" / "test-vectors" / "audit-projection-records.json"
BOUNDARY_VECTOR_PATH = CONTRACT_ROOT / "chronicle" / "v1" / "test-vectors" / "chronicle-boundary-vectors.json"
VALID_INVOCATION_PHASES: dict[str, tuple[str, str | None]] = {
    "succeeded": ("accepted", "accepted"),
    "rejected": ("rejected", None),
    "expired": ("accepted", "rejected"),
    "revoked": ("accepted", "rejected"),
}
INVALID_INVOCATION_PHASES = tuple(
    (disposition, entry_validation, return_validation)
    for disposition, required in VALID_INVOCATION_PHASES.items()
    for entry_validation in ("accepted", "rejected")
    for return_validation in ("accepted", "rejected", None)
    if (entry_validation, return_validation) != required
)


def _document() -> dict[str, Any]:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def _refresh_projection_digest(document: dict[str, Any]) -> None:
    document["expected_projection_digest"] = canonical_digest(document["expected_projection"])


def _record(document: dict[str, Any], kind: str, **matches: Any) -> dict[str, Any]:
    return next(
        record
        for record in document["records"]
        if record["kind"] == kind and all(record[field] == expected for field, expected in matches.items())
    )


def _seal_record(record: dict[str, Any]) -> None:
    unhashed = dict(record)
    unhashed.pop("record_hash", None)
    domain = RECORD_HASH_DOMAIN + API_VERSION.encode() + b"\x00" + record["kind"].encode() + b"\x00"
    record["record_hash"] = "sha256:" + hashlib.sha256(domain + canonical_json_bytes(unhashed)).hexdigest()


def _refresh_records_digest(document: dict[str, Any]) -> None:
    document["records_digest"] = canonical_digest(document["records"])


def _replace_hash_references(value: Any, replacements: dict[str, str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str) and item in replacements:
                value[key] = replacements[item]
            else:
                _replace_hash_references(item, replacements)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, str) and item in replacements:
                value[index] = replacements[item]
            else:
                _replace_hash_references(item, replacements)


def _reseal_document(document: dict[str, Any]) -> None:
    replacements: dict[str, str] = {}
    for record in document["records"]:
        previous_hash = record["record_hash"]
        _replace_hash_references(record, replacements)
        _seal_record(record)
        replacements[previous_hash] = record["record_hash"]
    document["records"].sort(key=lambda item: (item["recorded_at"], item["record_id"]))
    _refresh_records_digest(document)
    document["expected_projection"] = _derive_expected_projection(
        document["records"],
        as_of=document["as_of"],
    )
    _refresh_projection_digest(document)


def test_pinned_generated_mirror_loads_with_all_sections_and_no_authority() -> None:
    document = load_pinned_audit_projection(ROOT)
    projection = document["expected_projection"]

    assert document["authority_effect"] == "none"
    assert document["synthetic"] is True
    assert document["contains_private_identity"] is False
    assert document["expected_projection_digest"] == canonical_digest(projection)
    assert set(projection) == {name for name, _ in PROJECTION_FIELDS}
    assert len(projection) == 16
    derived = _derive_expected_projection(document["records"], as_of=document["as_of"])
    assert canonical_json_bytes(derived) == canonical_json_bytes(projection)


def test_public_vector_bytes_and_source_lock_are_exactly_pinned() -> None:
    raw_vector = VECTOR_PATH.read_bytes()
    raw_source_lock = (CONTRACT_ROOT / "SOURCE.lock.json").read_bytes()
    source_lock = load_json_strict(raw_source_lock)

    assert "sha256:" + hashlib.sha256(raw_vector).hexdigest() == PINNED_AUDIT_VECTOR_SHA256
    assert "sha256:" + hashlib.sha256(raw_source_lock).hexdigest() == PINNED_SOURCE_LOCK_SHA256
    assert source_lock == PINNED_SOURCE_LOCK
    assert source_lock["canonical_commit"] == PINNED_CANONICAL_COMMIT
    assert source_lock["generated_file_count"] == 25
    assert source_lock["source_lock_version"] == 2
    assert source_lock["private_identity_included"] is False
    assert set(source_lock["files"]) == set(PINNED_SOURCE_FILES)


def test_canonical_boundary_vector_binds_source_and_record_evidence() -> None:
    raw_boundary = BOUNDARY_VECTOR_PATH.read_bytes()
    boundary = load_json_strict(raw_boundary)

    assert "sha256:" + hashlib.sha256(raw_boundary).hexdigest() == PINNED_CHRONICLE_BOUNDARY_VECTOR_SHA256
    assert isinstance(boundary, dict)
    for envelope_name in ("append_envelope", "handoff_append_envelope"):
        envelope = boundary[envelope_name]
        assert isinstance(envelope, dict)
        evidence_hashes = envelope["evidence_hashes"]
        assert isinstance(evidence_hashes, list)
        assert envelope["source_attestation_hash"] in evidence_hashes
        for record in envelope["records"]:
            assert isinstance(record, dict)
            canonical_record = load_json_strict(record["canonical_record_json"].encode("utf-8"))
            assert isinstance(canonical_record, dict)
            cited_hashes: set[str] = set()

            def collect_evidence(value: object) -> None:
                if isinstance(value, dict):
                    for key, item in value.items():
                        if key in {
                            "evidence_hash",
                            "selection_evidence_hash",
                            "signing_evidence_hash",
                        } and isinstance(item, str):
                            cited_hashes.add(item)
                        elif key in {
                            "evidence_preconditions",
                            "input_evidence_hashes",
                            "result_evidence_hashes",
                        } and isinstance(item, list):
                            cited_hashes.update(digest for digest in item if isinstance(digest, str))
                        else:
                            collect_evidence(item)
                elif isinstance(value, list):
                    for item in value:
                        collect_evidence(item)

            collect_evidence(canonical_record)
            assert cited_hashes <= set(evidence_hashes)


def test_normalizer_returns_a_detached_projection() -> None:
    original = _document()["expected_projection"]
    normalized = normalize_expected_projection(original)

    normalized["episodes"][0]["state"] = "completed"

    assert original["episodes"][0]["state"] == "handed_off"


def test_vector_proves_identity_continuity_across_model_providers_and_handoff() -> None:
    projection = load_pinned_audit_projection(ROOT)["expected_projection"]
    episodes = projection["episodes"]
    handoff = projection["handoffs"][0]
    leases = projection["reasoning_leases"]

    assert {episode["identity_id"] for episode in episodes} == {"platform-steward"}
    assert {episode["model"]["provider"] for episode in episodes} == {
        "example-provider-a",
        "example-provider-b",
    }
    assert handoff["source_episode_id"] == episodes[0]["episode_id"]
    assert handoff["target_episode_id"] == episodes[1]["episode_id"]
    assert [(lease["generation"], lease["expected_previous_generation"]) for lease in leases] == [(1, 0), (2, 1)]


def test_vector_vocabulary_is_closed_and_complete() -> None:
    vocabulary = load_pinned_audit_projection(ROOT)["expected_projection"]["vocabulary"]

    assert vocabulary == {
        "claim_support_states": list(CLAIM_SUPPORT_STATES),
        "record_selection": "latest-revision-per-logical-id-then-record-hash",
        "time_basis": "fixed-as-of-inclusive-utc",
        "warning_categories": list(WARNING_CATEGORIES),
    }


def test_every_projection_section_rejects_unknown_fields() -> None:
    projection = _document()["expected_projection"]

    for section, value in projection.items():
        candidate = copy.deepcopy(projection)
        if isinstance(value, list):
            assert value, f"fixture section {section} must exercise its item contract"
            candidate[section][0]["future_field"] = "not-v1"
        else:
            candidate[section]["future_field"] = "not-v1"
        with pytest.raises(AuditProjectionError, match="unknown fields"):
            normalize_expected_projection(candidate)


def test_projection_and_envelope_reject_unknown_or_missing_fields() -> None:
    document = _document()
    document["future_contract"] = "v2"
    with pytest.raises(AuditProjectionError, match="unknown fields"):
        validate_audit_projection_document(document)

    projection = _document()["expected_projection"]
    del projection["warnings"]
    with pytest.raises(AuditProjectionError, match="missing fields"):
        normalize_expected_projection(projection)


@pytest.mark.parametrize(
    ("section", "field", "invalid"),
    [
        ("attested_embodiments", "embodiment", "browser-agent"),
        ("capability_candidates", "status", "installed"),
        ("capability_evaluations", "outcome", "confident"),
        ("capability_gaps", "status", "auto-closed"),
        ("capability_invocations", "disposition", "authorized"),
        ("capability_leases", "mode", "execute"),
        ("capability_promotions", "status", "deployed"),
        ("capability_revocations", "reactive_profile_state", "rolled-back"),
        ("claim_support_states", "support_state", "trusted"),
        ("episodes", "state", "merged"),
        ("foundry_admissions", "state", "running"),
        ("handoffs", "state", "claimed"),
        ("identity_timeline", "status", "immortal"),
        ("reasoning_leases", "state", "shared"),
        ("warnings", "category", "informational"),
    ],
)
def test_projection_rejects_unknown_enum_values(section: str, field: str, invalid: str) -> None:
    projection = _document()["expected_projection"]
    projection[section][0][field] = invalid

    with pytest.raises(AuditProjectionError, match="unsupported value|expected exact value"):
        normalize_expected_projection(projection)


@pytest.mark.parametrize(
    ("disposition", "entry_validation", "return_validation"),
    tuple(
        (disposition, entry_validation, return_validation)
        for disposition, (entry_validation, return_validation) in VALID_INVOCATION_PHASES.items()
    ),
)
def test_capability_invocation_accepts_only_closed_phase_mapping(
    disposition: str,
    entry_validation: str,
    return_validation: str | None,
) -> None:
    projection = _document()["expected_projection"]
    invocation = projection["capability_invocations"][0]
    invocation["disposition"] = disposition
    invocation["entry_validation"] = entry_validation
    invocation["return_validation"] = return_validation

    normalized = normalize_expected_projection(projection)
    assert normalized["capability_invocations"][0] == invocation


@pytest.mark.parametrize(
    ("disposition", "entry_validation", "return_validation"),
    INVALID_INVOCATION_PHASES,
)
def test_capability_invocation_rejects_every_impossible_phase_combination(
    disposition: str,
    entry_validation: str,
    return_validation: str | None,
) -> None:
    assert len(INVALID_INVOCATION_PHASES) == 20
    projection = _document()["expected_projection"]
    invocation = projection["capability_invocations"][0]
    invocation["disposition"] = disposition
    invocation["entry_validation"] = entry_validation
    invocation["return_validation"] = return_validation

    with pytest.raises(AuditProjectionError, match=rf"{disposition} invocation requires"):
        normalize_expected_projection(projection)


def test_projection_digest_binds_normalized_content() -> None:
    document = _document()
    document["expected_projection"]["episodes"][0]["model"]["provider"] = "another-provider"

    with pytest.raises(AuditProjectionError, match="does not bind the normalized projection"):
        validate_audit_projection_document(document)

    _refresh_projection_digest(document)
    with pytest.raises(AuditProjectionError, match="does not byte-match the deterministic projection"):
        validate_audit_projection_document(document)


def test_raw_records_are_validated_against_their_exact_closed_schema_before_hash_trust() -> None:
    document = _document()
    constitution = _record(document, "AgentConstitution", constitution_id="platform-steward-constitution")
    constitution["future_field"] = "resealed-but-not-v1"
    _seal_record(constitution)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="closed AgentConstitution schema violation"):
        validate_audit_projection_document(document)


def test_resealed_empty_projection_cannot_hide_the_validated_record_graph() -> None:
    document = _document()
    for section, value in document["expected_projection"].items():
        if isinstance(value, list):
            document["expected_projection"][section] = []
    _refresh_projection_digest(document)

    with pytest.raises(AuditProjectionError, match="does not byte-match the deterministic projection"):
        validate_audit_projection_document(document)


def test_resealed_missing_derived_warnings_are_rejected() -> None:
    document = _document()
    assert document["expected_projection"]["warnings"]
    document["expected_projection"]["warnings"] = []
    _refresh_projection_digest(document)

    with pytest.raises(AuditProjectionError, match="does not byte-match the deterministic projection"):
        validate_audit_projection_document(document)


def test_record_hash_binds_each_raw_record() -> None:
    document = _document()
    document["records"][0]["recorded_at"] = "2026-08-14T10:00:01Z"

    with pytest.raises(AuditProjectionError, match="does not match canonical record content"):
        validate_audit_projection_document(document)


def test_records_digest_binds_record_order() -> None:
    document = _document()
    document["records"][0], document["records"][1] = document["records"][1], document["records"][0]

    with pytest.raises(AuditProjectionError, match="does not bind the record array"):
        validate_audit_projection_document(document)


def test_accepted_handoff_must_target_its_exact_child_episode() -> None:
    document = _document()
    handoff = _record(document, "AgentHandoff", handoff_revision=2)
    handoff["accepted_episode_id"] = handoff["source_episode_id"]
    _seal_record(handoff)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="accepted handoff"):
        validate_audit_projection_document(document)


def test_handoff_cannot_reference_a_gap_materialized_after_issuance() -> None:
    document = _document()
    for handoff in (record for record in document["records"] if record["kind"] == "AgentHandoff"):
        handoff["issued_at"] = "2026-08-14T10:29:00Z"
    source_terminal = _record(document, "AgentEpisode", episode_revision=2)
    source_terminal["ended_at"] = "2026-08-14T10:29:00Z"
    _reseal_document(document)

    with pytest.raises(AuditProjectionError, match="new handoff must be pending"):
        validate_audit_projection_document(document)


def test_handed_off_episode_end_must_equal_pending_handoff_issuance() -> None:
    document = _document()
    source_terminal = _record(document, "AgentEpisode", episode_revision=2)
    source_terminal["ended_at"] = "2026-08-14T10:44:00Z"
    _reseal_document(document)

    with pytest.raises(AuditProjectionError, match="handed-off episode end"):
        validate_audit_projection_document(document)


def test_late_terminal_episode_cannot_be_reordered_after_authority_expiry() -> None:
    document = _document()
    source_terminal = _record(document, "AgentEpisode", episode_revision=2)
    source_terminal["recorded_at"] = "2026-08-14T11:05:00Z"
    accepted_handoff = _record(document, "AgentHandoff", handoff_revision=2)
    accepted_handoff["recorded_at"] = "2026-08-14T11:06:00Z"
    _reseal_document(document)

    with pytest.raises(
        AuditProjectionError,
        match="handoff reasoning-lease release|episode terminal revision",
    ):
        validate_audit_projection_document(document)


def test_capability_lease_cannot_predate_approved_promotion_materialization() -> None:
    document = _document()
    lease = _record(document, "CapabilityLease")
    lease["issued_at"] = "2026-08-14T11:59:00Z"
    _reseal_document(document)

    with pytest.raises(AuditProjectionError, match="signed-release and overlay binding"):
        validate_audit_projection_document(document)


@pytest.mark.parametrize(
    ("kind", "matches", "field", "invalid", "message"),
    [
        (
            "CapabilityCandidate",
            {},
            "closed_gap_hash",
            "sha256:" + "a" * 64,
            "present CapabilityGap",
        ),
        (
            "CapabilityCandidate",
            {},
            "foundry_admission_hash",
            "sha256:" + "b" * 64,
            "present FoundryAdmissionAttestation",
        ),
        (
            "CapabilityEvaluation",
            {},
            "candidate_hash",
            "sha256:" + "c" * 64,
            "present CapabilityCandidate",
        ),
        (
            "CapabilityEvaluation",
            {},
            "evaluator_attestation_hash",
            "sha256:" + "d" * 64,
            "present RuntimeAttestation",
        ),
        (
            "CapabilityPromotion",
            {"promotion_revision": 1},
            "evaluation_hash",
            "sha256:" + "e" * 64,
            "present CapabilityEvaluation",
        ),
        (
            "CapabilityInvocation",
            {"call_index": 1},
            "capability_id",
            "unrelated-capability",
            "unrelated to its exact lease",
        ),
    ],
)
def test_resealed_records_cannot_break_required_cross_record_links(
    kind: str,
    matches: dict[str, Any],
    field: str,
    invalid: Any,
    message: str,
) -> None:
    document = _document()
    record = _record(document, kind, **matches)
    record[field] = invalid
    _seal_record(record)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match=message):
        validate_audit_projection_document(document)


def test_revocation_release_must_match_a_present_capability_lease() -> None:
    document = _document()
    revocation = _record(document, "CapabilityRevocation")
    revocation["release"]["capability_id"] = "unrelated-capability"
    _seal_record(revocation)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="revocation is unrelated"):
        validate_audit_projection_document(document)


def test_review_requested_promotion_cannot_retain_signed_release_or_overlay() -> None:
    document = _document()
    promotion = _record(document, "CapabilityPromotion", promotion_revision=2)
    promotion["status"] = "review_requested"
    promotion["human_review"].update(
        {
            "decision": "pending",
            "evidence_hash": None,
            "provenance_state": "pending-unsigned",
            "reviewed_at": None,
            "reviewer_key_id": None,
            "signature_bundle_hash": None,
        }
    )
    assert promotion["signed_release"] is not None
    assert promotion["overlay_selection"] is not None
    _seal_record(promotion)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="promotion revision|must remain unsigned"):
        validate_audit_projection_document(document)


def test_duplicate_generation_one_reasoning_lease_owner_fails_cas() -> None:
    document = _document()
    original = _record(document, "ReasoningLease", lease_revision=1, generation=1)
    duplicate = copy.deepcopy(original)
    duplicate.update(
        {
            "record_id": "10000000-0000-4000-8000-000000000303",
            "lease_id": "10000000-0000-4000-8000-000000004003",
            "nonce": "10000000-0000-4000-8000-000000003303",
            "owner_episode_id": "10000000-0000-4000-8000-000000005003",
        }
    )
    _seal_record(duplicate)
    document["records"].append(duplicate)
    document["records"].sort(key=lambda item: (item["recorded_at"], item["record_id"]))
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="compare-and-swap ownership"):
        validate_audit_projection_document(document)


def test_runtime_attestation_issued_after_as_of_is_rejected_even_when_resealed() -> None:
    document = _document()
    attestation = _record(document, "RuntimeAttestation", embodiment="server-sentinel")
    attestation["issued_at"] = "2026-08-14T13:00:00Z"
    _seal_record(attestation)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="operational timestamp is after the fixed as_of"):
        validate_audit_projection_document(document)


@pytest.mark.parametrize(
    ("kind", "matches", "mutation"),
    [
        (
            "AgentConstitution",
            {"constitution_id": "platform-steward-constitution"},
            lambda record: record.__setitem__("effective_at", "2026-08-14T13:00:00Z"),
        ),
        (
            "KnowledgeClaim",
            {"claim_revision": 1},
            lambda record: record["evidence"][0].__setitem__("observed_at", "2026-08-14T13:00:00Z"),
        ),
        (
            "CapabilityInvocation",
            {"call_index": 1},
            lambda record: record["provider_validations"][0].__setitem__("validated_at", "2026-08-14T13:00:00Z"),
        ),
    ],
)
def test_all_operational_timestamps_are_bounded_by_as_of(
    kind: str,
    matches: dict[str, Any],
    mutation: Any,
) -> None:
    document = _document()
    record = _record(document, kind, **matches)
    mutation(record)
    _seal_record(record)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="operational timestamp is after the fixed as_of"):
        validate_audit_projection_document(document)


def test_platform_steward_cannot_be_resealed_as_a_dynamic_foundry_embodiment() -> None:
    document = _document()
    foundry = _record(document, "RuntimeAttestation", embodiment="foundry-replay")
    steward_descriptor = _record(document, "AgentIdentityDescriptor", identity_id="platform-steward")
    steward_revision = _record(
        document,
        "AgentIdentityRevision",
        identity={
            "identity_epoch": 1,
            "identity_id": "platform-steward",
            "identity_revision": 1,
        },
    )
    foundry["identity"] = copy.deepcopy(steward_revision["identity"])
    foundry["identity_descriptor_hash"] = steward_descriptor["record_hash"]
    foundry["identity_revision_hash"] = steward_revision["record_hash"]
    foundry["constitution_hash"] = steward_revision["constitution_hash"]
    assert foundry["dynamic_cordis_allowed"] is True
    _seal_record(foundry)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="runtime attestation identity, embodiment"):
        validate_audit_projection_document(document)


def test_provider_revalidates_the_exact_lease_and_attestation_on_every_call() -> None:
    document = _document()
    invocation = _record(document, "CapabilityInvocation", call_index=1)
    invocation["provider_validations"][1]["lease_hash"] = "sha256:" + "f" * 64
    _seal_record(invocation)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="revalidate the exact lease"):
        validate_audit_projection_document(document)


def test_capability_invocation_provider_must_match_the_leased_audience() -> None:
    document = _document()
    invocation = _record(document, "CapabilityInvocation", call_index=1)
    invocation["provider_id"] = "unrelated-provider"
    _seal_record(invocation)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="unrelated to its exact lease"):
        validate_audit_projection_document(document)


def test_capability_invocation_cannot_predate_its_lease() -> None:
    document = _document()
    invocation = _record(document, "CapabilityInvocation", call_index=1)
    invocation["started_at"] = "2026-08-14T12:04:00Z"
    invocation["completed_at"] = "2026-08-14T12:04:30Z"
    invocation["provider_validations"][0]["validated_at"] = invocation["started_at"]
    invocation["provider_validations"][1]["validated_at"] = invocation["completed_at"]
    _seal_record(invocation)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="unrelated to its exact lease|chronology or budget"):
        validate_audit_projection_document(document)


def test_successful_invocation_after_effective_revocation_is_rejected() -> None:
    document = _document()
    invocation = _record(document, "CapabilityInvocation", call_index=2)
    invocation["disposition"] = "succeeded"
    invocation["provider_validations"] = [
        {
            **invocation["provider_validations"][0],
            "result": "accepted",
        },
        {
            **invocation["provider_validations"][0],
            "phase": "before_return",
            "result": "accepted",
        },
    ]
    invocation["result_hash"] = "sha256:" + "a" * 64
    _seal_record(invocation)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="chronology or budget"):
        validate_audit_projection_document(document)


def test_revoked_invocation_cannot_claim_entry_acceptance_after_revocation() -> None:
    document = _document()
    invocation = _record(document, "CapabilityInvocation", call_index=2)
    invocation["disposition"] = "revoked"
    invocation["provider_validations"] = [
        {
            **invocation["provider_validations"][0],
            "result": "accepted",
        },
        {
            **invocation["provider_validations"][0],
            "phase": "before_return",
        },
    ]
    _seal_record(invocation)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="chronology or budget"):
        validate_audit_projection_document(document)


def test_capability_invocation_call_index_cannot_be_replayed() -> None:
    document = _document()
    invocation = _record(document, "CapabilityInvocation", call_index=2)
    invocation["call_index"] = 1
    _seal_record(invocation)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="call index was replayed"):
        validate_audit_projection_document(document)


def test_capability_revocation_cannot_be_effective_before_lease_issuance() -> None:
    document = _document()
    revocation = _record(document, "CapabilityRevocation")
    revocation["effective_at"] = "2026-08-14T12:04:00Z"
    _seal_record(revocation)
    _refresh_records_digest(document)

    with pytest.raises(AuditProjectionError, match="embedded evidence|revocation is unrelated"):
        validate_audit_projection_document(document)


def test_parser_and_canonicalizer_reject_ambiguous_json() -> None:
    with pytest.raises(AuditProjectionError, match="duplicate JSON object key"):
        load_json_strict(b'{"synthetic":true,"synthetic":false}')
    with pytest.raises(AuditProjectionError, match="floating-point"):
        canonical_json_bytes({"budget": 1.5})
    with pytest.raises(AuditProjectionError, match="safe range"):
        canonical_json_bytes({"budget": 9_007_199_254_740_992})


@pytest.mark.parametrize(
    "value",
    [
        {"value": "\ud800"},
        {"\udfff": "value"},
    ],
)
def test_canonicalizer_rejects_unpaired_surrogates_in_strings_and_keys(value: dict[str, str]) -> None:
    with pytest.raises(AuditProjectionError, match="unpaired Unicode surrogate"):
        canonical_json_bytes(value)


@pytest.mark.parametrize("payload", [b'{"value":"\\ud800"}', b'{"\\udfff":"value"}'])
def test_strict_parser_rejects_escaped_unpaired_surrogates(payload: bytes) -> None:
    with pytest.raises(AuditProjectionError, match="unpaired Unicode surrogate"):
        load_json_strict(payload)


def test_invalid_calendar_timestamp_is_rejected() -> None:
    document = _document()
    document["as_of"] = "2026-02-31T12:30:00Z"

    with pytest.raises(AuditProjectionError, match="real calendar instant"):
        validate_audit_projection_document(document)


def test_dynamic_cordis_is_rejected_outside_foundry() -> None:
    projection = _document()["expected_projection"]
    sentinel = next(item for item in projection["attested_embodiments"] if item["embodiment"] == "server-sentinel")
    sentinel["dynamic_cordis_allowed"] = True

    with pytest.raises(AuditProjectionError, match="only valid in the isolated Foundry"):
        normalize_expected_projection(projection)


def test_foundry_denials_and_isolation_gate_set_are_exact() -> None:
    projection = _document()["expected_projection"]
    projection["foundry_admissions"][0]["denied_capabilities"].pop()
    with pytest.raises(AuditProjectionError, match="every denied capability"):
        normalize_expected_projection(projection)

    projection = _document()["expected_projection"]
    projection["foundry_admissions"][0]["isolation_checks"].pop()
    with pytest.raises(AuditProjectionError, match="every Foundry isolation check"):
        normalize_expected_projection(projection)


def test_foundry_projection_cannot_claim_production_or_credentials() -> None:
    for field in ("production_network_access", "credential_access"):
        projection = _document()["expected_projection"]
        projection["foundry_admissions"][0][field] = True
        with pytest.raises(AuditProjectionError, match="expected exact value False"):
            normalize_expected_projection(projection)


def test_failed_evaluation_can_only_produce_investigation_artifact() -> None:
    projection = _document()["expected_projection"]
    evaluation = projection["capability_evaluations"][0]
    evaluation["outcome"] = "failed"
    evaluation["terminal_artifact"] = "draft_promotion_artifact"

    with pytest.raises(AuditProjectionError, match="failed evaluation requires investigation_artifact"):
        normalize_expected_projection(projection)


def test_promotion_never_conveys_publish_merge_install_or_deploy_authority() -> None:
    for field in ("may_publish", "may_merge", "may_install", "may_deploy"):
        projection = _document()["expected_projection"]
        projection["capability_promotions"][0][field] = True
        with pytest.raises(AuditProjectionError, match="expected exact value False"):
            normalize_expected_projection(projection)


def test_approved_release_requires_human_signature_and_overlay_binding() -> None:
    for field in ("signed_release_present", "overlay_selection_present"):
        projection = _document()["expected_projection"]
        projection["capability_promotions"][0][field] = False
        with pytest.raises(AuditProjectionError, match="exact human approval, signed release, and overlay selection"):
            normalize_expected_projection(projection)


def test_revocation_requires_provider_rejection_and_deactivated_profile() -> None:
    projection = _document()["expected_projection"]
    projection["capability_revocations"][0]["provider_rejection_required"] = False
    with pytest.raises(AuditProjectionError, match="expected exact value True"):
        normalize_expected_projection(projection)


def test_warning_code_cannot_be_relabelled() -> None:
    projection = _document()["expected_projection"]
    projection["warnings"][0]["category"] = "pending"

    with pytest.raises(AuditProjectionError, match="do not match its closed code"):
        normalize_expected_projection(projection)


def test_tampered_source_lock_fails_before_projection_consumption(tmp_path: Path) -> None:
    checkout = tmp_path / "dash"
    shutil.copytree(CONTRACT_ROOT, checkout / "contracts" / "platform-steward")
    lock_path = checkout / "contracts" / "platform-steward" / "SOURCE.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["canonical_commit"] = "0" * 40
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    with pytest.raises(AuditProjectionError, match="pinned contract digest mismatch"):
        load_pinned_audit_projection(checkout)


def test_tampered_or_extra_generated_file_fails_bundle_parity(tmp_path: Path) -> None:
    checkout = tmp_path / "dash"
    copied = checkout / "contracts" / "platform-steward"
    shutil.copytree(CONTRACT_ROOT, copied)
    schema = copied / "v1" / "agent-episode.schema.json"
    schema.write_bytes(schema.read_bytes() + b"\n")

    with pytest.raises(AuditProjectionError, match="digest mismatch"):
        load_pinned_audit_projection(checkout)

    shutil.rmtree(copied)
    shutil.copytree(CONTRACT_ROOT, copied)
    (copied / "v1" / "future.schema.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(AuditProjectionError, match="missing or unexpected files"):
        load_pinned_audit_projection(checkout)


def test_consumer_module_has_no_runtime_writer_or_network_surface() -> None:
    source = (ROOT / "dash" / "platform_steward_audit_projection.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert imported_roots.isdisjoint(
        {
            "subprocess",
            "socket",
            "requests",
            "httpx",
            "psycopg",
            "sqlalchemy",
            "docker",
            "paramiko",
        }
    )
    for forbidden in (
        "os.environ",
        "write_text(",
        "write_bytes(",
        'open("w',
    ):
        assert forbidden not in source
