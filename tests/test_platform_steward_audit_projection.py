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
    CLAIM_SUPPORT_STATES,
    PINNED_AUDIT_VECTOR_SHA256,
    PINNED_CANONICAL_COMMIT,
    PINNED_SOURCE_LOCK,
    PROJECTION_FIELDS,
    WARNING_CATEGORIES,
    AuditProjectionError,
    canonical_digest,
    canonical_json_bytes,
    load_json_strict,
    load_pinned_audit_projection,
    normalize_expected_projection,
    validate_audit_projection_document,
)

ROOT = Path(__file__).parents[1]
CONTRACT_ROOT = ROOT / "contracts" / "platform-steward"
VECTOR_PATH = CONTRACT_ROOT / "v1" / "test-vectors" / "audit-projection-records.json"


def _document() -> dict[str, Any]:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def _refresh_projection_digest(document: dict[str, Any]) -> None:
    document["expected_projection_digest"] = canonical_digest(document["expected_projection"])


def test_pinned_generated_mirror_loads_with_all_sections_and_no_authority() -> None:
    document = load_pinned_audit_projection(ROOT)
    projection = document["expected_projection"]

    assert document["authority_effect"] == "none"
    assert document["synthetic"] is True
    assert document["contains_private_identity"] is False
    assert document["expected_projection_digest"] == canonical_digest(projection)
    assert set(projection) == {name for name, _ in PROJECTION_FIELDS}
    assert len(projection) == 16


def test_public_vector_bytes_and_source_lock_are_exactly_pinned() -> None:
    raw_vector = VECTOR_PATH.read_bytes()
    source_lock = load_json_strict((CONTRACT_ROOT / "SOURCE.lock.json").read_bytes())

    assert "sha256:" + hashlib.sha256(raw_vector).hexdigest() == PINNED_AUDIT_VECTOR_SHA256
    assert source_lock == PINNED_SOURCE_LOCK
    assert source_lock["canonical_commit"] == PINNED_CANONICAL_COMMIT
    assert source_lock["generated_file_count"] == 19


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


def test_projection_digest_binds_normalized_content() -> None:
    document = _document()
    document["expected_projection"]["episodes"][0]["model"]["provider"] = "another-provider"

    with pytest.raises(AuditProjectionError, match="does not bind the normalized projection"):
        validate_audit_projection_document(document)

    _refresh_projection_digest(document)
    validated = validate_audit_projection_document(document)
    assert validated["expected_projection"]["episodes"][0]["model"]["provider"] == "another-provider"


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


def test_parser_and_canonicalizer_reject_ambiguous_json() -> None:
    with pytest.raises(AuditProjectionError, match="duplicate JSON object key"):
        load_json_strict(b'{"synthetic":true,"synthetic":false}')
    with pytest.raises(AuditProjectionError, match="floating-point"):
        canonical_json_bytes({"budget": 1.5})
    with pytest.raises(AuditProjectionError, match="safe range"):
        canonical_json_bytes({"budget": 9_007_199_254_740_992})


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

    with pytest.raises(AuditProjectionError, match="compiled closed source lock"):
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
