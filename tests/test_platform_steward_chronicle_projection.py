"""Adversarial tests for the signed, read-only Chronicle projection boundary."""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
import re
from dataclasses import FrozenInstanceError, dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import pytest

import dash.platform_steward_chronicle_projection as consumer_module
from dash.platform_steward_audit_projection import (
    API_VERSION,
    RECORD_HASH_DOMAIN,
    canonical_digest,
    canonical_json_bytes,
    load_json_strict,
)
from dash.platform_steward_chronicle_projection import (
    SNAPSHOT_DIGEST_DOMAIN,
    AuthenticatedChronicleProjectionSnapshot,
    ChronicleProjectionAuthenticationClaim,
    ChronicleProjectionDerivationVerifier,
    ChronicleProjectionRevocationAuthority,
    ChronicleProjectionSequenceChainState,
    ChronicleProjectionSequenceClaim,
    ChronicleProjectionSnapshotAuthenticator,
    ChronicleProjectionSnapshotDependencies,
    ChronicleProjectionSourceAuthority,
    ChronicleProjectionTrustedMonotonicClock,
    load_authenticated_chronicle_projection_snapshot,
    verify_exact_projection_from_canonical_records,
)

ROOT = Path(__file__).parents[1]
CONTRACT_ROOT = ROOT / "contracts" / "platform-steward"
BOUNDARY_VECTOR_PATH = CONTRACT_ROOT / "chronicle" / "v1" / "test-vectors" / "chronicle-boundary-vectors.json"
AUDIT_VECTOR_PATH = CONTRACT_ROOT / "v1" / "test-vectors" / "audit-projection-records.json"
BOUNDARY_VECTOR = cast(dict[str, Any], load_json_strict(BOUNDARY_VECTOR_PATH.read_bytes()))
AUDIT_VECTOR = cast(dict[str, Any], load_json_strict(AUDIT_VECTOR_PATH.read_bytes()))
GENERATED_SNAPSHOT = cast(dict[str, Any], BOUNDARY_VECTOR["projection_snapshots"]["dash-ops-reader"])
CANONICAL_RECORDS = tuple(canonical_json_bytes(record) for record in AUDIT_VECTOR["records"])
VECTOR_SNAPSHOT_DIGEST = "sha256:8c063b18f00a929e7ff4a0c3445b5f3e641f96cc9055a8cf2973f299acc3553d"
VECTOR_PROJECTION_DIGEST = "sha256:c687463c423272e74b33de81ec9f3afb052c7e9464d2c954ac328217801b1693"
VECTOR_RECORDS_DIGEST = "sha256:9c6865de2b32f3e3a0616ae40ab54a0bdb70f2211d7884802301df154e4e312b"
VECTOR_SIGNATURE_BUNDLE = "sha256:" + "d" * 64
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _snapshot() -> dict[str, Any]:
    return copy.deepcopy(GENERATED_SNAPSHOT)


def _raw_snapshot(snapshot: dict[str, Any]) -> bytes:
    return canonical_json_bytes(snapshot)


def _seal_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    sealed = copy.deepcopy(snapshot)
    digest_document = {
        key: value for key, value in sealed.items() if key not in {"snapshot_digest", "signature_bundle_hash"}
    }
    sealed["snapshot_digest"] = (
        "sha256:" + hashlib.sha256(SNAPSHOT_DIGEST_DOMAIN + canonical_json_bytes(digest_document)).hexdigest()
    )
    return sealed


def _seal_record(record: dict[str, Any]) -> None:
    unhashed = dict(record)
    unhashed.pop("record_hash", None)
    domain = RECORD_HASH_DOMAIN + API_VERSION.encode() + b"\x00" + record["kind"].encode() + b"\x00"
    record["record_hash"] = "sha256:" + hashlib.sha256(domain + canonical_json_bytes(unhashed)).hexdigest()


def _next_snapshot(previous: dict[str, Any], serial: int, **overrides: Any) -> dict[str, Any]:
    candidate = _snapshot()
    candidate.update(
        {
            "snapshot_id": f"30000000-0000-4000-8000-{serial:012d}",
            "snapshot_nonce": f"40000000-0000-4000-8000-{serial:012d}",
            "snapshot_sequence": previous["snapshot_sequence"] + 1,
            "previous_snapshot_hash": previous["snapshot_digest"],
            "generated_at": "2026-08-14T12:32:00Z",
            "expires_at": "2026-08-14T12:36:00Z",
        }
    )
    candidate.update(overrides)
    return _seal_snapshot(candidate)


def _decision(value: object, default: object) -> object:
    selected = default if value is None else value
    if isinstance(selected, Exception):
        raise selected
    return selected


class AuthenticatorStub(ChronicleProjectionSnapshotAuthenticator):
    def __init__(self, *, results: dict[str, object] | None = None) -> None:
        self.results = results or {}
        self.phases: list[str] = []
        self.claims: list[ChronicleProjectionAuthenticationClaim] = []

    def authenticate_snapshot(self, claim: ChronicleProjectionAuthenticationClaim, phase: str) -> object:
        self.phases.append(phase)
        self.claims.append(claim)
        default = (
            claim.audience == "dash-ops-reader"
            and claim.signature_bundle_hash == VECTOR_SIGNATURE_BUNDLE
            and claim.producer_key_id == "dockhand-chronicle-projector-key-v1"
        )
        return _decision(self.results.get(phase), default)


class SourceAuthorityStub(ChronicleProjectionSourceAuthority):
    def __init__(self, *, results: dict[str, object] | None = None) -> None:
        self.results = results or {}
        self.phases: list[str] = []

    def confirm_source_authority(self, claim: ChronicleProjectionAuthenticationClaim, phase: str) -> object:
        self.phases.append(phase)
        default = (
            claim.source_repository == "https://github.com/masonjames/platform-infra"
            and claim.source_commit == "c02dbcdfacc6421c10eb863016d8aff346cef436"
            and claim.source_contract_manifest_digest
            == "sha256:d685f2fd4af55f7222f3c1205b55c4bf7c20c85d0cb3038a29fa0adf5b3211ee"
        )
        return _decision(self.results.get(phase), default)


class RevocationAuthorityStub(ChronicleProjectionRevocationAuthority):
    def __init__(self, *, results: dict[str, object] | None = None) -> None:
        self.results = results or {}
        self.phases: list[str] = []

    def confirm_not_revoked(self, claim: ChronicleProjectionAuthenticationClaim, phase: str) -> object:
        self.phases.append(phase)
        default = claim.revocation_identity == "chronicle-projection-release-v1"
        return _decision(self.results.get(phase), default)


class ClockStub(ChronicleProjectionTrustedMonotonicClock):
    def __init__(self, times: list[object] | None = None) -> None:
        self.times = times or ["2026-08-14T12:31:00Z", "2026-08-14T12:31:00Z"]
        self.reads = 0

    def read_trusted_time(self) -> str:
        selected = self.times[min(self.reads, len(self.times) - 1)]
        self.reads += 1
        if isinstance(selected, Exception):
            raise selected
        return cast(str, selected)


class DerivationVerifierStub(ChronicleProjectionDerivationVerifier):
    def __init__(
        self,
        *,
        records: tuple[bytes, ...] = CANONICAL_RECORDS,
        results: dict[str, object] | None = None,
    ) -> None:
        self.records = records
        self.results = results or {}
        self.phases: list[str] = []
        self.trusted_times: list[str] = []
        self.snapshots: list[Any] = []
        self.projections: list[Any] = []

    def verify_exact_projection(
        self,
        snapshot: Any,
        projection: Any,
        phase: str,
        trusted_time: str,
    ) -> object:
        self.phases.append(phase)
        self.trusted_times.append(trusted_time)
        self.snapshots.append(snapshot)
        self.projections.append(projection)
        default = verify_exact_projection_from_canonical_records(snapshot, projection, self.records)
        return _decision(self.results.get(phase), default)


@dataclass(frozen=True, slots=True)
class PersistentSequenceState:
    last: ChronicleProjectionSequenceClaim | None
    seen_ids: tuple[str, ...]
    seen_nonces: tuple[str, ...]
    seen_digests: tuple[str, ...]
    trusted_time_high_water: str | None


class SequenceStateStub(ChronicleProjectionSequenceChainState):
    def __init__(
        self,
        prior: PersistentSequenceState | None = None,
        *,
        observe_results: list[object] | None = None,
        accept_result: object | None = None,
    ) -> None:
        self.last = prior.last if prior else None
        self.seen_ids = set(prior.seen_ids if prior else ())
        self.seen_nonces = set(prior.seen_nonces if prior else ())
        self.seen_digests = set(prior.seen_digests if prior else ())
        self.trusted_time_high_water = prior.trusted_time_high_water if prior else None
        self.observe_results = list(observe_results or [])
        self.accept_result = accept_result
        self.observed_times: list[str] = []
        self.claims: list[ChronicleProjectionSequenceClaim] = []
        self.accept_calls = 0

    def observe_trusted_time(self, trusted_time: str) -> object:
        self.observed_times.append(trusted_time)
        if self.observe_results:
            selected = self.observe_results.pop(0)
            if isinstance(selected, Exception):
                raise selected
            if selected is not True:
                return selected
        try:
            valid = _TIMESTAMP_RE.fullmatch(trusted_time) is not None
            datetime.fromisoformat(trusted_time)
        except (TypeError, ValueError):
            valid = False
        if not valid or (self.trusted_time_high_water is not None and trusted_time < self.trusted_time_high_water):
            return False
        self.trusted_time_high_water = trusted_time
        return True

    def accept_exact_next_snapshot(self, claim: ChronicleProjectionSequenceClaim) -> object:
        self.accept_calls += 1
        self.claims.append(claim)
        if self.accept_result is not None:
            if isinstance(self.accept_result, Exception):
                raise self.accept_result
            if self.accept_result is not True:
                return self.accept_result
        if (
            self.trusted_time_high_water is None
            or claim.trusted_time_high_water != self.trusted_time_high_water
            or claim.snapshot_id in self.seen_ids
            or claim.snapshot_nonce in self.seen_nonces
            or claim.snapshot_digest in self.seen_digests
            or claim.chronicle_record_count != claim.chronicle_watermark
        ):
            return False
        if self.last is None:
            if claim.snapshot_sequence != 1 or claim.previous_snapshot_hash is not None:
                return False
        elif (
            claim.snapshot_sequence != self.last.snapshot_sequence + 1
            or claim.previous_snapshot_hash != self.last.snapshot_digest
            or claim.as_of < self.last.as_of
            or claim.generated_at < self.last.generated_at
            or claim.trusted_time_high_water < self.last.trusted_time_high_water
            or claim.chronicle_watermark < self.last.chronicle_watermark
            or claim.chronicle_record_count < self.last.chronicle_record_count
            or claim.chronicle_id != self.last.chronicle_id
            or claim.audience != self.last.audience
            or claim.installation_id != self.last.installation_id
            or (
                claim.chronicle_watermark == self.last.chronicle_watermark
                and (
                    claim.chronicle_record_count != self.last.chronicle_record_count
                    or claim.chronicle_records_digest != self.last.chronicle_records_digest
                )
            )
        ):
            return False
        self.seen_ids.add(claim.snapshot_id)
        self.seen_nonces.add(claim.snapshot_nonce)
        self.seen_digests.add(claim.snapshot_digest)
        self.last = claim
        return True

    def persistent_state(self) -> PersistentSequenceState:
        return PersistentSequenceState(
            last=self.last,
            seen_ids=tuple(sorted(self.seen_ids)),
            seen_nonces=tuple(sorted(self.seen_nonces)),
            seen_digests=tuple(sorted(self.seen_digests)),
            trusted_time_high_water=self.trusted_time_high_water,
        )


@dataclass(slots=True)
class Harness:
    authenticator: AuthenticatorStub
    source_authority: SourceAuthorityStub
    revocation_authority: RevocationAuthorityStub
    clock: ClockStub
    derivation_verifier: DerivationVerifierStub
    sequence_state: SequenceStateStub
    dependencies: ChronicleProjectionSnapshotDependencies


def _harness(
    *,
    authenticator: AuthenticatorStub | None = None,
    source_authority: SourceAuthorityStub | None = None,
    revocation_authority: RevocationAuthorityStub | None = None,
    clock: ClockStub | None = None,
    derivation_verifier: DerivationVerifierStub | None = None,
    sequence_state: SequenceStateStub | None = None,
) -> Harness:
    auth = authenticator or AuthenticatorStub()
    source = source_authority or SourceAuthorityStub()
    revocation = revocation_authority or RevocationAuthorityStub()
    trusted_clock = clock or ClockStub()
    derivation = derivation_verifier or DerivationVerifierStub()
    sequence = sequence_state or SequenceStateStub()
    dependencies = ChronicleProjectionSnapshotDependencies(
        enabled=True,
        authenticator=auth,
        source_authority=source,
        revocation_authority=revocation,
        trusted_clock=trusted_clock,
        derivation_verifier=derivation,
        sequence_chain_state=sequence,
    )
    return Harness(auth, source, revocation, trusted_clock, derivation, sequence, dependencies)


def _load(
    snapshot: dict[str, Any],
    dependencies: ChronicleProjectionSnapshotDependencies | None = None,
) -> AuthenticatedChronicleProjectionSnapshot | None:
    return load_authenticated_chronicle_projection_snapshot(
        _raw_snapshot(snapshot),
        dependencies or _harness().dependencies,
    )


def test_exact_generated_dash_vector_and_record_prefix_are_accepted_and_deeply_immutable() -> None:
    snapshot = _snapshot()
    harness = _harness()

    result = _load(snapshot, harness.dependencies)

    assert snapshot == GENERATED_SNAPSHOT
    assert snapshot["snapshot_digest"] == VECTOR_SNAPSHOT_DIGEST
    assert snapshot["projection_digest"] == VECTOR_PROJECTION_DIGEST
    assert snapshot["chronicle_records_digest"] == VECTOR_RECORDS_DIGEST
    assert snapshot["chronicle_record_count"] == snapshot["chronicle_watermark"] == len(CANONICAL_RECORDS) == 54
    assert result is not None
    assert result.snapshot["audience"] == "dash-ops-reader"
    assert result.snapshot["authority_effect"] == "none"
    assert result.projection["warnings"] and len(result.projection["warnings"]) == 7
    assert harness.authenticator.phases == ["entry", "before-return"]
    assert harness.source_authority.phases == ["entry", "before-return"]
    assert harness.revocation_authority.phases == ["entry", "before-return"]
    assert harness.derivation_verifier.phases == ["entry", "before-return"]
    assert harness.sequence_state.observed_times == ["2026-08-14T12:31:00Z"] * 2
    assert harness.sequence_state.accept_calls == 1
    assert verify_exact_projection_from_canonical_records(
        result.snapshot,
        result.projection,
        CANONICAL_RECORDS,
    )

    with pytest.raises(TypeError):
        cast(dict[str, Any], result.snapshot)["audience"] = "other"
    with pytest.raises(TypeError):
        cast(dict[str, Any], result.projection)["warnings"] = ()
    assert isinstance(result.projection["warnings"], tuple)
    with pytest.raises(FrozenInstanceError):
        harness.authenticator.claims[0].producer_id = "other"  # type: ignore[misc]


def test_consumer_is_inert_without_literal_enable_and_every_callable_dependency() -> None:
    snapshot = _snapshot()
    base = _harness()
    cases = [
        replace(base.dependencies, enabled=False),
        replace(base.dependencies, enabled=cast(Any, 1)),
        replace(base.dependencies, authenticator=None),
        replace(base.dependencies, source_authority=None),
        replace(base.dependencies, revocation_authority=None),
        replace(base.dependencies, trusted_clock=None),
        replace(base.dependencies, derivation_verifier=None),
        replace(base.dependencies, sequence_chain_state=None),
        replace(base.dependencies, authenticator=cast(Any, object())),
    ]
    for dependencies in cases:
        assert _load(snapshot, dependencies) is None
    assert base.authenticator.phases == []
    assert base.source_authority.phases == []
    assert base.revocation_authority.phases == []
    assert base.derivation_verifier.phases == []
    assert base.sequence_state.observed_times == []

    assert load_authenticated_chronicle_projection_snapshot(cast(Any, bytearray(b"{}")), base.dependencies) is None
    assert load_authenticated_chronicle_projection_snapshot(b"", base.dependencies) is None
    assert load_authenticated_chronicle_projection_snapshot(b"x" * (8 * 1024 * 1024 + 1), base.dependencies) is None


@pytest.mark.parametrize(
    "raw",
    [
        b'{"audience":"dash-ops-reader","audience":"dash-ops-reader"}',
        b'{"audience":"\\ud800"}',
        b'{"value":1.0}',
        b'{"value":9007199254740992}',
        b"{\xff}",
    ],
)
def test_strict_snapshot_parser_rejects_duplicate_malformed_and_noncanonical_json(raw: bytes) -> None:
    assert load_authenticated_chronicle_projection_snapshot(raw, _harness().dependencies) is None


def test_snapshot_bytes_must_be_exact_canonical_utf8() -> None:
    snapshot = _snapshot()
    pretty = json.dumps(snapshot, indent=2, ensure_ascii=False).encode()
    escaped = _raw_snapshot(snapshot).replace(b'"dash-ops-reader"', b'"\\u0064ash-ops-reader"', 1)
    noncanonical_number = _raw_snapshot(snapshot).replace(b'"snapshot_sequence":1', b'"snapshot_sequence":1.0')
    duplicate = _raw_snapshot(snapshot)[:-1] + b',"audience":"dash-ops-reader"}'
    for raw in (pretty, escaped, noncanonical_number, duplicate):
        assert load_authenticated_chronicle_projection_snapshot(raw, _harness().dependencies) is None


def test_closed_generated_schema_rejects_omissions_and_unknown_top_or_installation_fields() -> None:
    omitted = _snapshot()
    omitted.pop("snapshot_nonce")
    unknown = _snapshot()
    unknown["approval"] = "approved"
    unknown_installation = _snapshot()
    unknown_installation["installation"]["region"] = "synthetic"
    for snapshot in (omitted, unknown, unknown_installation):
        assert _load(_seal_snapshot(snapshot)) is None


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("audience",), "dash-ops"),
        (("installation", "installation_id"), "other-installation"),
        (("installation", "embodiment"), "mac-engineer"),
        (("installation", "host_class"), "local-mac"),
        (("mode",), "intent"),
        (("authority_effect",), "evidence-only"),
        (("read_only",), False),
        (("contains_private_identity",), True),
        (("source_repository",), "https://github.com/example/platform-infra"),
        (("source_commit",), "f" * 40),
        (("source_contract_manifest_digest",), "sha256:" + "f" * 64),
        (("projection_schema_digest",), "sha256:" + "f" * 64),
        (("source_attestation_hash",), "sha256:" + "f" * 64),
        (("producer_id",), "other-projector"),
        (("producer_key_id",), "other-projector-key"),
        (("producer_runtime_attestation_hash",), "sha256:" + "f" * 64),
        (("revocation_identity",), "other-revocation-head"),
        (("chronicle_id",), "other-chronicle"),
    ],
)
def test_exact_audience_installation_provenance_mode_and_authority_are_pinned(
    path: tuple[str, ...], value: Any
) -> None:
    snapshot = _snapshot()
    target = snapshot
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert _load(_seal_snapshot(snapshot)) is None


def test_ids_nonces_sequence_previous_count_and_watermark_are_strict() -> None:
    cases: list[dict[str, Any]] = []
    for field, value in (
        ("snapshot_id", "not-a-uuid"),
        ("snapshot_nonce", GENERATED_SNAPSHOT["snapshot_id"]),
        ("snapshot_sequence", 0),
        ("previous_snapshot_hash", "sha256:" + "f" * 64),
        ("chronicle_watermark", 55),
        ("chronicle_record_count", 53),
    ):
        snapshot = _snapshot()
        snapshot[field] = value
        cases.append(_seal_snapshot(snapshot))
    for snapshot in cases:
        permissive = _harness(
            derivation_verifier=DerivationVerifierStub(results={"entry": True, "before-return": True})
        )
        assert _load(snapshot, permissive.dependencies) is None
        assert permissive.authenticator.phases == []


def test_snapshot_projection_records_and_signature_bundle_digests_are_independent() -> None:
    wrong_snapshot = _snapshot()
    wrong_snapshot["snapshot_digest"] = "sha256:" + "f" * 64
    assert _load(wrong_snapshot) is None

    wrong_projection = _snapshot()
    wrong_projection["projection_digest"] = "sha256:" + "f" * 64
    assert _load(_seal_snapshot(wrong_projection)) is None

    wrong_records = _snapshot()
    wrong_records["chronicle_records_digest"] = "sha256:" + "f" * 64
    harness = _harness()
    assert _load(_seal_snapshot(wrong_records), harness.dependencies) is None
    assert harness.derivation_verifier.phases == ["entry"]

    wrong_signature = _snapshot()
    wrong_signature["signature_bundle_hash"] = "sha256:" + "f" * 64
    resealed = _seal_snapshot(wrong_signature)
    assert resealed["snapshot_digest"] == VECTOR_SNAPSHOT_DIGEST
    auth_harness = _harness()
    assert _load(resealed, auth_harness.dependencies) is None
    assert auth_harness.authenticator.phases == ["entry"]


def test_projection_json_rejects_whitespace_duplicate_keys_and_noncanonical_numbers() -> None:
    projection = AUDIT_VECTOR["expected_projection"]
    variants = [
        json.dumps(projection, indent=2, ensure_ascii=False),
        '{"warnings":[],' + canonical_json_bytes(projection).decode()[1:],
        canonical_json_bytes(projection).decode().replace('"identity_epoch":1', '"identity_epoch":1.0', 1),
    ]
    for text in variants:
        snapshot = _snapshot()
        snapshot["projection_canonical_json"] = text
        snapshot["projection_digest"] = "sha256:" + hashlib.sha256(text.encode()).hexdigest()
        assert _load(_seal_snapshot(snapshot)) is None


@pytest.mark.parametrize("warnings", [[], "fabricated"])
def test_exact_record_derivation_rejects_omitted_or_fabricated_warnings(warnings: object) -> None:
    projection = copy.deepcopy(AUDIT_VECTOR["expected_projection"])
    if warnings == "fabricated":
        projection["warnings"].append(
            {
                "category": "pending",
                "code": "pending-capability-gap",
                "source_id": "fabricated-gap",
                "source_kind": "CapabilityGap",
                "source_record_hash": "sha256:" + "f" * 64,
            }
        )
    else:
        projection["warnings"] = warnings
    snapshot = _snapshot()
    snapshot["projection_canonical_json"] = canonical_json_bytes(projection).decode()
    snapshot["projection_digest"] = canonical_digest(projection)
    harness = _harness()

    assert _load(_seal_snapshot(snapshot), harness.dependencies) is None
    assert harness.derivation_verifier.phases == ["entry"]
    assert harness.sequence_state.accept_calls == 0


def test_canonical_stored_record_helper_rejects_omission_reordering_and_bad_bytes() -> None:
    result = _load(_snapshot())
    assert result is not None
    invalid_sets = [
        CANONICAL_RECORDS[:-1],
        (CANONICAL_RECORDS[1], CANONICAL_RECORDS[0], *CANONICAL_RECORDS[2:]),
        (CANONICAL_RECORDS[0] + b" ", *CANONICAL_RECORDS[1:]),
        (b'{"kind":"AgentEpisode","kind":"AgentEpisode"}', *CANONICAL_RECORDS[1:]),
        (b'{"value":1.0}', *CANONICAL_RECORDS[1:]),
        (b'{"value":9007199254740992}', *CANONICAL_RECORDS[1:]),
        (b'{"value":"\\ud800"}', *CANONICAL_RECORDS[1:]),
        (b"{\xff}", *CANONICAL_RECORDS[1:]),
    ]
    for records in invalid_sets:
        assert not verify_exact_projection_from_canonical_records(result.snapshot, result.projection, records)


def test_canonical_stored_record_helper_rejects_resealed_record_hash_and_schema_tampering() -> None:
    result = _load(_snapshot())
    assert result is not None
    records = copy.deepcopy(AUDIT_VECTOR["records"])
    records[0]["record_hash"] = "sha256:" + "f" * 64
    raw_records = tuple(canonical_json_bytes(record) for record in records)
    snapshot = dict(result.snapshot)
    snapshot["chronicle_records_digest"] = canonical_digest(records)
    assert not verify_exact_projection_from_canonical_records(snapshot, result.projection, raw_records)

    records = copy.deepcopy(AUDIT_VECTOR["records"])
    records[0]["unexpected"] = True
    _seal_record(records[0])
    raw_records = tuple(canonical_json_bytes(record) for record in records)
    snapshot["chronicle_records_digest"] = canonical_digest(records)
    assert not verify_exact_projection_from_canonical_records(snapshot, result.projection, raw_records)


def test_full_generated_mirror_gate_is_required_by_loader_and_derivation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_mirror() -> None:
        raise RuntimeError("tampered mirror")

    monkeypatch.setattr(consumer_module, "load_pinned_audit_projection", fail_mirror)
    harness = _harness()
    assert _load(_snapshot(), harness.dependencies) is None
    assert harness.authenticator.phases == []
    assert not verify_exact_projection_from_canonical_records(
        cast(Any, GENERATED_SNAPSHOT),
        cast(Any, AUDIT_VECTOR["expected_projection"]),
        CANONICAL_RECORDS,
    )


def test_freshness_chronology_and_monotonic_clock_are_fail_closed() -> None:
    for times in (
        ["2026-08-14T12:35:00Z", "2026-08-14T12:35:00Z"],
        ["2026-08-14T12:29:59Z", "2026-08-14T12:29:59Z"],
        ["2026-08-14T12:31:00Z", "2026-08-14T12:30:59Z"],
    ):
        harness = _harness(clock=ClockStub(list(times)))
        assert _load(_snapshot(), harness.dependencies) is None
    rollback = _harness(clock=ClockStub(["2026-08-14T12:31:00Z", "2026-08-14T12:30:59Z"]))
    assert _load(_snapshot(), rollback.dependencies) is None
    assert rollback.sequence_state.observed_times == ["2026-08-14T12:31:00Z", "2026-08-14T12:30:59Z"]
    assert rollback.sequence_state.trusted_time_high_water == "2026-08-14T12:31:00Z"

    invalid_chronology = _snapshot()
    invalid_chronology["as_of"] = "2026-08-14T12:31:00Z"
    assert _load(_seal_snapshot(invalid_chronology)) is None

    invalid_calendar = _snapshot()
    invalid_calendar["generated_at"] = "2026-02-31T12:30:00Z"
    assert _load(_seal_snapshot(invalid_calendar)) is None


@pytest.mark.parametrize("phase", ["entry", "before-return"])
@pytest.mark.parametrize("result", [False, 1, RuntimeError("callback failure")])
@pytest.mark.parametrize("dependency", ["authenticator", "source", "revocation", "derivation"])
def test_every_decision_callback_requires_literal_true_and_exceptions_fail_closed(
    dependency: str,
    result: object,
    phase: str,
) -> None:
    kwargs: dict[str, Any] = {}
    results = {phase: result}
    if dependency == "authenticator":
        kwargs["authenticator"] = AuthenticatorStub(results=results)
    elif dependency == "source":
        kwargs["source_authority"] = SourceAuthorityStub(results=results)
    elif dependency == "revocation":
        kwargs["revocation_authority"] = RevocationAuthorityStub(results=results)
    else:
        kwargs["derivation_verifier"] = DerivationVerifierStub(results=results)
    harness = _harness(**kwargs)
    assert _load(_snapshot(), harness.dependencies) is None
    assert harness.sequence_state.accept_calls == 0


def test_clock_and_persistent_state_callbacks_require_exact_types_and_literal_true() -> None:
    invalid_clock = _harness(clock=ClockStub([1]))
    assert _load(_snapshot(), invalid_clock.dependencies) is None

    clock_error = _harness(clock=ClockStub([RuntimeError("clock failed")]))
    assert _load(_snapshot(), clock_error.dependencies) is None

    truthy_observe = _harness(sequence_state=SequenceStateStub(observe_results=[1]))
    assert _load(_snapshot(), truthy_observe.dependencies) is None

    truthy_accept = _harness(sequence_state=SequenceStateStub(accept_result=1))
    assert _load(_snapshot(), truthy_accept.dependencies) is None
    assert truthy_accept.sequence_state.accept_calls == 1

    raising_accept = _harness(sequence_state=SequenceStateStub(accept_result=RuntimeError("state failed")))
    assert _load(_snapshot(), raising_accept.dependencies) is None


def test_replay_rejection_retains_clock_floor_across_reconstructed_state() -> None:
    sequence = SequenceStateStub()
    first_harness = _harness(sequence_state=sequence)
    first = _snapshot()
    assert _load(first, first_harness.dependencies) is not None

    replay_harness = _harness(
        sequence_state=sequence,
        clock=ClockStub(["2026-08-14T12:34:00Z", "2026-08-14T12:34:00Z"]),
    )
    assert _load(first, replay_harness.dependencies) is None
    assert sequence.trusted_time_high_water == "2026-08-14T12:34:00Z"

    reconstructed = SequenceStateStub(sequence.persistent_state())
    rollback_harness = _harness(
        sequence_state=reconstructed,
        clock=ClockStub(["2026-08-14T12:33:59Z", "2026-08-14T12:33:59Z"]),
    )
    assert _load(_next_snapshot(first, 41), rollback_harness.dependencies) is None
    assert rollback_harness.authenticator.phases == []
    assert reconstructed.trusted_time_high_water == "2026-08-14T12:34:00Z"


def test_exact_next_chain_survives_reconstruction_and_rejects_gap_or_wrong_previous() -> None:
    first_state = SequenceStateStub()
    first_harness = _harness(sequence_state=first_state)
    first = _snapshot()
    assert _load(first, first_harness.dependencies) is not None
    persisted = first_state.persistent_state()
    assert persisted.last is not None
    assert persisted.last.snapshot_digest == VECTOR_SNAPSHOT_DIGEST
    assert persisted.last.chronicle_record_count == persisted.last.chronicle_watermark == 54
    assert persisted.last.chronicle_records_digest == VECTOR_RECORDS_DIGEST
    assert persisted.last.projection_digest == VECTOR_PROJECTION_DIGEST
    assert persisted.last.audience == "dash-ops-reader"

    gap = _next_snapshot(first, 42, snapshot_sequence=3)
    gap_harness = _harness(
        sequence_state=SequenceStateStub(persisted),
        clock=ClockStub(["2026-08-14T12:32:30Z", "2026-08-14T12:32:31Z"]),
    )
    assert _load(gap, gap_harness.dependencies) is None

    wrong_previous = _next_snapshot(first, 43, previous_snapshot_hash="sha256:" + "f" * 64)
    wrong_harness = _harness(
        sequence_state=SequenceStateStub(persisted),
        clock=ClockStub(["2026-08-14T12:32:30Z", "2026-08-14T12:32:31Z"]),
    )
    assert _load(wrong_previous, wrong_harness.dependencies) is None

    reconstructed = SequenceStateStub(persisted)
    next_harness = _harness(
        sequence_state=reconstructed,
        clock=ClockStub(["2026-08-14T12:32:30Z", "2026-08-14T12:32:31Z"]),
    )
    second = _next_snapshot(first, 44)
    assert _load(second, next_harness.dependencies) is not None
    assert reconstructed.last is not None
    assert reconstructed.last.snapshot_sequence == 2
    assert reconstructed.last.previous_snapshot_hash == VECTOR_SNAPSHOT_DIGEST
    assert reconstructed.last.trusted_time_high_water == "2026-08-14T12:32:31Z"


def test_atomic_chain_claim_binds_monotonic_source_and_equal_watermark_records() -> None:
    first_state = SequenceStateStub()
    first_harness = _harness(sequence_state=first_state)
    first = _snapshot()
    assert _load(first, first_harness.dependencies) is not None
    persisted = first_state.persistent_state()

    mutations = (
        {"as_of": "2026-08-14T12:29:59Z"},
        {"generated_at": "2026-08-14T12:29:59Z"},
        {"chronicle_watermark": 53, "chronicle_record_count": 53},
        {"chronicle_records_digest": "sha256:" + "f" * 64},
    )
    for serial, mutation in enumerate(mutations, start=50):
        state = SequenceStateStub(persisted)
        assert state.observe_trusted_time("2026-08-14T12:32:00Z") is True
        candidate = _next_snapshot(first, serial, **mutation)
        claim = ChronicleProjectionSequenceClaim(
            snapshot_id=candidate["snapshot_id"],
            snapshot_nonce=candidate["snapshot_nonce"],
            snapshot_sequence=candidate["snapshot_sequence"],
            previous_snapshot_hash=candidate["previous_snapshot_hash"],
            snapshot_digest=candidate["snapshot_digest"],
            as_of=candidate["as_of"],
            generated_at=candidate["generated_at"],
            trusted_time_high_water="2026-08-14T12:32:00Z",
            chronicle_id=candidate["chronicle_id"],
            chronicle_watermark=candidate["chronicle_watermark"],
            chronicle_record_count=candidate["chronicle_record_count"],
            chronicle_records_digest=candidate["chronicle_records_digest"],
            projection_digest=candidate["projection_digest"],
            audience="dash-ops-reader",
            installation_id=candidate["installation"]["installation_id"],
        )
        assert state.accept_exact_next_snapshot(claim) is False
        assert state.last == persisted.last


def test_loader_has_no_caller_now_and_module_exposes_no_runtime_or_mutation_surface() -> None:
    assert "now" not in inspect.signature(load_authenticated_chronicle_projection_snapshot).parameters
    source_path = ROOT / "dash" / "platform_steward_chronicle_projection.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
    assert imported_roots.isdisjoint(
        {
            "app",
            "db",
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
    for forbidden in ("os.environ", "write_text(", "write_bytes(", 'open("w', "FastAPI", "APIRouter"):
        assert forbidden not in source
    assert all(
        token not in consumer_module.__all__ for token in ("approve", "execute", "deploy", "publish", "append", "write")
    )


def test_source_only_consumer_paths_skip_ghcr_but_validation_remains_unfiltered() -> None:
    ghcr = (ROOT / ".github" / "workflows" / "ghcr-build.yml").read_text(encoding="utf-8")
    validate = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
    assert '      - "dash/platform_steward_chronicle_projection.py"' in ghcr
    assert '      - "tests/test_platform_steward_chronicle_projection.py"' in ghcr
    assert "paths-ignore:" not in validate
