"""Default-disabled reader for signed platform-steward Chronicle snapshots.

This module is a pure, source-only verification boundary.  It has no route,
network client, credential lookup, database adapter, approval surface,
executor, deployment hook, or platform mutation API.  Authenticity, source
authority, revocation state, trusted time, exact record-backed derivation, and
durable replay/chain state must all be injected by a caller.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Protocol, TypeAlias, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from dash.platform_steward_audit_projection import (
    PINNED_SOURCE_FILES,
    canonical_digest,
    canonical_json_bytes,
    load_json_strict,
    load_pinned_audit_projection,
    normalize_expected_projection,
    validate_audit_projection_document,
)

CHRONICLE_API_VERSION = "platform.masonjames.dev/steward-chronicle/v1"
SNAPSHOT_KIND = "ChronicleProjectionSnapshot"
SNAPSHOT_DIGEST_DOMAIN = b"platform-steward-chronicle-boundary-v1\x00ChronicleProjectionSnapshot\x00"
EXACT_AUDIENCE = "dash-ops-reader"
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
MAX_PROJECTION_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 10_000
MAX_CANONICAL_RECORD_BYTES = 4 * 1024 * 1024

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)

_SNAPSHOT_SCHEMA_RELATIVE = "chronicle/v1/chronicle-projection-snapshot.schema.json"
_SNAPSHOT_POLICY: Mapping[str, Any] = MappingProxyType(
    {
        "apiVersion": CHRONICLE_API_VERSION,
        "kind": SNAPSHOT_KIND,
        "projection_name": "platform-steward-audit-v1",
        "projection_schema_digest": "sha256:0e3fe94451990ef02f65ae1fdafd92569eedaf2ced0293e83a9b475515f41791",
        "source_repository": "https://github.com/masonjames/platform-infra",
        "source_commit": "c02dbcdfacc6421c10eb863016d8aff346cef436",
        "source_contract_manifest_digest": ("sha256:d685f2fd4af55f7222f3c1205b55c4bf7c20c85d0cb3038a29fa0adf5b3211ee"),
        "audience": EXACT_AUDIENCE,
        "installation": {
            "embodiment": "server-sentinel",
            "host_class": "near-platform-server",
            "installation_id": "synthetic-server-sentinel",
        },
        "mode": "read",
        "chronicle_id": "platform-steward-primary",
        "source_attestation_hash": "sha256:34ef9a4626df3fbf2cd3623c34a1d68cd5897748df29af87d0983aecd196768c",
        "producer_id": "dockhand-chronicle-projector",
        "producer_key_id": "dockhand-chronicle-projector-key-v1",
        "producer_runtime_attestation_hash": (
            "sha256:34ef9a4626df3fbf2cd3623c34a1d68cd5897748df29af87d0983aecd196768c"
        ),
        "revocation_identity": "chronicle-projection-release-v1",
        "authority_effect": "none",
        "read_only": True,
        "contains_private_identity": False,
    }
)

VerificationPhase: TypeAlias = Literal["entry", "before-return"]
ImmutableJSON: TypeAlias = None | bool | int | str | tuple["ImmutableJSON", ...] | Mapping[str, "ImmutableJSON"]


@dataclass(frozen=True, slots=True)
class ChronicleProjectionInstallation:
    installation_id: str
    embodiment: Literal["server-sentinel", "mac-engineer"]
    host_class: Literal["near-platform-server", "local-mac"]


@dataclass(frozen=True, slots=True)
class ChronicleProjectionAuthenticationClaim:
    snapshot_digest: str
    signature_bundle_hash: str
    audience: Literal["dash-ops-reader"]
    installation: ChronicleProjectionInstallation
    producer_id: str
    producer_key_id: str
    producer_runtime_attestation_hash: str
    source_attestation_hash: str
    source_repository: str
    source_commit: str
    source_contract_manifest_digest: str
    projection_schema_digest: str
    revocation_identity: str


@dataclass(frozen=True, slots=True)
class ChronicleProjectionSequenceClaim:
    snapshot_id: str
    snapshot_nonce: str
    snapshot_sequence: int
    previous_snapshot_hash: str | None
    snapshot_digest: str
    as_of: str
    generated_at: str
    trusted_time_high_water: str
    chronicle_id: str
    chronicle_watermark: int
    chronicle_record_count: int
    chronicle_records_digest: str
    projection_digest: str
    audience: Literal["dash-ops-reader"]
    installation_id: str


class ChronicleProjectionSnapshotAuthenticator(Protocol):
    """Authenticate the exact snapshot digest and external signature bundle."""

    def authenticate_snapshot(
        self,
        claim: ChronicleProjectionAuthenticationClaim,
        phase: VerificationPhase,
    ) -> object: ...


class ChronicleProjectionSourceAuthority(Protocol):
    """Confirm that the exact pinned source and producer remain authoritative."""

    def confirm_source_authority(
        self,
        claim: ChronicleProjectionAuthenticationClaim,
        phase: VerificationPhase,
    ) -> object: ...


class ChronicleProjectionRevocationAuthority(Protocol):
    """Return literal ``True`` only while every bound identity is unrevoked."""

    def confirm_not_revoked(
        self,
        claim: ChronicleProjectionAuthenticationClaim,
        phase: VerificationPhase,
    ) -> object: ...


class ChronicleProjectionTrustedMonotonicClock(Protocol):
    """Supply canonical trusted UTC time; callers cannot pass an ad-hoc now."""

    def read_trusted_time(self) -> str: ...


class ChronicleProjectionDerivationVerifier(Protocol):
    """Re-derive the exact projection from the snapshot-bound stored records."""

    def verify_exact_projection(
        self,
        snapshot: Mapping[str, ImmutableJSON],
        projection: Mapping[str, ImmutableJSON],
        phase: VerificationPhase,
        trusted_time: str,
    ) -> object: ...


class ChronicleProjectionSequenceChainState(Protocol):
    """Durably enforce trusted-time, replay, sequence, and high-water state."""

    def observe_trusted_time(self, trusted_time: str) -> object:
        """Atomically persist a nondecreasing trusted-time floor.

        The durable floor must survive rejected snapshots and process
        reconstruction.  Return literal ``True`` only after persistence.
        """

        ...

    def accept_exact_next_snapshot(self, claim: ChronicleProjectionSequenceClaim) -> object:
        """Atomically accept only the exact next durable chain/high-water claim.

        Implementations must reject reused ids, nonces, or digests; sequence
        gaps; wrong previous hashes; rollback of as-of, generation time,
        watermark, count, or trusted time; and record count/digest rebinding at
        an equal Chronicle watermark.  Return literal ``True`` only after the
        whole claim is durable.
        """

        ...


@dataclass(frozen=True, slots=True)
class ChronicleProjectionSnapshotDependencies:
    """All dependencies are absent and the consumer is inert by default."""

    enabled: bool = False
    authenticator: ChronicleProjectionSnapshotAuthenticator | None = None
    source_authority: ChronicleProjectionSourceAuthority | None = None
    revocation_authority: ChronicleProjectionRevocationAuthority | None = None
    trusted_clock: ChronicleProjectionTrustedMonotonicClock | None = None
    derivation_verifier: ChronicleProjectionDerivationVerifier | None = None
    sequence_chain_state: ChronicleProjectionSequenceChainState | None = None


@dataclass(frozen=True, slots=True)
class AuthenticatedChronicleProjectionSnapshot:
    """Deeply immutable, evidence-only result with no authority-bearing API."""

    snapshot: Mapping[str, ImmutableJSON]
    projection: Mapping[str, ImmutableJSON]


def _timestamp(value: object) -> str | None:
    if type(value) is not str or _UTC_TIMESTAMP_RE.fullmatch(value) is None:
        return None
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return None
    return value


def _deep_freeze(value: Any) -> ImmutableJSON:
    if value is None or type(value) in {bool, int, str}:
        return cast(None | bool | int | str, value)
    if isinstance(value, list | tuple):
        return tuple(_deep_freeze(item) for item in value)
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _deep_freeze(item) for key, item in value.items()})
    raise TypeError(f"unsupported immutable JSON value: {type(value).__name__}")


def _deep_thaw(value: object) -> object:
    if value is None or type(value) in {bool, int, str}:
        return value
    if isinstance(value, tuple | list):
        return [_deep_thaw(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _deep_thaw(item) for key, item in value.items()}
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def _within_json_budget(value: object, *, depth: int = 0) -> tuple[int, bool]:
    if depth > MAX_JSON_DEPTH:
        return 0, False
    if isinstance(value, list):
        total = 1
        for item in value:
            count, valid = _within_json_budget(item, depth=depth + 1)
            total += count
            if not valid or total > MAX_JSON_ITEMS:
                return total, False
        return total, True
    if isinstance(value, Mapping):
        total = 1
        for item in value.values():
            count, valid = _within_json_budget(item, depth=depth + 1)
            total += count
            if not valid or total > MAX_JSON_ITEMS:
                return total, False
        return total, True
    return 1, True


def _parse_canonical_json_bytes(payload: bytes) -> object:
    value = load_json_strict(payload)
    if not hmac.compare_digest(payload, canonical_json_bytes(value)):
        raise ValueError("JSON bytes are not the exact steward canonical serialization")
    _, valid_budget = _within_json_budget(value)
    if not valid_budget:
        raise ValueError("JSON exceeds the closed consumer resource budget")
    return value


def _load_snapshot_schema_validator() -> Draft202012Validator:
    contract_root = Path(__file__).resolve().parents[1] / "contracts" / "platform-steward"
    schema_path = contract_root / _SNAPSHOT_SCHEMA_RELATIVE
    if contract_root.is_symlink() or schema_path.is_symlink():
        raise ValueError("generated Chronicle schema paths cannot be symlinks")
    schema_bytes = schema_path.read_bytes()
    expected_digest = PINNED_SOURCE_FILES[_SNAPSHOT_SCHEMA_RELATIVE]
    actual_digest = "sha256:" + hashlib.sha256(schema_bytes).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_digest):
        raise ValueError("generated Chronicle snapshot schema digest mismatch")
    schema = load_json_strict(schema_bytes)
    if not isinstance(schema, dict):
        raise ValueError("generated Chronicle snapshot schema is not an object")
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _canonical_snapshot_digest(snapshot: Mapping[str, object]) -> str:
    digest_document = {
        key: value for key, value in snapshot.items() if key not in {"snapshot_digest", "signature_bundle_hash"}
    }
    return "sha256:" + hashlib.sha256(SNAPSHOT_DIGEST_DOMAIN + canonical_json_bytes(digest_document)).hexdigest()


def _normalize_snapshot(value: object) -> Mapping[str, ImmutableJSON] | None:
    if not isinstance(value, dict):
        return None
    validator = _load_snapshot_schema_validator()
    if not validator.is_valid(value):
        return None
    snapshot = cast(dict[str, object], value)
    installation = snapshot.get("installation")
    if not isinstance(installation, dict):
        return None
    for key, expected in _SNAPSHOT_POLICY.items():
        if key == "installation":
            if installation != expected:
                return None
        elif snapshot.get(key) != expected:
            return None

    snapshot_id = snapshot.get("snapshot_id")
    snapshot_nonce = snapshot.get("snapshot_nonce")
    sequence = snapshot.get("snapshot_sequence")
    previous = snapshot.get("previous_snapshot_hash")
    watermark = snapshot.get("chronicle_watermark")
    count = snapshot.get("chronicle_record_count")
    if (
        type(snapshot_id) is not str
        or _UUID_RE.fullmatch(snapshot_id) is None
        or type(snapshot_nonce) is not str
        or _UUID_RE.fullmatch(snapshot_nonce) is None
        or snapshot_id == snapshot_nonce
        or type(sequence) is not int
        or sequence < 1
        or ((sequence == 1) != (previous is None))
        or type(watermark) is not int
        or type(count) is not int
        or count != watermark
    ):
        return None

    generated_at = _timestamp(snapshot.get("generated_at"))
    as_of = _timestamp(snapshot.get("as_of"))
    expires_at = _timestamp(snapshot.get("expires_at"))
    if (
        generated_at is None
        or as_of is None
        or expires_at is None
        or as_of > generated_at
        or generated_at >= expires_at
    ):
        return None

    digest_fields = (
        "snapshot_digest",
        "signature_bundle_hash",
        "projection_digest",
        "projection_schema_digest",
        "chronicle_records_digest",
        "source_contract_manifest_digest",
        "source_attestation_hash",
        "producer_runtime_attestation_hash",
    )
    if any(
        type(snapshot.get(field)) is not str or _DIGEST_RE.fullmatch(cast(str, snapshot[field])) is None
        for field in digest_fields
    ):
        return None
    expected_snapshot_digest = _canonical_snapshot_digest(snapshot)
    if not hmac.compare_digest(cast(str, snapshot["snapshot_digest"]), expected_snapshot_digest):
        return None
    return cast(Mapping[str, ImmutableJSON], _deep_freeze(snapshot))


def _authentication_claim(
    snapshot: Mapping[str, ImmutableJSON],
) -> ChronicleProjectionAuthenticationClaim:
    installation = cast(Mapping[str, ImmutableJSON], snapshot["installation"])
    return ChronicleProjectionAuthenticationClaim(
        snapshot_digest=cast(str, snapshot["snapshot_digest"]),
        signature_bundle_hash=cast(str, snapshot["signature_bundle_hash"]),
        audience=cast(Literal["dash-ops-reader"], snapshot["audience"]),
        installation=ChronicleProjectionInstallation(
            installation_id=cast(str, installation["installation_id"]),
            embodiment=cast(Literal["server-sentinel", "mac-engineer"], installation["embodiment"]),
            host_class=cast(Literal["near-platform-server", "local-mac"], installation["host_class"]),
        ),
        producer_id=cast(str, snapshot["producer_id"]),
        producer_key_id=cast(str, snapshot["producer_key_id"]),
        producer_runtime_attestation_hash=cast(str, snapshot["producer_runtime_attestation_hash"]),
        source_attestation_hash=cast(str, snapshot["source_attestation_hash"]),
        source_repository=cast(str, snapshot["source_repository"]),
        source_commit=cast(str, snapshot["source_commit"]),
        source_contract_manifest_digest=cast(str, snapshot["source_contract_manifest_digest"]),
        projection_schema_digest=cast(str, snapshot["projection_schema_digest"]),
        revocation_identity=cast(str, snapshot["revocation_identity"]),
    )


def _sequence_claim(
    snapshot: Mapping[str, ImmutableJSON],
    trusted_time_high_water: str,
) -> ChronicleProjectionSequenceClaim:
    installation = cast(Mapping[str, ImmutableJSON], snapshot["installation"])
    return ChronicleProjectionSequenceClaim(
        snapshot_id=cast(str, snapshot["snapshot_id"]),
        snapshot_nonce=cast(str, snapshot["snapshot_nonce"]),
        snapshot_sequence=cast(int, snapshot["snapshot_sequence"]),
        previous_snapshot_hash=cast(str | None, snapshot["previous_snapshot_hash"]),
        snapshot_digest=cast(str, snapshot["snapshot_digest"]),
        as_of=cast(str, snapshot["as_of"]),
        generated_at=cast(str, snapshot["generated_at"]),
        trusted_time_high_water=trusted_time_high_water,
        chronicle_id=cast(str, snapshot["chronicle_id"]),
        chronicle_watermark=cast(int, snapshot["chronicle_watermark"]),
        chronicle_record_count=cast(int, snapshot["chronicle_record_count"]),
        chronicle_records_digest=cast(str, snapshot["chronicle_records_digest"]),
        projection_digest=cast(str, snapshot["projection_digest"]),
        audience=cast(Literal["dash-ops-reader"], snapshot["audience"]),
        installation_id=cast(str, installation["installation_id"]),
    )


def _fresh_at(snapshot: Mapping[str, ImmutableJSON], trusted_time: str) -> bool:
    return (
        _timestamp(trusted_time) is not None
        and cast(str, snapshot["generated_at"]) <= trusted_time
        and trusted_time < cast(str, snapshot["expires_at"])
    )


def verify_exact_projection_from_canonical_records(
    snapshot: Mapping[str, ImmutableJSON],
    projection: Mapping[str, ImmutableJSON],
    canonical_record_bytes: Sequence[bytes],
) -> bool:
    """Pure exact-derivation helper for an injected stored-record verifier.

    Each record must be supplied as its exact canonical stored bytes.  The
    helper validates every record/domain digest and relationship through the
    generated steward schemas, binds the ordered record-array count/digest,
    re-derives the projection at the snapshot's fixed ``as_of``, and therefore
    rejects omitted or fabricated warnings.  It performs no record lookup.
    """

    try:
        # This is also the complete generated-mirror provenance gate. It
        # verifies SOURCE.lock, both manifests, every generated file digest,
        # the exact file set, and the v1 schemas used below.
        load_pinned_audit_projection()
        expected_count = snapshot["chronicle_record_count"]
        expected_watermark = snapshot["chronicle_watermark"]
        if (
            type(expected_count) is not int
            or type(expected_watermark) is not int
            or expected_count != expected_watermark
            or len(canonical_record_bytes) != expected_count
        ):
            return False
        records: list[object] = []
        for raw_record in canonical_record_bytes:
            if type(raw_record) is not bytes or not 0 < len(raw_record) <= MAX_CANONICAL_RECORD_BYTES:
                return False
            record = _parse_canonical_json_bytes(bytes(raw_record))
            if not isinstance(record, dict):
                return False
            records.append(record)
        records_digest = canonical_digest(records)
        if not hmac.compare_digest(cast(str, snapshot["chronicle_records_digest"]), records_digest):
            return False

        projection_value_for_digest = _deep_thaw(projection)
        projection_bytes = canonical_json_bytes(projection_value_for_digest)
        if not hmac.compare_digest(
            cast(str, snapshot["projection_canonical_json"]).encode("utf-8"),
            projection_bytes,
        ):
            return False
        if not hmac.compare_digest(
            cast(str, snapshot["projection_digest"]),
            canonical_digest(projection_value_for_digest),
        ):
            return False

        projection_value = load_json_strict(projection_bytes)
        document = {
            "apiVersion": "platform.masonjames.dev/steward/v1",
            "as_of": snapshot["as_of"],
            "authority_effect": "none",
            "contains_private_identity": False,
            "expected_projection": projection_value,
            "expected_projection_digest": canonical_digest(projection_value),
            "kind": "PlatformStewardAuditProjectionRecords",
            "records": records,
            "records_digest": records_digest,
            "synthetic": True,
        }
        validated = validate_audit_projection_document(document)
        return hmac.compare_digest(
            canonical_json_bytes(validated["expected_projection"]),
            projection_bytes,
        )
    except Exception:
        return False


def load_authenticated_chronicle_projection_snapshot(
    raw_snapshot_bytes: bytes,
    dependencies: ChronicleProjectionSnapshotDependencies,
) -> AuthenticatedChronicleProjectionSnapshot | None:
    """Verify one signed, canonical, read-only Dash Chronicle snapshot.

    The boundary is intentionally fail-closed and returns ``None`` for every
    rejected input or dependency failure.  All decision callbacks must return
    the literal singleton ``True``.  Trusted time can only come from the
    injected monotonic clock, and its durable floor is observed before any
    authentication decision so later rejected attempts cannot erase it.
    """

    try:
        authenticator = dependencies.authenticator
        source_authority = dependencies.source_authority
        revocation_authority = dependencies.revocation_authority
        trusted_clock = dependencies.trusted_clock
        derivation_verifier = dependencies.derivation_verifier
        sequence_chain_state = dependencies.sequence_chain_state
        if (
            dependencies.enabled is not True
            or authenticator is None
            or source_authority is None
            or revocation_authority is None
            or trusted_clock is None
            or derivation_verifier is None
            or sequence_chain_state is None
            or not callable(getattr(authenticator, "authenticate_snapshot", None))
            or not callable(getattr(source_authority, "confirm_source_authority", None))
            or not callable(getattr(revocation_authority, "confirm_not_revoked", None))
            or not callable(getattr(trusted_clock, "read_trusted_time", None))
            or not callable(getattr(derivation_verifier, "verify_exact_projection", None))
            or not callable(getattr(sequence_chain_state, "observe_trusted_time", None))
            or not callable(getattr(sequence_chain_state, "accept_exact_next_snapshot", None))
            or type(raw_snapshot_bytes) is not bytes
            or not 0 < len(raw_snapshot_bytes) <= MAX_SNAPSHOT_BYTES
        ):
            return None

        # Fail closed if any generated schema, vector, manifest, or source-lock
        # byte has drifted before accepting a signed envelope.
        load_pinned_audit_projection()
        raw_copy = bytes(raw_snapshot_bytes)
        snapshot = _normalize_snapshot(_parse_canonical_json_bytes(raw_copy))
        if snapshot is None:
            return None
        auth_claim = _authentication_claim(snapshot)

        first_trusted_time = trusted_clock.read_trusted_time()
        if (
            type(first_trusted_time) is not str
            or _timestamp(first_trusted_time) is None
            or sequence_chain_state.observe_trusted_time(first_trusted_time) is not True
            or not _fresh_at(snapshot, first_trusted_time)
            or authenticator.authenticate_snapshot(auth_claim, "entry") is not True
            or source_authority.confirm_source_authority(auth_claim, "entry") is not True
            or revocation_authority.confirm_not_revoked(auth_claim, "entry") is not True
        ):
            return None

        projection_text = snapshot["projection_canonical_json"]
        if type(projection_text) is not str:
            return None
        projection_bytes = projection_text.encode("utf-8")
        if not 0 < len(projection_bytes) <= MAX_PROJECTION_BYTES:
            return None
        projection_value = _parse_canonical_json_bytes(projection_bytes)
        if not isinstance(projection_value, dict):
            return None
        if not hmac.compare_digest(cast(str, snapshot["projection_digest"]), canonical_digest(projection_value)):
            return None
        normalized_projection = normalize_expected_projection(projection_value)
        if not hmac.compare_digest(projection_bytes, canonical_json_bytes(normalized_projection)):
            return None
        projection = cast(Mapping[str, ImmutableJSON], _deep_freeze(normalized_projection))
        if (
            derivation_verifier.verify_exact_projection(
                snapshot,
                projection,
                "entry",
                first_trusted_time,
            )
            is not True
        ):
            return None

        final_trusted_time = trusted_clock.read_trusted_time()
        if type(final_trusted_time) is not str or _timestamp(final_trusted_time) is None:
            return None
        # Offer every canonical clock read to the durable floor before a later
        # rejection, so a reconstructed process cannot forget that observation.
        if sequence_chain_state.observe_trusted_time(final_trusted_time) is not True:
            return None
        if (
            final_trusted_time < first_trusted_time
            or not _fresh_at(snapshot, final_trusted_time)
            or authenticator.authenticate_snapshot(auth_claim, "before-return") is not True
            or source_authority.confirm_source_authority(auth_claim, "before-return") is not True
            or revocation_authority.confirm_not_revoked(auth_claim, "before-return") is not True
            or derivation_verifier.verify_exact_projection(
                snapshot,
                projection,
                "before-return",
                final_trusted_time,
            )
            is not True
        ):
            return None

        result = AuthenticatedChronicleProjectionSnapshot(snapshot=snapshot, projection=projection)
        if sequence_chain_state.accept_exact_next_snapshot(_sequence_claim(snapshot, final_trusted_time)) is not True:
            return None
        return result
    except Exception:
        return None


__all__ = [
    "AuthenticatedChronicleProjectionSnapshot",
    "ChronicleProjectionAuthenticationClaim",
    "ChronicleProjectionDerivationVerifier",
    "ChronicleProjectionInstallation",
    "ChronicleProjectionRevocationAuthority",
    "ChronicleProjectionSequenceChainState",
    "ChronicleProjectionSequenceClaim",
    "ChronicleProjectionSnapshotAuthenticator",
    "ChronicleProjectionSnapshotDependencies",
    "ChronicleProjectionSourceAuthority",
    "ChronicleProjectionTrustedMonotonicClock",
    "EXACT_AUDIENCE",
    "load_authenticated_chronicle_projection_snapshot",
    "verify_exact_projection_from_canonical_records",
]
