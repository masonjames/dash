"""Strict, read-only consumer for the platform-steward v1 audit projection.

The canonical contracts live in ``masonjames/platform-infra``.  This module
does not write storage, call a network, or grant authority.  It validates the
closed synthetic Chronicle records, deterministically re-derives their public
audit projection, and verifies exact source and generated-byte provenance.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, TypeAlias, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource, Unresolvable

API_VERSION = "platform.masonjames.dev/steward/v1"
AUDIT_VECTOR_KIND = "PlatformStewardAuditProjectionRecords"
HASH_ALGORITHM = "domain-separated-canonical-json-sha256-v1"
RECORD_HASH_DOMAIN = b"platform-steward-record-v1\x00"
PINNED_CANONICAL_COMMIT = "c02dbcdfacc6421c10eb863016d8aff346cef436"
PINNED_GENERATOR_SHA256 = "sha256:6ea228e5331dec4fb72be2fc077a940928291f230955103cb20eea33652c82d4"
PINNED_SCHEMA_MANIFEST_SHA256 = "sha256:d685f2fd4af55f7222f3c1205b55c4bf7c20c85d0cb3038a29fa0adf5b3211ee"
PINNED_AUDIT_VECTOR_SHA256 = "sha256:9866294256dd497d31a696a58f0db854a05064a6cb4f007b93a9f36f7236223e"
PINNED_CANONICAL_HASH_VECTOR_SHA256 = "sha256:4525bc33203e926e2dbe8aa6319be1d33a55c36c151573a522d7f3238370e603"

JSON_SAFE_INTEGER_MAX = 9_007_199_254_740_991
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")

CLAIM_SUPPORT_STATES = (
    "supported",
    "stale",
    "conflicted",
    "revoked",
    "unsupported",
    "superseded",
)
WARNING_CATEGORIES = ("stale", "conflicted", "revoked", "unsupported", "pending")
FOUNDRY_DENIED_CAPABILITIES = (
    "bash",
    "ssh",
    "onepassword",
    "docker-socket",
    "provider-credentials",
    "production-mcp",
    "external-write",
)
FOUNDRY_ISOLATION_CHECK_NAMES = (
    "bind-admission-controller",
    "bind-dependency-lock",
    "bind-fixture-bundle",
    "bind-image-digest",
    "bind-immutable-input-output-channel",
    "bind-license-inventory",
    "bind-network-policy",
    "bind-one-job-destruction-policy",
    "bind-runtime-profile",
    "bind-sbom",
    "bind-source-archive",
    "bind-source-provenance",
    "deny-bash-child-process",
    "deny-browser-half",
    "deny-devices",
    "deny-docker-socket",
    "deny-external-write",
    "deny-host-mounts",
    "deny-host-network-pid-ipc",
    "deny-host-sockets",
    "deny-metadata-services",
    "deny-onepassword",
    "deny-privileged-mode",
    "deny-production-mcp",
    "deny-production-routes",
    "deny-provider-credentials",
    "deny-publisher-signing-overlay-install",
    "deny-secret-environment",
    "deny-ssh",
    "deny-unapproved-cordis-services",
    "enforce-dns-policy",
    "enforce-egress-policy",
    "enforce-nonroot-readonly-rootfs",
    "enforce-resource-budgets",
    "separate-candidate-controller-evaluator",
    "verify-image-signature",
)
DETERMINISTIC_GATE_NAMES = (
    "dagger-gate",
    "deterministic-tests",
    "synthetic-or-replay-evaluation",
)
SECURITY_GATE_NAMES = (
    "cordis-disposal-not-external-rollback",
    "deny-bash",
    "deny-docker-socket",
    "deny-external-write",
    "deny-onepassword",
    "deny-production-mcp",
    "deny-provider-credentials",
    "deny-self-promotion-install",
    "deny-ssh",
    "dockhand-only-mutation",
    "prompt-injection-capability-candidates",
    "prompt-injection-issues",
    "prompt-injection-logs",
    "prompt-injection-mcp-results",
    "prompt-injection-prs",
    "secret-scan-clean",
    "verify-async-work-terminated",
    "verify-one-job-destruction",
)
KNOWLEDGE_TRANSITIONS = {
    "observed": frozenset({"inferred", "revoked"}),
    "inferred": frozenset({"proposed", "revoked"}),
    "proposed": frozenset({"accepted", "revoked"}),
    "accepted": frozenset({"superseded", "revoked"}),
    "superseded": frozenset(),
    "revoked": frozenset(),
}
AUTHORITY_MODE_RANK = {"read": 0, "intent": 1}
SUPPORTED_RECORD_KINDS = frozenset(
    {
        "AgentConstitution",
        "AgentEpisode",
        "AgentHandoff",
        "AgentIdentityDescriptor",
        "AgentIdentityRevision",
        "CapabilityCandidate",
        "CapabilityEvaluation",
        "CapabilityGap",
        "CapabilityInvocation",
        "CapabilityLease",
        "CapabilityPromotion",
        "CapabilityRevocation",
        "FoundryAdmissionAttestation",
        "KnowledgeClaim",
        "ReasoningLease",
        "RuntimeAttestation",
    }
)

JSONValue: TypeAlias = None | bool | int | str | list["JSONValue"] | dict[str, "JSONValue"]
Validator: TypeAlias = Callable[[object, str], JSONValue]
FieldSpec: TypeAlias = tuple[str, Validator]


class AuditProjectionError(ValueError):
    """Raised when a projection or its pinned provenance is not closed and valid."""


def _fail(path: str, message: str) -> AuditProjectionError:
    return AuditProjectionError(f"{path}: {message}")


def _unicode_scalar(value: str, path: str) -> str:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise _fail(path, "unpaired Unicode surrogate is forbidden") from exc
    return value


def _json_value(value: object, path: str) -> JSONValue:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _unicode_scalar(value, path)
    if isinstance(value, int):
        if not -JSON_SAFE_INTEGER_MAX <= value <= JSON_SAFE_INTEGER_MAX:
            raise _fail(path, "integer exceeds the JSON safe range")
        return value
    if isinstance(value, float):
        raise _fail(path, "floating-point values are not canonical")
    if isinstance(value, list):
        return [_json_value(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, Mapping):
        result: dict[str, JSONValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise _fail(path, "JSON object keys must be strings")
            _unicode_scalar(key, f"{path}.<key>")
            result[key] = _json_value(item, f"{path}.{key}")
        return result
    raise _fail(path, f"unsupported JSON value {type(value).__name__}")


def canonical_json_bytes(value: object) -> bytes:
    """Return path-independent canonical bytes for the steward JSON domain."""

    normalized = _json_value(value, "$")
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _strict_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AuditProjectionError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_json_strict(payload: bytes) -> JSONValue:
    """Parse UTF-8 JSON while rejecting duplicates and noncanonical numbers."""

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditProjectionError("JSON payload is not UTF-8") from exc
    try:
        value = json.loads(text, object_pairs_hook=_strict_json_pairs)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AuditProjectionError(f"invalid JSON: {exc}") from exc
    return _json_value(value, "$")


def _closed_object(value: object, path: str, fields: tuple[FieldSpec, ...]) -> dict[str, JSONValue]:
    if not isinstance(value, Mapping):
        raise _fail(path, "expected object")
    if any(not isinstance(key, str) for key in value):
        raise _fail(path, "object keys must be strings")
    expected = {name for name, _ in fields}
    actual = set(cast(Mapping[str, object], value))
    unknown = sorted(actual - expected)
    missing = sorted(expected - actual)
    if unknown:
        raise _fail(path, f"unknown fields: {', '.join(unknown)}")
    if missing:
        raise _fail(path, f"missing fields: {', '.join(missing)}")
    source = cast(Mapping[str, object], value)
    return {name: validator(source[name], f"{path}.{name}") for name, validator in fields}


def _string(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise _fail(path, "expected string")
    return value


def _bounded_string(value: object, path: str) -> str:
    result = _string(value, path)
    if not 1 <= len(result) <= 4096:
        raise _fail(path, "string length must be 1..4096")
    return result


def _identifier(value: object, path: str) -> str:
    result = _string(value, path)
    if len(result) > 200 or IDENTIFIER_RE.fullmatch(result) is None:
        raise _fail(path, "expected a lowercase steward identifier")
    return result


def _uuid(value: object, path: str) -> str:
    result = _string(value, path)
    if UUID_RE.fullmatch(result) is None:
        raise _fail(path, "expected canonical lowercase UUID")
    return result


def _digest(value: object, path: str) -> str:
    result = _string(value, path)
    if DIGEST_RE.fullmatch(result) is None:
        raise _fail(path, "expected lowercase sha256 digest")
    return result


def _timestamp(value: object, path: str) -> str:
    result = _string(value, path)
    if UTC_TIMESTAMP_RE.fullmatch(result) is None:
        raise _fail(path, "expected canonical whole-second UTC timestamp")
    try:
        datetime.fromisoformat(result)
    except ValueError as exc:
        raise _fail(path, "timestamp is not a real calendar instant") from exc
    return result


def _source_revision(value: object, path: str) -> str:
    result = _string(value, path)
    if SOURCE_REVISION_RE.fullmatch(result) is None:
        raise _fail(path, "expected a 40-character lowercase source revision")
    return result


def _boolean(value: object, path: str) -> bool:
    if type(value) is not bool:
        raise _fail(path, "expected boolean")
    return cast(bool, value)


def _integer(minimum: int = 0, maximum: int = JSON_SAFE_INTEGER_MAX) -> Validator:
    def validate(value: object, path: str) -> int:
        if type(value) is not int:
            raise _fail(path, "expected integer")
        result = cast(int, value)
        if not minimum <= result <= maximum:
            raise _fail(path, f"integer must be in {minimum}..{maximum}")
        return result

    return validate


def _enum(*allowed: str) -> Validator:
    accepted = frozenset(allowed)

    def validate(value: object, path: str) -> str:
        result = _string(value, path)
        if result not in accepted:
            raise _fail(path, f"unsupported value {result!r}")
        return result

    return validate


def _const(expected: JSONValue) -> Validator:
    def validate(value: object, path: str) -> JSONValue:
        if type(value) is not type(expected) or value != expected:
            raise _fail(path, f"expected exact value {expected!r}")
        return expected

    return validate


def _nullable(validator: Validator) -> Validator:
    def validate(value: object, path: str) -> JSONValue:
        if value is None:
            return None
        return validator(value, path)

    return validate


def _array(validator: Validator, *, maximum: int = 10_000) -> Validator:
    def validate(value: object, path: str) -> list[JSONValue]:
        if not isinstance(value, list):
            raise _fail(path, "expected array")
        if len(value) > maximum:
            raise _fail(path, f"array exceeds {maximum} items")
        return [validator(item, f"{path}[{index}]") for index, item in enumerate(value)]

    return validate


def _model(value: object, path: str) -> dict[str, JSONValue]:
    return _closed_object(
        value,
        path,
        (
            ("adapter_digest", _digest),
            ("model", _identifier),
            ("provider", _identifier),
            ("version", _identifier),
        ),
    )


def _candidate_budget(value: object, path: str) -> dict[str, JSONValue]:
    return _closed_object(
        value,
        path,
        (
            ("maximum_calls", _integer(1, 1_000_000)),
            ("maximum_cost_microunits", _integer(0, 1_000_000_000_000)),
            ("maximum_tokens", _integer(0, 1_000_000_000)),
        ),
    )


def _foundry_budget(value: object, path: str) -> dict[str, JSONValue]:
    return _closed_object(
        value,
        path,
        (
            ("cpu_millis", _integer(1)),
            ("egress_bytes", _integer(0)),
            ("maximum_tokens", _integer(0, 1_000_000_000)),
            ("memory_mebibytes", _integer(1)),
            ("wall_time_seconds", _integer(1)),
        ),
    )


def _review(expected_name: str) -> Validator:
    def validate(value: object, path: str) -> dict[str, JSONValue]:
        return _closed_object(
            value,
            path,
            (
                ("evidence_hash", _digest),
                ("name", _const(expected_name)),
                ("status", _enum("passed", "failed", "ambiguous")),
            ),
        )

    return validate


def _isolation_check(value: object, path: str) -> dict[str, JSONValue]:
    return _closed_object(
        value,
        path,
        (
            ("evidence_hash", _digest),
            ("name", _enum(*FOUNDRY_ISOLATION_CHECK_NAMES)),
            ("status", _const("passed")),
        ),
    )


def _foundry_denials(value: object, path: str) -> list[JSONValue]:
    result = cast(list[JSONValue], _array(_enum(*FOUNDRY_DENIED_CAPABILITIES), maximum=7)(value, path))
    if len(result) != len(FOUNDRY_DENIED_CAPABILITIES) or set(cast(list[str], result)) != set(
        FOUNDRY_DENIED_CAPABILITIES
    ):
        raise _fail(path, "must contain every denied capability exactly once")
    return result


def _isolation_checks(value: object, path: str) -> list[JSONValue]:
    result = cast(list[JSONValue], _array(_isolation_check, maximum=len(FOUNDRY_ISOLATION_CHECK_NAMES))(value, path))
    names = [cast(dict[str, JSONValue], item)["name"] for item in result]
    if len(names) != len(FOUNDRY_ISOLATION_CHECK_NAMES) or set(names) != set(FOUNDRY_ISOLATION_CHECK_NAMES):
        raise _fail(path, "must contain every Foundry isolation check exactly once")
    return result


def _deny_schema_retrieval(uri: str) -> Resource[Any]:
    raise NoSuchResource(uri)


def _load_schema_validators(generated_root: Path) -> dict[str, Any]:
    """Load only the digest-pinned local schemas into a no-retrieval registry."""

    manifest_path = generated_root / "schema-manifest.json"
    _assert_file_digest(manifest_path, PINNED_SCHEMA_MANIFEST_SHA256)
    manifest = load_json_strict(manifest_path.read_bytes())
    if not isinstance(manifest, dict) or not isinstance(manifest.get("schemas"), dict):
        raise AuditProjectionError("pinned schema manifest has no closed schema map")
    schema_hashes = cast(dict[str, JSONValue], manifest["schemas"])
    if len(schema_hashes) != 16:
        raise AuditProjectionError("pinned schema manifest must contain exactly 16 schemas")

    registry: Registry[Any] = Registry(retrieve=_deny_schema_retrieval)  # type: ignore[call-arg]
    schemas: list[dict[str, Any]] = []
    for filename, expected_digest in sorted(schema_hashes.items()):
        if not isinstance(expected_digest, str) or DIGEST_RE.fullmatch(expected_digest) is None:
            raise AuditProjectionError(f"invalid pinned schema digest for {filename}")
        path = generated_root / filename
        if path.is_symlink():
            raise AuditProjectionError(f"pinned schema cannot be a symlink: {filename}")
        _assert_file_digest(path, expected_digest)
        value = load_json_strict(path.read_bytes())
        if not isinstance(value, dict):
            raise AuditProjectionError(f"pinned schema is not an object: {filename}")
        schema = cast(dict[str, Any], value)
        try:
            Draft202012Validator.check_schema(schema)
            resource = Resource.from_contents(schema)
        except Exception as exc:
            raise AuditProjectionError(f"invalid pinned schema {filename}: {exc}") from exc
        schema_id = schema.get("$id")
        kind = schema.get("title")
        if not isinstance(schema_id, str) or not isinstance(kind, str) or kind not in SUPPORTED_RECORD_KINDS:
            raise AuditProjectionError(f"pinned schema identity is invalid: {filename}")
        registry = registry.with_resource(schema_id, resource)
        schemas.append(schema)

    validators: dict[str, Any] = {}
    format_checker = FormatChecker()
    for schema in schemas:
        kind = cast(str, schema["title"])
        if kind in validators:
            raise AuditProjectionError(f"duplicate pinned schema kind: {kind}")
        validators[kind] = Draft202012Validator(schema, registry=registry, format_checker=format_checker)
    if set(validators) != SUPPORTED_RECORD_KINDS:
        raise AuditProjectionError("pinned schema kinds do not match the closed steward v1 family")
    return validators


def _record_validator(schema_validators: Mapping[str, Any]) -> Validator:
    def validate(value: object, path: str) -> dict[str, JSONValue]:
        return _audit_record(value, path, schema_validators)

    return validate


def _audit_record(
    value: object,
    path: str,
    schema_validators: Mapping[str, Any],
) -> dict[str, JSONValue]:
    normalized = _json_value(value, path)
    if not isinstance(normalized, dict):
        raise _fail(path, "audit record must be an object")
    for field in ("apiVersion", "kind", "record_id", "recorded_at", "hash_algorithm", "record_hash"):
        if field not in normalized:
            raise _fail(path, f"audit record is missing common field {field}")
    if normalized["apiVersion"] != API_VERSION:
        raise _fail(path, "audit record has wrong apiVersion")
    kind = _string(normalized["kind"], f"{path}.kind")
    if kind not in SUPPORTED_RECORD_KINDS:
        raise _fail(f"{path}.kind", f"unsupported steward record kind {kind!r}")
    try:
        errors = sorted(
            schema_validators[kind].iter_errors(normalized),
            key=lambda error: (list(error.absolute_path), error.message),
        )
    except (KeyError, NoSuchResource, Unresolvable) as exc:
        raise _fail(path, f"schema resolution failed closed for {kind}: {exc}") from exc
    except Exception as exc:
        raise _fail(path, f"closed {kind} schema validation failed: {exc}") from exc
    if errors:
        error = errors[0]
        location = "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in error.absolute_path)
        raise _fail(f"{path}{location}", f"closed {kind} schema violation: {error.message}")
    _uuid(normalized["record_id"], f"{path}.record_id")
    _timestamp(normalized["recorded_at"], f"{path}.recorded_at")
    if normalized["hash_algorithm"] != HASH_ALGORITHM:
        raise _fail(path, "audit record has wrong hash algorithm")
    actual_hash = _digest(normalized["record_hash"], f"{path}.record_hash")
    unhashed = dict(normalized)
    unhashed.pop("record_hash")
    domain = RECORD_HASH_DOMAIN + API_VERSION.encode() + b"\x00" + kind.encode() + b"\x00"
    expected_hash = "sha256:" + hashlib.sha256(domain + canonical_json_bytes(unhashed)).hexdigest()
    if not hmac.compare_digest(actual_hash, expected_hash):
        raise _fail(f"{path}.record_hash", "does not match canonical record content")
    return normalized


def _identity_timeline_item(value: object, path: str) -> dict[str, JSONValue]:
    return _closed_object(
        value,
        path,
        (
            ("effective_at", _timestamp),
            ("event", _enum("identity-created", "identity-revision")),
            ("identity_epoch", _integer(1)),
            ("identity_id", _identifier),
            ("identity_revision", _integer(1)),
            ("record_hash", _digest),
            ("status", _enum("pending", "active", "superseded", "revoked", "retired")),
        ),
    )


def _attested_embodiment(value: object, path: str) -> dict[str, JSONValue]:
    result = _closed_object(
        value,
        path,
        (
            ("attestation_hash", _digest),
            ("dynamic_cordis_allowed", _boolean),
            ("embodiment", _enum("server-sentinel", "mac-engineer", "foundry-replay")),
            ("expires_at", _timestamp),
            ("identity_id", _identifier),
            ("installation_id", _identifier),
            ("issued_at", _timestamp),
            ("model", _model),
            ("runtime_profile_id", _identifier),
            ("session_id", _uuid),
            ("state", _enum("active", "expired")),
        ),
    )
    if result["dynamic_cordis_allowed"] is True and result["embodiment"] != "foundry-replay":
        raise _fail(path, "dynamic Cordis is only valid in the isolated Foundry embodiment")
    return result


def _episode(value: object, path: str) -> dict[str, JSONValue]:
    result = _closed_object(
        value,
        path,
        (
            ("embodiment", _enum("server-sentinel", "mac-engineer", "foundry-replay")),
            ("ended_at", _nullable(_timestamp)),
            ("episode_hash", _digest),
            ("episode_id", _uuid),
            ("handoff_id", _nullable(_uuid)),
            ("identity_id", _identifier),
            ("model", _model),
            ("parent_episode_id", _nullable(_uuid)),
            ("scope_id", _identifier),
            ("started_at", _timestamp),
            (
                "state",
                _enum(
                    "open",
                    "completed",
                    "handed_off",
                    "rejected",
                    "expired",
                    "investigation_artifact",
                    "draft_pr_request",
                ),
            ),
        ),
    )
    if result["state"] == "open" and result["ended_at"] is not None:
        raise _fail(path, "open episode cannot have ended_at")
    if result["state"] != "open" and result["ended_at"] is None:
        raise _fail(path, "terminal episode requires ended_at")
    return result


def _handoff(value: object, path: str) -> dict[str, JSONValue]:
    result = _closed_object(
        value,
        path,
        (
            ("expires_at", _timestamp),
            ("handoff_hash", _digest),
            ("handoff_id", _uuid),
            ("issued_at", _timestamp),
            ("source_episode_id", _uuid),
            ("state", _enum("pending", "accepted", "rejected", "expired")),
            ("target_embodiment", _enum("server-sentinel", "mac-engineer")),
            ("target_episode_id", _nullable(_uuid)),
            ("target_installation_id", _identifier),
        ),
    )
    if result["state"] == "accepted" and result["target_episode_id"] is None:
        raise _fail(path, "accepted handoff requires a target episode")
    return result


def _claim_support(value: object, path: str) -> dict[str, JSONValue]:
    result = _closed_object(
        value,
        path,
        (
            ("claim_hash", _digest),
            ("claim_id", _uuid),
            (
                "knowledge_state",
                _enum("observed", "inferred", "proposed", "accepted", "superseded", "revoked"),
            ),
            ("predicate", _identifier),
            ("source_episode_id", _uuid),
            ("subject", _bounded_string),
            ("support_state", _enum(*CLAIM_SUPPORT_STATES)),
            ("supported_until", _nullable(_timestamp)),
        ),
    )
    knowledge_state = result["knowledge_state"]
    support_state = result["support_state"]
    if knowledge_state == "revoked" and support_state != "revoked":
        raise _fail(path, "revoked knowledge must project as revoked support")
    if knowledge_state == "superseded" and support_state != "superseded":
        raise _fail(path, "superseded knowledge must project as superseded support")
    if knowledge_state in {"observed", "inferred", "proposed"} and support_state != "unsupported":
        raise _fail(path, "unaccepted knowledge must project as unsupported")
    if knowledge_state == "accepted" and support_state not in {"supported", "stale", "conflicted", "unsupported"}:
        raise _fail(path, "accepted knowledge has an impossible support state")
    return result


def _reasoning_lease(value: object, path: str) -> dict[str, JSONValue]:
    result = _closed_object(
        value,
        path,
        (
            ("embodiment", _enum("server-sentinel", "mac-engineer", "foundry-replay")),
            ("expected_previous_generation", _integer(0)),
            ("expires_at", _timestamp),
            ("generation", _integer(1)),
            ("issued_at", _timestamp),
            ("lease_hash", _digest),
            ("lease_id", _uuid),
            ("owner_episode_id", _uuid),
            ("scope_id", _identifier),
            ("state", _enum("active", "released", "revoked", "expired")),
        ),
    )
    if cast(int, result["generation"]) != cast(int, result["expected_previous_generation"]) + 1:
        raise _fail(path, "reasoning lease generation must advance the CAS predecessor by one")
    return result


def _capability_lease(value: object, path: str) -> dict[str, JSONValue]:
    return _closed_object(
        value,
        path,
        (
            ("audience", _identifier),
            ("capability_id", _identifier),
            ("expires_at", _timestamp),
            ("issued_at", _timestamp),
            ("lease_hash", _digest),
            ("lease_id", _uuid),
            ("mode", _enum("read", "intent")),
            ("permitted_interface", _identifier),
            ("state", _enum("active", "revoked", "expired")),
        ),
    )


def _capability_gap(value: object, path: str) -> dict[str, JSONValue]:
    result = _closed_object(
        value,
        path,
        (
            ("closed_at", _nullable(_timestamp)),
            ("gap_hash", _digest),
            ("gap_id", _uuid),
            ("required_interface", _identifier),
            ("source_episode_id", _uuid),
            ("status", _enum("open", "closed", "superseded", "revoked")),
        ),
    )
    if result["status"] == "open" and result["closed_at"] is not None:
        raise _fail(path, "open gap cannot have closed_at")
    if result["status"] != "open" and result["closed_at"] is None:
        raise _fail(path, "terminal gap requires closed_at")
    return result


def _foundry_admission(value: object, path: str) -> dict[str, JSONValue]:
    result = _closed_object(
        value,
        path,
        (
            ("admission_hash", _digest),
            ("admission_id", _uuid),
            ("admitted", _const(True)),
            ("budget", _foundry_budget),
            ("credential_access", _const(False)),
            ("denied_capabilities", _foundry_denials),
            ("dependency_lock_digest", _digest),
            ("expires_at", _timestamp),
            ("fixture_bundle_digest", _digest),
            ("image_digest", _digest),
            ("installation_id", _identifier),
            ("isolation_checks", _isolation_checks),
            ("issued_at", _timestamp),
            ("job_id", _uuid),
            ("network_policy_digest", _digest),
            ("production_network_access", _const(False)),
            ("sbom_digest", _digest),
            ("source_archive_digest", _digest),
            ("source_revision", _source_revision),
            ("state", _enum("active", "expired")),
            ("wipe_policy", _const("destroy-after-one-job")),
        ),
    )
    return result


def _capability_candidate(value: object, path: str) -> dict[str, JSONValue]:
    return _closed_object(
        value,
        path,
        (
            ("adversarial_review", _review("adversarial-review")),
            ("budget", _candidate_budget),
            ("candidate_hash", _digest),
            ("candidate_id", _uuid),
            ("closed_gap_hash", _digest),
            ("code_digest", _digest),
            ("dependency_lock_digest", _digest),
            ("foundry_admission_hash", _digest),
            ("identity_id", _identifier),
            ("interface_schema_digest", _digest),
            ("model", _model),
            ("reviewer", _identifier),
            ("reviewer_key_id", _identifier),
            ("self_install_allowed", _const(False)),
            ("self_promotion_allowed", _const(False)),
            ("signature_bundle_hash", _digest),
            ("source_digest", _digest),
            ("source_revision", _source_revision),
            ("static_review", _review("static-review")),
            ("status", _enum("draft", "evaluated", "rejected", "superseded")),
            ("tool_profile_digest", _digest),
        ),
    )


def _capability_evaluation(value: object, path: str) -> dict[str, JSONValue]:
    result = _closed_object(
        value,
        path,
        (
            ("candidate_hash", _digest),
            ("credentials_accessed", _const(False)),
            ("evaluation_hash", _digest),
            ("evaluation_id", _uuid),
            ("evaluator_attestation_hash", _digest),
            ("outcome", _enum("passed", "failed", "ambiguous")),
            ("production_accessed", _const(False)),
            ("terminal_artifact", _enum("investigation_artifact", "draft_promotion_artifact")),
        ),
    )
    expected = "draft_promotion_artifact" if result["outcome"] == "passed" else "investigation_artifact"
    if result["terminal_artifact"] != expected:
        raise _fail(path, f"{result['outcome']} evaluation requires {expected}")
    return result


def _capability_promotion(value: object, path: str) -> dict[str, JSONValue]:
    result = _closed_object(
        value,
        path,
        (
            ("evaluation_hash", _digest),
            ("human_decision", _enum("pending", "approved", "rejected")),
            ("may_deploy", _const(False)),
            ("may_install", _const(False)),
            ("may_merge", _const(False)),
            ("may_publish", _const(False)),
            ("overlay_selection_present", _boolean),
            ("permitted_action", _enum("investigation_artifact", "draft_pr_request")),
            ("promotion_hash", _digest),
            ("promotion_id", _uuid),
            ("signed_release_present", _boolean),
            ("status", _enum("draft", "review_requested", "approved_for_release", "rejected")),
        ),
    )
    if result["status"] == "approved_for_release" and (
        result["human_decision"] != "approved"
        or result["signed_release_present"] is not True
        or result["overlay_selection_present"] is not True
        or result["permitted_action"] != "draft_pr_request"
    ):
        raise _fail(path, "approved release requires exact human approval, signed release, and overlay selection")
    return result


def _capability_revocation(value: object, path: str) -> dict[str, JSONValue]:
    return _closed_object(
        value,
        path,
        (
            ("capability_id", _identifier),
            ("effective_at", _timestamp),
            ("provider_rejection_required", _const(True)),
            ("reactive_profile_state", _const("deactivated")),
            ("revocation_hash", _digest),
            ("revocation_id", _identifier),
            ("target_revocation_identity", _identifier),
        ),
    )


def _capability_invocation(value: object, path: str) -> dict[str, JSONValue]:
    result = _closed_object(
        value,
        path,
        (
            ("call_index", _integer(1)),
            ("capability_id", _identifier),
            ("completed_at", _timestamp),
            ("disposition", _enum("succeeded", "rejected", "expired", "revoked")),
            ("entry_validation", _enum("accepted", "rejected")),
            ("invocation_hash", _digest),
            ("invocation_id", _uuid),
            ("return_validation", _nullable(_enum("accepted", "rejected"))),
            ("started_at", _timestamp),
        ),
    )
    disposition = cast(str, result["disposition"])
    required_phases: dict[str, tuple[str, str | None]] = {
        "succeeded": ("accepted", "accepted"),
        "rejected": ("rejected", None),
        "expired": ("accepted", "rejected"),
        "revoked": ("accepted", "rejected"),
    }
    required_entry, required_return = required_phases[disposition]
    if result["entry_validation"] != required_entry or result["return_validation"] != required_return:
        raise _fail(
            path,
            f"{disposition} invocation requires entry_validation={required_entry!r} "
            f"and return_validation={required_return!r}",
        )
    return result


WARNING_RULES: dict[str, tuple[str, str]] = {
    "stale-knowledge-claim": ("stale", "KnowledgeClaim"),
    "conflicted-knowledge-claim": ("conflicted", "KnowledgeClaim"),
    "revoked-knowledge-claim": ("revoked", "KnowledgeClaim"),
    "unsupported-knowledge-claim": ("unsupported", "KnowledgeClaim"),
    "revoked-capability-lease": ("revoked", "CapabilityLease"),
    "pending-capability-gap": ("pending", "CapabilityGap"),
    "pending-capability-promotion": ("pending", "CapabilityPromotion"),
}


def _warning(value: object, path: str) -> dict[str, JSONValue]:
    result = _closed_object(
        value,
        path,
        (
            ("category", _enum(*WARNING_CATEGORIES)),
            ("code", _enum(*WARNING_RULES)),
            ("source_id", _bounded_string),
            ("source_kind", _enum("KnowledgeClaim", "CapabilityLease", "CapabilityGap", "CapabilityPromotion")),
            ("source_record_hash", _digest),
        ),
    )
    expected_category, expected_kind = WARNING_RULES[cast(str, result["code"])]
    if result["category"] != expected_category or result["source_kind"] != expected_kind:
        raise _fail(path, "warning category and source kind do not match its closed code")
    return result


def _vocabulary(value: object, path: str) -> dict[str, JSONValue]:
    return _closed_object(
        value,
        path,
        (
            ("claim_support_states", _const(list(CLAIM_SUPPORT_STATES))),
            ("record_selection", _const("latest-revision-per-logical-id-then-record-hash")),
            ("time_basis", _const("fixed-as-of-inclusive-utc")),
            ("warning_categories", _const(list(WARNING_CATEGORIES))),
        ),
    )


PROJECTION_FIELDS: tuple[FieldSpec, ...] = (
    ("attested_embodiments", _array(_attested_embodiment)),
    ("capability_candidates", _array(_capability_candidate)),
    ("capability_evaluations", _array(_capability_evaluation)),
    ("capability_gaps", _array(_capability_gap)),
    ("capability_invocations", _array(_capability_invocation)),
    ("capability_leases", _array(_capability_lease)),
    ("capability_promotions", _array(_capability_promotion)),
    ("capability_revocations", _array(_capability_revocation)),
    ("claim_support_states", _array(_claim_support)),
    ("episodes", _array(_episode)),
    ("foundry_admissions", _array(_foundry_admission)),
    ("handoffs", _array(_handoff)),
    ("identity_timeline", _array(_identity_timeline_item)),
    ("reasoning_leases", _array(_reasoning_lease)),
    ("vocabulary", _vocabulary),
    ("warnings", _array(_warning)),
)


def normalize_expected_projection(value: object, path: str = "$.expected_projection") -> dict[str, JSONValue]:
    """Validate every closed v1 projection section and return a detached copy."""

    return _closed_object(value, path, PROJECTION_FIELDS)


def _latest_audit_records(
    records: Sequence[Mapping[str, Any]],
    *,
    kind: str,
    id_field: str,
    revision_field: str | None = None,
) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for raw_record in records:
        if raw_record.get("kind") != kind:
            continue
        record = dict(raw_record)
        logical_id = record[id_field]
        current = latest.get(logical_id)
        candidate_key = (
            record[revision_field] if revision_field is not None else 1,
            record["recorded_at"],
            record["record_hash"],
        )
        current_key = (
            current[revision_field] if current is not None and revision_field else 1,
            current["recorded_at"] if current is not None else "",
            current["record_hash"] if current is not None else "",
        )
        if current is None or candidate_key > current_key:
            latest[logical_id] = record
    return [latest[logical_id] for logical_id in sorted(latest)]


def _derive_expected_projection(records: Sequence[Mapping[str, Any]], *, as_of: str) -> dict[str, Any]:
    """Port of platform-infra c02dbcdf project_public_audit_records."""

    canonical_as_of = _timestamp(as_of, "$.as_of")
    validated = [dict(record) for record in records if record["recorded_at"] <= canonical_as_of]
    identity_timeline: list[dict[str, Any]] = []
    for descriptor in sorted(
        (record for record in validated if record["kind"] == "AgentIdentityDescriptor"),
        key=lambda record: (record["created_at"], record["identity_id"]),
    ):
        identity_timeline.append(
            {
                "event": "identity-created",
                "identity_id": descriptor["identity_id"],
                "identity_revision": descriptor["initial_identity_revision"],
                "identity_epoch": descriptor["initial_identity_epoch"],
                "status": descriptor["status"],
                "effective_at": descriptor["created_at"],
                "record_hash": descriptor["record_hash"],
            }
        )
    for revision in sorted(
        (record for record in validated if record["kind"] == "AgentIdentityRevision"),
        key=lambda record: (
            record["effective_at"],
            record["identity"]["identity_id"],
            record["identity"]["identity_revision"],
        ),
    ):
        identity_timeline.append(
            {
                "event": "identity-revision",
                "identity_id": revision["identity"]["identity_id"],
                "identity_revision": revision["identity"]["identity_revision"],
                "identity_epoch": revision["identity"]["identity_epoch"],
                "status": revision["status"],
                "effective_at": revision["effective_at"],
                "record_hash": revision["record_hash"],
            }
        )
    identity_timeline.sort(
        key=lambda event: (
            event["effective_at"],
            event["identity_id"],
            event["event"],
            event["record_hash"],
        )
    )

    attestations = sorted(
        (
            record
            for record in validated
            if record["kind"] == "RuntimeAttestation" and record["issued_at"] <= canonical_as_of
        ),
        key=lambda record: (
            record["identity"]["identity_id"],
            record["embodiment"],
            record["issued_at"],
            record["record_hash"],
        ),
    )
    attested_embodiments = [
        {
            "attestation_hash": record["record_hash"],
            "identity_id": record["identity"]["identity_id"],
            "embodiment": record["embodiment"],
            "installation_id": record["installation_id"],
            "session_id": record["session_id"],
            "runtime_profile_id": record["runtime_profile_id"],
            "model": copy.deepcopy(record["model"]),
            "dynamic_cordis_allowed": record["dynamic_cordis_allowed"],
            "issued_at": record["issued_at"],
            "expires_at": record["expires_at"],
            "state": "active" if canonical_as_of < record["expires_at"] else "expired",
        }
        for record in attestations
    ]

    latest_episodes = _latest_audit_records(
        validated,
        kind="AgentEpisode",
        id_field="episode_id",
        revision_field="episode_revision",
    )
    episodes = [
        {
            "episode_id": record["episode_id"],
            "episode_hash": record["record_hash"],
            "identity_id": record["identity"]["identity_id"],
            "embodiment": record["embodiment"],
            "parent_episode_id": record["parent_episode_id"],
            "handoff_id": record["handoff_id"],
            "scope_id": record["scope"]["scope_id"],
            "model": copy.deepcopy(record["actual_model"]),
            "state": record["terminal_disposition"] or "open",
            "started_at": record["started_at"],
            "ended_at": record["ended_at"],
        }
        for record in latest_episodes
    ]

    latest_handoffs = _latest_audit_records(
        validated,
        kind="AgentHandoff",
        id_field="handoff_id",
        revision_field="handoff_revision",
    )
    handoffs = [
        {
            "handoff_id": record["handoff_id"],
            "handoff_hash": record["record_hash"],
            "source_episode_id": record["source_episode_id"],
            "target_episode_id": record["accepted_episode_id"],
            "target_embodiment": record["target_embodiment"],
            "target_installation_id": record["target_installation_id"],
            "state": record["terminal_disposition"],
            "issued_at": record["issued_at"],
            "expires_at": record["expires_at"],
        }
        for record in latest_handoffs
    ]

    latest_claims = _latest_audit_records(
        validated,
        kind="KnowledgeClaim",
        id_field="claim_id",
        revision_field="claim_revision",
    )
    claim_support_by_hash: dict[str, str] = {}
    for claim in latest_claims:
        evidence_hashes = {item["evidence_hash"] for item in claim["evidence"]}
        has_cited_evidence = any(item["trust_state"] in {"cited", "verified"} for item in claim["evidence"])
        if claim["knowledge_state"] == "revoked":
            support_state = "revoked"
        elif claim["knowledge_state"] == "superseded":
            support_state = "superseded"
        elif claim["knowledge_state"] != "accepted":
            support_state = "unsupported"
        elif claim["supported_until"] is not None and claim["supported_until"] <= canonical_as_of:
            support_state = "stale"
        elif not has_cited_evidence or not set(claim["evidence_preconditions"]).issubset(evidence_hashes):
            support_state = "unsupported"
        else:
            support_state = "supported"
        claim_support_by_hash[claim["record_hash"]] = support_state

    conflict_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for claim in latest_claims:
        if claim_support_by_hash[claim["record_hash"]] != "supported":
            continue
        conflict_groups.setdefault((claim["subject"], claim["predicate"]), []).append(claim)
    for group in conflict_groups.values():
        if len({claim["statement_hash"] for claim in group}) > 1:
            for claim in group:
                claim_support_by_hash[claim["record_hash"]] = "conflicted"

    claim_support_states = [
        {
            "claim_id": claim["claim_id"],
            "claim_hash": claim["record_hash"],
            "knowledge_state": claim["knowledge_state"],
            "support_state": claim_support_by_hash[claim["record_hash"]],
            "subject": claim["subject"],
            "predicate": claim["predicate"],
            "source_episode_id": claim["source_episode_id"],
            "supported_until": claim["supported_until"],
        }
        for claim in latest_claims
    ]

    latest_reasoning_leases = _latest_audit_records(
        validated,
        kind="ReasoningLease",
        id_field="lease_id",
        revision_field="lease_revision",
    )
    reasoning_leases = [
        {
            "lease_id": record["lease_id"],
            "lease_hash": record["record_hash"],
            "owner_episode_id": record["owner_episode_id"],
            "embodiment": record["embodiment"],
            "scope_id": record["scope"]["scope_id"],
            "generation": record["generation"],
            "expected_previous_generation": record["expected_previous_generation"],
            "state": (
                "expired"
                if record["state"] == "active" and record["expires_at"] <= canonical_as_of
                else record["state"]
            ),
            "issued_at": record["issued_at"],
            "expires_at": record["expires_at"],
        }
        for record in latest_reasoning_leases
    ]

    revocation_records = sorted(
        (record for record in validated if record["kind"] == "CapabilityRevocation"),
        key=lambda record: (record["effective_at"], record["revocation_id"]),
    )
    effective_revocations = {
        record["target_revocation_identity"]: record
        for record in revocation_records
        if record["effective_at"] <= canonical_as_of
    }
    capability_lease_records = sorted(
        (record for record in validated if record["kind"] == "CapabilityLease"),
        key=lambda record: (record["issued_at"], record["lease_id"]),
    )
    capability_leases = []
    for record in capability_lease_records:
        state = record["status"]
        if record["revocation_identity"] in effective_revocations:
            state = "revoked"
        elif state == "active" and record["expires_at"] <= canonical_as_of:
            state = "expired"
        capability_leases.append(
            {
                "lease_id": record["lease_id"],
                "lease_hash": record["record_hash"],
                "capability_id": record["capability_id"],
                "audience": record["audience"],
                "permitted_interface": record["permitted_interface"],
                "mode": record["mode"],
                "state": state,
                "issued_at": record["issued_at"],
                "expires_at": record["expires_at"],
            }
        )

    latest_gaps = _latest_audit_records(
        validated,
        kind="CapabilityGap",
        id_field="gap_id",
        revision_field="gap_revision",
    )
    capability_gaps = [
        {
            "gap_id": record["gap_id"],
            "gap_hash": record["record_hash"],
            "source_episode_id": record["source_episode_id"],
            "required_interface": record["required_interface"],
            "status": record["status"],
            "closed_at": record["closed_at"],
        }
        for record in latest_gaps
    ]

    admission_records = sorted(
        (
            record
            for record in validated
            if record["kind"] == "FoundryAdmissionAttestation" and record["issued_at"] <= canonical_as_of
        ),
        key=lambda record: (record["issued_at"], record["admission_id"]),
    )
    foundry_admissions = [
        {
            "admission_id": record["admission_id"],
            "admission_hash": record["record_hash"],
            "job_id": record["job_id"],
            "installation_id": record["installation_id"],
            "image_digest": record["image_digest"],
            "source_revision": record["source_revision"],
            "source_archive_digest": record["source_archive_digest"],
            "dependency_lock_digest": record["dependency_lock_digest"],
            "sbom_digest": record["sbom_digest"],
            "network_policy_digest": record["network_policy_digest"],
            "fixture_bundle_digest": record["fixture_bundle_digest"],
            "denied_capabilities": copy.deepcopy(record["denied_capabilities"]),
            "isolation_checks": copy.deepcopy(record["isolation_checks"]),
            "budget": copy.deepcopy(record["budget"]),
            "wipe_policy": record["wipe_policy"],
            "production_network_access": record["production_network_access"],
            "credential_access": record["credential_access"],
            "admitted": record["admitted"],
            "issued_at": record["issued_at"],
            "expires_at": record["expires_at"],
            "state": (
                "denied"
                if not record["admitted"]
                else "expired"
                if record["expires_at"] <= canonical_as_of
                else "active"
            ),
        }
        for record in admission_records
    ]

    candidate_records = sorted(
        (record for record in validated if record["kind"] == "CapabilityCandidate"),
        key=lambda record: (record["recorded_at"], record["candidate_id"]),
    )
    capability_candidates = [
        {
            "candidate_id": record["candidate_id"],
            "candidate_hash": record["record_hash"],
            "identity_id": record["identity"]["identity_id"],
            "closed_gap_hash": record["closed_gap_hash"],
            "foundry_admission_hash": record["foundry_admission_hash"],
            "source_revision": record["source_revision"],
            "source_digest": record["source_digest"],
            "code_digest": record["code_digest"],
            "dependency_lock_digest": record["dependency_lock_digest"],
            "interface_schema_digest": record["interface_schema_digest"],
            "model": copy.deepcopy(record["model"]),
            "tool_profile_digest": record["tool_profile_digest"],
            "budget": copy.deepcopy(record["budget"]),
            "static_review": copy.deepcopy(record["static_review"]),
            "adversarial_review": copy.deepcopy(record["adversarial_review"]),
            "reviewer": record["reviewer"],
            "reviewer_key_id": record["reviewer_key_id"],
            "signature_bundle_hash": record["signature_bundle_hash"],
            "self_promotion_allowed": record["self_promotion_allowed"],
            "self_install_allowed": record["self_install_allowed"],
            "status": record["status"],
        }
        for record in candidate_records
    ]

    evaluation_records = sorted(
        (record for record in validated if record["kind"] == "CapabilityEvaluation"),
        key=lambda record: (record["recorded_at"], record["evaluation_id"]),
    )
    capability_evaluations = [
        {
            "evaluation_id": record["evaluation_id"],
            "evaluation_hash": record["record_hash"],
            "candidate_hash": record["candidate_hash"],
            "evaluator_attestation_hash": record["evaluator_attestation_hash"],
            "outcome": record["outcome"],
            "terminal_artifact": record["terminal_artifact"],
            "production_accessed": record["production_accessed"],
            "credentials_accessed": record["credentials_accessed"],
        }
        for record in evaluation_records
    ]

    latest_promotions = _latest_audit_records(
        validated,
        kind="CapabilityPromotion",
        id_field="promotion_id",
        revision_field="promotion_revision",
    )
    capability_promotions = [
        {
            "promotion_id": record["promotion_id"],
            "promotion_hash": record["record_hash"],
            "evaluation_hash": record["evaluation_hash"],
            "human_decision": record["human_review"]["decision"],
            "signed_release_present": record["signed_release"] is not None,
            "overlay_selection_present": record["overlay_selection"] is not None,
            "permitted_action": record["permitted_action"],
            "status": record["status"],
            "may_publish": record["may_publish"],
            "may_merge": record["may_merge"],
            "may_install": record["may_install"],
            "may_deploy": record["may_deploy"],
        }
        for record in latest_promotions
    ]

    capability_revocations = [
        {
            "revocation_id": record["revocation_id"],
            "revocation_hash": record["record_hash"],
            "target_revocation_identity": record["target_revocation_identity"],
            "capability_id": record["release"]["capability_id"],
            "effective_at": record["effective_at"],
            "reactive_profile_state": record["reactive_profile_state"],
            "provider_rejection_required": record["provider_rejection_required"],
        }
        for record in revocation_records
    ]

    invocation_records = sorted(
        (record for record in validated if record["kind"] == "CapabilityInvocation"),
        key=lambda record: (record["started_at"], record["invocation_id"]),
    )
    capability_invocations = [
        {
            "invocation_id": record["invocation_id"],
            "invocation_hash": record["record_hash"],
            "capability_id": record["capability_id"],
            "call_index": record["call_index"],
            "disposition": record["disposition"],
            "entry_validation": record["provider_validations"][0]["result"],
            "return_validation": (
                record["provider_validations"][1]["result"] if len(record["provider_validations"]) == 2 else None
            ),
            "started_at": record["started_at"],
            "completed_at": record["completed_at"],
        }
        for record in invocation_records
    ]

    warnings: list[dict[str, Any]] = []
    for claim in claim_support_states:
        if claim["support_state"] in {"stale", "conflicted", "revoked", "unsupported"}:
            warnings.append(
                {
                    "category": claim["support_state"],
                    "code": f"{claim['support_state']}-knowledge-claim",
                    "source_kind": "KnowledgeClaim",
                    "source_id": claim["claim_id"],
                    "source_record_hash": claim["claim_hash"],
                }
            )
    for lease in capability_leases:
        if lease["state"] == "revoked":
            warnings.append(
                {
                    "category": "revoked",
                    "code": "revoked-capability-lease",
                    "source_kind": "CapabilityLease",
                    "source_id": lease["lease_id"],
                    "source_record_hash": lease["lease_hash"],
                }
            )
    for gap in capability_gaps:
        if gap["status"] == "open":
            warnings.append(
                {
                    "category": "pending",
                    "code": "pending-capability-gap",
                    "source_kind": "CapabilityGap",
                    "source_id": gap["gap_id"],
                    "source_record_hash": gap["gap_hash"],
                }
            )
    for promotion_record in capability_promotions:
        if promotion_record["status"] in {"draft", "review_requested"}:
            warnings.append(
                {
                    "category": "pending",
                    "code": "pending-capability-promotion",
                    "source_kind": "CapabilityPromotion",
                    "source_id": promotion_record["promotion_id"],
                    "source_record_hash": promotion_record["promotion_hash"],
                }
            )
    warnings.sort(
        key=lambda warning: (
            warning["category"],
            warning["source_kind"],
            warning["source_id"],
            warning["source_record_hash"],
        )
    )

    return {
        "vocabulary": {
            "record_selection": "latest-revision-per-logical-id-then-record-hash",
            "time_basis": "fixed-as-of-inclusive-utc",
            "claim_support_states": list(CLAIM_SUPPORT_STATES),
            "warning_categories": list(WARNING_CATEGORIES),
        },
        "identity_timeline": identity_timeline,
        "attested_embodiments": attested_embodiments,
        "episodes": episodes,
        "handoffs": handoffs,
        "claim_support_states": claim_support_states,
        "reasoning_leases": reasoning_leases,
        "capability_leases": capability_leases,
        "capability_gaps": capability_gaps,
        "foundry_admissions": foundry_admissions,
        "capability_candidates": capability_candidates,
        "capability_evaluations": capability_evaluations,
        "capability_promotions": capability_promotions,
        "capability_revocations": capability_revocations,
        "capability_invocations": capability_invocations,
        "warnings": warnings,
    }


_OPERATIONAL_TIMESTAMP_FIELDS = frozenset(
    {
        "closed_at",
        "completed_at",
        "created_at",
        "effective_at",
        "ended_at",
        "issued_at",
        "observed_at",
        "reviewed_at",
        "selected_at",
        "signed_at",
        "started_at",
        "validated_at",
    }
)


def _identity_key(record: Mapping[str, Any]) -> tuple[str, int, int]:
    identity = record["identity"]
    return (
        identity["identity_id"],
        identity["identity_revision"],
        identity["identity_epoch"],
    )


def _validate_record_relationships(records: Sequence[Mapping[str, Any]], *, as_of: str) -> None:
    """Replay the closed synthetic Chronicle graph without granting authority."""

    canonical_as_of = _timestamp(as_of, "$.as_of")
    ordered_keys = [(record["recorded_at"], record["record_id"]) for record in records]
    if ordered_keys != sorted(ordered_keys):
        raise _fail("$.records", "records are not in canonical chronology and record-id order")

    by_hash = {record["record_hash"]: record for record in records}
    index_by_hash = {record["record_hash"]: index for index, record in enumerate(records)}

    def record_error(record: Mapping[str, Any], message: str, field: str | None = None) -> AuditProjectionError:
        suffix = f".{field}" if field is not None else ""
        return _fail(f"$.records[{index_by_hash[record['record_hash']]}]{suffix}", message)

    def require_reference(
        record: Mapping[str, Any],
        reference_hash: str,
        expected_kind: str,
        *,
        field: str,
        operational_at: str | None = None,
    ) -> Mapping[str, Any]:
        reference = by_hash.get(reference_hash)
        if reference is None or reference["kind"] != expected_kind:
            raise record_error(record, f"does not reference a present {expected_kind}", field)
        boundary = operational_at or record["recorded_at"]
        if reference["recorded_at"] > record["recorded_at"] or reference["recorded_at"] > boundary:
            raise record_error(record, f"references a non-causal {expected_kind}", field)
        return reference

    def check_operational_times(record: Mapping[str, Any]) -> None:
        recorded_at = record["recorded_at"]
        observed_times: list[tuple[str, str]] = []

        def walk(value: Any, path: str) -> None:
            if isinstance(value, Mapping):
                for key, nested in value.items():
                    nested_path = f"{path}.{key}"
                    if key in _OPERATIONAL_TIMESTAMP_FIELDS and nested is not None:
                        timestamp = _timestamp(nested, nested_path)
                        if timestamp > canonical_as_of:
                            raise _fail(nested_path, "operational timestamp is after the fixed as_of")
                        if timestamp > recorded_at:
                            raise _fail(nested_path, "operational timestamp postdates its Chronicle record")
                        if key == "observed_at":
                            observed_times.append((nested_path, timestamp))
                    walk(nested, nested_path)
            elif isinstance(value, list):
                for item_index, nested in enumerate(value):
                    walk(nested, f"{path}[{item_index}]")

        walk(record, f"$.records[{index_by_hash[record['record_hash']]}]")
        evidence_boundary = (
            record["ended_at"]
            if record["kind"] == "AgentEpisode" and record["ended_at"] is not None
            else record["issued_at"]
            if record["kind"] == "AgentHandoff"
            else record["effective_at"]
            if record["kind"] == "CapabilityRevocation"
            else recorded_at
        )
        for observed_path, observed_at in observed_times:
            if observed_at > evidence_boundary:
                raise _fail(observed_path, "embedded evidence postdates its causal use")

    for record in records:
        check_operational_times(record)

    constitutions: dict[str, Mapping[str, Any]] = {}
    constitution_by_hash: dict[str, Mapping[str, Any]] = {}
    descriptors: dict[str, Mapping[str, Any]] = {}
    revisions: dict[str, list[Mapping[str, Any]]] = {}

    for record in records:
        if record["kind"] == "AgentConstitution":
            previous = constitutions.get(record["constitution_id"])
            installations = record["supported_installations"]
            installation_ids = [item["installation_id"] for item in installations]
            if (
                record["provenance_state"] != "externally-authenticated"
                or record["status"] != "active"
                or len(installation_ids) != len(set(installation_ids))
                or any(item["embodiment"] not in record["supported_installation_classes"] for item in installations)
            ):
                raise record_error(record, "constitution is not an active, closed installation policy")
            if previous is None:
                if record["constitution_revision"] != 1 or record["prior_constitution_hash"] is not None:
                    raise record_error(record, "initial constitution chain is invalid")
            elif (
                record["constitution_revision"] != previous["constitution_revision"] + 1
                or record["prior_constitution_hash"] != previous["record_hash"]
                or record["owner_id"] != previous["owner_id"]
                or record["effective_at"] < previous["effective_at"]
                or record["recorded_at"] < previous["recorded_at"]
            ):
                raise record_error(record, "constitution revision chain is invalid")
            constitutions[record["constitution_id"]] = record
            constitution_by_hash[record["record_hash"]] = record
        elif record["kind"] == "AgentIdentityDescriptor":
            if record["identity_id"] in descriptors:
                raise record_error(record, "immutable identity descriptor is duplicated")
            constitution = constitution_by_hash.get(record["constitution_hash"])
            if (
                constitution is None
                or constitution["recorded_at"] > record["created_at"]
                or record["owner_id"] != constitution["owner_id"]
                or record["status"] != "active"
                or record["provenance_state"] != "externally-authenticated"
                or not set(record["permitted_embodiments"]).issubset(
                    set(constitution["supported_installation_classes"])
                )
                or AUTHORITY_MODE_RANK[record["maximum_authority_mode"]]
                > AUTHORITY_MODE_RANK[constitution["authority_ceiling"]["maximum_mode"]]
            ):
                raise record_error(record, "identity descriptor exceeds or predates its constitution")
            descriptors[record["identity_id"]] = record
        elif record["kind"] == "AgentIdentityRevision":
            identity_id = record["identity"]["identity_id"]
            descriptor = descriptors.get(identity_id)
            constitution = constitution_by_hash.get(record["constitution_hash"])
            history = revisions.setdefault(identity_id, [])
            previous = history[-1] if history else None
            if (
                descriptor is None
                or constitution is None
                or record["status"] != "active"
                or record["provenance_state"] != "externally-authenticated"
                or descriptor["owner_id"] != constitution["owner_id"]
                or descriptor["recorded_at"] > record["effective_at"]
                or constitution["recorded_at"] > record["effective_at"]
            ):
                raise record_error(record, "identity revision has no causal active descriptor and constitution")
            if previous is None:
                if (
                    record["identity"]["identity_revision"] != descriptor["initial_identity_revision"]
                    or record["identity"]["identity_epoch"] != descriptor["initial_identity_epoch"]
                    or record["prior_revision_hash"] is not None
                    or record["constitution_hash"] != descriptor["constitution_hash"]
                ):
                    raise record_error(record, "initial identity revision does not match its descriptor")
            else:
                previous_identity = previous["identity"]
                same_epoch = (
                    record["identity"]["identity_epoch"] == previous_identity["identity_epoch"]
                    and record["identity"]["identity_revision"] == previous_identity["identity_revision"] + 1
                )
                next_epoch = (
                    record["identity"]["identity_epoch"] == previous_identity["identity_epoch"] + 1
                    and record["identity"]["identity_revision"] == 1
                )
                if (
                    not (same_epoch or next_epoch)
                    or record["prior_revision_hash"] != previous["record_hash"]
                    or record["effective_at"] < previous["effective_at"]
                    or record["recorded_at"] < previous["recorded_at"]
                ):
                    raise record_error(record, "identity revision or epoch chain is invalid")
            history.append(record)

    if set(descriptors) != set(revisions):
        raise _fail("$.records", "every identity descriptor must have a materialized revision")

    def current_identity(
        record: Mapping[str, Any],
        *,
        operational_at: str | None = None,
        allow_foundry_runtime: bool = False,
    ) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
        identity_id = record["identity"]["identity_id"]
        if identity_id != "platform-steward" and not (
            allow_foundry_runtime
            and record["kind"] == "RuntimeAttestation"
            and identity_id == "platform-foundry-evaluator"
        ):
            raise record_error(record, "operational record is owned by an unsupported identity", "identity")
        descriptor = descriptors.get(identity_id)
        boundary = operational_at or record["recorded_at"]
        applicable = [
            revision
            for revision in revisions.get(identity_id, [])
            if revision["recorded_at"] <= record["recorded_at"] and revision["effective_at"] <= boundary
        ]
        if descriptor is None or not applicable:
            raise record_error(record, "identity head is not materialized before this operation", "identity")
        revision = applicable[-1]
        if _identity_key(record) != _identity_key(revision):
            raise record_error(record, "identity revision or epoch does not match the causal identity head", "identity")
        constitution = constitution_by_hash.get(revision["constitution_hash"])
        if (
            constitution is None
            or descriptor["recorded_at"] > boundary
            or revision["recorded_at"] > boundary
            or constitution["recorded_at"] > boundary
        ):
            raise record_error(record, "identity references are not causal", "identity")
        return descriptor, revision, constitution

    admissions_by_hash: dict[str, Mapping[str, Any]] = {}
    admission_ids: set[str] = set()
    foundry_jobs: set[str] = set()
    attestations_by_hash: dict[str, Mapping[str, Any]] = {}
    attestation_ids: set[str] = set()
    sessions: set[str] = set()
    reasoning_heads: dict[str, Mapping[str, Any]] = {}
    reasoning_nonce_owners: dict[tuple[str, str], str] = {}
    active_reasoning: dict[bytes, Mapping[str, Any]] = {}
    scope_generations: dict[bytes, int] = {}
    episode_heads: dict[str, Mapping[str, Any]] = {}
    handoff_heads: dict[str, Mapping[str, Any]] = {}
    claim_heads: dict[str, Mapping[str, Any]] = {}
    gap_heads: dict[str, Mapping[str, Any]] = {}
    candidates_by_hash: dict[str, Mapping[str, Any]] = {}
    candidate_ids: set[str] = set()
    evaluations_by_hash: dict[str, Mapping[str, Any]] = {}
    evaluation_ids: set[str] = set()
    promotion_heads: dict[str, Mapping[str, Any]] = {}
    approved_selections: dict[str, Mapping[str, Any]] = {}
    capability_leases_by_hash: dict[str, Mapping[str, Any]] = {}
    capability_lease_ids: set[str] = set()
    capability_nonces: set[tuple[str, str]] = set()
    revocations_by_release: dict[bytes, Mapping[str, Any]] = {}
    revocation_ids: set[str] = set()
    invocation_ids: set[str] = set()
    invocation_nonces: set[tuple[str, str]] = set()
    invocation_indices: set[tuple[str, int]] = set()
    settled_usage: dict[str, dict[str, int]] = {}

    reasoning_immutable = (
        "identity",
        "runtime_attestation_hash",
        "runtime_installation_id",
        "scope",
        "issuer",
        "issuer_key_id",
        "audience",
        "issued_at",
        "expires_at",
        "nonce",
        "budget",
        "revocation_identity",
        "evidence_preconditions",
        "owner_episode_id",
        "embodiment",
        "interface_id",
        "mode",
        "generation",
        "expected_previous_generation",
    )

    for record in records:
        kind = record["kind"]
        if kind in {"AgentConstitution", "AgentIdentityDescriptor", "AgentIdentityRevision"}:
            continue

        if kind == "FoundryAdmissionAttestation":
            if record["admission_id"] in admission_ids or record["job_id"] in foundry_jobs:
                raise record_error(record, "Foundry admission or job identifier is duplicated")
            if not record["issued_at"] <= record["recorded_at"] < record["expires_at"]:
                raise record_error(record, "Foundry admission validity window is invalid")
            check_names = [check["name"] for check in record["isolation_checks"]]
            if (
                set(record["denied_capabilities"]) != set(FOUNDRY_DENIED_CAPABILITIES)
                or len(check_names) != len(set(check_names))
                or set(check_names) != set(FOUNDRY_ISOLATION_CHECK_NAMES)
                or any(check["status"] != "passed" for check in record["isolation_checks"])
                or record["production_network_access"]
                or record["credential_access"]
            ):
                raise record_error(record, "Foundry isolation admission is incomplete")
            admission_ids.add(record["admission_id"])
            foundry_jobs.add(record["job_id"])
            admissions_by_hash[record["record_hash"]] = record
            continue

        if kind == "RuntimeAttestation":
            descriptor, revision, constitution = current_identity(
                record,
                operational_at=record["issued_at"],
                allow_foundry_runtime=True,
            )
            if record["attestation_id"] in attestation_ids or record["session_id"] in sessions:
                raise record_error(record, "runtime attestation or session identifier is duplicated")
            expected_host = {
                "server-sentinel": "near-platform-server",
                "mac-engineer": "local-mac",
                "foundry-replay": "ephemeral-foundry",
            }[record["embodiment"]]
            if (
                record["embodiment"] not in descriptor["permitted_embodiments"]
                or record["embodiment"] not in constitution["supported_installation_classes"]
                or record["host_class"] != expected_host
                or record["identity_descriptor_hash"] != descriptor["record_hash"]
                or record["identity_revision_hash"] != revision["record_hash"]
                or record["constitution_hash"] != constitution["record_hash"]
                or not record["issued_at"] <= record["recorded_at"] < record["expires_at"]
            ):
                raise record_error(record, "runtime attestation identity, embodiment, or validity binding is invalid")
            if record["embodiment"] != "foundry-replay":
                installation = next(
                    (
                        item
                        for item in constitution["supported_installations"]
                        if item["installation_id"] == record["installation_id"]
                    ),
                    None,
                )
                if (
                    record["dynamic_cordis_allowed"]
                    or record["isolation_admission_hash"] is not None
                    or installation is None
                    or installation["embodiment"] != record["embodiment"]
                    or installation["host_class"] != record["host_class"]
                    or installation["admission_state"] != "admitted"
                    or not installation["runtime_enabled"]
                ):
                    raise record_error(record, "non-Foundry runtime is not enabled by its constitution")
            else:
                if record["identity"]["identity_id"] != "platform-foundry-evaluator":
                    raise record_error(record, "platform-steward cannot use the foundry-replay embodiment")
                admission = admissions_by_hash.get(record["isolation_admission_hash"])
                if (
                    admission is None
                    or not admission["admitted"]
                    or not record["dynamic_cordis_allowed"]
                    or admission["installation_id"] != record["installation_id"]
                    or admission["issued_at"] > record["issued_at"]
                    or admission["recorded_at"] > record["issued_at"]
                    or admission["expires_at"] < record["expires_at"]
                ):
                    raise record_error(record, "Foundry runtime lacks an exact admitted isolation record")
            attestation_ids.add(record["attestation_id"])
            sessions.add(record["session_id"])
            attestations_by_hash[record["record_hash"]] = record
            continue

        if kind == "ReasoningLease":
            _, revision, constitution = current_identity(record, operational_at=record["issued_at"])
            attestation = require_reference(
                record,
                record["runtime_attestation_hash"],
                "RuntimeAttestation",
                field="runtime_attestation_hash",
                operational_at=record["issued_at"],
            )
            if (
                attestation["record_hash"] not in attestations_by_hash
                or _identity_key(attestation) != _identity_key(record)
                or record["identity_revision_hash"] != revision["record_hash"]
                or record["constitution_hash"] != constitution["record_hash"]
                or attestation["identity_revision_hash"] != revision["record_hash"]
                or attestation["constitution_hash"] != constitution["record_hash"]
                or attestation["installation_id"] != record["runtime_installation_id"]
                or attestation["embodiment"] != record["embodiment"]
                or record["audience"] != "platform-steward"
                or attestation["issued_at"] > record["issued_at"]
                or attestation["expires_at"] < record["expires_at"]
                or record["issued_at"] >= record["expires_at"]
            ):
                raise record_error(record, "reasoning lease is not bound to its causal runtime and identity")
            scope_key = canonical_json_bytes(record["scope"])
            previous = reasoning_heads.get(record["lease_id"])
            nonce_key = (record["issuer"], record["nonce"])
            nonce_owner = reasoning_nonce_owners.get(nonce_key)
            if nonce_owner is not None and nonce_owner != record["lease_id"]:
                raise record_error(record, "reasoning lease issuer nonce was replayed")
            if previous is None:
                previous_generation = scope_generations.get(scope_key, 0)
                if (
                    record["state"] != "active"
                    or record["lease_revision"] != 1
                    or record["prior_lease_hash"] is not None
                    or not record["issued_at"] <= record["recorded_at"] < record["expires_at"]
                    or scope_key in active_reasoning
                    or record["expected_previous_generation"] != previous_generation
                    or record["generation"] != previous_generation + 1
                ):
                    raise record_error(record, "reasoning lease compare-and-swap ownership is invalid")
            elif (
                previous["state"] != "active"
                or record["state"] == "active"
                or record["lease_revision"] != previous["lease_revision"] + 1
                or record["prior_lease_hash"] != previous["record_hash"]
                or any(record[field] != previous[field] for field in reasoning_immutable)
                or (record["state"] == "expired" and record["recorded_at"] < record["expires_at"])
                or (record["state"] != "expired" and record["recorded_at"] >= record["expires_at"])
                or active_reasoning.get(scope_key, {}).get("record_hash") != previous["record_hash"]
            ):
                raise record_error(record, "reasoning lease terminal revision is invalid")
            if previous is not None and record["state"] == "released":
                pending_transfers = [
                    handoff
                    for handoff in handoff_heads.values()
                    if handoff["terminal_disposition"] == "pending"
                    and handoff["source_episode_id"] == record["owner_episode_id"]
                    and handoff["source_reasoning_lease_hash"] == previous["record_hash"]
                ]
                if pending_transfers:
                    owner_episode = episode_heads.get(record["owner_episode_id"])
                    transfer = pending_transfers[0]
                    if (
                        len(pending_transfers) != 1
                        or owner_episode is None
                        or owner_episode["terminal_disposition"] != "handed_off"
                        or owner_episode["ended_at"] != transfer["issued_at"]
                        or transfer["recorded_at"] > owner_episode["recorded_at"]
                        or owner_episode["recorded_at"] > record["recorded_at"]
                    ):
                        raise record_error(record, "handoff reasoning-lease release is out of causal order")
            reasoning_nonce_owners.setdefault(nonce_key, record["lease_id"])
            reasoning_heads[record["lease_id"]] = record
            scope_generations[scope_key] = record["generation"]
            if record["state"] == "active":
                active_reasoning[scope_key] = record
            else:
                active_reasoning.pop(scope_key, None)
            continue

        if kind == "AgentEpisode":
            current_identity(record, operational_at=record["started_at"])
            attestation = require_reference(
                record,
                record["runtime_attestation_hash"],
                "RuntimeAttestation",
                field="runtime_attestation_hash",
                operational_at=record["started_at"],
            )
            lease = require_reference(
                record,
                record["reasoning_lease_hash"],
                "ReasoningLease",
                field="reasoning_lease_hash",
                operational_at=record["started_at"],
            )
            if (
                lease["state"] != "active"
                or _identity_key(record) != _identity_key(attestation)
                or _identity_key(record) != _identity_key(lease)
                or record["actual_model"] != attestation["model"]
                or record["embodiment"] != attestation["embodiment"]
                or record["episode_id"] != lease["owner_episode_id"]
                or record["scope"] != lease["scope"]
                or not lease["issued_at"] <= record["started_at"] < lease["expires_at"]
                or not attestation["issued_at"] <= record["started_at"] < attestation["expires_at"]
            ):
                raise record_error(record, "episode is not exactly bound to its runtime and reasoning lease")
            previous = episode_heads.get(record["episode_id"])
            if previous is None:
                if (
                    record["episode_revision"] != 1
                    or record["prior_episode_hash"] is not None
                    or active_reasoning.get(canonical_json_bytes(record["scope"]), {}).get("record_hash")
                    != lease["record_hash"]
                ):
                    raise record_error(record, "new episode does not own the active reasoning lease")
                if record["parent_episode_id"] is not None:
                    parent = episode_heads.get(record["parent_episode_id"])
                    if parent is None or parent["recorded_at"] > record["started_at"]:
                        raise record_error(record, "parent episode is absent or non-causal", "parent_episode_id")
                if record["handoff_id"] is not None:
                    episode_transfer = handoff_heads.get(record["handoff_id"])
                    parent = episode_heads.get(record["parent_episode_id"])
                    source_active = (
                        by_hash.get(episode_transfer["source_reasoning_lease_hash"])
                        if episode_transfer is not None
                        else None
                    )
                    source_release = (
                        reasoning_heads.get(source_active["lease_id"])
                        if source_active is not None and source_active["kind"] == "ReasoningLease"
                        else None
                    )
                    if (
                        episode_transfer is None
                        or episode_transfer["terminal_disposition"] != "pending"
                        or parent is None
                        or parent["terminal_disposition"] != "handed_off"
                        or source_active is None
                        or source_active["kind"] != "ReasoningLease"
                        or source_release is None
                        or source_release["state"] != "released"
                        or source_release["prior_lease_hash"] != source_active["record_hash"]
                        or episode_transfer["target_embodiment"] != record["embodiment"]
                        or episode_transfer["target_installation_id"] != attestation["installation_id"]
                        or episode_transfer["source_episode_id"] != record["parent_episode_id"]
                        or parent["scope"] != record["scope"]
                        or parent["ended_at"] != episode_transfer["issued_at"]
                        or not episode_transfer["recorded_at"]
                        <= parent["recorded_at"]
                        <= source_release["recorded_at"]
                        <= lease["recorded_at"]
                        <= record["recorded_at"]
                    ):
                        raise record_error(record, "target episode is not exactly bound to a pending handoff")
            else:
                authority_expiry = min(lease["expires_at"], attestation["expires_at"])
                episode_invariant_fields = (
                    "identity",
                    "parent_episode_id",
                    "handoff_id",
                    "runtime_attestation_hash",
                    "reasoning_lease_hash",
                    "embodiment",
                    "scope",
                    "actual_model",
                    "objective_hash",
                    "started_at",
                    "transcript_included",
                )
                if (
                    previous["terminal_disposition"] is not None
                    or record["episode_revision"] != previous["episode_revision"] + 1
                    or record["prior_episode_hash"] != previous["record_hash"]
                    or record["terminal_disposition"] is None
                    or any(record[field] != previous[field] for field in episode_invariant_fields)
                    or record["evidence"][: len(previous["evidence"])] != previous["evidence"]
                    or record["ended_at"] < record["started_at"]
                    or record["ended_at"] < previous["recorded_at"]
                    or (
                        record["terminal_disposition"] == "expired"
                        and (record["ended_at"] < authority_expiry or record["recorded_at"] < authority_expiry)
                    )
                    or (
                        record["terminal_disposition"] != "expired"
                        and (
                            record["ended_at"] >= lease["expires_at"]
                            or record["ended_at"] >= attestation["expires_at"]
                            or record["recorded_at"] > lease["expires_at"]
                            or record["recorded_at"] > attestation["expires_at"]
                        )
                    )
                ):
                    raise record_error(record, "episode terminal revision or provenance is invalid")
                if record["terminal_disposition"] == "handed_off":
                    pending_transfers = [
                        handoff
                        for handoff in handoff_heads.values()
                        if handoff["terminal_disposition"] == "pending"
                        and handoff["source_episode_id"] == record["episode_id"]
                        and handoff["source_reasoning_lease_hash"] == record["reasoning_lease_hash"]
                    ]
                    if (
                        len(pending_transfers) != 1
                        or pending_transfers[0]["recorded_at"] > record["recorded_at"]
                        or record["ended_at"] != pending_transfers[0]["issued_at"]
                    ):
                        raise record_error(record, "handed-off episode end is not bound to its pending handoff")
            episode_heads[record["episode_id"]] = record
            continue

        if kind == "AgentHandoff":
            current_identity(record, operational_at=record["issued_at"])
            source_episode = episode_heads.get(record["source_episode_id"])
            source_lease = require_reference(
                record,
                record["source_reasoning_lease_hash"],
                "ReasoningLease",
                field="source_reasoning_lease_hash",
                operational_at=record["issued_at"],
            )
            if (
                source_episode is None
                or source_episode["reasoning_lease_hash"] != source_lease["record_hash"]
                or _identity_key(source_episode) != _identity_key(record)
                or source_episode["recorded_at"] > record["issued_at"]
                or record["issued_at"] >= record["expires_at"]
                or (record["terminal_disposition"] == "expired" and record["recorded_at"] < record["expires_at"])
                or (record["terminal_disposition"] != "expired" and record["recorded_at"] >= record["expires_at"])
            ):
                raise record_error(record, "handoff source episode, lease, or chronology is invalid")
            previous = handoff_heads.get(record["handoff_id"])
            if previous is None:
                if (
                    record["handoff_revision"] != 1
                    or record["prior_handoff_hash"] is not None
                    or record["terminal_disposition"] != "pending"
                    or record["accepted_episode_id"] is not None
                    or source_lease["state"] != "active"
                    or reasoning_heads.get(source_lease["lease_id"], {}).get("record_hash")
                    != source_lease["record_hash"]
                    or any(claim_id not in claim_heads for claim_id in record["claim_ids"])
                    or any(gap_id not in gap_heads for gap_id in record["capability_gap_ids"])
                    or any(
                        claim_heads[claim_id]["recorded_at"] > record["issued_at"] for claim_id in record["claim_ids"]
                    )
                    or any(
                        gap_heads[gap_id]["recorded_at"] > record["issued_at"]
                        for gap_id in record["capability_gap_ids"]
                    )
                ):
                    raise record_error(record, "new handoff must be pending from the active source owner")
            else:
                handoff_invariant_fields = (
                    "identity",
                    "source_episode_id",
                    "source_reasoning_lease_hash",
                    "target_embodiment",
                    "target_installation_id",
                    "evidence",
                    "claim_ids",
                    "capability_gap_ids",
                    "summary_artifact_hash",
                    "transcript_included",
                    "issued_at",
                    "expires_at",
                )
                if (
                    previous["terminal_disposition"] != "pending"
                    or record["handoff_revision"] != previous["handoff_revision"] + 1
                    or record["prior_handoff_hash"] != previous["record_hash"]
                    or any(record[field] != previous[field] for field in handoff_invariant_fields)
                ):
                    raise record_error(record, "handoff revision chain or immutable binding changed")
                if record["terminal_disposition"] == "accepted":
                    target_episode = episode_heads.get(record["accepted_episode_id"])
                    latest_source = episode_heads.get(record["source_episode_id"])
                    latest_source_lease = reasoning_heads.get(source_lease["lease_id"])
                    if target_episode is None:
                        raise record_error(record, "accepted handoff target episode is absent", "accepted_episode_id")
                    target_lease = by_hash.get(target_episode["reasoning_lease_hash"])
                    target_attestation = attestations_by_hash.get(target_episode["runtime_attestation_hash"])
                    if (
                        latest_source is None
                        or latest_source["terminal_disposition"] != "handed_off"
                        or latest_source["ended_at"] != previous["issued_at"]
                        or latest_source_lease is None
                        or latest_source_lease["state"] != "released"
                        or latest_source_lease["prior_lease_hash"] != source_lease["record_hash"]
                        or target_episode["handoff_id"] != record["handoff_id"]
                        or target_episode["parent_episode_id"] != record["source_episode_id"]
                        or target_lease is None
                        or target_lease["kind"] != "ReasoningLease"
                        or target_lease["state"] != "active"
                        or target_lease["scope"] != source_lease["scope"]
                        or target_lease["generation"] != source_lease["generation"] + 1
                        or target_lease["expected_previous_generation"] != source_lease["generation"]
                        or active_reasoning.get(canonical_json_bytes(source_lease["scope"]), {}).get("record_hash")
                        != target_lease["record_hash"]
                        or target_attestation is None
                        or target_attestation["embodiment"] != record["target_embodiment"]
                        or target_attestation["installation_id"] != record["target_installation_id"]
                        or not previous["recorded_at"]
                        <= latest_source["recorded_at"]
                        <= latest_source_lease["recorded_at"]
                        <= target_lease["recorded_at"]
                        <= target_episode["recorded_at"]
                        <= record["recorded_at"]
                    ):
                        raise record_error(record, "accepted handoff is not bound to an exact lease transfer")
                elif (
                    record["terminal_disposition"] not in {"rejected", "expired"}
                    or record["accepted_episode_id"] is not None
                ):
                    raise record_error(record, "handoff terminal disposition is invalid")
            handoff_heads[record["handoff_id"]] = record
            continue

        if kind == "KnowledgeClaim":
            current_identity(record)
            source_episode = episode_heads.get(record["source_episode_id"])
            previous = claim_heads.get(record["claim_id"])
            if (
                source_episode is None
                or _identity_key(source_episode) != _identity_key(record)
                or source_episode["recorded_at"] > record["recorded_at"]
            ):
                raise record_error(record, "knowledge claim source episode is absent or mismatched")
            if previous is None:
                if (
                    record["claim_revision"] != 1
                    or record["prior_claim_hash"] is not None
                    or record["knowledge_state"] != "observed"
                    or record["supersedes_claim_hash"] is not None
                ):
                    raise record_error(record, "new knowledge claim must begin observed")
            else:
                claim_invariant_fields = (
                    "source_episode_id",
                    "source_domain",
                    "subject",
                    "predicate",
                    "statement_hash",
                    "evidence",
                    "evidence_preconditions",
                    "supported_until",
                )
                if (
                    record["claim_revision"] != previous["claim_revision"] + 1
                    or record["prior_claim_hash"] != previous["record_hash"]
                    or record["knowledge_state"] not in KNOWLEDGE_TRANSITIONS[previous["knowledge_state"]]
                    or any(record[field] != previous[field] for field in claim_invariant_fields)
                    or (
                        record["knowledge_state"] == "superseded"
                        and record["supersedes_claim_hash"] != previous["record_hash"]
                    )
                    or (record["knowledge_state"] != "superseded" and record["supersedes_claim_hash"] is not None)
                ):
                    raise record_error(record, "illegal knowledge-state promotion")
            claim_heads[record["claim_id"]] = record
            continue

        if kind == "CapabilityGap":
            current_identity(record)
            source_episode = episode_heads.get(record["source_episode_id"])
            previous = gap_heads.get(record["gap_id"])
            if (
                source_episode is None
                or _identity_key(source_episode) != _identity_key(record)
                or source_episode["scope"] != record["scope"]
            ):
                raise record_error(record, "capability gap is not bound to its source episode")
            if any(gap_id not in gap_heads for gap_id in record["recurring_gap_ids"]):
                raise record_error(record, "capability gap recurrence target is absent")
            if previous is None:
                if record["gap_revision"] != 1 or record["prior_gap_hash"] is not None or record["status"] != "open":
                    raise record_error(record, "new capability gap must begin open")
            else:
                gap_invariant_fields = (
                    "source_episode_id",
                    "scope",
                    "title",
                    "description",
                    "required_interface",
                    "required_interface_schema_digest",
                    "evidence",
                    "recurring_gap_ids",
                )
                if (
                    previous["status"] != "open"
                    or record["gap_revision"] != previous["gap_revision"] + 1
                    or record["prior_gap_hash"] != previous["record_hash"]
                    or record["status"] not in {"closed", "superseded", "revoked"}
                    or any(record[field] != previous[field] for field in gap_invariant_fields)
                    or record["closed_at"] < previous["recorded_at"]
                ):
                    raise record_error(record, "capability gap revision chain is invalid")
            gap_heads[record["gap_id"]] = record
            continue

        if kind == "CapabilityCandidate":
            current_identity(record)
            if record["candidate_id"] in candidate_ids:
                raise record_error(record, "capability candidate identifier is duplicated")
            gap = require_reference(record, record["closed_gap_hash"], "CapabilityGap", field="closed_gap_hash")
            admission = require_reference(
                record,
                record["foundry_admission_hash"],
                "FoundryAdmissionAttestation",
                field="foundry_admission_hash",
            )
            if (
                gap["status"] != "closed"
                or gap_heads.get(gap["gap_id"], {}).get("record_hash") != gap["record_hash"]
                or admission["record_hash"] not in admissions_by_hash
                or not admission["admitted"]
                or admission["expires_at"] <= record["recorded_at"]
                or record["source_revision"] != admission["source_revision"]
                or record["source_digest"] != admission["source_archive_digest"]
                or record["dependency_lock_digest"] != admission["dependency_lock_digest"]
                or record["budget"]["maximum_tokens"] > admission["budget"]["maximum_tokens"]
                or record["interface_schema_digest"] != gap["required_interface_schema_digest"]
            ):
                raise record_error(record, "capability candidate gap or Foundry admission binding is invalid")
            candidate_ids.add(record["candidate_id"])
            candidates_by_hash[record["record_hash"]] = record
            continue

        if kind == "CapabilityEvaluation":
            current_identity(record)
            if record["evaluation_id"] in evaluation_ids:
                raise record_error(record, "capability evaluation identifier is duplicated")
            candidate = require_reference(
                record, record["candidate_hash"], "CapabilityCandidate", field="candidate_hash"
            )
            gap = require_reference(record, record["closed_gap_hash"], "CapabilityGap", field="closed_gap_hash")
            admission = require_reference(
                record,
                record["foundry_admission_hash"],
                "FoundryAdmissionAttestation",
                field="foundry_admission_hash",
            )
            evaluator = require_reference(
                record,
                record["evaluator_attestation_hash"],
                "RuntimeAttestation",
                field="evaluator_attestation_hash",
            )
            deterministic_names = [gate["name"] for gate in record["deterministic_gates"]]
            security_names = [gate["name"] for gate in record["security_gates"]]
            all_gates = [*record["deterministic_gates"], *record["security_gates"]]
            role_principals = (
                admission["issuer"],
                candidate["reviewer"],
                evaluator["issuer"],
                record["issuer"],
            )
            role_keys = (
                admission["signer_key_id"],
                candidate["reviewer_key_id"],
                evaluator["signer_key_id"],
                record["signer_key_id"],
            )
            if (
                candidate["record_hash"] not in candidates_by_hash
                or gap["status"] != "closed"
                or admission["record_hash"] not in admissions_by_hash
                or evaluator["record_hash"] not in attestations_by_hash
                or evaluator["embodiment"] != "foundry-replay"
                or evaluator["isolation_admission_hash"] != record["foundry_admission_hash"]
                or evaluator["model"] != record["evaluator_model"]
                or evaluator["identity"]["identity_id"] == record["identity"]["identity_id"]
                or evaluator["expires_at"] <= record["recorded_at"]
                or candidate["closed_gap_hash"] != record["closed_gap_hash"]
                or candidate["foundry_admission_hash"] != record["foundry_admission_hash"]
                or candidate["interface_schema_digest"] != gap["required_interface_schema_digest"]
                or not admission["admitted"]
                or admission["expires_at"] <= record["recorded_at"]
                or record["fixture_bundle_digest"] != admission["fixture_bundle_digest"]
                or candidate["source_revision"] != admission["source_revision"]
                or candidate["source_digest"] != admission["source_archive_digest"]
                or candidate["dependency_lock_digest"] != admission["dependency_lock_digest"]
                or len(deterministic_names) != len(set(deterministic_names))
                or set(deterministic_names) != set(DETERMINISTIC_GATE_NAMES)
                or len(security_names) != len(set(security_names))
                or set(security_names) != set(SECURITY_GATE_NAMES)
                or len(set(role_principals)) != len(role_principals)
                or len(set(role_keys)) != len(role_keys)
            ):
                raise record_error(record, "capability evaluation provenance graph or gate manifest is invalid")
            candidate_reviews_pass = (
                all(candidate[field]["status"] == "passed" for field in ("static_review", "adversarial_review"))
                and candidate["status"] == "evaluated"
            )
            gates_pass = all(gate["status"] == "passed" for gate in all_gates)
            if record["outcome"] == "passed":
                if (
                    not candidate_reviews_pass
                    or not gates_pass
                    or record["terminal_artifact"] != "draft_promotion_artifact"
                ):
                    raise record_error(record, "passed evaluation is not derived from every required gate")
            elif record["terminal_artifact"] != "investigation_artifact":
                raise record_error(record, "failed or ambiguous evaluation may only produce an investigation")
            evaluation_ids.add(record["evaluation_id"])
            evaluations_by_hash[record["record_hash"]] = record
            continue

        if kind == "CapabilityPromotion":
            current_identity(record)
            evaluation = require_reference(
                record, record["evaluation_hash"], "CapabilityEvaluation", field="evaluation_hash"
            )
            candidate = require_reference(
                record, record["candidate_hash"], "CapabilityCandidate", field="candidate_hash"
            )
            gap = require_reference(record, record["closed_gap_hash"], "CapabilityGap", field="closed_gap_hash")
            if (
                evaluation["record_hash"] not in evaluations_by_hash
                or evaluation["outcome"] != "passed"
                or evaluation["terminal_artifact"] != "draft_promotion_artifact"
                or candidate["record_hash"] not in candidates_by_hash
                or gap["status"] != "closed"
                or evaluation["candidate_hash"] != record["candidate_hash"]
                or evaluation["closed_gap_hash"] != record["closed_gap_hash"]
                or candidate["closed_gap_hash"] != record["closed_gap_hash"]
                or record["permitted_action"] != "draft_pr_request"
                or record["draft_pr_request_hash"] is None
                or any(record[field] for field in ("may_publish", "may_merge", "may_install", "may_deploy"))
            ):
                raise record_error(record, "capability promotion is not bound to a closed passed evaluation")
            previous = promotion_heads.get(record["promotion_id"])
            if previous is None:
                if (
                    record["promotion_revision"] != 1
                    or record["prior_promotion_hash"] is not None
                    or record["status"] not in {"draft", "review_requested"}
                ):
                    raise record_error(record, "new capability promotion must begin as a draft review request")
            else:
                promotion_immutable_fields = (
                    "identity",
                    "closed_gap_hash",
                    "candidate_hash",
                    "evaluation_hash",
                    "draft_pr_request_hash",
                    "permitted_action",
                    "may_publish",
                    "may_merge",
                    "may_install",
                    "may_deploy",
                )
                valid_next = (
                    record["status"] in {"approved_for_release", "rejected"}
                    if previous["status"] == "review_requested"
                    else record["status"] in {"review_requested", "rejected"}
                    if previous["status"] == "draft"
                    else False
                )
                if (
                    record["promotion_revision"] != previous["promotion_revision"] + 1
                    or record["prior_promotion_hash"] != previous["record_hash"]
                    or any(record[field] != previous[field] for field in promotion_immutable_fields)
                    or not valid_next
                ):
                    raise record_error(record, "promotion revision chain or immutable binding changed")
            review = record["human_review"]
            if record["status"] in {"draft", "review_requested"}:
                if (
                    review["decision"] != "pending"
                    or review["provenance_state"] != "pending-unsigned"
                    or any(
                        review[field] is not None
                        for field in (
                            "reviewer_key_id",
                            "signature_bundle_hash",
                            "reviewed_at",
                            "evidence_hash",
                        )
                    )
                    or record["signed_release"] is not None
                    or record["overlay_selection"] is not None
                ):
                    raise record_error(record, "review-requested promotion must remain unsigned")
            elif record["status"] == "approved_for_release":
                signed = record["signed_release"]
                selection = record["overlay_selection"]
                release = signed["release"] if signed is not None else None
                if (
                    previous is None
                    or review["decision"] != "approved"
                    or review["provenance_state"] != "externally-authenticated"
                    or any(
                        review[field] is None
                        for field in (
                            "reviewer_key_id",
                            "signature_bundle_hash",
                            "reviewed_at",
                            "evidence_hash",
                        )
                    )
                    or signed is None
                    or release is None
                    or selection is None
                    or review["reviewed_at"] < max(evaluation["recorded_at"], previous["recorded_at"])
                    or signed["artifact_digest"] != candidate["code_digest"]
                    or release["package_digest"] != candidate["code_digest"]
                    or release["interface_schema_digest"] != candidate["interface_schema_digest"]
                    or selection["signed_release_digest"] != canonical_digest(signed)
                    or selection["release_binding_digest"] != canonical_digest(release)
                    or any(
                        selection[field] != release[field]
                        for field in (
                            "release_id",
                            "capability_id",
                            "package_digest",
                            "profile_digest",
                            "overlay_selection_digest",
                        )
                    )
                    or not review["reviewed_at"] <= signed["signed_at"] <= selection["selected_at"]
                ):
                    raise record_error(record, "release approval is not exactly bound to review, artifact, and overlay")
                approved_selections[canonical_digest(selection)] = record
            elif record["status"] == "rejected":
                if (
                    previous is None
                    or review["decision"] != "rejected"
                    or review["provenance_state"] != "externally-authenticated"
                    or any(
                        review[field] is None
                        for field in (
                            "reviewer_key_id",
                            "signature_bundle_hash",
                            "reviewed_at",
                            "evidence_hash",
                        )
                    )
                    or review["reviewed_at"] < max(evaluation["recorded_at"], previous["recorded_at"])
                    or record["signed_release"] is not None
                    or record["overlay_selection"] is not None
                ):
                    raise record_error(record, "promotion terminal status and decision mismatch")
            else:
                raise record_error(record, "promotion terminal status and decision mismatch")
            promotion_heads[record["promotion_id"]] = record
            continue

        if kind == "CapabilityLease":
            _, revision, constitution = current_identity(record, operational_at=record["issued_at"])
            if record["lease_id"] in capability_lease_ids:
                raise record_error(record, "capability lease identifier is duplicated")
            nonce_key = (record["issuer"], record["nonce"])
            if nonce_key in capability_nonces:
                raise record_error(record, "capability lease nonce was replayed")
            attestation = require_reference(
                record,
                record["runtime_attestation_hash"],
                "RuntimeAttestation",
                field="runtime_attestation_hash",
                operational_at=record["issued_at"],
            )
            promotion = approved_selections.get(record["overlay_selection_hash"])
            release = promotion["signed_release"]["release"] if promotion is not None else None
            selected_candidate = by_hash.get(promotion["candidate_hash"]) if promotion is not None else None
            selected_gap = by_hash.get(promotion["closed_gap_hash"]) if promotion is not None else None
            if (
                promotion is None
                or release is None
                or selected_candidate is None
                or selected_gap is None
                or promotion["recorded_at"] > record["issued_at"]
                or record["release"] != release
                or record["capability_id"] != release["capability_id"]
                or record["permitted_interface"] != selected_gap["required_interface"]
                or _identity_key(record) != _identity_key(attestation)
                or record["identity_revision_hash"] != revision["record_hash"]
                or record["constitution_hash"] != constitution["record_hash"]
                or record["runtime_installation_id"] != attestation["installation_id"]
                or record["status"] != "active"
                or not record["issued_at"] <= record["recorded_at"] < record["expires_at"]
                or attestation["issued_at"] > record["issued_at"]
                or attestation["expires_at"] < record["expires_at"]
                or AUTHORITY_MODE_RANK[record["mode"]]
                > AUTHORITY_MODE_RANK[constitution["authority_ceiling"]["maximum_mode"]]
            ):
                raise record_error(record, "capability lease lacks exact signed-release and overlay binding")
            capability_lease_ids.add(record["lease_id"])
            capability_nonces.add(nonce_key)
            capability_leases_by_hash[record["record_hash"]] = record
            continue

        if kind == "CapabilityRevocation":
            current_identity(record, operational_at=record["effective_at"])
            if record["revocation_id"] in revocation_ids:
                raise record_error(record, "capability revocation identifier is duplicated")
            matching_lease = next(
                (
                    lease
                    for lease in capability_leases_by_hash.values()
                    if lease["revocation_identity"] == record["target_revocation_identity"]
                    and lease["release"] == record["release"]
                ),
                None,
            )
            if (
                matching_lease is None
                or record["overlay_selection_hash"] != matching_lease["overlay_selection_hash"]
                or record["release"]["capability_id"] != matching_lease["capability_id"]
                or matching_lease["recorded_at"] > record["effective_at"]
                or matching_lease["issued_at"] > record["effective_at"]
            ):
                raise record_error(record, "capability revocation is unrelated to its target lease")
            release_key = canonical_json_bytes(record["release"])
            previous = revocations_by_release.get(release_key)
            if previous is None or record["effective_at"] < previous["effective_at"]:
                revocations_by_release[release_key] = record
            revocation_ids.add(record["revocation_id"])
            continue

        if kind == "CapabilityInvocation":
            current_identity(record, operational_at=record["started_at"])
            if record["invocation_id"] in invocation_ids:
                raise record_error(record, "capability invocation identifier is duplicated")
            replay_key = (record["capability_lease_hash"], record["call_nonce"])
            index_key = (record["capability_lease_hash"], record["call_index"])
            if replay_key in invocation_nonces or index_key in invocation_indices:
                raise record_error(record, "capability invocation nonce or call index was replayed")
            invocation_lease = capability_leases_by_hash.get(record["capability_lease_hash"])
            invocation_attestation = attestations_by_hash.get(record["runtime_attestation_hash"])
            if (
                invocation_lease is None
                or invocation_attestation is None
                or invocation_lease["runtime_attestation_hash"] != invocation_attestation["record_hash"]
                or invocation_lease["recorded_at"] > record["started_at"]
                or invocation_attestation["recorded_at"] > record["started_at"]
                or _identity_key(record) != _identity_key(invocation_lease)
                or _identity_key(record) != _identity_key(invocation_attestation)
                or record["capability_id"] != invocation_lease["capability_id"]
                or record["permitted_interface"] != invocation_lease["permitted_interface"]
                or record["mode"] != invocation_lease["mode"]
                or record["provider_id"] != invocation_lease["audience"]
            ):
                raise record_error(record, "capability invocation is unrelated to its exact lease and attestation")
            usage = settled_usage.setdefault(
                record["capability_lease_hash"],
                {"calls": 0, "tokens": 0, "cost_microunits": 0},
            )
            started = record["started_at"]
            completed = record["completed_at"]
            expiry = min(invocation_lease["expires_at"], invocation_attestation["expires_at"])
            revocation = revocations_by_release.get(canonical_json_bytes(invocation_lease["release"]))
            revocation_cause = (
                max(revocation["effective_at"], revocation["recorded_at"]) if revocation is not None else None
            )
            next_usage = {
                "calls": usage["calls"] + record["settled_usage"]["calls"],
                "tokens": usage["tokens"] + record["settled_usage"]["tokens"],
                "cost_microunits": usage["cost_microunits"] + record["settled_usage"]["cost_microunits"],
            }
            if (
                started < invocation_lease["issued_at"]
                or started < invocation_attestation["issued_at"]
                or completed < started
                or record["call_index"] != usage["calls"] + 1
                or any(next_usage[key] > invocation_lease["budget"][f"maximum_{key}"] for key in next_usage)
                or (record["disposition"] != "rejected" and started >= expiry)
                or (record["disposition"] == "succeeded" and completed >= expiry)
                or (
                    record["disposition"] == "succeeded"
                    and revocation is not None
                    and revocation["effective_at"] <= completed
                )
                or (record["disposition"] == "expired" and completed < expiry)
                or (
                    record["disposition"] == "revoked"
                    and (revocation_cause is None or started >= revocation_cause or revocation_cause > completed)
                )
            ):
                raise record_error(record, "capability invocation chronology or budget is invalid")
            validations = record["provider_validations"]
            expected_phases = ["entry"] if record["disposition"] == "rejected" else ["entry", "before_return"]
            expected_results = (
                ["accepted", "accepted"]
                if record["disposition"] == "succeeded"
                else ["rejected"]
                if record["disposition"] == "rejected"
                else ["accepted", "rejected"]
            )
            validation_times = [item["validated_at"] for item in validations]
            if (
                [item["phase"] for item in validations] != expected_phases
                or [item["result"] for item in validations] != expected_results
                or any(
                    item["lease_hash"] != invocation_lease["record_hash"]
                    or item["attestation_hash"] != invocation_attestation["record_hash"]
                    for item in validations
                )
                or any(not started <= item["validated_at"] <= completed for item in validations)
                or validation_times != sorted(validation_times)
                or (record["disposition"] == "expired" and not (validation_times[0] < expiry <= validation_times[-1]))
                or (
                    record["disposition"] == "revoked"
                    and (
                        revocation_cause is None or not (validation_times[0] < revocation_cause <= validation_times[-1])
                    )
                )
                or (record["disposition"] == "succeeded" and record["result_hash"] is None)
                or (record["disposition"] != "succeeded" and record["result_hash"] is not None)
            ):
                raise record_error(record, "provider did not revalidate the exact lease on every call phase")
            invocation_ids.add(record["invocation_id"])
            invocation_nonces.add(replay_key)
            invocation_indices.add(index_key)
            settled_usage[record["capability_lease_hash"]] = next_usage
            continue

        raise record_error(record, f"no semantic replay handler for {kind}")

    episode_ids = set(episode_heads)
    for lease in reasoning_heads.values():
        if lease["owner_episode_id"] not in episode_ids:
            raise record_error(lease, "reasoning lease owner episode is absent", "owner_episode_id")


def _validate_audit_projection_document(
    value: object,
    *,
    schema_validators: Mapping[str, Any],
) -> dict[str, JSONValue]:
    """Validate with validators loaded from a caller-verified generated root."""

    document = _closed_object(
        value,
        "$",
        (
            ("apiVersion", _const(API_VERSION)),
            ("as_of", _timestamp),
            ("authority_effect", _const("none")),
            ("contains_private_identity", _const(False)),
            ("expected_projection", normalize_expected_projection),
            ("expected_projection_digest", _digest),
            ("kind", _const(AUDIT_VECTOR_KIND)),
            ("records", _array(_record_validator(schema_validators))),
            ("records_digest", _digest),
            ("synthetic", _const(True)),
        ),
    )
    expected_projection = cast(dict[str, JSONValue], document["expected_projection"])
    expected_digest = canonical_digest(expected_projection)
    if not hmac.compare_digest(cast(str, document["expected_projection_digest"]), expected_digest):
        raise _fail("$.expected_projection_digest", "does not bind the normalized projection")
    records = cast(list[JSONValue], document["records"])
    records_digest = canonical_digest(records)
    if not hmac.compare_digest(cast(str, document["records_digest"]), records_digest):
        raise _fail("$.records_digest", "does not bind the record array")
    canonical_as_of = cast(str, document["as_of"])
    record_ids: set[str] = set()
    record_hashes: set[str] = set()
    for index, item in enumerate(records):
        record = cast(dict[str, JSONValue], item)
        if cast(str, record["recorded_at"]) > canonical_as_of:
            raise _fail(f"$.records[{index}].recorded_at", "future record leaked into fixed as_of projection")
        record_id = cast(str, record["record_id"])
        record_hash = cast(str, record["record_hash"])
        if record_id in record_ids or record_hash in record_hashes:
            raise _fail(f"$.records[{index}]", "duplicate record identity or hash")
        record_ids.add(record_id)
        record_hashes.add(record_hash)
    _validate_record_relationships(
        cast(list[dict[str, Any]], records),
        as_of=canonical_as_of,
    )
    derived_projection = normalize_expected_projection(
        _derive_expected_projection(
            cast(list[dict[str, Any]], records),
            as_of=canonical_as_of,
        ),
        "$.derived_projection",
    )
    if not hmac.compare_digest(
        canonical_json_bytes(expected_projection),
        canonical_json_bytes(derived_projection),
    ):
        raise _fail(
            "$.expected_projection",
            "does not byte-match the deterministic projection derived from validated records",
        )
    for index, item in enumerate(cast(list[JSONValue], expected_projection["attested_embodiments"])):
        attestation = cast(dict[str, JSONValue], item)
        expected_state = "active" if canonical_as_of < cast(str, attestation["expires_at"]) else "expired"
        if attestation["state"] != expected_state:
            raise _fail(f"$.expected_projection.attested_embodiments[{index}].state", "does not match as_of")
    for index, item in enumerate(cast(list[JSONValue], expected_projection["foundry_admissions"])):
        admission = cast(dict[str, JSONValue], item)
        expected_state = "active" if canonical_as_of < cast(str, admission["expires_at"]) else "expired"
        if admission["state"] != expected_state:
            raise _fail(f"$.expected_projection.foundry_admissions[{index}].state", "does not match as_of")
    return document


def validate_audit_projection_document(value: object) -> dict[str, JSONValue]:
    """Validate a public projection without interpreting it as authority."""

    generated_root = Path(__file__).resolve().parents[1] / "contracts" / "platform-steward" / "v1"
    return _validate_audit_projection_document(
        value,
        schema_validators=_load_schema_validators(generated_root),
    )


PINNED_SOURCE_LOCK: dict[str, JSONValue] = {
    "canonical_commit": PINNED_CANONICAL_COMMIT,
    "canonical_generator": {
        "path": "ops/steward/contracts/steward_v1.py",
        "sha256": PINNED_GENERATOR_SHA256,
    },
    "canonical_repository": "https://github.com/masonjames/platform-infra",
    "generated_directory": "contracts/platform-steward/v1",
    "generated_file_count": 19,
    "schema_manifest": {
        "path": "contracts/platform-steward/v1/schema-manifest.json",
        "sha256": PINNED_SCHEMA_MANIFEST_SHA256,
    },
    "source_lock_version": 1,
    "test_vectors": {
        "audit_projection": {
            "path": "contracts/platform-steward/v1/test-vectors/audit-projection-records.json",
            "sha256": PINNED_AUDIT_VECTOR_SHA256,
        },
        "canonical_hash": {
            "path": "contracts/platform-steward/v1/test-vectors/canonical-hash-vectors.json",
            "sha256": PINNED_CANONICAL_HASH_VECTOR_SHA256,
        },
    },
}


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_file_digest(path: Path, expected: str) -> None:
    try:
        actual = _file_digest(path)
    except OSError as exc:
        raise AuditProjectionError(f"cannot read pinned contract file {path}: {exc}") from exc
    if not hmac.compare_digest(actual, expected):
        raise AuditProjectionError(f"pinned contract digest mismatch for {path}: {actual}")


def _validate_source_lock(value: object) -> None:
    normalized = _json_value(value, "$")
    if normalized != PINNED_SOURCE_LOCK:
        raise AuditProjectionError("SOURCE.lock.json does not match the compiled closed source lock")


def load_pinned_audit_projection(repository_root: Path | None = None) -> dict[str, JSONValue]:
    """Verify the complete generated mirror and load its read-only projection.

    No caller-selected hash or source revision is accepted.  The function reads
    only the checked-in lock, manifest, generated schemas, and public vector.
    """

    root = repository_root or Path(__file__).resolve().parents[1]
    contract_root = root / "contracts" / "platform-steward"
    lock_path = contract_root / "SOURCE.lock.json"
    if contract_root.is_symlink() or lock_path.is_symlink():
        raise AuditProjectionError("pinned contract root and source lock cannot be symlinks")
    try:
        source_lock = load_json_strict(lock_path.read_bytes())
    except OSError as exc:
        raise AuditProjectionError(f"cannot read pinned source lock {lock_path}: {exc}") from exc
    _validate_source_lock(source_lock)

    generated_root = contract_root / "v1"
    manifest_path = generated_root / "schema-manifest.json"
    if generated_root.is_symlink() or manifest_path.is_symlink():
        raise AuditProjectionError("generated contract root and manifest cannot be symlinks")
    _assert_file_digest(manifest_path, PINNED_SCHEMA_MANIFEST_SHA256)
    manifest_value = load_json_strict(manifest_path.read_bytes())
    if not isinstance(manifest_value, dict):
        raise AuditProjectionError("schema manifest must be an object")
    expected_manifest_keys = {
        "apiVersion",
        "canonical_source",
        "canonical_source_sha256",
        "kind",
        "schema_dialect",
        "schemas",
        "test_vectors",
    }
    if set(manifest_value) != expected_manifest_keys:
        raise AuditProjectionError("schema manifest is not the closed v1 shape")
    if manifest_value["apiVersion"] != API_VERSION:
        raise AuditProjectionError("schema manifest has wrong apiVersion")
    if manifest_value["canonical_source"] != "ops/steward/contracts/steward_v1.py":
        raise AuditProjectionError("schema manifest has wrong canonical generator path")
    if manifest_value["canonical_source_sha256"] != PINNED_GENERATOR_SHA256:
        raise AuditProjectionError("schema manifest has wrong canonical generator digest")
    if manifest_value["kind"] != "PlatformStewardSchemaManifest":
        raise AuditProjectionError("schema manifest has wrong kind")
    if manifest_value["schema_dialect"] != "https://json-schema.org/draft/2020-12/schema":
        raise AuditProjectionError("schema manifest has wrong dialect")

    schemas = manifest_value["schemas"]
    test_vectors = manifest_value["test_vectors"]
    if not isinstance(schemas, dict) or len(schemas) != 16:
        raise AuditProjectionError("schema manifest must list exactly 16 schemas")
    if not isinstance(test_vectors, dict) or set(test_vectors) != {
        "test-vectors/audit-projection-records.json",
        "test-vectors/canonical-hash-vectors.json",
    }:
        raise AuditProjectionError("schema manifest has the wrong test-vector set")

    expected_relative_files = {Path("schema-manifest.json")}
    for filename, digest in {**schemas, **test_vectors}.items():
        if not isinstance(filename, str) or Path(filename).is_absolute() or ".." in Path(filename).parts:
            raise AuditProjectionError("schema manifest contains an unsafe relative path")
        if not isinstance(digest, str) or DIGEST_RE.fullmatch(digest) is None:
            raise AuditProjectionError(f"schema manifest has invalid digest for {filename}")
        relative = Path(filename)
        expected_relative_files.add(relative)
        path = generated_root / relative
        if path.is_symlink():
            raise AuditProjectionError(f"generated contract mirror cannot contain symlink {relative}")
        _assert_file_digest(path, digest)

    actual_relative_files: set[Path] = set()
    for path in generated_root.rglob("*"):
        if path.is_symlink():
            raise AuditProjectionError(f"generated contract mirror cannot contain symlink {path}")
        if path.is_file():
            actual_relative_files.add(path.relative_to(generated_root))
    if actual_relative_files != expected_relative_files or len(actual_relative_files) != 19:
        raise AuditProjectionError("generated contract mirror contains missing or unexpected files")

    audit_vector_path = generated_root / "test-vectors" / "audit-projection-records.json"
    _assert_file_digest(audit_vector_path, PINNED_AUDIT_VECTOR_SHA256)
    return _validate_audit_projection_document(
        load_json_strict(audit_vector_path.read_bytes()),
        schema_validators=_load_schema_validators(generated_root),
    )
