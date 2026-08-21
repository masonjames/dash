"""Hosted PostgreSQL proof for search paths and the disabled Chronicle candidate."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict

from dash.platform_steward_audit_projection import (
    _derive_expected_projection,
    canonical_digest,
    canonical_json_bytes,
)
from scripts import migrate_ops

ROOT = Path(__file__).resolve().parents[1]
_DSN_ENV = "DASH_TEST_POSTGRES_DSN"
_EXPECTED_DATABASE = "dash_search_path_ci"
_CANDIDATE = ROOT / "db/migrations/ops_agent_chronicle_v1_disabled.sql"
_VECTOR = ROOT / "contracts/platform-steward/v1/test-vectors/audit-projection-records.json"
_BOUNDARY_VECTOR = ROOT / "contracts/platform-steward/chronicle/v1/test-vectors/chronicle-boundary-vectors.json"
_BOUNDARY_DOCUMENT = json.loads(_BOUNDARY_VECTOR.read_text(encoding="utf-8"))
_BOUNDARY_APPEND = _BOUNDARY_DOCUMENT["append_envelope"]
_ROLE_SECRETS = {
    "DASH_OPS_READER_PASSWORD": "dash_ops_reader-integration-only",
    "DASH_OPS_INDEXER_PASSWORD": "dash_ops_indexer-integration-only",
    "DOCKHAND_OPS_WRITER_PASSWORD": "dockhand_ops_writer-integration-only",
    "DASH_API_RUNTIME_PASSWORD": "dash_api_runtime-integration-only",
}
_IDENTITY_ID = "platform-steward"
_CONSTITUTION_HASH = _BOUNDARY_APPEND["identity"]["constitution_hash"]
_SOURCE_ATTESTATION_HASH = _BOUNDARY_APPEND["source_attestation_hash"]
_SIGNATURE_BUNDLE_HASH = "sha256:" + "3" * 64
_INSTALLATION_ID = "synthetic-server-sentinel"
_AUDIENCE = "dockhand-chronicle-writer"
_SCOPES = {
    "audit": {
        "scope_type": "task",
        "scope_id": "chronicle-postgres-replay",
        "installation_id": _INSTALLATION_ID,
        "resource_type": "test-database",
        "resource_id": "dash-search-path-ci",
    },
    "adversarial": {
        "scope_type": "task",
        "scope_id": "chronicle-cas-shape-adversarial",
        "installation_id": _INSTALLATION_ID,
        "resource_type": "test-database",
        "resource_id": "dash-search-path-ci",
    },
    "basic": {
        "scope_type": "task",
        "scope_id": "chronicle-basic-cas",
        "installation_id": _INSTALLATION_ID,
        "resource_type": "test-database",
        "resource_id": "dash-search-path-ci",
    },
    "race": {
        "scope_type": "task",
        "scope_id": "chronicle-lease-race",
        "installation_id": _INSTALLATION_ID,
        "resource_type": "test-database",
        "resource_id": "dash-search-path-ci",
    },
    "vector": {
        "scope_type": "journey",
        "scope_id": "synthetic-convergence-journey",
        "installation_id": "synthetic-platform-installation",
        "resource_type": "platform-installation",
        "resource_id": "synthetic-platform-installation",
    },
}


def chronicle_test_uuid(namespace: int, number: int) -> str:
    """Return a deterministic canonical v4 UUID for disposable database proof."""

    return f"{namespace:08x}-0000-4000-8000-{number:012x}"


def chronicle_test_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def chronicle_test_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def chronicle_test_record(
    *,
    record_id: str,
    kind: str,
    logical_id: str,
    logical_revision: int = 1,
    prior_record_hash: str | None = None,
    fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one provider-shaped canonical byte/state binding for SQL tests."""

    logical_fields: dict[str, Any]
    if kind == "AgentEpisode":
        logical_fields = {
            "episode_id": logical_id,
            "episode_revision": logical_revision,
            "prior_episode_hash": prior_record_hash,
        }
    elif kind == "ReasoningLease":
        logical_fields = {
            "lease_id": logical_id,
            "lease_revision": logical_revision,
            "prior_lease_hash": prior_record_hash,
        }
    else:
        logical_fields = {}
    document: dict[str, Any] = {
        "apiVersion": "platform.masonjames.dev/steward/v1",
        "kind": kind,
        "record_id": record_id,
        **logical_fields,
        **(fields or {}),
    }
    record_hash_domain = (
        b"platform-steward-record-v1\x00" + document["apiVersion"].encode() + b"\x00" + kind.encode() + b"\x00"
    )
    document["record_hash"] = chronicle_test_digest(record_hash_domain + canonical_json_bytes(document))
    canonical_bytes = canonical_json_bytes(document)
    return {
        "document": document,
        "record_id": record_id,
        "record_kind": kind,
        "record_hash": document["record_hash"],
        "logical_id": logical_id,
        "logical_revision": logical_revision,
        "prior_record_hash": prior_record_hash,
        "canonical_bytes": canonical_bytes,
        "canonical_bytes_sha256": chronicle_test_digest(canonical_bytes),
    }


_REVISION_FIELDS: dict[str, tuple[str, str, str]] = {
    "AgentConstitution": (
        "constitution_id",
        "constitution_revision",
        "prior_constitution_hash",
    ),
    "AgentEpisode": ("episode_id", "episode_revision", "prior_episode_hash"),
    "AgentHandoff": ("handoff_id", "handoff_revision", "prior_handoff_hash"),
    "CapabilityGap": ("gap_id", "gap_revision", "prior_gap_hash"),
    "CapabilityPromotion": (
        "promotion_id",
        "promotion_revision",
        "prior_promotion_hash",
    ),
    "KnowledgeClaim": ("claim_id", "claim_revision", "prior_claim_hash"),
    "ReasoningLease": ("lease_id", "lease_revision", "prior_lease_hash"),
}
_LOGICAL_ID_FIELDS = {
    "AgentIdentityDescriptor": "identity_id",
    "CapabilityCandidate": "candidate_id",
    "CapabilityEvaluation": "evaluation_id",
    "CapabilityInvocation": "invocation_id",
    "CapabilityLease": "lease_id",
    "CapabilityRevocation": "revocation_id",
    "FoundryAdmissionAttestation": "admission_id",
    "RuntimeAttestation": "attestation_id",
}


def chronicle_record_evidence_hashes(record: dict[str, Any]) -> set[str]:
    """Mirror the closed canonical record evidence citation traversal."""

    collected: set[str] = set()
    scalar_fields = {
        "evidence_hash",
        "selection_evidence_hash",
        "signing_evidence_hash",
    }
    array_fields = {
        "evidence_preconditions",
        "input_evidence_hashes",
        "result_evidence_hashes",
    }

    def collect(item: Any, *, field: str | None = None) -> None:
        if field in scalar_fields and isinstance(item, str):
            collected.add(item)
            return
        if field in array_fields and isinstance(item, list):
            collected.update(value for value in item if isinstance(value, str))
            return
        if isinstance(item, dict):
            for key, nested in item.items():
                collect(nested, field=key)
        elif isinstance(item, list):
            for nested in item:
                collect(nested)

    collect(record)
    return collected


def chronicle_vector_record(record: dict[str, Any]) -> dict[str, Any]:
    """Derive the trusted logical binding used by the canonical reference oracle."""

    kind = record["kind"]
    if kind == "AgentIdentityRevision":
        logical_id = record["identity"]["identity_id"]
        logical_revision = record["identity"]["identity_revision"]
        prior_record_hash = record["prior_revision_hash"]
    elif kind == "AgentIdentityDescriptor":
        logical_id = record["identity_id"]
        logical_revision = record["initial_identity_revision"]
        prior_record_hash = None
    elif kind in _REVISION_FIELDS:
        id_field, revision_field, prior_field = _REVISION_FIELDS[kind]
        logical_id = record[id_field]
        logical_revision = record[revision_field]
        prior_record_hash = record[prior_field]
    else:
        logical_id = record[_LOGICAL_ID_FIELDS[kind]]
        logical_revision = 1
        prior_record_hash = None
    canonical_bytes = canonical_json_bytes(record)
    return {
        "document": record,
        "record_id": record["record_id"],
        "record_kind": kind,
        "record_hash": record["record_hash"],
        "logical_id": logical_id,
        "logical_revision": logical_revision,
        "prior_record_hash": prior_record_hash,
        "canonical_bytes": canonical_bytes,
        "canonical_bytes_sha256": chronicle_test_digest(canonical_bytes),
    }


def chronicle_boundary_decision(
    envelope_name: str,
    *,
    trusted_time: str,
    outbox_number: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], bytes]:
    """Add only provider-derived bindings to one canonical signed envelope."""

    envelope = copy.deepcopy(_BOUNDARY_DOCUMENT[envelope_name])
    records: list[dict[str, Any]] = []
    for embedded in envelope["records"]:
        document = json.loads(embedded["canonical_record_json"])
        record = chronicle_vector_record(document)
        assert record["canonical_bytes"].decode() == embedded["canonical_record_json"]
        assert record["record_id"] == embedded["record_id"]
        assert record["record_kind"] == embedded["record_kind"]
        assert record["record_hash"] == embedded["record_hash"]
        records.append(record)

    outbox_intent = {
        "outbox_id": chronicle_test_uuid(0x44000000, outbox_number),
        "projection_name": "platform-steward-audit-v1",
        "request_digest": envelope["request_digest"],
        "authority_effect": "none",
    }
    envelope.update(
        {
            "trusted_time": trusted_time,
            "record_bindings": [
                {
                    "record_id": record["record_id"],
                    "record_kind": record["record_kind"],
                    "record_hash": record["record_hash"],
                    "logical_id": record["logical_id"],
                    "logical_revision": record["logical_revision"],
                    "prior_record_hash": record["prior_record_hash"],
                    "canonical_bytes_sha256": record["canonical_bytes_sha256"],
                }
                for record in records
            ],
            "capability_reservation": None,
            "outbox_intent": outbox_intent,
        }
    )
    return envelope, records, canonical_json_bytes(outbox_intent)


def chronicle_test_decision(
    *,
    request_number: int,
    writer_sequence: int,
    previous_envelope_hash: str | None,
    trusted_time: datetime,
    binding: dict[str, str],
    records: list[dict[str, Any]],
    chronicle_id: str,
    scope: dict[str, str],
    reasoning_cas_preconditions: list[dict[str, Any]] | None = None,
    capability_reservation: dict[str, Any] | None = None,
    nonce: str | None = None,
    outbox_number: int | None = None,
) -> tuple[dict[str, Any], bytes]:
    """Build the exact closed JSON object accepted from the Dockhand provider."""

    request_id = chronicle_test_uuid(0x40000000, request_number)
    request_nonce = nonce or chronicle_test_uuid(0x41000000, request_number)
    request_digest = chronicle_test_digest(
        canonical_json_bytes(
            {
                "chronicle_id": chronicle_id,
                "record_hashes": [record["record_hash"] for record in records],
                "request_id": request_id,
                "writer_id": binding["writer_id"],
                "writer_sequence": writer_sequence,
            }
        )
    )
    outbox_id = chronicle_test_uuid(
        0x42000000,
        request_number if outbox_number is None else outbox_number,
    )
    outbox_intent = {
        "outbox_id": outbox_id,
        "projection_name": "platform-steward-audit-v1",
        "request_digest": request_digest,
        "authority_effect": "none",
    }
    decision = {
        "apiVersion": "platform.masonjames.dev/steward-chronicle/v1",
        "kind": "ChronicleAppendEnvelope",
        "request_id": request_id,
        "request_nonce": request_nonce,
        "writer_sequence": writer_sequence,
        "previous_envelope_hash": previous_envelope_hash,
        "submitted_at": chronicle_test_timestamp(trusted_time - timedelta(seconds=1)),
        "expires_at": chronicle_test_timestamp(trusted_time + timedelta(minutes=5)),
        "chronicle_id": chronicle_id,
        "identity": {
            "identity_id": _IDENTITY_ID,
            "identity_revision": 1,
            "identity_epoch": 1,
            "constitution_hash": _CONSTITUTION_HASH,
        },
        "audience": _AUDIENCE,
        "installation": {
            "installation_id": _INSTALLATION_ID,
            "embodiment": "server-sentinel",
            "host_class": "near-platform-server",
        },
        "mode": "intent",
        "writer_id": binding["writer_id"],
        "writer_key_id": binding["writer_key_id"],
        "writer_runtime_attestation_hash": binding["runtime_attestation_hash"],
        "writer_session_id": binding["writer_session_id"],
        "source_attestation_hash": _SOURCE_ATTESTATION_HASH,
        "interface_id": "dockhand-chronicle-append-v1",
        "records": [
            {
                "record_id": record["record_id"],
                "record_kind": record["record_kind"],
                "record_hash": record["record_hash"],
                "canonical_record_json": record["canonical_bytes"].decode(),
            }
            for record in records
        ],
        "scope_bindings": [
            {
                "scope": scope,
                "runtime_attestation_hashes": [binding["runtime_attestation_hash"]],
                "record_hashes": [record["record_hash"] for record in records],
            }
        ],
        "reasoning_cas_preconditions": reasoning_cas_preconditions or [],
        "capability_budget": {
            "maximum_calls": 10,
            "maximum_tokens": 1_000,
            "maximum_cost_microunits": 1_000,
        },
        "evidence_hashes": sorted(
            {
                _SOURCE_ATTESTATION_HASH,
                *(
                    evidence_hash
                    for record in records
                    for evidence_hash in chronicle_record_evidence_hashes(record["document"])
                ),
            }
        ),
        "authority_effect": "chronicle-append-only",
        "request_digest": request_digest,
        "signature_bundle_hash": _SIGNATURE_BUNDLE_HASH,
        "trusted_time": chronicle_test_timestamp(trusted_time),
        "record_bindings": [
            {
                "record_id": record["record_id"],
                "record_kind": record["record_kind"],
                "record_hash": record["record_hash"],
                "logical_id": record["logical_id"],
                "logical_revision": record["logical_revision"],
                "prior_record_hash": record["prior_record_hash"],
                "canonical_bytes_sha256": record["canonical_bytes_sha256"],
            }
            for record in records
        ],
        "capability_reservation": capability_reservation,
        "outbox_intent": outbox_intent,
    }
    return decision, canonical_json_bytes(outbox_intent)


def chronicle_execute_append(
    connection: psycopg.Connection[Any],
    decision: dict[str, Any],
    records: list[dict[str, Any]],
    outbox_intent_bytes: bytes,
) -> tuple[Any, ...]:
    """Execute the one-call provider boundary and return its pre-COMMIT candidate."""

    row = connection.execute(
        """
        SELECT request_id,
               chronicle_watermark,
               record_commits,
               reasoning_cas_results,
               audit_outbox_watermark
        FROM ops.chronicle_test_append_v1(
            %s::jsonb,
            %s::text[],
            %s::text[],
            %s::text[],
            %s::bytea[],
            %s::bytea
        )
        """,
        (
            json.dumps(decision, separators=(",", ":"), sort_keys=True),
            [record["record_id"] for record in records],
            [record["record_kind"] for record in records],
            [record["record_hash"] for record in records],
            [record["canonical_bytes"] for record in records],
            outbox_intent_bytes,
        ),
    ).fetchone()
    assert row is not None
    return row


_REPLAY_STATE_FIELDS = (
    "chronicle_id",
    "writer_id",
    "writer_key_id",
    "request_id",
    "request_nonce",
    "writer_head_sequence",
    "writer_head_digest",
    "request_id_digest",
    "request_nonce_digest",
    "committed_request_digest",
    "committed_at",
    "commit_result",
    "rejected_request_digest",
    "rejection_reason",
    "rejected_at",
    "rejection_atomic_no_commit",
)


def chronicle_resolve_request(
    connection: psycopg.Connection[Any],
    decision: dict[str, Any],
) -> dict[str, Any]:
    """Resolve the exact canonical durable replay-state row."""

    row = connection.execute(
        """
        SELECT *
        FROM ops.chronicle_test_resolve_request_v1(
            %s::text,
            %s::text,
            %s::text,
            %s::uuid,
            %s::uuid
        )
        """,
        (
            decision["chronicle_id"],
            decision["writer_id"],
            decision["writer_key_id"],
            decision["request_id"],
            decision["request_nonce"],
        ),
    ).fetchone()
    assert row is not None
    return dict(zip(_REPLAY_STATE_FIELDS, row, strict=True))


def chronicle_record_rejection(
    connection: psycopg.Connection[Any],
    decision: dict[str, Any],
    *,
    reason: str,
    rejected_at: datetime,
    atomic_no_commit: bool,
) -> dict[str, Any]:
    """Persist one separate-transaction non-evidence rejection tombstone."""

    row = connection.execute(
        """
        SELECT *
        FROM ops.chronicle_test_record_rejection_v1(
            %s::text,
            %s::text,
            %s::text,
            %s::uuid,
            %s::uuid,
            %s::text,
            %s::text,
            %s::timestamptz,
            %s::boolean
        )
        """,
        (
            decision["chronicle_id"],
            decision["writer_id"],
            decision["writer_key_id"],
            decision["request_id"],
            decision["request_nonce"],
            decision["request_digest"],
            reason,
            rejected_at,
            atomic_no_commit,
        ),
    ).fetchone()
    assert row is not None
    return dict(zip(_REPLAY_STATE_FIELDS, row, strict=True))


def chronicle_seed_authority(
    connection: psycopg.Connection[Any],
    base_time: datetime,
) -> dict[str, dict[str, str]]:
    """Seed only owner-controlled test registries in the disposable database."""

    connection.execute(
        """
        INSERT INTO ops.chronicle_evidence (
            evidence_hash, source_domain, captured_at, expires_at
        ) VALUES (%s, 'platform-operations', %s, %s)
        """,
        (_SOURCE_ATTESTATION_HASH, base_time - timedelta(days=2), base_time + timedelta(days=1)),
    )
    vector = json.loads(_VECTOR.read_text(encoding="utf-8"))
    vector_evidence_hashes = sorted(
        {evidence_hash for record in vector["records"] for evidence_hash in chronicle_record_evidence_hashes(record)}
        - {_SOURCE_ATTESTATION_HASH}
    )
    with connection.cursor() as cursor:
        cursor.executemany(
            """
            INSERT INTO ops.chronicle_evidence (
                evidence_hash, source_domain, captured_at, expires_at
            ) VALUES (%s, 'canonical-fixture', %s, %s)
            ON CONFLICT (evidence_hash) DO NOTHING
            """,
            [
                (
                    evidence_hash,
                    base_time - timedelta(days=2),
                    base_time + timedelta(days=1),
                )
                for evidence_hash in vector_evidence_hashes
            ],
        )
    bindings: dict[str, dict[str, str]] = {}
    for index, name in enumerate(("a", "b", "c", "replay", "budget"), start=1):
        writer_id = f"dockhand-chronicle-writer-{name}"
        writer_key_id = f"dockhand-chronicle-writer-key-{name}"
        signer_id = f"dockhand-chronicle-signer-{name}"
        runtime_hash = "sha256:" + f"{index + 3:x}" * 64
        writer_session_id = chronicle_test_uuid(0x43000000, index)
        binding_id = f"binding-{name}"
        connection.execute(
            """
            INSERT INTO ops.chronicle_signers (
                signer_id, writer_id, writer_key_id, algorithm,
                public_key_digest, admitted_at, expires_at
            ) VALUES (%s, %s, %s, 'ed25519', %s, %s, %s)
            """,
            (
                signer_id,
                writer_id,
                writer_key_id,
                "sha256:" + f"{index + 7:x}" * 64,
                base_time - timedelta(days=2),
                base_time + timedelta(days=1),
            ),
        )
        connection.execute(
            """
            INSERT INTO ops.chronicle_runtime_attestations (
                runtime_attestation_hash, identity_id, identity_revision,
                identity_epoch, installation_id, embodiment, host_class,
                admitted_at, expires_at
            ) VALUES (%s, %s, 1, 1, %s, 'server-sentinel',
                      'near-platform-server', %s, %s)
            """,
            (
                runtime_hash,
                _IDENTITY_ID,
                _INSTALLATION_ID,
                base_time - timedelta(days=2),
                base_time + timedelta(days=1),
            ),
        )
        connection.execute(
            """
            INSERT INTO ops.chronicle_identity_runtime_bindings (
                binding_id, writer_id, writer_key_id, identity_id,
                identity_revision, identity_epoch, constitution_hash,
                writer_runtime_attestation_hash, source_attestation_hash,
                audience, installation_id, embodiment, host_class,
                writer_session_id, interface_id, mode, signer_id,
                admitted_at, expires_at
            ) VALUES (
                %s, %s, %s, %s, 1, 1, %s, %s, %s, %s, %s,
                'server-sentinel', 'near-platform-server', %s,
                'dockhand-chronicle-append-v1', 'intent', %s, %s, %s
            )
            """,
            (
                binding_id,
                writer_id,
                writer_key_id,
                _IDENTITY_ID,
                _CONSTITUTION_HASH,
                runtime_hash,
                _SOURCE_ATTESTATION_HASH,
                _AUDIENCE,
                _INSTALLATION_ID,
                writer_session_id,
                signer_id,
                base_time - timedelta(days=2),
                base_time + timedelta(days=1),
            ),
        )
        for scope in _SCOPES.values():
            connection.execute(
                """
                INSERT INTO ops.chronicle_identity_runtime_scopes (
                    binding_id, scope_type, scope_id, installation_id,
                    resource_type, resource_id, admitted_at, expires_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    binding_id,
                    scope["scope_type"],
                    scope["scope_id"],
                    scope["installation_id"],
                    scope["resource_type"],
                    scope["resource_id"],
                    base_time - timedelta(days=2),
                    base_time + timedelta(days=1),
                ),
            )
        bindings[name] = {
            "binding_id": binding_id,
            "writer_id": writer_id,
            "writer_key_id": writer_key_id,
            "runtime_attestation_hash": runtime_hash,
            "writer_session_id": writer_session_id,
        }

    alias_runtime_hash = "sha256:" + "9" * 64
    alias_session_id = chronicle_test_uuid(0x43000000, 6)
    connection.execute(
        """
        INSERT INTO ops.chronicle_runtime_attestations (
            runtime_attestation_hash, identity_id, identity_revision,
            identity_epoch, installation_id, embodiment, host_class,
            admitted_at, expires_at
        ) VALUES (%s, %s, 1, 1, %s, 'server-sentinel',
                  'near-platform-server', %s, %s)
        """,
        (
            alias_runtime_hash,
            _IDENTITY_ID,
            _INSTALLATION_ID,
            base_time - timedelta(days=2),
            base_time + timedelta(days=1),
        ),
    )
    connection.execute(
        """
        INSERT INTO ops.chronicle_identity_runtime_bindings (
            binding_id, writer_id, writer_key_id, identity_id,
            identity_revision, identity_epoch, constitution_hash,
            writer_runtime_attestation_hash, source_attestation_hash,
            audience, installation_id, embodiment, host_class,
            writer_session_id, interface_id, mode, signer_id,
            admitted_at, expires_at
        ) VALUES (
            'binding-a-alias', %s, %s, %s, 1, 1, %s, %s, %s, %s, %s,
            'server-sentinel', 'near-platform-server', %s,
            'dockhand-chronicle-append-v1', 'intent',
            'dockhand-chronicle-signer-a', %s, %s
        )
        """,
        (
            bindings["a"]["writer_id"],
            bindings["a"]["writer_key_id"],
            _IDENTITY_ID,
            _CONSTITUTION_HASH,
            alias_runtime_hash,
            _SOURCE_ATTESTATION_HASH,
            _AUDIENCE,
            _INSTALLATION_ID,
            alias_session_id,
            base_time - timedelta(days=2),
            base_time + timedelta(days=1),
        ),
    )
    for scope in _SCOPES.values():
        connection.execute(
            """
            INSERT INTO ops.chronicle_identity_runtime_scopes (
                binding_id, scope_type, scope_id, installation_id,
                resource_type, resource_id, admitted_at, expires_at
            ) VALUES ('binding-a-alias', %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                scope["scope_type"],
                scope["scope_id"],
                scope["installation_id"],
                scope["resource_type"],
                scope["resource_id"],
                base_time - timedelta(days=2),
                base_time + timedelta(days=1),
            ),
        )
    bindings["a_alias"] = {
        "binding_id": "binding-a-alias",
        "writer_id": bindings["a"]["writer_id"],
        "writer_key_id": bindings["a"]["writer_key_id"],
        "runtime_attestation_hash": alias_runtime_hash,
        "writer_session_id": alias_session_id,
    }

    boundary_append = _BOUNDARY_DOCUMENT["append_envelope"]
    boundary_handoff = _BOUNDARY_DOCUMENT["handoff_append_envelope"]
    boundary_target_lease = next(
        json.loads(record["canonical_record_json"])
        for record in boundary_handoff["records"]
        if record["record_kind"] == "ReasoningLease"
        and json.loads(record["canonical_record_json"])["state"] == "active"
    )
    boundary_signer_id = "dockhand-chronicle-signer-boundary"
    boundary_binding_id = "binding-boundary"
    connection.execute(
        """
        INSERT INTO ops.chronicle_signers (
            signer_id, writer_id, writer_key_id, algorithm,
            public_key_digest, admitted_at, expires_at
        ) VALUES (%s, %s, %s, 'ed25519', %s, %s, %s)
        """,
        (
            boundary_signer_id,
            boundary_append["writer_id"],
            boundary_append["writer_key_id"],
            "sha256:" + "b" * 64,
            base_time - timedelta(days=2),
            base_time + timedelta(days=1),
        ),
    )
    for runtime in (
        {
            "hash": boundary_append["writer_runtime_attestation_hash"],
            "installation_id": boundary_append["installation"]["installation_id"],
            "embodiment": boundary_append["installation"]["embodiment"],
            "host_class": boundary_append["installation"]["host_class"],
        },
        {
            "hash": boundary_target_lease["runtime_attestation_hash"],
            "installation_id": boundary_target_lease["runtime_installation_id"],
            "embodiment": "mac-engineer",
            "host_class": "local-mac",
        },
    ):
        connection.execute(
            """
            INSERT INTO ops.chronicle_runtime_attestations (
                runtime_attestation_hash, identity_id, identity_revision,
                identity_epoch, installation_id, embodiment, host_class,
                admitted_at, expires_at
            ) VALUES (%s, %s, 1, 1, %s, %s, %s, %s, %s)
            ON CONFLICT (runtime_attestation_hash) DO NOTHING
            """,
            (
                runtime["hash"],
                boundary_append["identity"]["identity_id"],
                runtime["installation_id"],
                runtime["embodiment"],
                runtime["host_class"],
                base_time - timedelta(days=2),
                base_time + timedelta(days=1),
            ),
        )
    connection.execute(
        """
        INSERT INTO ops.chronicle_identity_runtime_bindings (
            binding_id, writer_id, writer_key_id, identity_id,
            identity_revision, identity_epoch, constitution_hash,
            writer_runtime_attestation_hash, source_attestation_hash,
            audience, installation_id, embodiment, host_class,
            writer_session_id, interface_id, mode, signer_id,
            admitted_at, expires_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s
        )
        """,
        (
            boundary_binding_id,
            boundary_append["writer_id"],
            boundary_append["writer_key_id"],
            boundary_append["identity"]["identity_id"],
            boundary_append["identity"]["identity_revision"],
            boundary_append["identity"]["identity_epoch"],
            boundary_append["identity"]["constitution_hash"],
            boundary_append["writer_runtime_attestation_hash"],
            boundary_append["source_attestation_hash"],
            boundary_append["audience"],
            boundary_append["installation"]["installation_id"],
            boundary_append["installation"]["embodiment"],
            boundary_append["installation"]["host_class"],
            boundary_append["writer_session_id"],
            boundary_append["interface_id"],
            boundary_append["mode"],
            boundary_signer_id,
            base_time - timedelta(days=2),
            base_time + timedelta(days=1),
        ),
    )
    boundary_scope = boundary_append["scope_bindings"][0]["scope"]
    connection.execute(
        """
        INSERT INTO ops.chronicle_identity_runtime_scopes (
            binding_id, scope_type, scope_id, installation_id,
            resource_type, resource_id, admitted_at, expires_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            boundary_binding_id,
            boundary_scope["scope_type"],
            boundary_scope["scope_id"],
            boundary_scope["installation_id"],
            boundary_scope["resource_type"],
            boundary_scope["resource_id"],
            base_time - timedelta(days=2),
            base_time + timedelta(days=1),
        ),
    )
    bindings["boundary"] = {
        "binding_id": boundary_binding_id,
        "writer_id": boundary_append["writer_id"],
        "writer_key_id": boundary_append["writer_key_id"],
        "runtime_attestation_hash": boundary_append["writer_runtime_attestation_hash"],
        "writer_session_id": boundary_append["writer_session_id"],
    }
    return bindings


def chronicle_race_append(
    barrier: threading.Barrier,
    writer_settings: dict[str, str],
    decision: dict[str, Any],
    records: list[dict[str, Any]],
    outbox_bytes: bytes,
) -> tuple[str, Any]:
    try:
        with psycopg.connect(**writer_settings) as connection:
            barrier.wait(timeout=10)
            return "ok", chronicle_execute_append(connection, decision, records, outbox_bytes)
    except psycopg.DatabaseError as error:
        return "error", error.sqlstate


@pytest.mark.skipif(not os.getenv(_DSN_ENV), reason="explicit PostgreSQL integration DSN is required")
def test_live_owner_collision_resolves_only_canonical_warehouse(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prove the existing boundary plus disabled, durable, atomic Chronicle storage."""

    dsn = os.environ[_DSN_ENV]
    connection_settings = conninfo_to_dict(dsn)
    assert connection_settings.get("dbname") == _EXPECTED_DATABASE

    with psycopg.connect(dsn, autocommit=True) as connection:
        pristine = connection.execute(
            """
            SELECT to_regnamespace('ops') IS NULL
               AND NOT EXISTS (
                   SELECT 1 FROM pg_roles
                   WHERE rolname IN (
                       'dash_ops_reader', 'dash_ops_indexer',
                       'dockhand_ops_writer', 'dash_api_runtime'
                   )
               )
            """
        ).fetchone()
        assert pristine == (True,), "integration database must be disposable and pristine"

        connection.execute("CREATE SCHEMA ai")
        connection.execute("CREATE SCHEMA dash")
        for schema in ("ai", "dash"):
            connection.execute(f"CREATE TABLE {schema}.desired_services (id SERIAL PRIMARY KEY, marker TEXT NOT NULL)")
            connection.execute(
                f"INSERT INTO {schema}.desired_services (marker) VALUES (%s)",
                (f"{schema}-sentinel",),
            )
        connection.execute(
            """
            CREATE FUNCTION public.md5(TEXT) RETURNS TEXT
            LANGUAGE SQL IMMUTABLE
            RETURN 'poisoned-public-md5'
            """
        )

    for key, value in _ROLE_SECRETS.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("DB_DRIVER", "postgresql+psycopg")
    monkeypatch.setenv("DB_HOST", connection_settings.get("host", "127.0.0.1"))
    monkeypatch.setenv("DB_PORT", connection_settings.get("port", "5432"))
    monkeypatch.setenv("DB_USER", connection_settings.get("user", "ai"))
    monkeypatch.setenv("DB_PASS", connection_settings.get("password", ""))
    monkeypatch.setenv("DB_DATABASE", _EXPECTED_DATABASE)
    # Keep the hosted DSN as the exact test connection source. This also lets
    # maintainers reproduce the proof over a local Unix socket without adding
    # another environment variable or opening a TCP listener.
    monkeypatch.setattr(migrate_ops, "build_db_url", lambda: dsn)

    migrate_ops.main()
    migrate_ops.main()

    base_settings = {
        "host": connection_settings.get("host", "127.0.0.1"),
        "port": connection_settings.get("port", "5432"),
        "dbname": _EXPECTED_DATABASE,
    }
    writer_settings = {
        **base_settings,
        "user": "dockhand_ops_writer",
        "password": _ROLE_SECRETS["DOCKHAND_OPS_WRITER_PASSWORD"],
    }
    base_time = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
    disabled_record = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 1),
        kind="AgentEpisode",
        logical_id="disabled-record",
    )
    disabled_binding = {
        "writer_id": "dockhand-chronicle-writer-a",
        "writer_key_id": "dockhand-chronicle-writer-key-a",
        "runtime_attestation_hash": "sha256:" + "4" * 64,
        "writer_session_id": chronicle_test_uuid(0x43000000, 1),
    }
    disabled_decision, disabled_outbox = chronicle_test_decision(
        request_number=1,
        writer_sequence=1,
        previous_envelope_hash=None,
        trusted_time=base_time,
        binding=disabled_binding,
        records=[disabled_record],
        chronicle_id="chronicle-disabled-test",
        scope=_SCOPES["audit"],
    )

    with psycopg.connect(dsn, autocommit=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ops.schema_migrations").fetchone() == (9,)
        assert connection.execute(
            "SELECT checksum FROM ops.schema_migrations WHERE name = %s",
            (_CANDIDATE.name,),
        ).fetchone() == (hashlib.sha256(_CANDIDATE.read_bytes()).hexdigest(),)
        with pytest.raises(psycopg.DatabaseError) as disabled_error:
            chronicle_execute_append(connection, disabled_decision, [disabled_record], disabled_outbox)
        assert disabled_error.value.sqlstate == "P2D01"
        with pytest.raises(psycopg.DatabaseError) as disabled_resolver_error:
            chronicle_resolve_request(connection, disabled_decision)
        assert disabled_resolver_error.value.sqlstate == "P2D01"
        with pytest.raises(psycopg.DatabaseError) as disabled_rejection_error:
            chronicle_record_rejection(
                connection,
                disabled_decision,
                reason="authority_changed",
                rejected_at=base_time,
                atomic_no_commit=False,
            )
        assert disabled_rejection_error.value.sqlstate == "P2D01"

        bindings = chronicle_seed_authority(connection, base_time)
        connection.execute(
            """
            UPDATE ops.chronicle_candidate_gate
            SET enabled = TRUE,
                enabled_at = %s,
                enabled_reason = 'disposable DASH_TEST_POSTGRES_DSN proof'
            WHERE singleton
            """,
            (base_time,),
        )
        connection.execute((ROOT / "db/runtime_role_privileges.sql").read_text())

        assert connection.execute("SELECT marker FROM ai.desired_services").fetchone() == ("ai-sentinel",)
        assert connection.execute("SELECT marker FROM dash.desired_services").fetchone() == ("dash-sentinel",)
        assert connection.execute("SELECT last_value, is_called FROM ai.desired_services_id_seq").fetchone() == (
            1,
            True,
        )
        connection.execute("SET search_path = public")
        resolved_md5 = connection.execute(
            "SELECT md5('canonical'), public.md5('canonical'), pg_catalog.md5('canonical')"
        ).fetchone()
        assert resolved_md5 is not None
        assert resolved_md5[0] == resolved_md5[2]
        assert resolved_md5[1] == "poisoned-public-md5"

    # The generated platform-infra boundary vector is a byte-exact SQL oracle,
    # not a hand-maintained near-copy. Provider-derived state bindings are
    # added around the signed envelope, then each proof transaction is rolled
    # back so the later 54-record replay still starts from a pristine Chronicle.
    boundary_decision, boundary_records, boundary_outbox = chronicle_boundary_decision(
        "append_envelope",
        trusted_time=_BOUNDARY_DOCUMENT["append_receipt"]["trusted_time"],
        outbox_number=1,
    )
    with psycopg.connect(dsn) as connection:
        connection.execute("SET LOCAL ROLE dockhand_ops_writer")
        boundary_result = chronicle_execute_append(
            connection,
            boundary_decision,
            boundary_records,
            boundary_outbox,
        )
        assert boundary_result == (
            boundary_decision["request_id"],
            _BOUNDARY_DOCUMENT["append_receipt"]["chronicle_watermark"],
            _BOUNDARY_DOCUMENT["append_receipt"]["record_commits"],
            _BOUNDARY_DOCUMENT["append_receipt"]["reasoning_cas_results"],
            _BOUNDARY_DOCUMENT["append_receipt"]["outbox_watermark"],
        )
        connection.rollback()

    handoff_decision, handoff_records, handoff_outbox = chronicle_boundary_decision(
        "handoff_append_envelope",
        trusted_time="2026-08-14T10:53:01Z",
        outbox_number=2,
    )
    handoff_precondition = handoff_decision["reasoning_cas_preconditions"][0]
    audit_vector = json.loads(_VECTOR.read_text(encoding="utf-8"))
    source_episode_hash = handoff_records[1]["prior_record_hash"]
    source_episode_record = chronicle_vector_record(
        next(record for record in audit_vector["records"] if record["record_hash"] == source_episode_hash)
    )
    prerequisite_active_decision, prerequisite_active_outbox = chronicle_test_decision(
        request_number=500,
        writer_sequence=1,
        previous_envelope_hash=None,
        trusted_time=datetime(2026, 8, 14, 10, 6, 1, tzinfo=UTC),
        binding=bindings["replay"],
        records=boundary_records,
        chronicle_id=handoff_decision["chronicle_id"],
        scope=_SCOPES["vector"],
        reasoning_cas_preconditions=[
            handoff_precondition
            | {
                "expected_generation": 0,
                "expected_active_reasoning_lease_hash": None,
            }
        ],
    )
    prerequisite_episode_decision, prerequisite_episode_outbox = chronicle_test_decision(
        request_number=501,
        writer_sequence=2,
        previous_envelope_hash=prerequisite_active_decision["request_digest"],
        trusted_time=datetime(2026, 8, 14, 10, 30, tzinfo=UTC),
        binding=bindings["replay"],
        records=[source_episode_record],
        chronicle_id=handoff_decision["chronicle_id"],
        scope=_SCOPES["vector"],
    )
    with psycopg.connect(dsn) as connection:
        connection.execute("SET LOCAL ROLE dockhand_ops_writer")
        chronicle_execute_append(
            connection,
            prerequisite_active_decision,
            boundary_records,
            prerequisite_active_outbox,
        )
        chronicle_execute_append(
            connection,
            prerequisite_episode_decision,
            [source_episode_record],
            prerequisite_episode_outbox,
        )
        handoff_result = chronicle_execute_append(
            connection,
            handoff_decision,
            handoff_records,
            handoff_outbox,
        )
        assert handoff_result[0] == handoff_decision["request_id"]
        assert handoff_result[1] == 8
        assert handoff_result[2] == [
            {
                "record_id": record["record_id"],
                "record_kind": record["record_kind"],
                "record_hash": record["record_hash"],
                "append_sequence": index,
            }
            for index, record in enumerate(handoff_records, start=3)
        ]
        assert handoff_result[3] == [
            {
                "identity_id": handoff_precondition["identity_id"],
                "scope_type": handoff_precondition["scope_type"],
                "scope_id": handoff_precondition["scope_id"],
                "previous_generation": 1,
                "committed_generation": 2,
                "previous_active_reasoning_lease_hash": (handoff_precondition["expected_active_reasoning_lease_hash"]),
                "committed_active_reasoning_lease_hash": handoff_records[3]["record_hash"],
            }
        ]
        assert handoff_result[4] == 3
        connection.rollback()

    with psycopg.connect(dsn, autocommit=True) as connection:
        assert connection.execute(
            """
            SELECT
                (SELECT count(*) FROM ops.chronicle_append_requests
                 WHERE request_id IN (%s, %s, %s, %s)),
                (SELECT count(*) FROM ops.chronicle_records
                 WHERE record_hash = ANY(%s::text[])),
                (SELECT count(*) FROM ops.chronicle_reasoning_leases
                 WHERE identity_id = %s AND scope_type = %s AND scope_id = %s)
            """,
            (
                boundary_decision["request_id"],
                handoff_decision["request_id"],
                prerequisite_active_decision["request_id"],
                prerequisite_episode_decision["request_id"],
                [record["record_hash"] for record in boundary_records + [source_episode_record] + handoff_records],
                handoff_precondition["identity_id"],
                handoff_precondition["scope_type"],
                handoff_precondition["scope_id"],
            ),
        ).fetchone() == (0, 0, 0)

    basic_scope = _SCOPES["basic"]
    basic_lease = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 2),
        kind="ReasoningLease",
        logical_id="basic-reasoning-lease",
        fields={
            "state": "active",
            "generation": 1,
            "expected_previous_generation": 0,
            "identity": {"identity_id": _IDENTITY_ID},
            "scope": {
                "scope_type": basic_scope["scope_type"],
                "scope_id": basic_scope["scope_id"],
            },
        },
    )
    basic_episode = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 3),
        kind="AgentEpisode",
        logical_id="basic-episode",
    )
    basic_records = [basic_lease, basic_episode]
    basic_decision, basic_outbox = chronicle_test_decision(
        request_number=2,
        writer_sequence=1,
        previous_envelope_hash=None,
        trusted_time=base_time,
        binding=bindings["a"],
        records=basic_records,
        chronicle_id="chronicle-atomic-test",
        scope=basic_scope,
        reasoning_cas_preconditions=[
            {
                "identity_id": _IDENTITY_ID,
                "scope_type": basic_scope["scope_type"],
                "scope_id": basic_scope["scope_id"],
                "expected_generation": 0,
                "expected_active_reasoning_lease_hash": None,
            }
        ],
    )
    with psycopg.connect(**writer_settings) as connection:
        basic_result = chronicle_execute_append(connection, basic_decision, basic_records, basic_outbox)
        assert basic_result[0] == basic_decision["request_id"]
        assert basic_result[1] == 2
        assert [item["append_sequence"] for item in basic_result[2]] == [1, 2]
        assert basic_result[2][-1]["record_hash"] == basic_episode["record_hash"]
        assert basic_result[3] == [
            {
                "identity_id": _IDENTITY_ID,
                "scope_type": basic_scope["scope_type"],
                "scope_id": basic_scope["scope_id"],
                "previous_generation": 0,
                "committed_generation": 1,
                "previous_active_reasoning_lease_hash": None,
                "committed_active_reasoning_lease_hash": basic_lease["record_hash"],
            }
        ]
        assert basic_result[4] == 1
        assert all("record_committed" not in item for item in basic_result[2])

    with psycopg.connect(dsn, autocommit=True) as connection:
        assert connection.execute(
            """
            SELECT canonical_record_bytes, canonical_bytes_sha256
            FROM ops.chronicle_records WHERE record_id = %s
            """,
            (basic_episode["record_id"],),
        ).fetchone() == (basic_episode["canonical_bytes"], basic_episode["canonical_bytes_sha256"])
        assert connection.execute(
            """
            SELECT chronicle_watermark, audit_outbox_watermark
            FROM ops.chronicle_append_state
            WHERE chronicle_id = 'chronicle-atomic-test'
            """
        ).fetchone() == (2, 1)
        assert connection.execute(
            """
            SELECT generation, active_reasoning_lease_hash
            FROM ops.chronicle_reasoning_leases
            WHERE identity_id = %s AND scope_type = %s AND scope_id = %s
            """,
            (_IDENTITY_ID, basic_scope["scope_type"], basic_scope["scope_id"]),
        ).fetchone() == (1, basic_lease["record_hash"])
        assert connection.execute(
            """
            SELECT last_writer_sequence, last_envelope_hash
            FROM ops.chronicle_replay_sequences
            WHERE writer_id = %s AND writer_key_id = %s
            """,
            (bindings["a"]["writer_id"], bindings["a"]["writer_key_id"]),
        ).fetchone() == (1, basic_decision["request_digest"])
        assert connection.execute(
            """
            SELECT high_water FROM ops.chronicle_trusted_clock
            WHERE chronicle_id = 'chronicle-atomic-test'
            """
        ).fetchone() == (base_time,)

    # Model a committed request whose acknowledgement was lost. An exact retry
    # returns the stored result tuple without another append/outbox/state write.
    with psycopg.connect(**writer_settings) as connection:
        recovered_basic_result = chronicle_execute_append(
            connection,
            basic_decision,
            basic_records,
            basic_outbox,
        )
    assert recovered_basic_result == basic_result
    with psycopg.connect(dsn, autocommit=True) as connection:
        assert connection.execute(
            """
            SELECT
                (SELECT count(*) FROM ops.chronicle_append_requests),
                (SELECT count(*) FROM ops.chronicle_records),
                (SELECT count(*) FROM ops.chronicle_outbox)
            """
        ).fetchone() == (1, 2, 1)

    with psycopg.connect(**writer_settings) as connection:
        committed_state = chronicle_resolve_request(connection, basic_decision)
        assert committed_state["request_id_digest"] == basic_decision["request_digest"]
        assert committed_state["request_nonce_digest"] == basic_decision["request_digest"]
        assert committed_state["committed_request_digest"] == basic_decision["request_digest"]
        assert committed_state["commit_result"] == {
            "chronicle_watermark": basic_result[1],
            "record_commits": basic_result[2],
            "reasoning_cas_results": basic_result[3],
            "outbox_watermark": basic_result[4],
        }
        assert committed_state["rejected_request_digest"] is None
        assert committed_state["rejection_atomic_no_commit"] is None
        committed_wins_state = chronicle_record_rejection(
            connection,
            basic_decision,
            reason="internal_failure",
            rejected_at=base_time + timedelta(seconds=1),
            atomic_no_commit=True,
        )
        assert committed_wins_state == committed_state

    rejected_record = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 140),
        kind="AgentEpisode",
        logical_id="durable-preflight-rejection",
    )
    rejected_decision, rejected_outbox = chronicle_test_decision(
        request_number=140,
        writer_sequence=2,
        previous_envelope_hash=basic_decision["request_digest"],
        trusted_time=base_time + timedelta(seconds=1),
        binding=bindings["a"],
        records=[rejected_record],
        chronicle_id="chronicle-tombstone-test",
        scope=_SCOPES["audit"],
    )
    rejected_decision["audience"] = "wrong-audience"
    rejected_at = base_time + timedelta(seconds=10)
    with psycopg.connect(**writer_settings) as connection:
        rejected_state = chronicle_record_rejection(
            connection,
            rejected_decision,
            reason="audience_mismatch",
            rejected_at=rejected_at,
            atomic_no_commit=False,
        )
    assert rejected_state["request_id_digest"] == rejected_decision["request_digest"]
    assert rejected_state["request_nonce_digest"] == rejected_decision["request_digest"]
    assert rejected_state["committed_request_digest"] is None
    assert rejected_state["rejected_request_digest"] == rejected_decision["request_digest"]
    assert rejected_state["rejection_reason"] == "audience_mismatch"
    assert rejected_state["rejected_at"] == chronicle_test_timestamp(rejected_at)
    assert rejected_state["rejection_atomic_no_commit"] is False

    # Exact rejection retries preserve the first durable reason/time/atomicity,
    # even when the caller reaches the recorder after a lost response.
    with psycopg.connect(**writer_settings) as connection:
        exact_rejected_retry = chronicle_record_rejection(
            connection,
            rejected_decision,
            reason="internal_failure",
            rejected_at=rejected_at - timedelta(seconds=5),
            atomic_no_commit=True,
        )
    assert exact_rejected_retry == rejected_state
    with psycopg.connect(**writer_settings) as connection:
        assert chronicle_resolve_request(connection, rejected_decision) == rejected_state

    # A rejection tombstone is outside Chronicle: it advances only the durable
    # trusted-time high-water, never a record, request, evidence, outbox,
    # Chronicle watermark, or writer head. Direct append is blocked by the
    # durable claims in a separate transaction.
    with psycopg.connect(dsn, autocommit=True) as connection:
        assert connection.execute(
            """
            SELECT
                (SELECT count(*) FROM ops.chronicle_append_requests),
                (SELECT count(*) FROM ops.chronicle_records),
                (SELECT count(*) FROM ops.chronicle_append_request_evidence),
                (SELECT count(*) FROM ops.chronicle_outbox),
                (SELECT last_writer_sequence
                 FROM ops.chronicle_replay_sequences
                 WHERE writer_id = %s AND writer_key_id = %s),
                (SELECT high_water FROM ops.chronicle_trusted_clock
                 WHERE chronicle_id = %s)
            """,
            (
                bindings["a"]["writer_id"],
                bindings["a"]["writer_key_id"],
                rejected_decision["chronicle_id"],
            ),
        ).fetchone() == (1, 2, 1, 1, 1, rejected_at)
    with psycopg.connect(**writer_settings, autocommit=True) as connection:
        with pytest.raises(psycopg.DatabaseError) as rejected_append_error:
            chronicle_execute_append(
                connection,
                rejected_decision,
                [rejected_record],
                rejected_outbox,
            )
        assert rejected_append_error.value.sqlstate == "P2D02"

    reconstructed_stale_record = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 146),
        kind="AgentEpisode",
        logical_id="reconstructed-clock-rollback",
    )
    reconstructed_stale_decision, reconstructed_stale_outbox = chronicle_test_decision(
        request_number=146,
        writer_sequence=1,
        previous_envelope_hash=None,
        trusted_time=base_time + timedelta(seconds=5),
        binding=bindings["b"],
        records=[reconstructed_stale_record],
        chronicle_id=rejected_decision["chronicle_id"],
        scope=_SCOPES["audit"],
    )
    with psycopg.connect(dsn, autocommit=True) as connection:
        evidence_count_before_stale_reconstruction = connection.execute(
            "SELECT count(*) FROM ops.chronicle_evidence"
        ).fetchone()[0]
    with psycopg.connect(**writer_settings, autocommit=True) as connection:
        with pytest.raises(psycopg.DatabaseError) as stale_reconstruction_error:
            chronicle_execute_append(
                connection,
                reconstructed_stale_decision,
                [reconstructed_stale_record],
                reconstructed_stale_outbox,
            )
        assert stale_reconstruction_error.value.sqlstate == "P2D05"
    with psycopg.connect(dsn, autocommit=True) as connection:
        assert connection.execute(
            """
            SELECT
                (SELECT count(*) FROM ops.chronicle_append_requests
                 WHERE request_id = %s),
                (SELECT count(*) FROM ops.chronicle_records
                 WHERE record_id = %s),
                (SELECT count(*) FROM ops.chronicle_outbox
                 WHERE request_id = %s),
                (SELECT count(*) FROM ops.chronicle_replay_request_claims
                 WHERE request_id = %s),
                (SELECT count(*) FROM ops.chronicle_replay_nonce_claims
                 WHERE writer_id = %s AND request_nonce = %s),
                (SELECT count(*) FROM ops.chronicle_append_state
                 WHERE chronicle_id = %s),
                (SELECT count(*) FROM ops.chronicle_evidence),
                (SELECT high_water FROM ops.chronicle_trusted_clock
                 WHERE chronicle_id = %s)
            """,
            (
                reconstructed_stale_decision["request_id"],
                reconstructed_stale_record["record_id"],
                reconstructed_stale_decision["request_id"],
                reconstructed_stale_decision["request_id"],
                reconstructed_stale_decision["writer_id"],
                reconstructed_stale_decision["request_nonce"],
                reconstructed_stale_decision["chronicle_id"],
                reconstructed_stale_decision["chronicle_id"],
            ),
        ).fetchone() == (
            0,
            0,
            0,
            0,
            0,
            0,
            evidence_count_before_stale_reconstruction,
            rejected_at,
        )

    # Exact reconstruction is allowed after the registry has moved on, while a
    # new request from that revoked signer is refused and burns no identifier.
    fresh_revoked_decision = json.loads(json.dumps(rejected_decision))
    fresh_revoked_decision["request_id"] = chronicle_test_uuid(0x40000000, 141)
    fresh_revoked_decision["request_nonce"] = chronicle_test_uuid(0x41000000, 141)
    fresh_revoked_decision["request_digest"] = chronicle_test_digest(b"revoked-signer")
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(
            """
            UPDATE ops.chronicle_signers
            SET revoked_at = %s,
                revocation_record_hash = %s
            WHERE writer_id = %s AND writer_key_id = %s
            """,
            (
                base_time + timedelta(seconds=2),
                "sha256:" + "e" * 64,
                bindings["a"]["writer_id"],
                bindings["a"]["writer_key_id"],
            ),
        )
    with psycopg.connect(**writer_settings) as connection:
        assert (
            chronicle_record_rejection(
                connection,
                rejected_decision,
                reason="audience_mismatch",
                rejected_at=base_time + timedelta(seconds=3),
                atomic_no_commit=False,
            )
            == rejected_state
        )
    with psycopg.connect(**writer_settings, autocommit=True) as connection:
        with pytest.raises(psycopg.DatabaseError) as revoked_signer_error:
            chronicle_record_rejection(
                connection,
                fresh_revoked_decision,
                reason="audience_mismatch",
                rejected_at=base_time + timedelta(seconds=3),
                atomic_no_commit=False,
            )
        assert revoked_signer_error.value.sqlstate == "P2D09"
    with psycopg.connect(dsn, autocommit=True) as connection:
        assert connection.execute(
            """
            SELECT count(*) FROM ops.chronicle_replay_request_claims
            WHERE request_id = %s
            """,
            (fresh_revoked_decision["request_id"],),
        ).fetchone() == (0,)
        connection.execute(
            """
            UPDATE ops.chronicle_signers
            SET revoked_at = NULL, revocation_record_hash = NULL
            WHERE writer_id = %s AND writer_key_id = %s
            """,
            (bindings["a"]["writer_id"], bindings["a"]["writer_key_id"]),
        )

    # Full asymmetric collision matrix. Every still-free identifier is burned
    # to the attempted digest without overwriting the already claimed side.
    request_collision = json.loads(json.dumps(basic_decision))
    request_collision["chronicle_id"] = rejected_decision["chronicle_id"]
    request_collision["request_nonce"] = chronicle_test_uuid(0x41000000, 142)
    request_collision["request_digest"] = chronicle_test_digest(b"request-collision")
    nonce_collision = json.loads(json.dumps(basic_decision))
    nonce_collision["chronicle_id"] = rejected_decision["chronicle_id"]
    nonce_collision["request_id"] = chronicle_test_uuid(0x40000000, 143)
    nonce_collision["request_digest"] = chronicle_test_digest(b"nonce-collision")
    cross_collision = json.loads(json.dumps(basic_decision))
    cross_collision["chronicle_id"] = rejected_decision["chronicle_id"]
    cross_collision["request_nonce"] = rejected_decision["request_nonce"]
    cross_collision["request_digest"] = chronicle_test_digest(b"cross-collision")
    with psycopg.connect(**writer_settings) as connection:
        request_collision_state = chronicle_record_rejection(
            connection,
            request_collision,
            reason="replay_conflict",
            rejected_at=base_time + timedelta(seconds=11),
            atomic_no_commit=False,
        )
        nonce_collision_state = chronicle_record_rejection(
            connection,
            nonce_collision,
            reason="replay_conflict",
            rejected_at=base_time + timedelta(seconds=12),
            atomic_no_commit=False,
        )
        cross_collision_state = chronicle_record_rejection(
            connection,
            cross_collision,
            reason="replay_conflict",
            rejected_at=base_time + timedelta(seconds=13),
            atomic_no_commit=False,
        )
    assert request_collision_state["request_id_digest"] == basic_decision["request_digest"]
    assert request_collision_state["request_nonce_digest"] == request_collision["request_digest"]
    assert request_collision_state["rejected_request_digest"] is None
    assert nonce_collision_state["request_id_digest"] == nonce_collision["request_digest"]
    assert nonce_collision_state["request_nonce_digest"] == basic_decision["request_digest"]
    assert nonce_collision_state["rejected_request_digest"] is None
    assert cross_collision_state["request_id_digest"] == basic_decision["request_digest"]
    assert cross_collision_state["request_nonce_digest"] == rejected_decision["request_digest"]
    assert cross_collision_state["rejected_request_digest"] is None

    changed_rejected_digest = json.loads(json.dumps(rejected_decision))
    changed_rejected_digest["request_digest"] = chronicle_test_digest(b"changed-retry")
    with psycopg.connect(**writer_settings) as connection:
        changed_retry_state = chronicle_record_rejection(
            connection,
            changed_rejected_digest,
            reason="replay_conflict",
            rejected_at=base_time + timedelta(seconds=14),
            atomic_no_commit=False,
        )
    assert changed_retry_state["request_id_digest"] == rejected_decision["request_digest"]
    assert changed_retry_state["request_nonce_digest"] == rejected_decision["request_digest"]
    assert changed_retry_state["rejected_request_digest"] == rejected_decision["request_digest"]
    assert changed_retry_state["rejection_reason"] == "audience_mismatch"

    rebound_decision = json.loads(json.dumps(basic_decision))
    rebound_decision["audience"] = "forged-retry-audience"
    with psycopg.connect(**writer_settings, autocommit=True) as connection:
        with pytest.raises(psycopg.DatabaseError) as rebound_error:
            chronicle_execute_append(
                connection,
                rebound_decision,
                basic_records,
                basic_outbox,
            )
        assert rebound_error.value.sqlstate == "P2D02"

    alias_nonce_record = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 101),
        kind="AgentEpisode",
        logical_id="alias-nonce-replay",
    )
    alias_nonce_decision, alias_nonce_outbox = chronicle_test_decision(
        request_number=101,
        writer_sequence=2,
        previous_envelope_hash=basic_decision["request_digest"],
        trusted_time=base_time + timedelta(seconds=1),
        binding=bindings["a_alias"],
        records=[alias_nonce_record],
        chronicle_id="chronicle-atomic-test",
        scope=_SCOPES["audit"],
        nonce=basic_decision["request_nonce"],
    )
    with psycopg.connect(**writer_settings, autocommit=True) as connection:
        with pytest.raises(psycopg.DatabaseError) as alias_nonce_error:
            chronicle_execute_append(
                connection,
                alias_nonce_decision,
                [alias_nonce_record],
                alias_nonce_outbox,
            )
        assert alias_nonce_error.value.sqlstate == "P2D02"

    alias_reset_record = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 102),
        kind="AgentEpisode",
        logical_id="alias-sequence-reset",
    )
    alias_reset_decision, alias_reset_outbox = chronicle_test_decision(
        request_number=102,
        writer_sequence=1,
        previous_envelope_hash=None,
        trusted_time=base_time + timedelta(seconds=1),
        binding=bindings["a_alias"],
        records=[alias_reset_record],
        chronicle_id="chronicle-atomic-test",
        scope=_SCOPES["audit"],
    )
    with psycopg.connect(**writer_settings, autocommit=True) as connection:
        with pytest.raises(psycopg.DatabaseError) as alias_reset_error:
            chronicle_execute_append(
                connection,
                alias_reset_decision,
                [alias_reset_record],
                alias_reset_outbox,
            )
        assert alias_reset_error.value.sqlstate == "P2D03"

    canonical_probe = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 103),
        kind="AgentEpisode",
        logical_id="strict-canonical-json",
    )
    canonical_text = canonical_probe["canonical_bytes"].decode()
    first_member_end = canonical_text.index(",")
    duplicate_key_text = (
        '{"apiVersion":"platform.masonjames.dev/steward/v1",'
        + canonical_text[len('{"apiVersion":"platform.masonjames.dev/steward/v1",') :]
    )
    duplicate_key_text = (
        duplicate_key_text[:first_member_end]
        + ',"apiVersion":"platform.masonjames.dev/steward/v1"'
        + duplicate_key_text[first_member_end:]
    )
    malformed_variants = (
        (103, duplicate_key_text.encode()),
        (104, b"{ " + canonical_probe["canonical_bytes"][1:]),
    )
    for request_number, malformed_bytes in malformed_variants:
        malformed_record = {
            **canonical_probe,
            "canonical_bytes": malformed_bytes,
            "canonical_bytes_sha256": chronicle_test_digest(malformed_bytes),
        }
        malformed_decision, malformed_outbox = chronicle_test_decision(
            request_number=request_number,
            writer_sequence=2,
            previous_envelope_hash=basic_decision["request_digest"],
            trusted_time=base_time + timedelta(seconds=1),
            binding=bindings["a"],
            records=[malformed_record],
            chronicle_id="chronicle-atomic-test",
            scope=_SCOPES["audit"],
        )
        with psycopg.connect(**writer_settings, autocommit=True) as connection:
            with pytest.raises(psycopg.DatabaseError) as malformed_error:
                chronicle_execute_append(
                    connection,
                    malformed_decision,
                    [malformed_record],
                    malformed_outbox,
                )
            assert malformed_error.value.sqlstate == "P2D06"

    forged_domain_record = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 106),
        kind="AgentEpisode",
        logical_id="mutually-forged-record-hash",
    )
    forged_domain_hash = "sha256:" + "0" * 64
    forged_domain_document = {
        **forged_domain_record["document"],
        "record_hash": forged_domain_hash,
    }
    forged_domain_bytes = canonical_json_bytes(forged_domain_document)
    forged_domain_record = {
        **forged_domain_record,
        "document": forged_domain_document,
        "record_hash": forged_domain_hash,
        "canonical_bytes": forged_domain_bytes,
        "canonical_bytes_sha256": chronicle_test_digest(forged_domain_bytes),
    }
    forged_domain_decision, forged_domain_outbox = chronicle_test_decision(
        request_number=106,
        writer_sequence=2,
        previous_envelope_hash=basic_decision["request_digest"],
        trusted_time=base_time + timedelta(seconds=1),
        binding=bindings["a"],
        records=[forged_domain_record],
        chronicle_id="chronicle-atomic-test",
        scope=_SCOPES["audit"],
    )
    with psycopg.connect(**writer_settings, autocommit=True) as connection:
        with pytest.raises(psycopg.DatabaseError) as forged_domain_error:
            chronicle_execute_append(
                connection,
                forged_domain_decision,
                [forged_domain_record],
                forged_domain_outbox,
            )
        assert forged_domain_error.value.sqlstate == "P2D06"
        assert "canonical steward domain" in str(forged_domain_error.value)

    cited_evidence = "sha256:" + "f" * 64
    evidence_record = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 105),
        kind="AgentEpisode",
        logical_id="omitted-record-evidence",
        fields={"evidence": [{"evidence_hash": cited_evidence}]},
    )
    evidence_decision, evidence_outbox = chronicle_test_decision(
        request_number=105,
        writer_sequence=2,
        previous_envelope_hash=basic_decision["request_digest"],
        trusted_time=base_time + timedelta(seconds=1),
        binding=bindings["a"],
        records=[evidence_record],
        chronicle_id="chronicle-atomic-test",
        scope=_SCOPES["audit"],
    )
    evidence_decision["evidence_hashes"].remove(cited_evidence)
    with psycopg.connect(**writer_settings, autocommit=True) as connection:
        with pytest.raises(psycopg.DatabaseError) as evidence_binding_error:
            chronicle_execute_append(
                connection,
                evidence_decision,
                [evidence_record],
                evidence_outbox,
            )
        assert evidence_binding_error.value.sqlstate == "P2D10"

    adversarial_scope = _SCOPES["adversarial"]
    cas_shape_cases: list[tuple[int, dict[str, Any], dict[str, str], dict[str, Any]]] = []
    missing_terminal = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 120),
        kind="ReasoningLease",
        logical_id="missing-terminal-target",
        fields={
            "state": "active",
            "generation": 2,
            "expected_previous_generation": 1,
            "identity": {"identity_id": _IDENTITY_ID},
            "scope": {
                "scope_type": basic_scope["scope_type"],
                "scope_id": basic_scope["scope_id"],
            },
        },
    )
    cas_shape_cases.append(
        (
            120,
            missing_terminal,
            basic_scope,
            {
                "identity_id": _IDENTITY_ID,
                "scope_type": basic_scope["scope_type"],
                "scope_id": basic_scope["scope_id"],
                "expected_generation": 1,
                "expected_active_reasoning_lease_hash": basic_lease["record_hash"],
            },
        )
    )
    terminal_wrong_previous = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 121),
        kind="ReasoningLease",
        logical_id="basic-reasoning-lease",
        logical_revision=2,
        prior_record_hash=basic_lease["record_hash"],
        fields={
            "state": "released",
            "generation": 1,
            "expected_previous_generation": 1,
            "identity": {"identity_id": _IDENTITY_ID},
            "scope": {
                "scope_type": basic_scope["scope_type"],
                "scope_id": basic_scope["scope_id"],
            },
        },
    )
    cas_shape_cases.append(
        (
            121,
            terminal_wrong_previous,
            basic_scope,
            {
                "identity_id": _IDENTITY_ID,
                "scope_type": basic_scope["scope_type"],
                "scope_id": basic_scope["scope_id"],
                "expected_generation": 1,
                "expected_active_reasoning_lease_hash": basic_lease["record_hash"],
            },
        )
    )
    terminal_wrong_revision = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 122),
        kind="ReasoningLease",
        logical_id="wrong-terminal-revision",
        fields={
            "state": "released",
            "generation": 1,
            "expected_previous_generation": 0,
            "identity": {"identity_id": _IDENTITY_ID},
            "scope": {
                "scope_type": basic_scope["scope_type"],
                "scope_id": basic_scope["scope_id"],
            },
        },
    )
    cas_shape_cases.append(
        (
            122,
            terminal_wrong_revision,
            basic_scope,
            {
                "identity_id": _IDENTITY_ID,
                "scope_type": basic_scope["scope_type"],
                "scope_id": basic_scope["scope_id"],
                "expected_generation": 1,
                "expected_active_reasoning_lease_hash": basic_lease["record_hash"],
            },
        )
    )
    active_wrong_revision = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 123),
        kind="ReasoningLease",
        logical_id="basic-reasoning-lease",
        logical_revision=2,
        prior_record_hash=basic_lease["record_hash"],
        fields={
            "state": "active",
            "generation": 1,
            "expected_previous_generation": 0,
            "identity": {"identity_id": _IDENTITY_ID},
            "scope": {
                "scope_type": adversarial_scope["scope_type"],
                "scope_id": adversarial_scope["scope_id"],
            },
        },
    )
    cas_shape_cases.append(
        (
            123,
            active_wrong_revision,
            adversarial_scope,
            {
                "identity_id": _IDENTITY_ID,
                "scope_type": adversarial_scope["scope_type"],
                "scope_id": adversarial_scope["scope_id"],
                "expected_generation": 0,
                "expected_active_reasoning_lease_hash": None,
            },
        )
    )
    active_wrong_generation = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 124),
        kind="ReasoningLease",
        logical_id="wrong-active-generation",
        fields={
            "state": "active",
            "generation": 2,
            "expected_previous_generation": 0,
            "identity": {"identity_id": _IDENTITY_ID},
            "scope": {
                "scope_type": adversarial_scope["scope_type"],
                "scope_id": adversarial_scope["scope_id"],
            },
        },
    )
    cas_shape_cases.append(
        (
            124,
            active_wrong_generation,
            adversarial_scope,
            {
                "identity_id": _IDENTITY_ID,
                "scope_type": adversarial_scope["scope_type"],
                "scope_id": adversarial_scope["scope_id"],
                "expected_generation": 0,
                "expected_active_reasoning_lease_hash": None,
            },
        )
    )
    active_wrong_expected = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 125),
        kind="ReasoningLease",
        logical_id="wrong-active-expected",
        fields={
            "state": "active",
            "generation": 1,
            "expected_previous_generation": 1,
            "identity": {"identity_id": _IDENTITY_ID},
            "scope": {
                "scope_type": adversarial_scope["scope_type"],
                "scope_id": adversarial_scope["scope_id"],
            },
        },
    )
    cas_shape_cases.append(
        (
            125,
            active_wrong_expected,
            adversarial_scope,
            {
                "identity_id": _IDENTITY_ID,
                "scope_type": adversarial_scope["scope_type"],
                "scope_id": adversarial_scope["scope_id"],
                "expected_generation": 0,
                "expected_active_reasoning_lease_hash": None,
            },
        )
    )
    for request_number, record, scope, precondition in cas_shape_cases:
        decision, outbox = chronicle_test_decision(
            request_number=request_number,
            writer_sequence=2,
            previous_envelope_hash=basic_decision["request_digest"],
            trusted_time=base_time + timedelta(seconds=1),
            binding=bindings["a"],
            records=[record],
            chronicle_id="chronicle-atomic-test",
            scope=scope,
            reasoning_cas_preconditions=[precondition],
        )
        with psycopg.connect(**writer_settings, autocommit=True) as connection:
            with pytest.raises(psycopg.DatabaseError) as cas_shape_error:
                chronicle_execute_append(connection, decision, [record], outbox)
            assert cas_shape_error.value.sqlstate == "P2D07"
        if request_number == 120:
            with psycopg.connect(**writer_settings) as connection:
                atomic_rejection_state = chronicle_record_rejection(
                    connection,
                    decision,
                    reason="cas_conflict",
                    rejected_at=base_time + timedelta(seconds=1),
                    atomic_no_commit=True,
                )
            assert atomic_rejection_state["rejection_reason"] == "cas_conflict"
            assert atomic_rejection_state["rejection_atomic_no_commit"] is True
            assert atomic_rejection_state["committed_request_digest"] is None
            with psycopg.connect(**writer_settings) as connection:
                reconstructed_atomic_rejection = chronicle_record_rejection(
                    connection,
                    decision,
                    reason="internal_failure",
                    rejected_at=base_time + timedelta(seconds=40),
                    atomic_no_commit=False,
                )
            assert reconstructed_atomic_rejection == atomic_rejection_state

    released_lease = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 20),
        kind="ReasoningLease",
        logical_id="basic-reasoning-lease",
        logical_revision=2,
        prior_record_hash=basic_lease["record_hash"],
        fields={
            "state": "released",
            "generation": 1,
            "expected_previous_generation": 0,
            "identity": {"identity_id": _IDENTITY_ID},
            "scope": {
                "scope_type": basic_scope["scope_type"],
                "scope_id": basic_scope["scope_id"],
            },
        },
    )
    release_decision, release_outbox = chronicle_test_decision(
        request_number=20,
        writer_sequence=2,
        previous_envelope_hash=basic_decision["request_digest"],
        trusted_time=base_time + timedelta(seconds=1),
        binding=bindings["a"],
        records=[released_lease],
        chronicle_id="chronicle-atomic-test",
        scope=basic_scope,
        reasoning_cas_preconditions=[
            {
                "identity_id": _IDENTITY_ID,
                "scope_type": basic_scope["scope_type"],
                "scope_id": basic_scope["scope_id"],
                "expected_generation": 1,
                "expected_active_reasoning_lease_hash": basic_lease["record_hash"],
            }
        ],
    )
    with psycopg.connect(**writer_settings) as connection:
        release_result = chronicle_execute_append(
            connection,
            release_decision,
            [released_lease],
            release_outbox,
        )
        assert release_result[1] == 3
        assert release_result[3] == [
            {
                "identity_id": _IDENTITY_ID,
                "scope_type": basic_scope["scope_type"],
                "scope_id": basic_scope["scope_id"],
                "previous_generation": 1,
                "committed_generation": 1,
                "previous_active_reasoning_lease_hash": basic_lease["record_hash"],
                "committed_active_reasoning_lease_hash": None,
            }
        ]
        assert release_result[4] == 2

    with psycopg.connect(dsn, autocommit=True) as connection:
        assert connection.execute(
            """
            SELECT generation, active_reasoning_lease_hash
            FROM ops.chronicle_reasoning_leases
            WHERE identity_id = %s AND scope_type = %s AND scope_id = %s
            """,
            (_IDENTITY_ID, basic_scope["scope_type"], basic_scope["scope_id"]),
        ).fetchone() == (1, None)

    forged_binding_record = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 21),
        kind="AgentEpisode",
        logical_id="derived-binding-proof",
    )
    forged_binding_decision, forged_binding_outbox = chronicle_test_decision(
        request_number=21,
        writer_sequence=3,
        previous_envelope_hash=release_decision["request_digest"],
        trusted_time=base_time + timedelta(seconds=2),
        binding=bindings["a"],
        records=[forged_binding_record],
        chronicle_id="chronicle-atomic-test",
        scope=_SCOPES["audit"],
    )
    forged_binding_decision["record_bindings"][0]["logical_id"] = "forged-logical-id"
    with psycopg.connect(**writer_settings, autocommit=True) as connection:
        with pytest.raises(psycopg.DatabaseError) as forged_binding_error:
            chronicle_execute_append(
                connection,
                forged_binding_decision,
                [forged_binding_record],
                forged_binding_outbox,
            )
        assert forged_binding_error.value.sqlstate == "P2D06"

    clock_record = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 4),
        kind="AgentEpisode",
        logical_id="clock-rollback",
    )
    clock_decision, clock_outbox = chronicle_test_decision(
        request_number=3,
        writer_sequence=1,
        previous_envelope_hash=None,
        trusted_time=base_time - timedelta(seconds=1),
        binding=bindings["b"],
        records=[clock_record],
        chronicle_id="chronicle-atomic-test",
        scope=_SCOPES["audit"],
    )
    with psycopg.connect(**writer_settings, autocommit=True) as connection:
        with pytest.raises(psycopg.DatabaseError) as clock_error:
            chronicle_execute_append(connection, clock_decision, [clock_record], clock_outbox)
        assert clock_error.value.sqlstate == "P2D05"

    race_scope = _SCOPES["race"]
    lease_inputs: list[tuple[dict[str, Any], list[dict[str, Any]], bytes]] = []
    for offset, name in enumerate(("b", "c"), start=4):
        lease = chronicle_test_record(
            record_id=chronicle_test_uuid(0x30000000, offset + 1),
            kind="ReasoningLease",
            logical_id=f"lease-race-{name}",
            fields={
                "state": "active",
                "generation": 1,
                "expected_previous_generation": 0,
                "identity": {"identity_id": _IDENTITY_ID},
                "scope": {
                    "scope_type": race_scope["scope_type"],
                    "scope_id": race_scope["scope_id"],
                },
            },
        )
        decision, outbox = chronicle_test_decision(
            request_number=offset,
            writer_sequence=1,
            previous_envelope_hash=None,
            trusted_time=base_time + timedelta(seconds=1),
            binding=bindings[name],
            records=[lease],
            chronicle_id="chronicle-atomic-test",
            scope=race_scope,
            reasoning_cas_preconditions=[
                {
                    "identity_id": _IDENTITY_ID,
                    "scope_type": race_scope["scope_type"],
                    "scope_id": race_scope["scope_id"],
                    "expected_generation": 0,
                    "expected_active_reasoning_lease_hash": None,
                }
            ],
        )
        lease_inputs.append((decision, [lease], outbox))

    lease_barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as executor:
        lease_results = list(
            executor.map(
                lambda item: chronicle_race_append(lease_barrier, writer_settings, *item),
                lease_inputs,
            )
        )
    assert sorted(status for status, _ in lease_results) == ["error", "ok"]
    assert [value for status, value in lease_results if status == "error"] == ["P2D07"]

    nonce_inputs: list[tuple[dict[str, Any], list[dict[str, Any]], bytes]] = []
    shared_nonce = chronicle_test_uuid(0x41000000, 99)
    for offset in (7, 8):
        record = chronicle_test_record(
            record_id=chronicle_test_uuid(0x30000000, offset),
            kind="AgentEpisode",
            logical_id=f"nonce-race-{offset}",
        )
        decision, outbox = chronicle_test_decision(
            request_number=offset,
            writer_sequence=3,
            previous_envelope_hash=release_decision["request_digest"],
            trusted_time=base_time + timedelta(seconds=2),
            binding=bindings["a"],
            records=[record],
            chronicle_id="chronicle-atomic-test",
            scope=_SCOPES["audit"],
            nonce=shared_nonce,
        )
        nonce_inputs.append((decision, [record], outbox))

    nonce_barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as executor:
        nonce_results = list(
            executor.map(
                lambda item: chronicle_race_append(nonce_barrier, writer_settings, *item),
                nonce_inputs,
            )
        )
    assert sorted(status for status, _ in nonce_results) == ["error", "ok"]
    assert [value for status, value in nonce_results if status == "error"] == ["P2D02"]

    with psycopg.connect(dsn, autocommit=True) as connection:
        replay_states = {
            row[0]: (row[1], row[2])
            for row in connection.execute(
                """
                SELECT writer_id, last_writer_sequence, last_envelope_hash
                FROM ops.chronicle_replay_sequences
                WHERE writer_id IN (%s, %s)
                """,
                (bindings["b"]["writer_id"], bindings["c"]["writer_id"]),
            ).fetchall()
        }
        binding_a_state = connection.execute(
            """
            SELECT last_writer_sequence, last_envelope_hash
            FROM ops.chronicle_replay_sequences
            WHERE writer_id = %s AND writer_key_id = %s
            """,
            (bindings["a"]["writer_id"], bindings["a"]["writer_key_id"]),
        ).fetchone()
        assert binding_a_state is not None and binding_a_state[0] == 3

    budget_runtime = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 130),
        kind="RuntimeAttestation",
        logical_id="budget-runtime-attestation",
        fields={"attestation_id": "budget-runtime-attestation"},
    )
    budget_lease = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 131),
        kind="CapabilityLease",
        logical_id="shared-capability-budget",
        fields={
            "lease_id": "shared-capability-budget",
            "issuer": "budget-lease-issuer",
            "nonce": chronicle_test_uuid(0x44000000, 1),
            "capability_id": "chronicle-budget-proof",
            "identity": {
                "identity_id": _IDENTITY_ID,
                "identity_revision": 1,
                "identity_epoch": 1,
            },
            "audience": _AUDIENCE,
            "runtime_attestation_hash": budget_runtime["record_hash"],
            "runtime_installation_id": _INSTALLATION_ID,
            "scope": _SCOPES["audit"],
            "release": {
                "capability_id": "chronicle-budget-proof",
                "release_id": "chronicle-budget-proof-v1",
            },
            "overlay_selection_hash": "sha256:" + "a" * 64,
            "permitted_interface": "chronicle-budget-proof-v1",
            "mode": "intent",
            "revocation_identity": "chronicle-budget-proof-revocation",
            "status": "active",
            "budget": {
                "maximum_calls": 1,
                "maximum_tokens": 600,
                "maximum_cost_microunits": 600,
            },
            "issued_at": chronicle_test_timestamp(base_time - timedelta(minutes=2)),
            "recorded_at": chronicle_test_timestamp(base_time - timedelta(minutes=1)),
            "expires_at": chronicle_test_timestamp(base_time + timedelta(days=1)),
        },
    )
    budget_seed_decision, budget_seed_outbox = chronicle_test_decision(
        request_number=130,
        writer_sequence=1,
        previous_envelope_hash=None,
        trusted_time=base_time + timedelta(seconds=2),
        binding=bindings["budget"],
        records=[budget_runtime, budget_lease],
        chronicle_id="chronicle-capability-test",
        scope=_SCOPES["audit"],
    )
    with psycopg.connect(**writer_settings) as connection:
        budget_seed_result = chronicle_execute_append(
            connection,
            budget_seed_decision,
            [budget_runtime, budget_lease],
            budget_seed_outbox,
        )
    assert budget_seed_result[1] == 2

    budget_inputs: list[tuple[dict[str, Any], list[dict[str, Any]], bytes]] = []
    for offset, name in enumerate(("b", "c"), start=9):
        state = replay_states.get(bindings[name]["writer_id"], (0, None))
        invocation = chronicle_test_record(
            record_id=chronicle_test_uuid(0x30000000, offset),
            kind="CapabilityInvocation",
            logical_id=f"budget-race-{name}",
            fields={
                "invocation_id": f"budget-race-{name}",
                "call_nonce": chronicle_test_uuid(0x45000000, offset),
                "call_index": 1,
                "capability_lease_hash": budget_lease["record_hash"],
                "runtime_attestation_hash": budget_runtime["record_hash"],
                "capability_id": "chronicle-budget-proof",
                "identity": {
                    "identity_id": _IDENTITY_ID,
                    "identity_revision": 1,
                    "identity_epoch": 1,
                },
                "permitted_interface": "chronicle-budget-proof-v1",
                "mode": "intent",
                "disposition": "succeeded",
                "settled_usage": {
                    "calls": 1,
                    "tokens": 600,
                    "cost_microunits": 600,
                },
                "started_at": chronicle_test_timestamp(base_time + timedelta(seconds=2)),
                "completed_at": chronicle_test_timestamp(base_time + timedelta(seconds=3)),
                "recorded_at": chronicle_test_timestamp(base_time + timedelta(seconds=3)),
                "provider_validations": [
                    {
                        "phase": "entry",
                        "result": "accepted",
                        "lease_hash": budget_lease["record_hash"],
                        "attestation_hash": budget_runtime["record_hash"],
                        "validated_at": chronicle_test_timestamp(base_time + timedelta(seconds=2)),
                    },
                    {
                        "phase": "before_return",
                        "result": "accepted",
                        "lease_hash": budget_lease["record_hash"],
                        "attestation_hash": budget_runtime["record_hash"],
                        "validated_at": chronicle_test_timestamp(base_time + timedelta(seconds=3)),
                    },
                ],
                "result_hash": "sha256:" + "b" * 64,
            },
        )
        decision, outbox = chronicle_test_decision(
            request_number=offset,
            writer_sequence=state[0] + 1,
            previous_envelope_hash=state[1],
            trusted_time=base_time + timedelta(seconds=3),
            binding=bindings[name],
            records=[invocation],
            chronicle_id="chronicle-atomic-test",
            scope=_SCOPES["audit"],
            capability_reservation={
                "capability_lease_id": "shared-capability-budget",
                "expected_generation": 0,
                "calls": 1,
                "tokens": 600,
                "cost_microunits": 600,
            },
        )
        budget_inputs.append((decision, [invocation], outbox))

    budget_barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as executor:
        budget_results = list(
            executor.map(
                lambda item: chronicle_race_append(budget_barrier, writer_settings, *item),
                budget_inputs,
            )
        )
    assert sorted(status for status, _ in budget_results) == ["error", "ok"]
    assert [value for status, value in budget_results if status == "error"] == ["P2D08"]

    with psycopg.connect(dsn, autocommit=True) as connection:
        assert connection.execute(
            """
            SELECT generation, last_call_index, used_calls, used_tokens,
                   used_cost_microunits
            FROM ops.chronicle_capability_state
            WHERE capability_lease_id = 'shared-capability-budget'
            """
        ).fetchone() == (1, 1, 1, 600, 600)
        assert connection.execute(
            """
            SELECT count(*), min(call_index), max(call_index)
            FROM ops.chronicle_capability_invocations
            WHERE capability_lease_id = 'shared-capability-budget'
            """
        ).fetchone() == (1, 1, 1)
        binding_a_state = connection.execute(
            """
            SELECT last_writer_sequence, last_envelope_hash
            FROM ops.chronicle_replay_sequences
            WHERE writer_id = %s AND writer_key_id = %s
            """,
            (bindings["a"]["writer_id"], bindings["a"]["writer_key_id"]),
        ).fetchone()
        assert binding_a_state is not None
        atomic_before = connection.execute(
            """
            SELECT
                (SELECT count(*) FROM ops.chronicle_records),
                (SELECT count(*) FROM ops.chronicle_append_requests),
                (SELECT count(*) FROM ops.chronicle_outbox),
                state.chronicle_watermark,
                state.audit_outbox_watermark,
                replay.last_writer_sequence,
                replay.last_envelope_hash,
                clock.high_water
            FROM ops.chronicle_append_state AS state
            CROSS JOIN ops.chronicle_replay_sequences AS replay
            CROSS JOIN ops.chronicle_trusted_clock AS clock
            WHERE state.chronicle_id = 'chronicle-atomic-test'
              AND replay.writer_id = %s
              AND replay.writer_key_id = %s
              AND clock.chronicle_id = state.chronicle_id
            """,
            (bindings["a"]["writer_id"], bindings["a"]["writer_key_id"]),
        ).fetchone()
        assert atomic_before is not None

    atomic_record = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 11),
        kind="AgentEpisode",
        logical_id="atomic-rollback",
    )
    atomic_decision, atomic_outbox = chronicle_test_decision(
        request_number=11,
        writer_sequence=binding_a_state[0] + 1,
        previous_envelope_hash=binding_a_state[1],
        trusted_time=base_time + timedelta(seconds=4),
        binding=bindings["a"],
        records=[atomic_record],
        chronicle_id="chronicle-atomic-test",
        scope=_SCOPES["audit"],
        outbox_number=2,
    )
    with psycopg.connect(**writer_settings, autocommit=True) as connection:
        with pytest.raises(psycopg.DatabaseError) as atomic_error:
            chronicle_execute_append(connection, atomic_decision, [atomic_record], atomic_outbox)
        assert atomic_error.value.sqlstate == "P2D06"

    with psycopg.connect(dsn, autocommit=True) as connection:
        atomic_after = connection.execute(
            """
            SELECT
                (SELECT count(*) FROM ops.chronicle_records),
                (SELECT count(*) FROM ops.chronicle_append_requests),
                (SELECT count(*) FROM ops.chronicle_outbox),
                state.chronicle_watermark,
                state.audit_outbox_watermark,
                replay.last_writer_sequence,
                replay.last_envelope_hash,
                clock.high_water
            FROM ops.chronicle_append_state AS state
            CROSS JOIN ops.chronicle_replay_sequences AS replay
            CROSS JOIN ops.chronicle_trusted_clock AS clock
            WHERE state.chronicle_id = 'chronicle-atomic-test'
              AND replay.writer_id = %s
              AND replay.writer_key_id = %s
              AND clock.chronicle_id = state.chronicle_id
            """,
            (bindings["a"]["writer_id"], bindings["a"]["writer_key_id"]),
        ).fetchone()
        assert atomic_after == atomic_before
        connection.execute(
            """
            CREATE FUNCTION ops.chronicle_test_deferred_commit_failure()
            RETURNS trigger
            LANGUAGE plpgsql
            SET search_path = pg_catalog, ops
            AS $$
            BEGIN
                IF NEW.logical_id = 'commit-fail' THEN
                    RAISE EXCEPTION USING
                        ERRCODE = 'PX999',
                        MESSAGE = 'disposable deferred commit failure';
                END IF;
                RETURN NEW;
            END
            $$
            """
        )
        connection.execute(
            """
            CREATE CONSTRAINT TRIGGER chronicle_test_deferred_commit_failure
            AFTER INSERT ON ops.chronicle_records
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            EXECUTE FUNCTION ops.chronicle_test_deferred_commit_failure()
            """
        )

    commit_fail_record = chronicle_test_record(
        record_id=chronicle_test_uuid(0x30000000, 12),
        kind="AgentEpisode",
        logical_id="commit-fail",
    )
    commit_fail_decision, commit_fail_outbox = chronicle_test_decision(
        request_number=12,
        writer_sequence=binding_a_state[0] + 1,
        previous_envelope_hash=binding_a_state[1],
        trusted_time=base_time + timedelta(seconds=5),
        binding=bindings["a"],
        records=[commit_fail_record],
        chronicle_id="chronicle-atomic-test",
        scope=_SCOPES["audit"],
    )
    commit_candidate: tuple[Any, ...] | None = None
    with pytest.raises(psycopg.DatabaseError) as commit_error:
        with psycopg.connect(**writer_settings) as connection:
            commit_candidate = chronicle_execute_append(
                connection,
                commit_fail_decision,
                [commit_fail_record],
                commit_fail_outbox,
            )
            assert commit_candidate[2][0]["record_id"] == commit_fail_record["record_id"]
            assert "record_committed" not in commit_candidate[2][0]
    assert commit_error.value.sqlstate == "PX999"
    assert commit_candidate is not None

    with psycopg.connect(dsn, autocommit=True) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM ops.chronicle_records WHERE record_id = %s",
            (commit_fail_record["record_id"],),
        ).fetchone() == (0,)
        assert (
            connection.execute(
                """
            SELECT last_writer_sequence, last_envelope_hash
            FROM ops.chronicle_replay_sequences
            WHERE writer_id = %s AND writer_key_id = %s
            """,
                (bindings["a"]["writer_id"], bindings["a"]["writer_key_id"]),
            ).fetchone()
            == binding_a_state
        )
        for statement in (
            "UPDATE ops.chronicle_records SET record_id = record_id",
            "DELETE FROM ops.chronicle_records WHERE FALSE",
            "TRUNCATE ops.chronicle_records",
        ):
            with pytest.raises(psycopg.DatabaseError) as immutable_error:
                connection.execute(statement)
            assert immutable_error.value.sqlstate == "PCH11"
        for relation, assignment in (
            ("chronicle_replay_request_claims", "claimed_at = claimed_at"),
            ("chronicle_replay_nonce_claims", "claimed_at = claimed_at"),
            ("chronicle_rejection_attempts", "rejected_at = rejected_at"),
        ):
            for statement in (
                f"UPDATE ops.{relation} SET {assignment}",
                f"DELETE FROM ops.{relation} WHERE FALSE",
                f"TRUNCATE ops.{relation}",
            ):
                with pytest.raises(psycopg.DatabaseError) as immutable_error:
                    connection.execute(statement)
                assert immutable_error.value.sqlstate == "PCH11"

    with psycopg.connect(**writer_settings, autocommit=True) as connection:
        connection.execute("SELECT COUNT(*) FROM ops.ops_shadow_readiness").fetchone()
        connection.execute("SELECT COUNT(*) FROM ops.chronicle_audit_projection_v1").fetchone()
        for statement in (
            "SELECT COUNT(*) FROM ops.chronicle_records",
            "SELECT COUNT(*) FROM ops.chronicle_rejection_attempts",
            "UPDATE ops.chronicle_candidate_gate SET enabled = FALSE",
            "DELETE FROM ops.chronicle_records WHERE FALSE",
            "TRUNCATE ops.chronicle_records",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute(statement)

    vector = json.loads(_VECTOR.read_text(encoding="utf-8"))
    fixture_records = [chronicle_vector_record(record) for record in vector["records"]]
    assert len(fixture_records) == 54
    assert canonical_digest([record["document"] for record in fixture_records]) == vector["records_digest"]
    # The fixture bundle is a deterministic digest order, while the reference
    # Chronicle event order admits the target runtime before the six-record
    # handoff transaction. Preserve every fixture byte/hash and replay the
    # exact InMemoryChronicle event order:
    #   target RuntimeAttestation, then pending handoff, handed-off source,
    #   released source lease, active target lease, open target, accepted handoff.
    vector_records = (
        fixture_records[:14]
        + [fixture_records[17]]
        + fixture_records[14:17]
        + fixture_records[18:21]
        + fixture_records[21:]
    )
    batch_ranges = (
        (0, 6),
        (6, 12),
        (12, 15),
        (15, 21),
        (21, 27),
        (27, 33),
        (33, 39),
        (39, 45),
        (45, 51),
        (51, 54),
    )
    previous_digest: str | None = None
    lease_state: dict[tuple[str, str, str], tuple[int, str | None]] = {}
    for sequence, (batch_start, batch_end) in enumerate(batch_ranges, start=1):
        batch = vector_records[batch_start:batch_end]
        cas_preconditions: list[dict[str, Any]] = []
        active_targets = [
            record
            for record in batch
            if record["record_kind"] == "ReasoningLease" and record["document"]["state"] == "active"
        ]
        for target in active_targets:
            document = target["document"]
            key = (
                document["identity"]["identity_id"],
                document["scope"]["scope_type"],
                document["scope"]["scope_id"],
            )
            previous_generation, previous_hash = lease_state.get(key, (0, None))
            assert document["generation"] == previous_generation + 1
            cas_preconditions.append(
                {
                    "identity_id": key[0],
                    "scope_type": key[1],
                    "scope_id": key[2],
                    "expected_generation": previous_generation,
                    "expected_active_reasoning_lease_hash": previous_hash,
                }
            )
        decision, outbox = chronicle_test_decision(
            request_number=100 + sequence,
            writer_sequence=sequence,
            previous_envelope_hash=previous_digest,
            trusted_time=base_time + timedelta(seconds=20 + sequence),
            binding=bindings["replay"],
            records=batch,
            chronicle_id="platform-steward-replay-test",
            scope=_SCOPES["vector"],
            reasoning_cas_preconditions=cas_preconditions,
        )
        if sequence == 4:
            adversarial_transfer_batches = (
                # The target active lease may not precede the terminal source.
                batch[:2] + [batch[3], batch[2]] + batch[4:],
                # A bare terminal/active pair is not an authenticated handoff.
                batch[2:4],
            )
            for case_index, invalid_transfer in enumerate(
                adversarial_transfer_batches,
                start=1,
            ):
                invalid_decision, invalid_outbox = chronicle_test_decision(
                    request_number=300 + case_index,
                    writer_sequence=sequence,
                    previous_envelope_hash=previous_digest,
                    trusted_time=base_time + timedelta(seconds=20 + sequence),
                    binding=bindings["replay"],
                    records=invalid_transfer,
                    chronicle_id="platform-steward-replay-test",
                    scope=_SCOPES["vector"],
                    reasoning_cas_preconditions=cas_preconditions,
                )
                with psycopg.connect(**writer_settings, autocommit=True) as connection:
                    with pytest.raises(psycopg.DatabaseError) as transfer_error:
                        chronicle_execute_append(
                            connection,
                            invalid_decision,
                            invalid_transfer,
                            invalid_outbox,
                        )
                    assert transfer_error.value.sqlstate == "P2D07"
        with psycopg.connect(**writer_settings) as connection:
            result = chronicle_execute_append(connection, decision, batch, outbox)
            assert result[1] == batch_end
            assert len(result[2]) == len(batch)
            assert len(result[3]) == len(cas_preconditions)
            assert result[4] == sequence
        for target in active_targets:
            document = target["document"]
            key = (
                document["identity"]["identity_id"],
                document["scope"]["scope_type"],
                document["scope"]["scope_id"],
            )
            lease_state[key] = (document["generation"], target["record_hash"])
        previous_digest = decision["request_digest"]

    with psycopg.connect(dsn, autocommit=True) as connection:
        stored = connection.execute(
            """
            SELECT canonical_record_bytes, record_hash, canonical_bytes_sha256,
                   append_sequence
            FROM ops.chronicle_records
            WHERE chronicle_id = 'platform-steward-replay-test'
            ORDER BY append_sequence
            """
        ).fetchall()
        assert len(stored) == 54
        assert [row[0] for row in stored] == [record["canonical_bytes"] for record in vector_records]
        assert [row[1] for row in stored] == [record["record_hash"] for record in vector_records]
        assert [row[2] for row in stored] == [record["canonical_bytes_sha256"] for record in vector_records]
        assert [row[3] for row in stored] == list(range(1, 55))
        assert connection.execute(
            """
            SELECT chronicle_watermark, audit_outbox_watermark
            FROM ops.chronicle_append_state
            WHERE chronicle_id = 'platform-steward-replay-test'
            """
        ).fetchone() == (54, 10)
        assert connection.execute(
            """
            SELECT count(*) FROM ops.chronicle_audit_projection_v1
            WHERE chronicle_id = 'platform-steward-replay-test'
            """
        ).fetchone() == (54,)
        for durable_kinds in (
            ("AgentIdentityDescriptor", "AgentIdentityRevision"),
            ("KnowledgeClaim",),
        ):
            expected = [
                (
                    record["record_kind"],
                    record["logical_id"],
                    record["logical_revision"],
                    record["record_hash"],
                    record["canonical_bytes"],
                )
                for record in vector_records
                if record["record_kind"] in durable_kinds
            ]
            durable = connection.execute(
                """
                SELECT record_kind, logical_id, logical_revision, record_hash,
                       canonical_record_bytes
                FROM ops.chronicle_records
                WHERE chronicle_id = 'platform-steward-replay-test'
                  AND record_kind = ANY(%s::text[])
                ORDER BY append_sequence
                """,
                (list(durable_kinds),),
            ).fetchall()
            assert durable == expected

        capability_lease = next(
            record["document"] for record in vector_records if record["record_kind"] == "CapabilityLease"
        )
        assert connection.execute(
            """
            SELECT status, generation, last_call_index, used_calls,
                   used_tokens, used_cost_microunits, revoked_at,
                   revocation_record_hash
            FROM ops.chronicle_capability_state
            WHERE capability_lease_id = %s
            """,
            (capability_lease["lease_id"],),
        ).fetchone() == (
            "revoked",
            2,
            2,
            2,
            20,
            100,
            datetime(2026, 8, 14, 12, 20, tzinfo=UTC),
            next(record["record_hash"] for record in vector_records if record["record_kind"] == "CapabilityRevocation"),
        )
        assert connection.execute(
            """
            SELECT call_index, disposition, settled_calls, settled_tokens,
                   settled_cost_microunits, entry_result,
                   before_return_result
            FROM ops.chronicle_capability_invocations
            WHERE capability_lease_id = %s
            ORDER BY call_index
            """,
            (capability_lease["lease_id"],),
        ).fetchall() == [
            (1, "succeeded", 1, 20, 100, "accepted", "accepted"),
            (2, "rejected", 1, 0, 0, "rejected", None),
        ]
        assert connection.execute(
            """
            SELECT target_revocation_identity, revocation_cause_at,
                   provider_rejection_required, reactive_profile_state,
                   cordis_disposal_is_external_rollback
            FROM ops.chronicle_capability_revocations
            WHERE capability_lease_id = %s
            """,
            (capability_lease["lease_id"],),
        ).fetchone() == (
            capability_lease["revocation_identity"],
            datetime(2026, 8, 14, 12, 20, tzinfo=UTC),
            True,
            "deactivated",
            False,
        )

    replayed_documents = [json.loads(row[0]) for row in stored]
    replayed_projection = _derive_expected_projection(
        replayed_documents,
        as_of=vector["as_of"],
    )
    assert canonical_digest(replayed_documents) == canonical_digest([record["document"] for record in vector_records])
    assert canonical_digest(replayed_projection) == vector["expected_projection_digest"]
    assert canonical_json_bytes(replayed_projection) == canonical_json_bytes(vector["expected_projection"])

    chronicle_function_signatures = (
        "ops.chronicle_test_append_v1(jsonb,text[],text[],text[],bytea[],bytea)",
        "ops.chronicle_test_resolve_request_v1(text,text,text,uuid,uuid)",
        ("ops.chronicle_test_record_rejection_v1(text,text,text,uuid,uuid,text,text,timestamp with time zone,boolean)"),
    )
    with psycopg.connect(dsn, autocommit=True) as connection:
        chronicle_function_oids = [
            connection.execute(
                "SELECT to_regprocedure(%s)::oid",
                (signature,),
            ).fetchone()[0]
            for signature in chronicle_function_signatures
        ]
        assert all(chronicle_function_oids)

    role_paths = {
        "dash_api_runtime": "public, dash, ai",
        "dash_ops_reader": "ops, public, dash",
    }
    for role, expected_path in role_paths.items():
        secret_key = {
            "dash_api_runtime": "DASH_API_RUNTIME_PASSWORD",
            "dash_ops_reader": "DASH_OPS_READER_PASSWORD",
        }[role]
        with psycopg.connect(
            **base_settings,
            user=role,
            password=_ROLE_SECRETS[secret_key],
            autocommit=True,
        ) as connection:
            assert connection.execute("SHOW search_path").fetchone() == (expected_path,)
            assert connection.execute(
                """
                SELECT namespace.nspname
                FROM pg_class AS class
                JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
                WHERE class.oid = to_regclass('desired_services')
                """
            ).fetchone() == ("public",)
            connection.execute("SELECT COUNT(*) FROM desired_services").fetchone()
            for function_oid in chronicle_function_oids:
                assert connection.execute(
                    "SELECT has_function_privilege(current_user, %s::oid, 'EXECUTE')",
                    (function_oid,),
                ).fetchone() == (False,)

            if role == "dash_ops_reader":
                connection.execute("SELECT COUNT(*) FROM ops.chronicle_audit_projection_v1").fetchone()
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("SELECT COUNT(*) FROM ops.chronicle_records").fetchone()
            else:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("SELECT COUNT(*) FROM ops.chronicle_audit_projection_v1").fetchone()
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("SELECT marker FROM ai.desired_services").fetchone()
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("SELECT nextval('ai.desired_services_id_seq')").fetchone()
