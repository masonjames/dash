import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHRONICLE_MIGRATION = ROOT / "db/migrations/ops_agent_chronicle_v1_disabled.sql"
CHRONICLE_CHECKSUM = CHRONICLE_MIGRATION.with_suffix(".sql.sha256")


def test_privileged_migration_installs_pgvector_before_runtime() -> None:
    runner = (ROOT / "scripts/migrate_ops.py").read_text()
    migration_name = "ops_runtime_prerequisites.sql"
    assert migration_name in runner

    migration = (ROOT / "db/migrations" / migration_name).read_text()
    assert "CREATE EXTENSION IF NOT EXISTS vector" in migration


def test_runtime_privileges_are_reconciled_after_skipped_migrations() -> None:
    runner = (ROOT / "scripts/migrate_ops.py").read_text()
    reconciliation = (ROOT / "db/runtime_role_privileges.sql").read_text()

    assert runner.index("for migration in migrations:") < runner.index('root / "db" / "runtime_role_privileges.sql"')
    assert 'print(f"already applied {migration.name}")' in runner
    assert "reconciled runtime role privileges" in runner
    assert "REVOKE ALL PRIVILEGES ON ops.schema_migrations" in reconciliation
    assert "ops.ops_retrieval_documents, ops.ops_retrieval_index_status" in reconciliation
    assert "FROM dockhand_ops_writer" in reconciliation
    assert "TO dash_ops_indexer" in reconciliation
    assert "ops_portal_request_nonces" in reconciliation
    assert "FROM dash_ops_reader, dash_ops_indexer, dash_api_runtime" in reconciliation


def test_runtime_role_contract_denies_database_scratch_space() -> None:
    runner = (ROOT / "scripts/migrate_ops.py").read_text()

    assert "REVOKE CREATE, TEMPORARY ON DATABASE" in runner
    assert "if read_only:" not in runner


def test_migrations_and_runtime_ignore_user_schema_shadow_tables() -> None:
    runner = (ROOT / "scripts/migrate_ops.py").read_text()
    reconciliation = (ROOT / "db/runtime_role_privileges.sql").read_text()
    shadow_relations = (
        "desired_services",
        "actual_services",
        "drift_observations",
        "deploy_events",
        "docker_events",
        "incident_markers",
        "update_status",
        "state_snapshots",
        "ops_unified_timeline",
    )

    pin = 'connection.execute("SET LOCAL search_path = public")'
    assert pin in runner
    assert runner.index(pin) < runner.index('connection.execute("CREATE SCHEMA IF NOT EXISTS ops")')
    assert runner.index(pin) < runner.index("for migration in migrations:")
    assert "SET LOCAL search_path = public, pg_catalog" not in runner

    for relation in shadow_relations:
        assert f"'{relation}'" in reconciliation
    assert "REVOKE ALL PRIVILEGES ON TABLE ai.%I FROM dash_api_runtime" in reconciliation
    assert "REVOKE ALL PRIVILEGES ON SEQUENCE ai.%I FROM dash_api_runtime" in reconciliation
    assert "GRANT USAGE ON SCHEMA ops, public, dash TO dash_ops_reader" in reconciliation
    assert "public.ops_unified_timeline TO dash_ops_reader" in reconciliation
    assert "ALTER ROLE dash_ops_reader SET search_path = ops, public, dash" in reconciliation
    assert "ALTER ROLE dash_ops_indexer SET search_path = ops, public, dash" in reconciliation
    assert "SET search_path = ops, dash, public" not in reconciliation
    assert "ALTER ROLE dash_api_runtime SET search_path = public, dash, ai" in reconciliation
    assert "ALTER ROLE dash_api_runtime SET search_path = dash, public, ai" not in reconciliation
    assert "ALTER ROLE dash_api_runtime SET search_path = ai, dash, public" not in reconciliation


def test_shadow_readiness_requires_full_path_attempt_telemetry() -> None:
    runner = (ROOT / "scripts/migrate_ops.py").read_text()
    migration_name = "ops_shadow_attempts.sql"
    migration = (ROOT / "db/migrations" / migration_name).read_text()

    assert migration_name in runner
    assert "CREATE TABLE IF NOT EXISTS ops.ops_shadow_attempts" in migration
    assert "failed_attempts = 0" in migration
    assert "incomplete_attempts = 0" in migration
    assert "attempt.covered_days = 7" in migration
    assert "CREATE OR REPLACE VIEW ops.ops_shadow_readiness" in migration


def test_agent_chronicle_migration_is_checksummed_registered_and_disabled() -> None:
    runner = (ROOT / "scripts/migrate_ops.py").read_text()
    candidate = CHRONICLE_MIGRATION.read_bytes()
    pinned_checksum = CHRONICLE_CHECKSUM.read_text(encoding="ascii").strip()

    assert CHRONICLE_MIGRATION.name in runner
    assert runner.count('root / "db" / "migrations" / "ops_') == 9
    assert hashlib.sha256(candidate).hexdigest() == pinned_checksum
    assert b"REGISTERED AND DEFAULT-DISABLED" in candidate
    assert b"enabled BOOLEAN NOT NULL DEFAULT FALSE" in candidate
    assert b"VALUES (TRUE, FALSE)" in candidate
    assert b"neither action authorizes enabling the Chronicle writer gate" in candidate
    assert b"never delete, truncate, or rewrite Chronicle history" in candidate


def test_agent_chronicle_candidate_persists_every_mechanical_state_family() -> None:
    candidate = CHRONICLE_MIGRATION.read_text()
    required_relations = (
        "chronicle_candidate_gate",
        "chronicle_signers",
        "chronicle_evidence",
        "chronicle_runtime_attestations",
        "chronicle_identity_runtime_bindings",
        "chronicle_identity_runtime_scopes",
        "chronicle_trusted_clock",
        "chronicle_replay_sequences",
        "chronicle_replay_nonces",
        "chronicle_replay_request_claims",
        "chronicle_replay_nonce_claims",
        "chronicle_rejection_attempts",
        "chronicle_capability_state",
        "chronicle_capability_revocations",
        "chronicle_capability_invocations",
        "chronicle_append_state",
        "chronicle_append_requests",
        "chronicle_records",
        "chronicle_reasoning_leases",
        "chronicle_append_request_evidence",
        "chronicle_append_scopes",
        "chronicle_append_scope_runtime_attestations",
        "chronicle_append_scope_records",
        "chronicle_append_request_reasoning_cas",
        "chronicle_outbox",
        "chronicle_outbox_delivery_state",
    )
    for relation in required_relations:
        assert f"CREATE TABLE IF NOT EXISTS ops.{relation}" in candidate

    assert "canonical_record_bytes BYTEA NOT NULL" in candidate
    assert "canonical_bytes_sha256 TEXT NOT NULL" in candidate
    assert "UNIQUE (record_kind, logical_id, logical_revision)" in candidate
    assert "UNIQUE (chronicle_id, append_sequence)" in candidate
    assert "Every Chronicle record must be scope-bound exactly once" in candidate
    assert "v_last_append_sequence :=" in candidate
    assert "chronicle_watermark := v_last_append_sequence" in candidate
    assert "audit_outbox_watermark := v_append_state.audit_outbox_watermark + 1" in candidate
    assert "claim_source IN ('committed', 'rejected')" in candidate
    assert "rejection_atomic_no_commit BOOLEAN NOT NULL" in candidate

    for record_kind in (
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
    ):
        assert f"'{record_kind}'" in candidate


def test_agent_chronicle_candidate_matches_frozen_dockhand_shapes() -> None:
    candidate = CHRONICLE_MIGRATION.read_text()

    for field in (
        "'canonical_bytes_sha256'",
        "'logical_id'",
        "'logical_revision'",
        "'prior_record_hash'",
        "'record_hash'",
        "'record_id'",
        "'record_kind'",
    ):
        assert field in candidate
    for field in (
        "'calls'",
        "'capability_lease_id'",
        "'cost_microunits'",
        "'expected_generation'",
        "'tokens'",
    ):
        assert field in candidate
    for field in (
        "'authority_effect'",
        "'outbox_id'",
        "'projection_name'",
        "'request_digest'",
    ):
        assert field in candidate

    assert "jsonb_typeof(v_reservation) NOT IN ('null', 'object')" in candidate
    assert "reasoning_cas_preconditions" in candidate
    assert "expected_active_reasoning_lease_hash" in candidate
    assert "previous_active_reasoning_lease_hash" in candidate
    assert "committed_active_reasoning_lease_hash" in candidate
    assert "v_derived_logical_id := v_record_json->>'constitution_id'" in candidate
    assert "v_derived_logical_id := v_record_json->>'identity_id'" in candidate
    assert "v_record_json->'identity'->>'identity_revision'" in candidate
    assert "v_derived_logical_id := v_record_json->>'episode_id'" in candidate
    assert "v_derived_logical_id := v_record_json->>'lease_id'" in candidate
    assert "logical state binding does not match canonical bytes" in candidate
    assert "convert_to('platform-steward-record-v1', 'UTF8')" in candidate
    assert "v_record_json - 'record_hash'" in candidate
    assert "record hash does not match the canonical steward domain" in candidate
    assert "Chronicle reasoning CAS replacement requires its exact terminal record" in candidate
    assert "v_committed_generation := v_expected_generation + 1" in candidate
    assert "v_committed_generation := v_expected_generation;" in candidate
    assert "v_committed_active_hash := NULL" in candidate
    assert "v_terminal_lease_revision <> 2" in candidate
    assert "v_target_lease_revision <> 1" in candidate
    assert "Chronicle handoff transfer must use the exact ordered six-record transaction" in candidate
    assert "v_capability.last_call_index + 1" in candidate
    assert "Chronicle capability reservation is not bound to one committed invocation" in candidate
    assert "Chronicle canonical record evidence is not in the envelope set" in candidate
    assert "Chronicle source attestation is not in the evidence set" in candidate


def test_agent_chronicle_candidate_has_closed_rejections_and_full_commit_shape() -> None:
    candidate = CHRONICLE_MIGRATION.read_text()

    for sqlstate in (
        "P2D01",
        "P2D02",
        "P2D03",
        "P2D04",
        "P2D05",
        "P2D06",
        "P2D07",
        "P2D08",
        "P2D09",
        "P2D10",
        "PCH11",
    ):
        assert f"ERRCODE = '{sqlstate}'" in candidate or f"{sqlstate} " in candidate
    assert "Constraint, connection, transaction-exit, and COMMIT" in candidate
    assert "record_commits JSONB" in candidate
    assert "reasoning_cas_results JSONB" in candidate
    assert "jsonb_array_length(record_commits) <> v_record_count" in candidate
    assert "jsonb_array_length(reasoning_cas_results) <> v_cas_count" in candidate
    assert "max(committed.append_sequence)" in candidate
    assert "record_committed" not in candidate
    assert "CREATE OR REPLACE FUNCTION ops.chronicle_test_resolve_request_v1(" in candidate
    assert "CREATE OR REPLACE FUNCTION ops.chronicle_test_record_rejection_v1(" in candidate
    assert "rejection_atomic_no_commit BOOLEAN" in candidate
    assert "Chronicle rejection decision moved behind the trusted clock" in candidate
    assert "GREATEST(clock.high_water, EXCLUDED.high_water)" in candidate
    assert "GREATEST(clock.updated_at, EXCLUDED.updated_at)" in candidate
    for reason in (
        "expired_request",
        "audience_mismatch",
        "scope_binding_mismatch",
        "source_attestation_invalid",
        "replay_conflict",
        "cas_conflict",
        "internal_failure",
    ):
        assert f"'{reason}'" in candidate


def test_agent_chronicle_candidate_is_trigger_immutable_and_acl_is_explicit() -> None:
    candidate = CHRONICLE_MIGRATION.read_text()
    reconciliation = (ROOT / "db/runtime_role_privileges.sql").read_text()

    assert "BEFORE UPDATE OR DELETE OR TRUNCATE" in candidate
    assert "ERRCODE = 'PCH11'" in candidate
    assert "SECURITY DEFINER" in candidate
    assert "SET search_path = pg_catalog, ops" in candidate
    assert "TO dockhand_ops_writer" in candidate

    assert reconciliation.count("class.relname NOT LIKE 'chronicle\\_%' ESCAPE '\\'") == 3
    assert "GRANT SELECT ON ALL TABLES IN SCHEMA ops TO dockhand_ops_writer" not in reconciliation
    assert "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public, ops" not in reconciliation
    assert "ops.chronicle_test_append_v1(jsonb,text[],text[],text[],bytea[],bytea)" in reconciliation
    assert "ops.chronicle_test_resolve_request_v1(text,text,text,uuid,uuid)" in reconciliation
    assert "text,text,text,uuid,uuid,text,text,timestamp with time zone,boolean)" in reconciliation
    assert "GRANT SELECT ON ops.ops_shadow_readiness TO dockhand_ops_writer" in reconciliation
    assert "GRANT SELECT ON ops.chronicle_audit_projection_v1" in reconciliation
    assert "TO dockhand_ops_writer, dash_ops_reader" in reconciliation


def test_registered_agent_chronicle_paths_trigger_immutable_image_publication() -> None:
    workflow = (ROOT / ".github/workflows/ghcr-build.yml").read_text()
    registered_runtime_paths = (
        "db/migrations/ops_agent_chronicle_v1_disabled.sql",
        "db/migrations/ops_agent_chronicle_v1_disabled.sql.sha256",
        "db/runtime_role_privileges.sql",
        "scripts/migrate_ops.py",
    )

    for path in registered_runtime_paths:
        assert f'- "{path}"' not in workflow
