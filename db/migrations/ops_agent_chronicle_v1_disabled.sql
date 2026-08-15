-- Agent Chronicle v1 durable persistence candidate.
--
-- UNREGISTERED AND DEFAULT-DISABLED:
--   * scripts/migrate_ops.py must not list this file.
--   * its sibling .sha256 file pins these exact source bytes.
--   * source and tests do not authorize applying it outside the disposable
--     DASH_TEST_POSTGRES_DSN database.
--   * the database owner alone may enable ops.chronicle_candidate_gate.
--   * mutable gate/registry/high-water/CAS/budget/delivery rows are authorized
--     database-owner state. Runtime roles receive no direct relation access;
--     immutable history is guarded even against owner UPDATE/DELETE/TRUNCATE.
--
-- platform-infra owns Chronicle schemas, record semantics, canonicalization,
-- and the reference oracle. This Dash-owned source only enforces mechanical
-- byte/hash bindings, persistence, uniqueness, replay, CAS, budget, clock,
-- append-only, outbox, and least-privilege invariants. Dockhand remains the
-- sole operational writer and calls only the explicit SECURITY DEFINER append,
-- replay-resolution, and non-evidence rejection-recording functions.
-- Rollback means disable the writer and owner gate, then reverse the source
-- rollout; never delete, truncate, or rewrite Chronicle history. The candidate
-- is additive, and disabled objects may remain inert for forensic continuity.
--
-- Closed deterministic function rejection SQLSTATEs (raised before COMMIT):
--   P2D01 authority/gate changed or request no longer current
--   P2D02 request, digest, or nonce replay
--   P2D03 writer sequence conflict
--   P2D04 previous-envelope chain mismatch
--   P2D05 trusted-clock rollback
--   P2D06 malformed mechanical record, byte, scope, or outbox mapping
--   P2D07 ReasoningLease compare-and-swap conflict
--   P2D08 capability budget, expiry, generation, or revocation conflict
--   P2D09 identity, signer, runtime, installation, or scope binding conflict
--   P2D10 required evidence unavailable, expired, or revoked
--
-- PCH11 is deliberately not part of Dockhand's rejection mapping. It is used
-- only when a direct database session attempts UPDATE, DELETE, or TRUNCATE on
-- immutable history. Constraint, connection, transaction-exit, and COMMIT
-- failures are not mapped. Callers must treat them as commit uncertainty and
-- emit neither a receipt nor a signed rejection disposition.

CREATE TABLE IF NOT EXISTS ops.chronicle_candidate_gate (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    enabled_at TIMESTAMPTZ,
    enabled_reason TEXT,
    CHECK (
        (enabled AND enabled_at IS NOT NULL AND enabled_reason IS NOT NULL)
        OR (NOT enabled AND enabled_at IS NULL AND enabled_reason IS NULL)
    )
);

INSERT INTO ops.chronicle_candidate_gate (singleton, enabled)
VALUES (TRUE, FALSE)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS ops.chronicle_signers (
    signer_id TEXT PRIMARY KEY CHECK (signer_id <> ''),
    writer_id TEXT NOT NULL CHECK (writer_id <> ''),
    writer_key_id TEXT NOT NULL UNIQUE CHECK (writer_key_id <> ''),
    algorithm TEXT NOT NULL CHECK (algorithm <> ''),
    public_key_digest TEXT NOT NULL
        CHECK (public_key_digest ~ '^sha256:[0-9a-f]{64}$'),
    admitted_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_record_hash TEXT
        CHECK (
            revocation_record_hash IS NULL
            OR revocation_record_hash ~ '^sha256:[0-9a-f]{64}$'
        ),
    CHECK (expires_at > admitted_at),
    CHECK (
        (revoked_at IS NULL AND revocation_record_hash IS NULL)
        OR (revoked_at IS NOT NULL AND revocation_record_hash IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_evidence (
    evidence_hash TEXT PRIMARY KEY
        CHECK (evidence_hash ~ '^sha256:[0-9a-f]{64}$'),
    source_domain TEXT NOT NULL CHECK (source_domain <> ''),
    captured_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_record_hash TEXT
        CHECK (
            revocation_record_hash IS NULL
            OR revocation_record_hash ~ '^sha256:[0-9a-f]{64}$'
        ),
    CHECK (expires_at IS NULL OR expires_at > captured_at),
    CHECK (
        (revoked_at IS NULL AND revocation_record_hash IS NULL)
        OR (revoked_at IS NOT NULL AND revocation_record_hash IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_runtime_attestations (
    runtime_attestation_hash TEXT PRIMARY KEY
        CHECK (runtime_attestation_hash ~ '^sha256:[0-9a-f]{64}$'),
    identity_id TEXT NOT NULL CHECK (identity_id <> ''),
    identity_revision BIGINT NOT NULL CHECK (identity_revision > 0),
    identity_epoch BIGINT NOT NULL CHECK (identity_epoch > 0),
    installation_id TEXT NOT NULL CHECK (installation_id <> ''),
    embodiment TEXT NOT NULL
        CHECK (embodiment IN ('server-sentinel', 'mac-engineer')),
    host_class TEXT NOT NULL
        CHECK (host_class IN ('near-platform-server', 'local-mac')),
    admitted_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_record_hash TEXT
        CHECK (
            revocation_record_hash IS NULL
            OR revocation_record_hash ~ '^sha256:[0-9a-f]{64}$'
        ),
    CHECK (expires_at > admitted_at),
    CHECK (
        (revoked_at IS NULL AND revocation_record_hash IS NULL)
        OR (revoked_at IS NOT NULL AND revocation_record_hash IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_identity_runtime_bindings (
    binding_id TEXT PRIMARY KEY CHECK (binding_id <> ''),
    writer_id TEXT NOT NULL CHECK (writer_id <> ''),
    writer_key_id TEXT NOT NULL CHECK (writer_key_id <> ''),
    identity_id TEXT NOT NULL CHECK (identity_id <> ''),
    identity_revision BIGINT NOT NULL CHECK (identity_revision > 0),
    identity_epoch BIGINT NOT NULL CHECK (identity_epoch > 0),
    constitution_hash TEXT NOT NULL
        CHECK (constitution_hash ~ '^sha256:[0-9a-f]{64}$'),
    writer_runtime_attestation_hash TEXT NOT NULL
        REFERENCES ops.chronicle_runtime_attestations (runtime_attestation_hash),
    source_attestation_hash TEXT NOT NULL
        REFERENCES ops.chronicle_evidence (evidence_hash),
    audience TEXT NOT NULL CHECK (audience <> ''),
    installation_id TEXT NOT NULL CHECK (installation_id <> ''),
    embodiment TEXT NOT NULL
        CHECK (embodiment IN ('server-sentinel', 'mac-engineer')),
    host_class TEXT NOT NULL
        CHECK (host_class IN ('near-platform-server', 'local-mac')),
    writer_session_id UUID NOT NULL,
    interface_id TEXT NOT NULL
        CHECK (interface_id = 'dockhand-chronicle-append-v1'),
    mode TEXT NOT NULL CHECK (mode = 'intent'),
    signer_id TEXT NOT NULL REFERENCES ops.chronicle_signers (signer_id),
    admitted_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_record_hash TEXT
        CHECK (
            revocation_record_hash IS NULL
            OR revocation_record_hash ~ '^sha256:[0-9a-f]{64}$'
        ),
    UNIQUE (
        writer_id,
        writer_key_id,
        identity_id,
        identity_revision,
        identity_epoch,
        constitution_hash,
        writer_runtime_attestation_hash,
        source_attestation_hash,
        audience,
        installation_id,
        embodiment,
        host_class,
        writer_session_id,
        interface_id,
        mode
    ),
    CHECK (expires_at > admitted_at),
    CHECK (
        (revoked_at IS NULL AND revocation_record_hash IS NULL)
        OR (revoked_at IS NOT NULL AND revocation_record_hash IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_identity_runtime_scopes (
    binding_id TEXT NOT NULL
        REFERENCES ops.chronicle_identity_runtime_bindings (binding_id),
    scope_type TEXT NOT NULL
        CHECK (scope_type IN ('installation', 'incident', 'journey', 'task')),
    scope_id TEXT NOT NULL CHECK (scope_id <> ''),
    installation_id TEXT NOT NULL CHECK (installation_id <> ''),
    resource_type TEXT NOT NULL CHECK (resource_type <> ''),
    resource_id TEXT NOT NULL CHECK (resource_id <> ''),
    admitted_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_record_hash TEXT
        CHECK (
            revocation_record_hash IS NULL
            OR revocation_record_hash ~ '^sha256:[0-9a-f]{64}$'
        ),
    PRIMARY KEY (
        binding_id,
        scope_type,
        scope_id,
        installation_id,
        resource_type,
        resource_id
    ),
    CHECK (expires_at > admitted_at),
    CHECK (
        (revoked_at IS NULL AND revocation_record_hash IS NULL)
        OR (revoked_at IS NOT NULL AND revocation_record_hash IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_trusted_clock (
    chronicle_id TEXT PRIMARY KEY CHECK (chronicle_id <> ''),
    high_water TIMESTAMPTZ NOT NULL,
    last_request_id UUID NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS ops.chronicle_replay_sequences (
    writer_id TEXT NOT NULL CHECK (writer_id <> ''),
    writer_key_id TEXT NOT NULL CHECK (writer_key_id <> ''),
    last_writer_sequence BIGINT NOT NULL DEFAULT 0
        CHECK (last_writer_sequence >= 0),
    last_envelope_hash TEXT
        CHECK (
            last_envelope_hash IS NULL
            OR last_envelope_hash ~ '^sha256:[0-9a-f]{64}$'
        ),
    last_request_id UUID,
    updated_at TIMESTAMPTZ,
    PRIMARY KEY (writer_id, writer_key_id),
    CHECK (
        (last_writer_sequence = 0 AND last_envelope_hash IS NULL
            AND last_request_id IS NULL AND updated_at IS NULL)
        OR (last_writer_sequence > 0 AND last_envelope_hash IS NOT NULL
            AND last_request_id IS NOT NULL AND updated_at IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_replay_nonces (
    writer_id TEXT NOT NULL CHECK (writer_id <> ''),
    writer_key_id TEXT NOT NULL CHECK (writer_key_id <> ''),
    request_nonce UUID NOT NULL,
    writer_sequence BIGINT NOT NULL CHECK (writer_sequence > 0),
    request_id UUID NOT NULL UNIQUE,
    request_digest TEXT NOT NULL UNIQUE
        CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    accepted_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (writer_id, request_nonce),
    UNIQUE (writer_id, writer_key_id, writer_sequence)
);

-- Rejected attempts cannot share the append transaction: an exception rolls
-- that transaction back. These two immutable claim ledgers let the separate
-- rejection recorder reserve every still-unclaimed identifier, including the
-- asymmetric collision cases where only the request id or only the
-- writer-scoped nonce is new. Existing bindings are never overwritten.
CREATE TABLE IF NOT EXISTS ops.chronicle_replay_request_claims (
    request_id UUID PRIMARY KEY,
    request_digest TEXT NOT NULL
        CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    chronicle_id TEXT NOT NULL CHECK (chronicle_id <> ''),
    writer_id TEXT NOT NULL CHECK (writer_id <> ''),
    writer_key_id TEXT NOT NULL CHECK (writer_key_id <> ''),
    request_nonce UUID NOT NULL,
    claim_source TEXT NOT NULL
        CHECK (claim_source IN ('committed', 'rejected')),
    claimed_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS ops.chronicle_replay_nonce_claims (
    writer_id TEXT NOT NULL CHECK (writer_id <> ''),
    request_nonce UUID NOT NULL,
    request_digest TEXT NOT NULL
        CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    chronicle_id TEXT NOT NULL CHECK (chronicle_id <> ''),
    writer_key_id TEXT NOT NULL CHECK (writer_key_id <> ''),
    request_id UUID NOT NULL,
    claim_source TEXT NOT NULL
        CHECK (claim_source IN ('committed', 'rejected')),
    claimed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (writer_id, request_nonce)
);

CREATE TABLE IF NOT EXISTS ops.chronicle_rejection_attempts (
    chronicle_id TEXT NOT NULL CHECK (chronicle_id <> ''),
    writer_id TEXT NOT NULL CHECK (writer_id <> ''),
    writer_key_id TEXT NOT NULL CHECK (writer_key_id <> ''),
    request_id UUID NOT NULL,
    request_nonce UUID NOT NULL,
    request_digest TEXT NOT NULL
        CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    rejection_reason TEXT NOT NULL CHECK (
        rejection_reason IN (
            'expired_request',
            'future_request',
            'writer_sequence_conflict',
            'previous_envelope_mismatch',
            'identity_mismatch',
            'audience_mismatch',
            'installation_mismatch',
            'mode_mismatch',
            'scope_binding_mismatch',
            'budget_exceeded',
            'evidence_unavailable',
            'source_attestation_invalid',
            'record_invalid',
            'replay_conflict',
            'cas_conflict',
            'chronicle_rejected',
            'authority_changed',
            'trusted_clock_rollback',
            'internal_failure'
        )
    ),
    rejected_at TIMESTAMPTZ NOT NULL,
    rejection_atomic_no_commit BOOLEAN NOT NULL,
    PRIMARY KEY (
        chronicle_id,
        writer_id,
        writer_key_id,
        request_id,
        request_nonce,
        request_digest
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_capability_state (
    capability_lease_id TEXT PRIMARY KEY CHECK (capability_lease_id <> ''),
    lease_record_hash TEXT NOT NULL UNIQUE
        CHECK (lease_record_hash ~ '^sha256:[0-9a-f]{64}$'),
    issuer TEXT NOT NULL CHECK (issuer <> ''),
    issuer_nonce UUID NOT NULL,
    capability_id TEXT NOT NULL CHECK (capability_id <> ''),
    identity_id TEXT NOT NULL CHECK (identity_id <> ''),
    identity_revision BIGINT NOT NULL CHECK (identity_revision > 0),
    identity_epoch BIGINT NOT NULL CHECK (identity_epoch > 0),
    audience TEXT NOT NULL CHECK (audience <> ''),
    runtime_attestation_hash TEXT NOT NULL
        CHECK (runtime_attestation_hash ~ '^sha256:[0-9a-f]{64}$'),
    runtime_installation_id TEXT NOT NULL
        CHECK (runtime_installation_id <> ''),
    scope JSONB NOT NULL CHECK (jsonb_typeof(scope) = 'object'),
    release_bytes BYTEA NOT NULL CHECK (octet_length(release_bytes) > 0),
    release_sha256 TEXT NOT NULL
        CHECK (release_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    overlay_selection_hash TEXT NOT NULL
        CHECK (overlay_selection_hash ~ '^sha256:[0-9a-f]{64}$'),
    permitted_interface TEXT NOT NULL CHECK (permitted_interface <> ''),
    mode TEXT NOT NULL CHECK (mode IN ('read', 'intent')),
    revocation_identity TEXT NOT NULL UNIQUE CHECK (revocation_identity <> ''),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
    generation BIGINT NOT NULL DEFAULT 0 CHECK (generation >= 0),
    last_call_index BIGINT NOT NULL DEFAULT 0 CHECK (last_call_index >= 0),
    max_calls BIGINT NOT NULL CHECK (max_calls >= 0),
    used_calls BIGINT NOT NULL DEFAULT 0 CHECK (used_calls >= 0),
    max_tokens BIGINT NOT NULL CHECK (max_tokens >= 0),
    used_tokens BIGINT NOT NULL DEFAULT 0 CHECK (used_tokens >= 0),
    max_cost_microunits BIGINT NOT NULL CHECK (max_cost_microunits >= 0),
    used_cost_microunits BIGINT NOT NULL DEFAULT 0
        CHECK (used_cost_microunits >= 0),
    expires_at TIMESTAMPTZ NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_record_hash TEXT
        CHECK (
            revocation_record_hash IS NULL
            OR revocation_record_hash ~ '^sha256:[0-9a-f]{64}$'
        ),
    last_request_id UUID,
    updated_at TIMESTAMPTZ,
    UNIQUE (issuer, issuer_nonce),
    CHECK (issued_at <= recorded_at AND recorded_at < expires_at),
    CHECK (last_call_index = used_calls),
    CHECK (used_calls <= max_calls),
    CHECK (used_tokens <= max_tokens),
    CHECK (used_cost_microunits <= max_cost_microunits),
    CHECK (
        (revoked_at IS NULL AND revocation_record_hash IS NULL)
        OR (revoked_at IS NOT NULL AND revocation_record_hash IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_capability_revocations (
    revocation_id TEXT PRIMARY KEY CHECK (revocation_id <> ''),
    capability_lease_id TEXT NOT NULL
        REFERENCES ops.chronicle_capability_state (capability_lease_id),
    target_revocation_identity TEXT NOT NULL CHECK (target_revocation_identity <> ''),
    revocation_record_hash TEXT NOT NULL UNIQUE
        CHECK (revocation_record_hash ~ '^sha256:[0-9a-f]{64}$'),
    release_sha256 TEXT NOT NULL
        CHECK (release_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    overlay_selection_hash TEXT NOT NULL
        CHECK (overlay_selection_hash ~ '^sha256:[0-9a-f]{64}$'),
    effective_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    revocation_cause_at TIMESTAMPTZ NOT NULL,
    provider_rejection_required BOOLEAN NOT NULL CHECK (provider_rejection_required),
    reactive_profile_state TEXT NOT NULL CHECK (reactive_profile_state = 'deactivated'),
    cordis_disposal_is_external_rollback BOOLEAN NOT NULL
        CHECK (NOT cordis_disposal_is_external_rollback),
    request_id UUID NOT NULL UNIQUE,
    CHECK (effective_at <= recorded_at),
    CHECK (revocation_cause_at = GREATEST(effective_at, recorded_at)),
    UNIQUE (capability_lease_id, revocation_cause_at)
);

CREATE TABLE IF NOT EXISTS ops.chronicle_capability_invocations (
    invocation_id TEXT PRIMARY KEY CHECK (invocation_id <> ''),
    invocation_record_hash TEXT NOT NULL UNIQUE
        CHECK (invocation_record_hash ~ '^sha256:[0-9a-f]{64}$'),
    capability_lease_id TEXT NOT NULL
        REFERENCES ops.chronicle_capability_state (capability_lease_id),
    capability_lease_hash TEXT NOT NULL
        CHECK (capability_lease_hash ~ '^sha256:[0-9a-f]{64}$'),
    call_nonce UUID NOT NULL,
    call_index BIGINT NOT NULL CHECK (call_index > 0),
    runtime_attestation_hash TEXT NOT NULL
        CHECK (runtime_attestation_hash ~ '^sha256:[0-9a-f]{64}$'),
    capability_id TEXT NOT NULL CHECK (capability_id <> ''),
    permitted_interface TEXT NOT NULL CHECK (permitted_interface <> ''),
    mode TEXT NOT NULL CHECK (mode IN ('read', 'intent')),
    disposition TEXT NOT NULL
        CHECK (disposition IN ('succeeded', 'rejected', 'expired', 'revoked')),
    settled_calls BIGINT NOT NULL CHECK (settled_calls = 1),
    settled_tokens BIGINT NOT NULL CHECK (settled_tokens >= 0),
    settled_cost_microunits BIGINT NOT NULL
        CHECK (settled_cost_microunits >= 0),
    entry_result TEXT NOT NULL CHECK (entry_result IN ('accepted', 'rejected')),
    before_return_result TEXT
        CHECK (before_return_result IS NULL OR before_return_result = 'accepted'
            OR before_return_result = 'rejected'),
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    request_id UUID NOT NULL,
    UNIQUE (capability_lease_hash, call_nonce),
    UNIQUE (capability_lease_hash, call_index),
    CHECK (started_at <= completed_at AND completed_at <= recorded_at),
    CHECK (
        (disposition = 'rejected' AND entry_result = 'rejected'
            AND before_return_result IS NULL)
        OR (disposition = 'succeeded' AND entry_result = 'accepted'
            AND before_return_result = 'accepted')
        OR (disposition IN ('expired', 'revoked') AND entry_result = 'accepted'
            AND before_return_result = 'rejected')
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_append_state (
    chronicle_id TEXT PRIMARY KEY CHECK (chronicle_id <> ''),
    chronicle_watermark BIGINT NOT NULL DEFAULT 0
        CHECK (chronicle_watermark >= 0),
    audit_outbox_watermark BIGINT NOT NULL DEFAULT 0
        CHECK (audit_outbox_watermark >= 0),
    last_request_digest TEXT
        CHECK (
            last_request_digest IS NULL
            OR last_request_digest ~ '^sha256:[0-9a-f]{64}$'
        ),
    updated_at TIMESTAMPTZ,
    CHECK (
        (chronicle_watermark = 0 AND audit_outbox_watermark = 0
            AND last_request_digest IS NULL AND updated_at IS NULL)
        OR (chronicle_watermark > 0 AND audit_outbox_watermark > 0
            AND last_request_digest IS NOT NULL AND updated_at IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_append_requests (
    request_id UUID PRIMARY KEY,
    api_version TEXT NOT NULL
        CHECK (api_version = 'platform.masonjames.dev/steward-chronicle/v1'),
    kind TEXT NOT NULL CHECK (kind = 'ChronicleAppendEnvelope'),
    request_nonce UUID NOT NULL,
    writer_sequence BIGINT NOT NULL CHECK (writer_sequence > 0),
    previous_envelope_hash TEXT
        CHECK (
            previous_envelope_hash IS NULL
            OR previous_envelope_hash ~ '^sha256:[0-9a-f]{64}$'
        ),
    submitted_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    trusted_time TIMESTAMPTZ NOT NULL,
    chronicle_id TEXT NOT NULL CHECK (chronicle_id <> ''),
    identity_id TEXT NOT NULL CHECK (identity_id <> ''),
    identity_revision BIGINT NOT NULL CHECK (identity_revision > 0),
    identity_epoch BIGINT NOT NULL CHECK (identity_epoch > 0),
    constitution_hash TEXT NOT NULL
        CHECK (constitution_hash ~ '^sha256:[0-9a-f]{64}$'),
    audience TEXT NOT NULL CHECK (audience <> ''),
    installation_id TEXT NOT NULL CHECK (installation_id <> ''),
    embodiment TEXT NOT NULL
        CHECK (embodiment IN ('server-sentinel', 'mac-engineer')),
    host_class TEXT NOT NULL
        CHECK (host_class IN ('near-platform-server', 'local-mac')),
    writer_id TEXT NOT NULL CHECK (writer_id <> ''),
    writer_key_id TEXT NOT NULL CHECK (writer_key_id <> ''),
    writer_runtime_attestation_hash TEXT NOT NULL
        CHECK (writer_runtime_attestation_hash ~ '^sha256:[0-9a-f]{64}$'),
    writer_session_id UUID NOT NULL,
    source_attestation_hash TEXT NOT NULL
        CHECK (source_attestation_hash ~ '^sha256:[0-9a-f]{64}$'),
    interface_id TEXT NOT NULL
        CHECK (interface_id = 'dockhand-chronicle-append-v1'),
    mode TEXT NOT NULL CHECK (mode = 'intent'),
    maximum_calls BIGINT NOT NULL CHECK (maximum_calls >= 1),
    maximum_tokens BIGINT NOT NULL CHECK (maximum_tokens >= 0),
    maximum_cost_microunits BIGINT NOT NULL
        CHECK (maximum_cost_microunits >= 0),
    evidence_count SMALLINT NOT NULL CHECK (evidence_count BETWEEN 1 AND 256),
    authority_effect TEXT NOT NULL
        CHECK (authority_effect = 'chronicle-append-only'),
    request_digest TEXT NOT NULL UNIQUE
        CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    signature_bundle_hash TEXT NOT NULL
        CHECK (signature_bundle_hash ~ '^sha256:[0-9a-f]{64}$'),
    canonical_envelope_bytes BYTEA NOT NULL
        CHECK (octet_length(canonical_envelope_bytes) > 0),
    canonical_envelope_sha256 TEXT NOT NULL
        CHECK (canonical_envelope_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    binding_id TEXT NOT NULL
        REFERENCES ops.chronicle_identity_runtime_bindings (binding_id),
    capability_lease_id TEXT,
    capability_previous_generation BIGINT,
    capability_committed_generation BIGINT,
    chronicle_watermark BIGINT NOT NULL CHECK (chronicle_watermark > 0),
    first_append_sequence BIGINT NOT NULL CHECK (first_append_sequence > 0),
    last_append_sequence BIGINT NOT NULL CHECK (last_append_sequence > 0),
    audit_outbox_watermark BIGINT NOT NULL
        CHECK (audit_outbox_watermark > 0),
    record_count SMALLINT NOT NULL CHECK (record_count BETWEEN 1 AND 6),
    committed_at TIMESTAMPTZ NOT NULL,
    UNIQUE (chronicle_id, chronicle_watermark),
    UNIQUE (chronicle_id, audit_outbox_watermark),
    CHECK (expires_at > submitted_at),
    CHECK (trusted_time >= submitted_at AND trusted_time < expires_at),
    CHECK (last_append_sequence = chronicle_watermark),
    CHECK (last_append_sequence >= first_append_sequence),
    CHECK (last_append_sequence - first_append_sequence + 1 = record_count),
    CHECK (
        (capability_lease_id IS NULL
            AND capability_previous_generation IS NULL
            AND capability_committed_generation IS NULL)
        OR (capability_lease_id IS NOT NULL
            AND capability_previous_generation IS NOT NULL
            AND capability_committed_generation
                = capability_previous_generation + 1)
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_records (
    record_hash TEXT PRIMARY KEY
        CHECK (record_hash ~ '^sha256:[0-9a-f]{64}$'),
    record_id UUID NOT NULL UNIQUE,
    record_kind TEXT NOT NULL
        CHECK (
            record_kind IN (
                'AgentConstitution',
                'AgentEpisode',
                'AgentHandoff',
                'AgentIdentityDescriptor',
                'AgentIdentityRevision',
                'CapabilityCandidate',
                'CapabilityEvaluation',
                'CapabilityGap',
                'CapabilityInvocation',
                'CapabilityLease',
                'CapabilityPromotion',
                'CapabilityRevocation',
                'FoundryAdmissionAttestation',
                'KnowledgeClaim',
                'ReasoningLease',
                'RuntimeAttestation'
            )
        ),
    record_api_version TEXT NOT NULL
        CHECK (record_api_version = 'platform.masonjames.dev/steward/v1'),
    logical_id TEXT NOT NULL CHECK (logical_id <> ''),
    logical_revision BIGINT NOT NULL CHECK (logical_revision > 0),
    prior_record_hash TEXT
        REFERENCES ops.chronicle_records (record_hash)
        DEFERRABLE INITIALLY DEFERRED,
    canonical_record_bytes BYTEA NOT NULL
        CHECK (octet_length(canonical_record_bytes) > 0),
    canonical_bytes_sha256 TEXT NOT NULL
        CHECK (canonical_bytes_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    request_id UUID NOT NULL
        REFERENCES ops.chronicle_append_requests (request_id),
    chronicle_id TEXT NOT NULL CHECK (chronicle_id <> ''),
    chronicle_watermark BIGINT NOT NULL CHECK (chronicle_watermark > 0),
    append_sequence BIGINT NOT NULL CHECK (append_sequence > 0),
    batch_ordinal SMALLINT NOT NULL CHECK (batch_ordinal BETWEEN 1 AND 6),
    committed_at TIMESTAMPTZ NOT NULL,
    UNIQUE (record_kind, logical_id, logical_revision),
    UNIQUE (chronicle_id, append_sequence),
    UNIQUE (request_id, batch_ordinal)
);

CREATE INDEX IF NOT EXISTS chronicle_records_logical_current_idx
    ON ops.chronicle_records (
        record_kind,
        logical_id,
        logical_revision DESC
    );

CREATE TABLE IF NOT EXISTS ops.chronicle_reasoning_leases (
    identity_id TEXT NOT NULL CHECK (identity_id <> ''),
    scope_type TEXT NOT NULL
        CHECK (scope_type IN ('installation', 'incident', 'journey', 'task')),
    scope_id TEXT NOT NULL CHECK (scope_id <> ''),
    generation BIGINT NOT NULL DEFAULT 0 CHECK (generation >= 0),
    active_reasoning_lease_hash TEXT
        CHECK (
            active_reasoning_lease_hash IS NULL
            OR active_reasoning_lease_hash ~ '^sha256:[0-9a-f]{64}$'
        ),
    last_request_id UUID,
    updated_at TIMESTAMPTZ,
    PRIMARY KEY (identity_id, scope_type, scope_id),
    UNIQUE (active_reasoning_lease_hash),
    CHECK (
        (generation = 0 AND active_reasoning_lease_hash IS NULL
            AND last_request_id IS NULL AND updated_at IS NULL)
        OR (generation > 0
            AND last_request_id IS NOT NULL AND updated_at IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_append_request_evidence (
    request_id UUID NOT NULL
        REFERENCES ops.chronicle_append_requests (request_id),
    evidence_hash TEXT NOT NULL
        REFERENCES ops.chronicle_evidence (evidence_hash),
    ordinal SMALLINT NOT NULL CHECK (ordinal BETWEEN 1 AND 256),
    PRIMARY KEY (request_id, evidence_hash),
    UNIQUE (request_id, ordinal)
);

CREATE TABLE IF NOT EXISTS ops.chronicle_append_scopes (
    request_id UUID NOT NULL
        REFERENCES ops.chronicle_append_requests (request_id),
    ordinal SMALLINT NOT NULL CHECK (ordinal BETWEEN 1 AND 6),
    scope_type TEXT NOT NULL
        CHECK (scope_type IN ('installation', 'incident', 'journey', 'task')),
    scope_id TEXT NOT NULL CHECK (scope_id <> ''),
    installation_id TEXT NOT NULL CHECK (installation_id <> ''),
    resource_type TEXT NOT NULL CHECK (resource_type <> ''),
    resource_id TEXT NOT NULL CHECK (resource_id <> ''),
    PRIMARY KEY (request_id, ordinal),
    UNIQUE (
        request_id,
        scope_type,
        scope_id,
        installation_id,
        resource_type,
        resource_id
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_append_scope_runtime_attestations (
    request_id UUID NOT NULL,
    scope_ordinal SMALLINT NOT NULL,
    runtime_attestation_hash TEXT NOT NULL
        REFERENCES ops.chronicle_runtime_attestations (runtime_attestation_hash),
    ordinal SMALLINT NOT NULL CHECK (ordinal BETWEEN 1 AND 6),
    PRIMARY KEY (request_id, scope_ordinal, runtime_attestation_hash),
    UNIQUE (request_id, scope_ordinal, ordinal),
    FOREIGN KEY (request_id, scope_ordinal)
        REFERENCES ops.chronicle_append_scopes (request_id, ordinal)
);

CREATE TABLE IF NOT EXISTS ops.chronicle_append_scope_records (
    request_id UUID NOT NULL,
    scope_ordinal SMALLINT NOT NULL,
    record_hash TEXT NOT NULL
        CHECK (record_hash ~ '^sha256:[0-9a-f]{64}$'),
    ordinal SMALLINT NOT NULL CHECK (ordinal BETWEEN 1 AND 6),
    PRIMARY KEY (request_id, scope_ordinal, record_hash),
    UNIQUE (request_id, record_hash),
    UNIQUE (request_id, scope_ordinal, ordinal),
    FOREIGN KEY (request_id, scope_ordinal)
        REFERENCES ops.chronicle_append_scopes (request_id, ordinal)
);

CREATE TABLE IF NOT EXISTS ops.chronicle_append_request_reasoning_cas (
    request_id UUID NOT NULL
        REFERENCES ops.chronicle_append_requests (request_id),
    ordinal SMALLINT NOT NULL CHECK (ordinal BETWEEN 1 AND 6),
    identity_id TEXT NOT NULL CHECK (identity_id <> ''),
    scope_type TEXT NOT NULL
        CHECK (scope_type IN ('installation', 'incident', 'journey', 'task')),
    scope_id TEXT NOT NULL CHECK (scope_id <> ''),
    previous_generation BIGINT NOT NULL CHECK (previous_generation >= 0),
    previous_active_reasoning_lease_hash TEXT
        CHECK (
            previous_active_reasoning_lease_hash IS NULL
            OR previous_active_reasoning_lease_hash
                ~ '^sha256:[0-9a-f]{64}$'
        ),
    committed_generation BIGINT NOT NULL CHECK (committed_generation >= 0),
    committed_active_reasoning_lease_hash TEXT
        CHECK (
            committed_active_reasoning_lease_hash IS NULL
            OR committed_active_reasoning_lease_hash
                ~ '^sha256:[0-9a-f]{64}$'
        ),
    PRIMARY KEY (request_id, ordinal),
    UNIQUE (request_id, identity_id, scope_type, scope_id),
    CHECK (
        (committed_generation = previous_generation
            AND committed_active_reasoning_lease_hash IS NULL)
        OR (committed_generation = previous_generation + 1
            AND committed_active_reasoning_lease_hash IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS ops.chronicle_outbox (
    outbox_id UUID PRIMARY KEY,
    request_id UUID NOT NULL UNIQUE
        REFERENCES ops.chronicle_append_requests (request_id),
    chronicle_id TEXT NOT NULL CHECK (chronicle_id <> ''),
    audit_outbox_watermark BIGINT NOT NULL CHECK (audit_outbox_watermark > 0),
    projection_name TEXT NOT NULL
        CHECK (projection_name = 'platform-steward-audit-v1'),
    request_digest TEXT NOT NULL
        CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    authority_effect TEXT NOT NULL CHECK (authority_effect = 'none'),
    outbox_intent_bytes BYTEA NOT NULL
        CHECK (octet_length(outbox_intent_bytes) > 0),
    outbox_intent_sha256 TEXT NOT NULL
        CHECK (outbox_intent_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (chronicle_id, audit_outbox_watermark)
);

CREATE TABLE IF NOT EXISTS ops.chronicle_outbox_delivery_state (
    outbox_id UUID PRIMARY KEY REFERENCES ops.chronicle_outbox (outbox_id),
    claim_generation BIGINT NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
    claimed_by TEXT,
    claimed_until TIMESTAMPTZ,
    delivery_attempts BIGINT NOT NULL DEFAULT 0 CHECK (delivery_attempts >= 0),
    delivered_at TIMESTAMPTZ,
    last_error_digest TEXT
        CHECK (
            last_error_digest IS NULL
            OR last_error_digest ~ '^sha256:[0-9a-f]{64}$'
        ),
    updated_at TIMESTAMPTZ,
    CHECK (
        (claimed_by IS NULL AND claimed_until IS NULL)
        OR (claimed_by IS NOT NULL AND claimed_until IS NOT NULL)
    )
);

CREATE OR REPLACE VIEW ops.chronicle_audit_projection_v1
WITH (security_barrier = TRUE)
AS
SELECT
    request.chronicle_id,
    request.chronicle_watermark,
    record.append_sequence,
    record.record_id::TEXT AS record_id,
    record.record_kind,
    record.record_api_version,
    record.logical_id,
    record.logical_revision,
    record.prior_record_hash,
    record.record_hash,
    record.canonical_bytes_sha256,
    request.identity_id,
    request.identity_revision,
    request.identity_epoch,
    request.audience,
    request.installation_id,
    request.embodiment,
    request.host_class,
    request.request_digest,
    request.trusted_time,
    record.committed_at,
    TRUE AS read_only,
    'none'::TEXT AS authority_effect,
    FALSE AS contains_private_identity
FROM ops.chronicle_records AS record
JOIN ops.chronicle_append_requests AS request
    ON request.request_id = record.request_id;

-- Re-serialize parsed JSON into the exact steward canonical byte domain. A
-- byte-for-byte comparison against this result rejects duplicate object keys
-- (which JSONB otherwise collapses), whitespace, unsorted keys, escaped
-- Unicode scalars, floating point spellings, and unsafe integers.
CREATE OR REPLACE FUNCTION ops.chronicle_canonical_json_text_v1(p_value JSONB)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, ops
AS $chronicle_canonical_json$
DECLARE
    v_kind TEXT := jsonb_typeof(p_value);
    v_rendered TEXT;
    v_number TEXT;
BEGIN
    CASE v_kind
        WHEN 'null' THEN
            RETURN 'null';
        WHEN 'boolean' THEN
            RETURN p_value::TEXT;
        WHEN 'number' THEN
            v_number := p_value::TEXT;
            IF v_number !~ '^-?(0|[1-9][0-9]*)$'
                OR v_number::NUMERIC < -9007199254740991
                OR v_number::NUMERIC > 9007199254740991
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D06',
                    MESSAGE = 'Chronicle canonical JSON permits only safe integers';
            END IF;
            RETURN v_number;
        WHEN 'string' THEN
            RETURN to_jsonb(p_value #>> '{}')::TEXT;
        WHEN 'array' THEN
            SELECT
                '[' || COALESCE(
                    string_agg(
                        ops.chronicle_canonical_json_text_v1(element.value),
                        ',' ORDER BY element.ordinality
                    ),
                    ''
                ) || ']'
            INTO v_rendered
            FROM jsonb_array_elements(p_value) WITH ORDINALITY
                AS element(value, ordinality);
            RETURN v_rendered;
        WHEN 'object' THEN
            SELECT
                '{' || COALESCE(
                    string_agg(
                        to_jsonb(member.key)::TEXT || ':' ||
                            ops.chronicle_canonical_json_text_v1(member.value),
                        ',' ORDER BY member.key COLLATE "C"
                    ),
                    ''
                ) || '}'
            INTO v_rendered
            FROM jsonb_each(p_value) AS member(key, value);
            RETURN v_rendered;
        ELSE
            RAISE EXCEPTION USING
                ERRCODE = 'P2D06',
                MESSAGE = 'Chronicle canonical JSON value kind is unsupported';
    END CASE;
END
$chronicle_canonical_json$;

REVOKE ALL PRIVILEGES ON FUNCTION
    ops.chronicle_canonical_json_text_v1(JSONB)
    FROM PUBLIC, dash_ops_reader, dash_ops_indexer, dockhand_ops_writer,
        dash_api_runtime;

CREATE OR REPLACE FUNCTION ops.chronicle_reject_immutable_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, ops
AS $chronicle_immutable_guard$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'PCH11',
        MESSAGE = format(
            'Agent Chronicle immutable relation %I.%I rejects %s',
            TG_TABLE_SCHEMA,
            TG_TABLE_NAME,
            TG_OP
        );
    RETURN NULL;
END
$chronicle_immutable_guard$;

DO $chronicle_install_immutable_guards$
DECLARE
    relation_name TEXT;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY[
        'chronicle_append_requests',
        'chronicle_records',
        'chronicle_append_request_evidence',
        'chronicle_append_scopes',
        'chronicle_append_scope_runtime_attestations',
        'chronicle_append_scope_records',
        'chronicle_append_request_reasoning_cas',
        'chronicle_replay_nonces',
        'chronicle_replay_request_claims',
        'chronicle_replay_nonce_claims',
        'chronicle_rejection_attempts',
        'chronicle_capability_revocations',
        'chronicle_capability_invocations',
        'chronicle_outbox'
    ]
    LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM pg_trigger
            WHERE tgrelid = format('ops.%I', relation_name)::regclass
              AND tgname = 'chronicle_immutable_mutation_guard'
              AND NOT tgisinternal
        ) THEN
            EXECUTE format(
                'CREATE TRIGGER chronicle_immutable_mutation_guard '
                'BEFORE UPDATE OR DELETE OR TRUNCATE ON ops.%I '
                'FOR EACH STATEMENT '
                'EXECUTE FUNCTION ops.chronicle_reject_immutable_mutation()',
                relation_name
            );
        END IF;
    END LOOP;
END
$chronicle_install_immutable_guards$;

CREATE OR REPLACE FUNCTION ops.chronicle_test_resolve_request_v1(
    p_chronicle_id TEXT,
    p_writer_id TEXT,
    p_writer_key_id TEXT,
    p_request_id UUID,
    p_request_nonce UUID
)
RETURNS TABLE (
    chronicle_id TEXT,
    writer_id TEXT,
    writer_key_id TEXT,
    request_id TEXT,
    request_nonce TEXT,
    writer_head_sequence BIGINT,
    writer_head_digest TEXT,
    request_id_digest TEXT,
    request_nonce_digest TEXT,
    committed_request_digest TEXT,
    committed_at TEXT,
    commit_result JSONB,
    rejected_request_digest TEXT,
    rejection_reason TEXT,
    rejected_at TEXT,
    rejection_atomic_no_commit BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ops
AS $chronicle_test_resolve_request$
DECLARE
    v_digest_pattern CONSTANT TEXT := '^sha256:[0-9a-f]{64}$';
    v_identifier_pattern CONSTANT TEXT := '^[a-z0-9][a-z0-9._:/-]*$';
    v_gate_enabled BOOLEAN;
    v_committed ops.chronicle_append_requests%ROWTYPE;
    v_rejected ops.chronicle_rejection_attempts%ROWTYPE;
BEGIN
    IF p_chronicle_id !~ v_identifier_pattern
        OR p_writer_id !~ v_identifier_pattern
        OR p_writer_key_id !~ v_identifier_pattern
        OR p_request_id IS NULL
        OR p_request_nonce IS NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle replay resolver binding is invalid';
    END IF;

    SELECT gate.enabled
    INTO v_gate_enabled
    FROM ops.chronicle_candidate_gate AS gate
    WHERE gate.singleton
    FOR SHARE;
    IF NOT FOUND OR NOT v_gate_enabled THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D01',
            MESSAGE = 'Agent Chronicle persistence candidate is disabled';
    END IF;

    chronicle_id := p_chronicle_id;
    writer_id := p_writer_id;
    writer_key_id := p_writer_key_id;
    request_id := p_request_id::TEXT;
    request_nonce := p_request_nonce::TEXT;
    writer_head_sequence := 0;
    writer_head_digest := NULL;
    request_id_digest := NULL;
    request_nonce_digest := NULL;
    committed_request_digest := NULL;
    committed_at := NULL;
    commit_result := NULL;
    rejected_request_digest := NULL;
    rejection_reason := NULL;
    rejected_at := NULL;
    rejection_atomic_no_commit := NULL;

    SELECT replay.last_writer_sequence, replay.last_envelope_hash
    INTO writer_head_sequence, writer_head_digest
    FROM ops.chronicle_replay_sequences AS replay
    WHERE replay.writer_id = p_writer_id
      AND replay.writer_key_id = p_writer_key_id;
    IF NOT FOUND THEN
        writer_head_sequence := 0;
        writer_head_digest := NULL;
    END IF;

    SELECT claim.request_digest
    INTO request_id_digest
    FROM ops.chronicle_replay_request_claims AS claim
    WHERE claim.request_id = p_request_id;

    SELECT claim.request_digest
    INTO request_nonce_digest
    FROM ops.chronicle_replay_nonce_claims AS claim
    WHERE claim.writer_id = p_writer_id
      AND claim.request_nonce = p_request_nonce;

    SELECT committed.*
    INTO v_committed
    FROM ops.chronicle_append_requests AS committed
    WHERE committed.request_id = p_request_id
      AND committed.chronicle_id = p_chronicle_id
      AND committed.writer_id = p_writer_id
      AND committed.writer_key_id = p_writer_key_id
      AND committed.request_nonce = p_request_nonce;

    IF FOUND THEN
        IF request_id_digest IS DISTINCT FROM v_committed.request_digest
            OR request_nonce_digest IS DISTINCT FROM v_committed.request_digest
            OR v_committed.request_digest !~ v_digest_pattern
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D02',
                MESSAGE = 'Chronicle committed replay claims are incomplete';
        END IF;
        committed_request_digest := v_committed.request_digest;
        committed_at := to_char(
            v_committed.committed_at AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS"Z"'
        );
        SELECT jsonb_build_object(
            'chronicle_watermark', v_committed.chronicle_watermark,
            'record_commits', COALESCE(
                (
                    SELECT jsonb_agg(
                        jsonb_build_object(
                            'record_id', record.record_id::TEXT,
                            'record_kind', record.record_kind,
                            'record_hash', record.record_hash,
                            'append_sequence', record.append_sequence
                        ) ORDER BY record.batch_ordinal
                    )
                    FROM ops.chronicle_records AS record
                    WHERE record.request_id = v_committed.request_id
                ),
                '[]'::JSONB
            ),
            'reasoning_cas_results', COALESCE(
                (
                    SELECT jsonb_agg(
                        jsonb_build_object(
                            'identity_id', result.identity_id,
                            'scope_type', result.scope_type,
                            'scope_id', result.scope_id,
                            'previous_generation', result.previous_generation,
                            'committed_generation', result.committed_generation,
                            'previous_active_reasoning_lease_hash',
                                result.previous_active_reasoning_lease_hash,
                            'committed_active_reasoning_lease_hash',
                                result.committed_active_reasoning_lease_hash
                        ) ORDER BY result.ordinal
                    )
                    FROM ops.chronicle_append_request_reasoning_cas AS result
                    WHERE result.request_id = v_committed.request_id
                ),
                '[]'::JSONB
            ),
            'outbox_watermark', v_committed.audit_outbox_watermark
        )
        INTO commit_result;
    ELSE
        SELECT rejected.*
        INTO v_rejected
        FROM ops.chronicle_rejection_attempts AS rejected
        WHERE rejected.chronicle_id = p_chronicle_id
          AND rejected.writer_id = p_writer_id
          AND rejected.writer_key_id = p_writer_key_id
          AND rejected.request_id = p_request_id
          AND rejected.request_nonce = p_request_nonce
          AND rejected.request_digest = request_id_digest
          AND rejected.request_digest = request_nonce_digest;
        IF FOUND THEN
            rejected_request_digest := v_rejected.request_digest;
            rejection_reason := v_rejected.rejection_reason;
            rejected_at := to_char(
                v_rejected.rejected_at AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS"Z"'
            );
            rejection_atomic_no_commit :=
                v_rejected.rejection_atomic_no_commit;
        END IF;
    END IF;

    RETURN NEXT;
END
$chronicle_test_resolve_request$;

CREATE OR REPLACE FUNCTION ops.chronicle_test_record_rejection_v1(
    p_chronicle_id TEXT,
    p_writer_id TEXT,
    p_writer_key_id TEXT,
    p_request_id UUID,
    p_request_nonce UUID,
    p_request_digest TEXT,
    p_rejection_reason TEXT,
    p_rejected_at TIMESTAMPTZ,
    p_atomic_no_commit BOOLEAN
)
RETURNS TABLE (
    chronicle_id TEXT,
    writer_id TEXT,
    writer_key_id TEXT,
    request_id TEXT,
    request_nonce TEXT,
    writer_head_sequence BIGINT,
    writer_head_digest TEXT,
    request_id_digest TEXT,
    request_nonce_digest TEXT,
    committed_request_digest TEXT,
    committed_at TEXT,
    commit_result JSONB,
    rejected_request_digest TEXT,
    rejection_reason TEXT,
    rejected_at TEXT,
    rejection_atomic_no_commit BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ops
AS $chronicle_test_record_rejection$
DECLARE
    v_digest_pattern CONSTANT TEXT := '^sha256:[0-9a-f]{64}$';
    v_identifier_pattern CONSTANT TEXT := '^[a-z0-9][a-z0-9._:/-]*$';
    v_closed_reasons CONSTANT TEXT[] := ARRAY[
        'expired_request',
        'future_request',
        'writer_sequence_conflict',
        'previous_envelope_mismatch',
        'identity_mismatch',
        'audience_mismatch',
        'installation_mismatch',
        'mode_mismatch',
        'scope_binding_mismatch',
        'budget_exceeded',
        'evidence_unavailable',
        'source_attestation_invalid',
        'record_invalid',
        'replay_conflict',
        'cas_conflict',
        'chronicle_rejected',
        'authority_changed',
        'trusted_clock_rollback',
        'internal_failure'
    ];
    v_gate_enabled BOOLEAN;
    v_exact_committed BOOLEAN;
    v_exact_rejected BOOLEAN;
    v_clock_high_water TIMESTAMPTZ;
BEGIN
    IF p_chronicle_id !~ v_identifier_pattern
        OR p_writer_id !~ v_identifier_pattern
        OR p_writer_key_id !~ v_identifier_pattern
        OR p_request_id IS NULL
        OR p_request_nonce IS NULL
        OR p_request_digest !~ v_digest_pattern
        OR p_rejection_reason IS NULL
        OR p_rejection_reason <> ALL(v_closed_reasons)
        OR p_rejected_at IS NULL
        OR date_trunc('second', p_rejected_at) <> p_rejected_at
        OR p_atomic_no_commit IS NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle rejection tombstone binding is invalid';
    END IF;

    SELECT gate.enabled
    INTO v_gate_enabled
    FROM ops.chronicle_candidate_gate AS gate
    WHERE gate.singleton
    FOR UPDATE;
    IF NOT FOUND OR NOT v_gate_enabled THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D01',
            MESSAGE = 'Agent Chronicle persistence candidate is disabled';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM ops.chronicle_append_requests AS committed
        WHERE committed.chronicle_id = p_chronicle_id
          AND committed.writer_id = p_writer_id
          AND committed.writer_key_id = p_writer_key_id
          AND committed.request_id = p_request_id
          AND committed.request_nonce = p_request_nonce
          AND committed.request_digest = p_request_digest
    )
    INTO v_exact_committed;
    IF v_exact_committed THEN
        RETURN QUERY
        SELECT resolved.*
        FROM ops.chronicle_test_resolve_request_v1(
            p_chronicle_id,
            p_writer_id,
            p_writer_key_id,
            p_request_id,
            p_request_nonce
        ) AS resolved;
        RETURN;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM ops.chronicle_rejection_attempts AS rejected
        JOIN ops.chronicle_replay_request_claims AS request_claim
          ON request_claim.request_id = rejected.request_id
         AND request_claim.request_digest = rejected.request_digest
        JOIN ops.chronicle_replay_nonce_claims AS nonce_claim
          ON nonce_claim.writer_id = rejected.writer_id
         AND nonce_claim.request_nonce = rejected.request_nonce
         AND nonce_claim.request_digest = rejected.request_digest
        WHERE rejected.chronicle_id = p_chronicle_id
          AND rejected.writer_id = p_writer_id
          AND rejected.writer_key_id = p_writer_key_id
          AND rejected.request_id = p_request_id
          AND rejected.request_nonce = p_request_nonce
          AND rejected.request_digest = p_request_digest
    )
    INTO v_exact_rejected;
    IF v_exact_rejected THEN
        RETURN QUERY
        SELECT resolved.*
        FROM ops.chronicle_test_resolve_request_v1(
            p_chronicle_id,
            p_writer_id,
            p_writer_key_id,
            p_request_id,
            p_request_nonce
        ) AS resolved;
        RETURN;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM ops.chronicle_signers AS signer
        WHERE signer.writer_id = p_writer_id
          AND signer.writer_key_id = p_writer_key_id
          AND signer.admitted_at <= p_rejected_at
          AND signer.expires_at > p_rejected_at
          AND (
              signer.revoked_at IS NULL
              OR signer.revoked_at > p_rejected_at
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D09',
            MESSAGE = 'Chronicle rejection writer key is not admitted';
    END IF;

    -- Rejections remain outside Chronicle evidence, records, outbox, and
    -- append watermarks, but their trusted observation time is durable state.
    -- The candidate gate is the global serializer; lock the per-Chronicle row
    -- as well so reconstruction cannot move time behind any committed or
    -- rejected observation. Exact committed/rejected recovery returned above
    -- and therefore cannot rewrite or lower this clock.
    SELECT clock.high_water
    INTO v_clock_high_water
    FROM ops.chronicle_trusted_clock AS clock
    WHERE clock.chronicle_id = p_chronicle_id
    FOR UPDATE;

    IF FOUND AND v_clock_high_water > p_rejected_at THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D05',
            MESSAGE = 'Chronicle rejection decision moved behind the trusted clock';
    END IF;

    INSERT INTO ops.chronicle_trusted_clock AS clock (
        chronicle_id,
        high_water,
        last_request_id,
        updated_at
    ) VALUES (
        p_chronicle_id,
        p_rejected_at,
        p_request_id,
        p_rejected_at
    )
    ON CONFLICT ON CONSTRAINT chronicle_trusted_clock_pkey DO UPDATE
    SET high_water = GREATEST(clock.high_water, EXCLUDED.high_water),
        last_request_id = EXCLUDED.last_request_id,
        updated_at = GREATEST(clock.updated_at, EXCLUDED.updated_at);

    INSERT INTO ops.chronicle_replay_request_claims (
        request_id,
        request_digest,
        chronicle_id,
        writer_id,
        writer_key_id,
        request_nonce,
        claim_source,
        claimed_at
    ) VALUES (
        p_request_id,
        p_request_digest,
        p_chronicle_id,
        p_writer_id,
        p_writer_key_id,
        p_request_nonce,
        'rejected',
        p_rejected_at
    ) ON CONFLICT ON CONSTRAINT chronicle_replay_request_claims_pkey
        DO NOTHING;

    INSERT INTO ops.chronicle_replay_nonce_claims (
        writer_id,
        request_nonce,
        request_digest,
        chronicle_id,
        writer_key_id,
        request_id,
        claim_source,
        claimed_at
    ) VALUES (
        p_writer_id,
        p_request_nonce,
        p_request_digest,
        p_chronicle_id,
        p_writer_key_id,
        p_request_id,
        'rejected',
        p_rejected_at
    ) ON CONFLICT ON CONSTRAINT chronicle_replay_nonce_claims_pkey
        DO NOTHING;

    INSERT INTO ops.chronicle_rejection_attempts (
        chronicle_id,
        writer_id,
        writer_key_id,
        request_id,
        request_nonce,
        request_digest,
        rejection_reason,
        rejected_at,
        rejection_atomic_no_commit
    ) VALUES (
        p_chronicle_id,
        p_writer_id,
        p_writer_key_id,
        p_request_id,
        p_request_nonce,
        p_request_digest,
        p_rejection_reason,
        p_rejected_at,
        p_atomic_no_commit
    ) ON CONFLICT ON CONSTRAINT chronicle_rejection_attempts_pkey
        DO NOTHING;

    RETURN QUERY
    SELECT resolved.*
    FROM ops.chronicle_test_resolve_request_v1(
        p_chronicle_id,
        p_writer_id,
        p_writer_key_id,
        p_request_id,
        p_request_nonce
    ) AS resolved;
END
$chronicle_test_record_rejection$;

CREATE OR REPLACE FUNCTION ops.chronicle_test_append_v1(
    p_decision JSONB,
    p_record_ids TEXT[],
    p_record_kinds TEXT[],
    p_record_hashes TEXT[],
    p_canonical_record_bytes BYTEA[],
    p_outbox_intent_bytes BYTEA
)
RETURNS TABLE (
    request_id TEXT,
    chronicle_watermark BIGINT,
    record_commits JSONB,
    reasoning_cas_results JSONB,
    audit_outbox_watermark BIGINT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ops
AS $chronicle_test_append$
DECLARE
    v_api_version CONSTANT TEXT :=
        'platform.masonjames.dev/steward-chronicle/v1';
    v_record_api_version CONSTANT TEXT :=
        'platform.masonjames.dev/steward/v1';
    v_uuid_pattern CONSTANT TEXT :=
        '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
    v_digest_pattern CONSTANT TEXT := '^sha256:[0-9a-f]{64}$';
    v_identifier_pattern CONSTANT TEXT := '^[a-z0-9][a-z0-9._:/-]*$';
    v_required_top_keys CONSTANT TEXT[] := ARRAY[
        'apiVersion',
        'audience',
        'authority_effect',
        'capability_budget',
        'capability_reservation',
        'chronicle_id',
        'evidence_hashes',
        'expires_at',
        'identity',
        'installation',
        'interface_id',
        'kind',
        'mode',
        'outbox_intent',
        'previous_envelope_hash',
        'reasoning_cas_preconditions',
        'record_bindings',
        'records',
        'request_digest',
        'request_id',
        'request_nonce',
        'scope_bindings',
        'signature_bundle_hash',
        'source_attestation_hash',
        'submitted_at',
        'trusted_time',
        'writer_id',
        'writer_key_id',
        'writer_runtime_attestation_hash',
        'writer_sequence',
        'writer_session_id'
    ];
    v_record_kinds CONSTANT TEXT[] := ARRAY[
        'AgentConstitution',
        'AgentEpisode',
        'AgentHandoff',
        'AgentIdentityDescriptor',
        'AgentIdentityRevision',
        'CapabilityCandidate',
        'CapabilityEvaluation',
        'CapabilityGap',
        'CapabilityInvocation',
        'CapabilityLease',
        'CapabilityPromotion',
        'CapabilityRevocation',
        'FoundryAdmissionAttestation',
        'KnowledgeClaim',
        'ReasoningLease',
        'RuntimeAttestation'
    ];
    v_gate_enabled BOOLEAN;
    v_binding ops.chronicle_identity_runtime_bindings%ROWTYPE;
    v_signer ops.chronicle_signers%ROWTYPE;
    v_existing_request ops.chronicle_append_requests%ROWTYPE;
    v_append_state ops.chronicle_append_state%ROWTYPE;
    v_replay ops.chronicle_replay_sequences%ROWTYPE;
    v_lease ops.chronicle_reasoning_leases%ROWTYPE;
    v_capability ops.chronicle_capability_state%ROWTYPE;
    v_identity JSONB;
    v_installation JSONB;
    v_budget JSONB;
    v_reservation JSONB;
    v_outbox JSONB;
    v_outbox_parsed JSONB;
    v_scope_binding JSONB;
    v_scope JSONB;
    v_record_entry JSONB;
    v_record_binding JSONB;
    v_record_json JSONB;
    v_cas JSONB;
    v_target_json JSONB;
    v_request_id UUID;
    v_request_nonce UUID;
    v_writer_session_id UUID;
    v_outbox_id UUID;
    v_request_digest TEXT;
    v_chronicle_id TEXT;
    v_previous_envelope_hash TEXT;
    v_writer_sequence BIGINT;
    v_submitted_at TIMESTAMPTZ;
    v_expires_at TIMESTAMPTZ;
    v_trusted_time TIMESTAMPTZ;
    v_record_count INTEGER;
    v_scope_count INTEGER;
    v_cas_count INTEGER;
    v_evidence_count INTEGER;
    v_index INTEGER;
    v_inner_index INTEGER;
    v_record_hash TEXT;
    v_runtime_hash TEXT;
    v_evidence_hash TEXT;
    v_canonical_digest TEXT;
    v_expected_record_hash TEXT;
    v_canonical_envelope_bytes BYTEA;
    v_canonical_envelope_sha256 TEXT;
    v_existing_request_count INTEGER;
    v_logical_revision BIGINT;
    v_prior_record_hash TEXT;
    v_derived_logical_id TEXT;
    v_derived_logical_revision BIGINT;
    v_derived_prior_record_hash TEXT;
    v_first_append_sequence BIGINT;
    v_last_append_sequence BIGINT;
    v_target_index INTEGER;
    v_target_count INTEGER;
    v_target_hash TEXT;
    v_target_generation BIGINT;
    v_target_expected_previous_generation BIGINT;
    v_target_lease_revision BIGINT;
    v_terminal_index INTEGER;
    v_terminal_count INTEGER;
    v_terminal_hash TEXT;
    v_terminal_json JSONB;
    v_terminal_generation BIGINT;
    v_terminal_expected_previous_generation BIGINT;
    v_terminal_lease_revision BIGINT;
    v_transfer_pending_handoff JSONB;
    v_transfer_source_episode JSONB;
    v_transfer_target_episode JSONB;
    v_transfer_accepted_handoff JSONB;
    v_transition_key_count INTEGER;
    v_expected_generation BIGINT;
    v_committed_generation BIGINT;
    v_expected_active_hash TEXT;
    v_committed_active_hash TEXT;
    v_budget_max_calls BIGINT;
    v_budget_max_tokens BIGINT;
    v_budget_max_cost BIGINT;
    v_reservation_expected_generation BIGINT;
    v_reservation_calls BIGINT;
    v_reservation_tokens BIGINT;
    v_reservation_cost BIGINT;
    v_capability_previous_generation BIGINT;
    v_capability_committed_generation BIGINT;
    v_capability_lease_id TEXT;
    v_capability_lease_hash TEXT;
    v_capability_invocation_count INTEGER := 0;
    v_capability_reservation_match_count INTEGER := 0;
    v_capability_reservation_candidate BOOLEAN := FALSE;
    v_capability_release_bytes BYTEA;
    v_capability_release_sha256 TEXT;
    v_capability_usage JSONB;
    v_capability_validations JSONB;
    v_capability_entry_result TEXT;
    v_capability_before_return_result TEXT;
    v_capability_call_index BIGINT;
    v_capability_calls BIGINT;
    v_capability_tokens BIGINT;
    v_capability_cost BIGINT;
    v_capability_started_at TIMESTAMPTZ;
    v_capability_completed_at TIMESTAMPTZ;
    v_capability_recorded_at TIMESTAMPTZ;
    v_capability_effective_at TIMESTAMPTZ;
    v_capability_revocation_cause_at TIMESTAMPTZ;
BEGIN
    -- This owner-controlled row is also the global transaction serializer.
    -- It prevents cross-chronicle races from bypassing global record and
    -- logical-revision uniqueness while keeping the candidate inert by default.
    SELECT gate.enabled
    INTO v_gate_enabled
    FROM ops.chronicle_candidate_gate AS gate
    WHERE gate.singleton
    FOR UPDATE;

    IF NOT FOUND OR NOT v_gate_enabled THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D01',
            MESSAGE = 'Agent Chronicle persistence candidate is disabled';
    END IF;

    IF jsonb_typeof(p_decision) <> 'object'
        OR NOT p_decision ?& v_required_top_keys
        OR p_decision - v_required_top_keys <> '{}'::JSONB
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle append decision must be a closed v1 object';
    END IF;

    IF p_decision->>'apiVersion' <> v_api_version
        OR p_decision->>'kind' <> 'ChronicleAppendEnvelope'
        OR p_decision->>'authority_effect' <> 'chronicle-append-only'
        OR p_decision->>'interface_id' <> 'dockhand-chronicle-append-v1'
        OR p_decision->>'mode' <> 'intent'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D01',
            MESSAGE = 'Chronicle append authority boundary changed';
    END IF;

    v_record_count := cardinality(p_record_ids);
    IF v_record_count IS NULL
        OR v_record_count NOT BETWEEN 1 AND 6
        OR cardinality(p_record_kinds) <> v_record_count
        OR cardinality(p_record_hashes) <> v_record_count
        OR cardinality(p_canonical_record_bytes) <> v_record_count
        OR jsonb_typeof(p_decision->'records') <> 'array'
        OR jsonb_array_length(p_decision->'records') <> v_record_count
        OR jsonb_typeof(p_decision->'record_bindings') <> 'array'
        OR jsonb_array_length(p_decision->'record_bindings') <> v_record_count
        OR (
            SELECT count(DISTINCT value) <> v_record_count
            FROM unnest(p_record_ids) AS value
        )
        OR (
            SELECT count(DISTINCT value) <> v_record_count
            FROM unnest(p_record_hashes) AS value
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle append requires 1..6 aligned unique record arrays';
    END IF;

    v_identity := p_decision->'identity';
    v_installation := p_decision->'installation';
    v_budget := p_decision->'capability_budget';
    v_reservation := p_decision->'capability_reservation';
    v_outbox := p_decision->'outbox_intent';

    IF jsonb_typeof(v_identity) <> 'object'
        OR NOT v_identity ?& ARRAY[
            'constitution_hash', 'identity_epoch',
            'identity_id', 'identity_revision'
        ]
        OR v_identity - ARRAY[
            'constitution_hash', 'identity_epoch',
            'identity_id', 'identity_revision'
        ] <> '{}'::JSONB
        OR jsonb_typeof(v_installation) <> 'object'
        OR NOT v_installation ?& ARRAY[
            'embodiment', 'host_class', 'installation_id'
        ]
        OR v_installation - ARRAY[
            'embodiment', 'host_class', 'installation_id'
        ] <> '{}'::JSONB
        OR jsonb_typeof(v_budget) <> 'object'
        OR NOT v_budget ?& ARRAY[
            'maximum_calls', 'maximum_cost_microunits', 'maximum_tokens'
        ]
        OR v_budget - ARRAY[
            'maximum_calls', 'maximum_cost_microunits', 'maximum_tokens'
        ] <> '{}'::JSONB
        OR jsonb_typeof(v_outbox) <> 'object'
        OR NOT v_outbox ?& ARRAY[
            'authority_effect', 'outbox_id',
            'projection_name', 'request_digest'
        ]
        OR v_outbox - ARRAY[
            'authority_effect', 'outbox_id',
            'projection_name', 'request_digest'
        ] <> '{}'::JSONB
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle identity, installation, budget, or outbox mapping is not closed';
    END IF;

    IF p_decision->>'request_id' !~ v_uuid_pattern
        OR p_decision->>'request_nonce' !~ v_uuid_pattern
        OR p_decision->>'writer_session_id' !~ v_uuid_pattern
        OR v_outbox->>'outbox_id' !~ v_uuid_pattern
        OR p_decision->>'request_digest' !~ v_digest_pattern
        OR p_decision->>'signature_bundle_hash' !~ v_digest_pattern
        OR p_decision->>'writer_runtime_attestation_hash' !~ v_digest_pattern
        OR p_decision->>'source_attestation_hash' !~ v_digest_pattern
        OR v_identity->>'constitution_hash' !~ v_digest_pattern
        OR p_decision->>'chronicle_id' !~ v_identifier_pattern
        OR p_decision->>'audience' !~ v_identifier_pattern
        OR p_decision->>'writer_id' !~ v_identifier_pattern
        OR p_decision->>'writer_key_id' !~ v_identifier_pattern
        OR v_identity->>'identity_id' !~ v_identifier_pattern
        OR v_installation->>'installation_id' !~ v_identifier_pattern
        OR v_installation->>'embodiment'
            NOT IN ('server-sentinel', 'mac-engineer')
        OR v_installation->>'host_class'
            NOT IN ('near-platform-server', 'local-mac')
        OR jsonb_typeof(p_decision->'writer_sequence') <> 'number'
        OR p_decision->>'writer_sequence' !~ '^[1-9][0-9]*$'
        OR jsonb_typeof(v_identity->'identity_revision') <> 'number'
        OR v_identity->>'identity_revision' !~ '^[1-9][0-9]*$'
        OR jsonb_typeof(v_identity->'identity_epoch') <> 'number'
        OR v_identity->>'identity_epoch' !~ '^[1-9][0-9]*$'
        OR jsonb_typeof(v_budget->'maximum_calls') <> 'number'
        OR v_budget->>'maximum_calls' !~ '^[1-9][0-9]*$'
        OR jsonb_typeof(v_budget->'maximum_tokens') <> 'number'
        OR v_budget->>'maximum_tokens' !~ '^[0-9]+$'
        OR jsonb_typeof(v_budget->'maximum_cost_microunits') <> 'number'
        OR v_budget->>'maximum_cost_microunits' !~ '^[0-9]+$'
        OR (
            jsonb_typeof(p_decision->'previous_envelope_hash') <> 'null'
            AND (
                jsonb_typeof(p_decision->'previous_envelope_hash') <> 'string'
                OR p_decision->>'previous_envelope_hash' !~ v_digest_pattern
            )
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle scalar identifier, digest, or integer mapping is invalid';
    END IF;

    IF p_decision->>'submitted_at'
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
        OR p_decision->>'expires_at'
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
        OR p_decision->>'trusted_time'
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle timestamps must be canonical whole-second UTC';
    END IF;

    BEGIN
        v_request_id := (p_decision->>'request_id')::UUID;
        v_request_nonce := (p_decision->>'request_nonce')::UUID;
        v_writer_session_id := (p_decision->>'writer_session_id')::UUID;
        v_outbox_id := (v_outbox->>'outbox_id')::UUID;
        v_writer_sequence := (p_decision->>'writer_sequence')::BIGINT;
        v_submitted_at := (p_decision->>'submitted_at')::TIMESTAMPTZ;
        v_expires_at := (p_decision->>'expires_at')::TIMESTAMPTZ;
        v_trusted_time := (p_decision->>'trusted_time')::TIMESTAMPTZ;
        v_budget_max_calls := (v_budget->>'maximum_calls')::BIGINT;
        v_budget_max_tokens := (v_budget->>'maximum_tokens')::BIGINT;
        v_budget_max_cost := (v_budget->>'maximum_cost_microunits')::BIGINT;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle scalar conversion is outside the supported range';
    END;

    v_request_digest := p_decision->>'request_digest';
    v_chronicle_id := p_decision->>'chronicle_id';
    v_previous_envelope_hash := p_decision->>'previous_envelope_hash';
    v_canonical_envelope_bytes := convert_to(
        ops.chronicle_canonical_json_text_v1(p_decision),
        'UTF8'
    );
    v_canonical_envelope_sha256 :=
        'sha256:' || encode(sha256(v_canonical_envelope_bytes), 'hex');

    IF p_outbox_intent_bytes IS NULL
        OR octet_length(p_outbox_intent_bytes) = 0
        OR v_outbox->>'projection_name' <> 'platform-steward-audit-v1'
        OR v_outbox->>'request_digest' IS DISTINCT FROM v_request_digest
        OR v_outbox->>'authority_effect' <> 'none'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle outbox intent is not bound to the request';
    END IF;

    BEGIN
        v_outbox_parsed := convert_from(p_outbox_intent_bytes, 'UTF8')::JSONB;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle outbox intent bytes are not UTF-8 JSON';
    END;
    IF convert_to(
            ops.chronicle_canonical_json_text_v1(v_outbox_parsed),
            'UTF8'
        ) IS DISTINCT FROM p_outbox_intent_bytes
        OR v_outbox_parsed IS DISTINCT FROM v_outbox
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle outbox bytes are not canonical or do not match the decision';
    END IF;

    -- A byte-exact committed retry is recovery, not replay. Return only the
    -- already durable commit tuple, with no state mutation. Any reuse of one
    -- durable identifier with a different envelope/array/outbox binding is a
    -- deterministic replay conflict.
    SELECT count(*)
    INTO v_existing_request_count
    FROM ops.chronicle_append_requests AS existing
    WHERE existing.request_id = v_request_id
       OR existing.request_digest = v_request_digest;

    IF v_existing_request_count > 0 THEN
        IF v_existing_request_count <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D02',
                MESSAGE = 'Chronicle request id and digest were rebound across commits';
        END IF;

        SELECT existing.*
        INTO v_existing_request
        FROM ops.chronicle_append_requests AS existing
        WHERE existing.request_id = v_request_id
           OR existing.request_digest = v_request_digest
        FOR SHARE;

        IF v_existing_request.request_id IS DISTINCT FROM v_request_id
            OR v_existing_request.request_digest IS DISTINCT FROM v_request_digest
            OR v_existing_request.writer_id
                IS DISTINCT FROM p_decision->>'writer_id'
            OR v_existing_request.writer_key_id
                IS DISTINCT FROM p_decision->>'writer_key_id'
            OR v_existing_request.request_nonce IS DISTINCT FROM v_request_nonce
            OR v_existing_request.canonical_envelope_bytes
                IS DISTINCT FROM v_canonical_envelope_bytes
            OR v_existing_request.canonical_envelope_sha256
                IS DISTINCT FROM v_canonical_envelope_sha256
            OR v_existing_request.record_count <> v_record_count
            OR (
                SELECT count(*)
                FROM ops.chronicle_records AS committed
                WHERE committed.request_id = v_existing_request.request_id
            ) <> v_record_count
            OR EXISTS (
                SELECT 1
                FROM generate_subscripts(p_record_ids, 1) AS item(index)
                LEFT JOIN ops.chronicle_records AS committed
                  ON committed.request_id = v_existing_request.request_id
                 AND committed.batch_ordinal = item.index
                WHERE committed.record_id
                        IS DISTINCT FROM p_record_ids[item.index]::UUID
                   OR committed.record_kind
                        IS DISTINCT FROM p_record_kinds[item.index]
                   OR committed.record_hash
                        IS DISTINCT FROM p_record_hashes[item.index]
                   OR committed.canonical_record_bytes
                        IS DISTINCT FROM p_canonical_record_bytes[item.index]
            )
            OR NOT EXISTS (
                SELECT 1
                FROM ops.chronicle_outbox AS committed_outbox
                WHERE committed_outbox.request_id = v_existing_request.request_id
                  AND committed_outbox.outbox_id = v_outbox_id
                  AND committed_outbox.request_digest = v_request_digest
                  AND committed_outbox.outbox_intent_bytes
                        = p_outbox_intent_bytes
            )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D02',
                MESSAGE = 'Chronicle committed retry changed its canonical binding';
        END IF;

        request_id := v_existing_request.request_id::TEXT;
        chronicle_watermark := v_existing_request.chronicle_watermark;
        audit_outbox_watermark :=
            v_existing_request.audit_outbox_watermark;
        SELECT COALESCE(
            jsonb_agg(
                jsonb_build_object(
                    'record_id', committed.record_id::TEXT,
                    'record_kind', committed.record_kind,
                    'record_hash', committed.record_hash,
                    'append_sequence', committed.append_sequence
                ) ORDER BY committed.batch_ordinal
            ),
            '[]'::JSONB
        )
        INTO record_commits
        FROM ops.chronicle_records AS committed
        WHERE committed.request_id = v_existing_request.request_id;

        SELECT COALESCE(
            jsonb_agg(
                jsonb_build_object(
                    'identity_id', committed.identity_id,
                    'scope_type', committed.scope_type,
                    'scope_id', committed.scope_id,
                    'previous_generation', committed.previous_generation,
                    'committed_generation', committed.committed_generation,
                    'previous_active_reasoning_lease_hash',
                        committed.previous_active_reasoning_lease_hash,
                    'committed_active_reasoning_lease_hash',
                        committed.committed_active_reasoning_lease_hash
                ) ORDER BY committed.ordinal
            ),
            '[]'::JSONB
        )
        INTO reasoning_cas_results
        FROM ops.chronicle_append_request_reasoning_cas AS committed
        WHERE committed.request_id = v_existing_request.request_id;

        RETURN NEXT;
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM ops.chronicle_replay_request_claims AS claim
        WHERE claim.request_id = v_request_id
    ) OR EXISTS (
        SELECT 1
        FROM ops.chronicle_replay_nonce_claims AS claim
        WHERE claim.writer_id = p_decision->>'writer_id'
          AND claim.request_nonce = v_request_nonce
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D02',
            MESSAGE = 'Chronicle request id or writer nonce is durably reserved';
    END IF;

    IF v_submitted_at > v_trusted_time OR v_trusted_time >= v_expires_at THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D01',
            MESSAGE = 'Chronicle append request is future-dated or expired';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM ops.chronicle_outbox AS existing_outbox
        WHERE existing_outbox.outbox_id = v_outbox_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle outbox id was already consumed';
    END IF;

    SELECT binding.*
    INTO v_binding
    FROM ops.chronicle_identity_runtime_bindings AS binding
    WHERE binding.writer_id = p_decision->>'writer_id'
      AND binding.writer_key_id = p_decision->>'writer_key_id'
      AND binding.identity_id = v_identity->>'identity_id'
      AND binding.identity_revision
            = (v_identity->>'identity_revision')::BIGINT
      AND binding.identity_epoch = (v_identity->>'identity_epoch')::BIGINT
      AND binding.constitution_hash = v_identity->>'constitution_hash'
      AND binding.writer_runtime_attestation_hash
            = p_decision->>'writer_runtime_attestation_hash'
      AND binding.source_attestation_hash
            = p_decision->>'source_attestation_hash'
      AND binding.audience = p_decision->>'audience'
      AND binding.installation_id = v_installation->>'installation_id'
      AND binding.embodiment = v_installation->>'embodiment'
      AND binding.host_class = v_installation->>'host_class'
      AND binding.writer_session_id = v_writer_session_id
      AND binding.interface_id = p_decision->>'interface_id'
      AND binding.mode = p_decision->>'mode'
    FOR SHARE;

    IF NOT FOUND
        OR v_binding.admitted_at > v_trusted_time
        OR v_binding.expires_at <= v_trusted_time
        OR v_binding.revoked_at IS NOT NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D09',
            MESSAGE = 'Chronicle identity/runtime/installation binding is not active';
    END IF;

    SELECT signer.*
    INTO v_signer
    FROM ops.chronicle_signers AS signer
    WHERE signer.signer_id = v_binding.signer_id
      AND signer.writer_id = v_binding.writer_id
      AND signer.writer_key_id = v_binding.writer_key_id
    FOR SHARE;

    IF NOT FOUND
        OR v_signer.admitted_at > v_trusted_time
        OR v_signer.expires_at <= v_trusted_time
        OR v_signer.revoked_at IS NOT NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D09',
            MESSAGE = 'Chronicle signer is not active for the writer binding';
    END IF;

    IF jsonb_typeof(p_decision->'evidence_hashes') <> 'array'
        OR jsonb_array_length(p_decision->'evidence_hashes') NOT BETWEEN 1 AND 256
        OR (
            SELECT count(*) <> count(DISTINCT value)
            FROM jsonb_array_elements_text(p_decision->'evidence_hashes')
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D10',
            MESSAGE = 'Chronicle evidence hashes must be a unique nonempty array';
    END IF;

    v_evidence_count := jsonb_array_length(p_decision->'evidence_hashes');
    FOR v_evidence_hash IN
        SELECT value
        FROM jsonb_array_elements_text(p_decision->'evidence_hashes')
    LOOP
        IF v_evidence_hash !~ v_digest_pattern
            OR NOT EXISTS (
                SELECT 1
                FROM ops.chronicle_evidence AS evidence
                WHERE evidence.evidence_hash = v_evidence_hash
                  AND evidence.captured_at <= v_trusted_time
                  AND (
                      evidence.expires_at IS NULL
                      OR evidence.expires_at > v_trusted_time
                  )
                  AND evidence.revoked_at IS NULL
            )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D10',
                MESSAGE = 'Chronicle required evidence is unavailable';
        END IF;
    END LOOP;

    IF NOT (
        (p_decision->'evidence_hashes')
            ? (p_decision->>'source_attestation_hash')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D10',
            MESSAGE = 'Chronicle source attestation is not in the evidence set';
    END IF;

    IF jsonb_typeof(p_decision->'scope_bindings') <> 'array'
        OR jsonb_array_length(p_decision->'scope_bindings') NOT BETWEEN 1 AND 6
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle scope bindings must contain 1..6 entries';
    END IF;
    v_scope_count := jsonb_array_length(p_decision->'scope_bindings');

    FOR v_index IN 0..v_scope_count - 1 LOOP
        v_scope_binding := (p_decision->'scope_bindings')->v_index;
        v_scope := v_scope_binding->'scope';
        IF jsonb_typeof(v_scope_binding) <> 'object'
            OR NOT v_scope_binding ?& ARRAY[
                'record_hashes', 'runtime_attestation_hashes', 'scope'
            ]
            OR v_scope_binding - ARRAY[
                'record_hashes', 'runtime_attestation_hashes', 'scope'
            ] <> '{}'::JSONB
            OR jsonb_typeof(v_scope) <> 'object'
            OR NOT v_scope ?& ARRAY[
                'installation_id', 'resource_id', 'resource_type',
                'scope_id', 'scope_type'
            ]
            OR v_scope - ARRAY[
                'installation_id', 'resource_id', 'resource_type',
                'scope_id', 'scope_type'
            ] <> '{}'::JSONB
            OR v_scope->>'scope_type'
                NOT IN ('installation', 'incident', 'journey', 'task')
            OR v_scope->>'scope_id' !~ v_identifier_pattern
            OR v_scope->>'installation_id' !~ v_identifier_pattern
            OR v_scope->>'resource_type' !~ v_identifier_pattern
            OR v_scope->>'resource_id' !~ v_identifier_pattern
            OR jsonb_typeof(v_scope_binding->'record_hashes') <> 'array'
            OR jsonb_array_length(v_scope_binding->'record_hashes')
                NOT BETWEEN 1 AND 6
            OR jsonb_typeof(v_scope_binding->'runtime_attestation_hashes')
                <> 'array'
            OR jsonb_array_length(
                v_scope_binding->'runtime_attestation_hashes'
            ) NOT BETWEEN 1 AND 6
            OR (
                SELECT count(*) <> count(DISTINCT value)
                FROM jsonb_array_elements_text(
                    v_scope_binding->'record_hashes'
                )
            )
            OR (
                SELECT count(*) <> count(DISTINCT value)
                FROM jsonb_array_elements_text(
                    v_scope_binding->'runtime_attestation_hashes'
                )
            )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D06',
                MESSAGE = 'Chronicle scope binding is not closed and unique';
        END IF;

        IF NOT EXISTS (
            SELECT 1
            FROM ops.chronicle_identity_runtime_scopes AS admitted_scope
            WHERE admitted_scope.binding_id = v_binding.binding_id
              AND admitted_scope.scope_type = v_scope->>'scope_type'
              AND admitted_scope.scope_id = v_scope->>'scope_id'
              AND admitted_scope.installation_id = v_scope->>'installation_id'
              AND admitted_scope.resource_type = v_scope->>'resource_type'
              AND admitted_scope.resource_id = v_scope->>'resource_id'
              AND admitted_scope.admitted_at <= v_trusted_time
              AND admitted_scope.expires_at > v_trusted_time
              AND admitted_scope.revoked_at IS NULL
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D09',
                MESSAGE = 'Chronicle scope is not active for the writer binding';
        END IF;

        FOR v_runtime_hash IN
            SELECT value
            FROM jsonb_array_elements_text(
                v_scope_binding->'runtime_attestation_hashes'
            )
        LOOP
            IF v_runtime_hash !~ v_digest_pattern
                OR NOT EXISTS (
                    SELECT 1
                    FROM ops.chronicle_runtime_attestations AS runtime
                    WHERE runtime.runtime_attestation_hash = v_runtime_hash
                      AND runtime.identity_id = v_identity->>'identity_id'
                      AND runtime.identity_revision
                            = (v_identity->>'identity_revision')::BIGINT
                      AND runtime.identity_epoch
                            = (v_identity->>'identity_epoch')::BIGINT
                      AND runtime.admitted_at <= v_trusted_time
                      AND runtime.expires_at > v_trusted_time
                      AND runtime.revoked_at IS NULL
                )
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D09',
                    MESSAGE = 'Chronicle scope runtime attestation is not active';
            END IF;
        END LOOP;

        FOR v_record_hash IN
            SELECT value
            FROM jsonb_array_elements_text(v_scope_binding->'record_hashes')
        LOOP
            IF v_record_hash !~ v_digest_pattern
                OR NOT v_record_hash = ANY(p_record_hashes)
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D06',
                    MESSAGE = 'Chronicle scope contains an unbound record hash';
            END IF;
        END LOOP;
    END LOOP;

    FOR v_index IN 1..v_record_count LOOP
        v_record_hash := p_record_hashes[v_index];
        IF (
            SELECT count(*)
            FROM jsonb_array_elements(p_decision->'scope_bindings') AS item,
                 jsonb_array_elements_text(item->'record_hashes') AS hash(value)
            WHERE hash.value = v_record_hash
        ) <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D06',
                MESSAGE = 'Every Chronicle record must be scope-bound exactly once';
        END IF;

        v_record_entry := (p_decision->'records')->(v_index - 1);
        v_record_binding := (p_decision->'record_bindings')->(v_index - 1);
        IF jsonb_typeof(v_record_entry) <> 'object'
            OR NOT v_record_entry ?& ARRAY[
                'canonical_record_json', 'record_hash',
                'record_id', 'record_kind'
            ]
            OR v_record_entry - ARRAY[
                'canonical_record_json', 'record_hash',
                'record_id', 'record_kind'
            ] <> '{}'::JSONB
            OR jsonb_typeof(v_record_binding) <> 'object'
            OR NOT v_record_binding ?& ARRAY[
                'canonical_bytes_sha256', 'logical_id', 'logical_revision',
                'prior_record_hash', 'record_hash', 'record_id', 'record_kind'
            ]
            OR v_record_binding - ARRAY[
                'canonical_bytes_sha256', 'logical_id', 'logical_revision',
                'prior_record_hash', 'record_hash', 'record_id', 'record_kind'
            ] <> '{}'::JSONB
            OR p_record_ids[v_index] !~ v_uuid_pattern
            OR p_record_kinds[v_index] <> ALL(v_record_kinds)
            OR p_record_hashes[v_index] !~ v_digest_pattern
            OR v_record_binding->>'canonical_bytes_sha256' !~ v_digest_pattern
            OR v_record_binding->>'logical_id' IS NULL
            OR v_record_binding->>'logical_id' = ''
            OR jsonb_typeof(v_record_binding->'logical_revision') <> 'number'
            OR v_record_binding->>'logical_revision' !~ '^[1-9][0-9]*$'
            OR (
                jsonb_typeof(v_record_binding->'prior_record_hash') <> 'null'
                AND (
                    jsonb_typeof(v_record_binding->'prior_record_hash') <> 'string'
                    OR v_record_binding->>'prior_record_hash' !~ v_digest_pattern
                )
            )
            OR v_record_entry->>'record_id' IS DISTINCT FROM p_record_ids[v_index]
            OR v_record_entry->>'record_kind' IS DISTINCT FROM p_record_kinds[v_index]
            OR v_record_entry->>'record_hash' IS DISTINCT FROM p_record_hashes[v_index]
            OR v_record_binding->>'record_id' IS DISTINCT FROM p_record_ids[v_index]
            OR v_record_binding->>'record_kind' IS DISTINCT FROM p_record_kinds[v_index]
            OR v_record_binding->>'record_hash' IS DISTINCT FROM p_record_hashes[v_index]
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D06',
                MESSAGE = 'Chronicle record arrays and decision bindings diverge';
        END IF;

        v_canonical_digest :=
            'sha256:' || encode(sha256(p_canonical_record_bytes[v_index]), 'hex');
        IF v_record_binding->>'canonical_bytes_sha256'
                IS DISTINCT FROM v_canonical_digest
            OR convert_to(v_record_entry->>'canonical_record_json', 'UTF8')
                IS DISTINCT FROM p_canonical_record_bytes[v_index]
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D06',
                MESSAGE = 'Chronicle canonical byte digest binding is invalid';
        END IF;

        BEGIN
            v_record_json :=
                convert_from(p_canonical_record_bytes[v_index], 'UTF8')::JSONB;
            v_logical_revision :=
                (v_record_binding->>'logical_revision')::BIGINT;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D06',
                MESSAGE = 'Chronicle record bytes or logical revision are invalid';
        END;

        IF convert_to(
                ops.chronicle_canonical_json_text_v1(v_record_json),
                'UTF8'
            ) IS DISTINCT FROM p_canonical_record_bytes[v_index]
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D06',
                MESSAGE = 'Chronicle record bytes are not strict canonical JSON';
        END IF;

        IF jsonb_typeof(v_record_json) <> 'object'
            OR v_record_json->>'apiVersion' <> v_record_api_version
            OR v_record_json->>'record_id' IS DISTINCT FROM p_record_ids[v_index]
            OR v_record_json->>'kind' IS DISTINCT FROM p_record_kinds[v_index]
            OR v_record_json->>'record_hash' IS DISTINCT FROM p_record_hashes[v_index]
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D06',
                MESSAGE = 'Chronicle canonical bytes do not match record metadata';
        END IF;

        -- The record hash is not the SHA-256 of the full stored document. It
        -- is the canonical steward domain hash with the top-level record_hash
        -- omitted before canonicalization. Derive it inside PostgreSQL so a
        -- caller cannot forge the embedded/array/decision digests together.
        v_expected_record_hash := 'sha256:' || encode(
            sha256(
                convert_to('platform-steward-record-v1', 'UTF8')
                || decode('00', 'hex')
                || convert_to(v_record_api_version, 'UTF8')
                || decode('00', 'hex')
                || convert_to(p_record_kinds[v_index], 'UTF8')
                || decode('00', 'hex')
                || convert_to(
                    ops.chronicle_canonical_json_text_v1(
                        v_record_json - 'record_hash'
                    ),
                    'UTF8'
                )
            ),
            'hex'
        );
        IF v_record_json->>'record_hash'
                IS DISTINCT FROM v_expected_record_hash
            OR p_record_hashes[v_index]
                IS DISTINCT FROM v_expected_record_hash
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D06',
                MESSAGE = 'Chronicle record hash does not match the canonical steward domain';
        END IF;

        IF EXISTS (
            SELECT 1
            FROM (
                SELECT cited.value #>> '{}' AS evidence_hash
                FROM jsonb_path_query(
                    v_record_json,
                    'lax $.**.evidence_hash'
                ) AS cited(value)
                UNION ALL
                SELECT cited.value #>> '{}'
                FROM jsonb_path_query(
                    v_record_json,
                    'lax $.**.selection_evidence_hash'
                ) AS cited(value)
                UNION ALL
                SELECT cited.value #>> '{}'
                FROM jsonb_path_query(
                    v_record_json,
                    'lax $.**.signing_evidence_hash'
                ) AS cited(value)
                UNION ALL
                SELECT cited.value #>> '{}'
                FROM jsonb_path_query(
                    v_record_json,
                    'lax $.**.evidence_preconditions[*]'
                ) AS cited(value)
                UNION ALL
                SELECT cited.value #>> '{}'
                FROM jsonb_path_query(
                    v_record_json,
                    'lax $.**.input_evidence_hashes[*]'
                ) AS cited(value)
                UNION ALL
                SELECT cited.value #>> '{}'
                FROM jsonb_path_query(
                    v_record_json,
                    'lax $.**.result_evidence_hashes[*]'
                ) AS cited(value)
            ) AS citation
            WHERE citation.evidence_hash !~ v_digest_pattern
               OR NOT (
                    p_decision->'evidence_hashes'
                        ? citation.evidence_hash
               )
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D10',
                MESSAGE = 'Chronicle canonical record evidence is not in the envelope set';
        END IF;

        -- The provider's derived state binding is never accepted as free-form
        -- metadata. Re-derive the exact logical family, revision, and prior
        -- hash mechanically from the already validated canonical record JSON.
        BEGIN
            CASE p_record_kinds[v_index]
                WHEN 'AgentConstitution' THEN
                    v_derived_logical_id := v_record_json->>'constitution_id';
                    v_derived_logical_revision :=
                        (v_record_json->>'constitution_revision')::BIGINT;
                    v_derived_prior_record_hash :=
                        v_record_json->>'prior_constitution_hash';
                WHEN 'AgentIdentityDescriptor' THEN
                    v_derived_logical_id := v_record_json->>'identity_id';
                    v_derived_logical_revision :=
                        (v_record_json->>'initial_identity_revision')::BIGINT;
                    v_derived_prior_record_hash := NULL;
                WHEN 'AgentIdentityRevision' THEN
                    v_derived_logical_id :=
                        v_record_json->'identity'->>'identity_id';
                    v_derived_logical_revision :=
                        (v_record_json->'identity'->>'identity_revision')::BIGINT;
                    v_derived_prior_record_hash :=
                        v_record_json->>'prior_revision_hash';
                WHEN 'AgentEpisode' THEN
                    v_derived_logical_id := v_record_json->>'episode_id';
                    v_derived_logical_revision :=
                        (v_record_json->>'episode_revision')::BIGINT;
                    v_derived_prior_record_hash :=
                        v_record_json->>'prior_episode_hash';
                WHEN 'AgentHandoff' THEN
                    v_derived_logical_id := v_record_json->>'handoff_id';
                    v_derived_logical_revision :=
                        (v_record_json->>'handoff_revision')::BIGINT;
                    v_derived_prior_record_hash :=
                        v_record_json->>'prior_handoff_hash';
                WHEN 'ReasoningLease' THEN
                    v_derived_logical_id := v_record_json->>'lease_id';
                    v_derived_logical_revision :=
                        (v_record_json->>'lease_revision')::BIGINT;
                    v_derived_prior_record_hash :=
                        v_record_json->>'prior_lease_hash';
                WHEN 'KnowledgeClaim' THEN
                    v_derived_logical_id := v_record_json->>'claim_id';
                    v_derived_logical_revision :=
                        (v_record_json->>'claim_revision')::BIGINT;
                    v_derived_prior_record_hash :=
                        v_record_json->>'prior_claim_hash';
                WHEN 'CapabilityGap' THEN
                    v_derived_logical_id := v_record_json->>'gap_id';
                    v_derived_logical_revision :=
                        (v_record_json->>'gap_revision')::BIGINT;
                    v_derived_prior_record_hash :=
                        v_record_json->>'prior_gap_hash';
                WHEN 'CapabilityPromotion' THEN
                    v_derived_logical_id := v_record_json->>'promotion_id';
                    v_derived_logical_revision :=
                        (v_record_json->>'promotion_revision')::BIGINT;
                    v_derived_prior_record_hash :=
                        v_record_json->>'prior_promotion_hash';
                WHEN 'RuntimeAttestation' THEN
                    v_derived_logical_id := v_record_json->>'attestation_id';
                    v_derived_logical_revision := 1;
                    v_derived_prior_record_hash := NULL;
                WHEN 'FoundryAdmissionAttestation' THEN
                    v_derived_logical_id := v_record_json->>'admission_id';
                    v_derived_logical_revision := 1;
                    v_derived_prior_record_hash := NULL;
                WHEN 'CapabilityCandidate' THEN
                    v_derived_logical_id := v_record_json->>'candidate_id';
                    v_derived_logical_revision := 1;
                    v_derived_prior_record_hash := NULL;
                WHEN 'CapabilityEvaluation' THEN
                    v_derived_logical_id := v_record_json->>'evaluation_id';
                    v_derived_logical_revision := 1;
                    v_derived_prior_record_hash := NULL;
                WHEN 'CapabilityLease' THEN
                    v_derived_logical_id := v_record_json->>'lease_id';
                    v_derived_logical_revision := 1;
                    v_derived_prior_record_hash := NULL;
                WHEN 'CapabilityInvocation' THEN
                    v_derived_logical_id := v_record_json->>'invocation_id';
                    v_derived_logical_revision := 1;
                    v_derived_prior_record_hash := NULL;
                WHEN 'CapabilityRevocation' THEN
                    v_derived_logical_id := v_record_json->>'revocation_id';
                    v_derived_logical_revision := 1;
                    v_derived_prior_record_hash := NULL;
                ELSE
                    RAISE EXCEPTION 'unsupported Chronicle record kind';
            END CASE;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D06',
                MESSAGE = 'Chronicle logical state cannot be derived from canonical bytes';
        END;

        IF v_derived_logical_id IS NULL
            OR v_derived_logical_id = ''
            OR v_derived_logical_revision IS NULL
            OR v_derived_logical_revision < 1
            OR (
                v_derived_prior_record_hash IS NOT NULL
                AND v_derived_prior_record_hash !~ v_digest_pattern
            )
            OR v_record_binding->>'logical_id'
                IS DISTINCT FROM v_derived_logical_id
            OR v_logical_revision IS DISTINCT FROM v_derived_logical_revision
            OR v_record_binding->>'prior_record_hash'
                IS DISTINCT FROM v_derived_prior_record_hash
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D06',
                MESSAGE = 'Chronicle logical state binding does not match canonical bytes';
        END IF;

        v_prior_record_hash := v_record_binding->>'prior_record_hash';
        IF (v_logical_revision = 1 AND v_prior_record_hash IS NOT NULL)
            OR (v_logical_revision > 1 AND v_prior_record_hash IS NULL)
            OR EXISTS (
                SELECT 1
                FROM ops.chronicle_records AS existing
                WHERE existing.record_id = p_record_ids[v_index]::UUID
                   OR existing.record_hash = p_record_hashes[v_index]
                   OR (
                       existing.record_kind = p_record_kinds[v_index]
                       AND existing.logical_id = v_record_binding->>'logical_id'
                       AND existing.logical_revision = v_logical_revision
                   )
            )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D06',
                MESSAGE = 'Chronicle record or logical revision is not globally unique';
        END IF;

        IF v_logical_revision > 1
            AND NOT EXISTS (
                SELECT 1
                FROM ops.chronicle_records AS prior
                WHERE prior.record_hash = v_prior_record_hash
                  AND prior.record_kind = p_record_kinds[v_index]
                  AND prior.logical_id = v_record_binding->>'logical_id'
                  AND prior.logical_revision = v_logical_revision - 1
                UNION ALL
                SELECT 1
                FROM generate_series(0, v_index - 2) AS prior_index
                WHERE (p_decision->'record_bindings')->prior_index
                        ->>'record_hash' = v_prior_record_hash
                  AND (p_decision->'record_bindings')->prior_index
                        ->>'record_kind' = p_record_kinds[v_index]
                  AND (p_decision->'record_bindings')->prior_index
                        ->>'logical_id' = v_record_binding->>'logical_id'
                  AND ((p_decision->'record_bindings')->prior_index
                        ->>'logical_revision')::BIGINT
                        = v_logical_revision - 1
            )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D06',
                MESSAGE = 'Chronicle prior logical revision binding is invalid';
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1
        FROM ops.chronicle_append_requests AS existing
        WHERE existing.request_id = v_request_id
           OR existing.request_digest = v_request_digest
    ) OR EXISTS (
        SELECT 1
        FROM ops.chronicle_replay_nonces AS nonce
        WHERE nonce.writer_id = p_decision->>'writer_id'
          AND (
              nonce.request_nonce = v_request_nonce
              OR nonce.request_id = v_request_id
              OR nonce.request_digest = v_request_digest
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D02',
            MESSAGE = 'Chronicle request, digest, or nonce was already consumed';
    END IF;

    INSERT INTO ops.chronicle_replay_sequences (writer_id, writer_key_id)
    VALUES (p_decision->>'writer_id', p_decision->>'writer_key_id')
    ON CONFLICT (writer_id, writer_key_id) DO NOTHING;

    SELECT replay.*
    INTO v_replay
    FROM ops.chronicle_replay_sequences AS replay
    WHERE replay.writer_id = p_decision->>'writer_id'
      AND replay.writer_key_id = p_decision->>'writer_key_id'
    FOR UPDATE;

    IF v_writer_sequence <> v_replay.last_writer_sequence + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D03',
            MESSAGE = 'Chronicle writer sequence is not the next value';
    END IF;

    IF (v_replay.last_writer_sequence = 0 AND v_previous_envelope_hash IS NOT NULL)
        OR (
            v_replay.last_writer_sequence > 0
            AND v_previous_envelope_hash
                IS DISTINCT FROM v_replay.last_envelope_hash
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D04',
            MESSAGE = 'Chronicle previous-envelope chain does not match';
    END IF;

    INSERT INTO ops.chronicle_append_state (chronicle_id)
    VALUES (v_chronicle_id)
    ON CONFLICT (chronicle_id) DO NOTHING;

    SELECT state.*
    INTO v_append_state
    FROM ops.chronicle_append_state AS state
    WHERE state.chronicle_id = v_chronicle_id
    FOR UPDATE;

    IF EXISTS (
        SELECT 1
        FROM ops.chronicle_trusted_clock AS clock
        WHERE clock.chronicle_id = v_chronicle_id
          AND clock.high_water > v_trusted_time
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D05',
            MESSAGE = 'Chronicle trusted clock moved backward';
    END IF;

    IF jsonb_typeof(v_reservation) NOT IN ('null', 'object') THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D08',
            MESSAGE = 'Chronicle capability reservation must be null or a closed object';
    END IF;

    v_capability_lease_id := NULL;
    v_capability_previous_generation := NULL;
    v_capability_committed_generation := NULL;
    IF jsonb_typeof(v_reservation) = 'object' THEN
        IF NOT v_reservation ?& ARRAY[
                'calls', 'capability_lease_id', 'cost_microunits',
                'expected_generation', 'tokens'
            ]
            OR v_reservation - ARRAY[
                'calls', 'capability_lease_id', 'cost_microunits',
                'expected_generation', 'tokens'
            ] <> '{}'::JSONB
            OR v_reservation->>'capability_lease_id' !~ v_identifier_pattern
            OR jsonb_typeof(v_reservation->'expected_generation') <> 'number'
            OR v_reservation->>'expected_generation' !~ '^[0-9]+$'
            OR jsonb_typeof(v_reservation->'calls') <> 'number'
            OR v_reservation->>'calls' !~ '^[0-9]+$'
            OR jsonb_typeof(v_reservation->'tokens') <> 'number'
            OR v_reservation->>'tokens' !~ '^[0-9]+$'
            OR jsonb_typeof(v_reservation->'cost_microunits') <> 'number'
            OR v_reservation->>'cost_microunits' !~ '^[0-9]+$'
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D08',
                MESSAGE = 'Chronicle capability reservation is not closed';
        END IF;
        BEGIN
            v_reservation_expected_generation :=
                (v_reservation->>'expected_generation')::BIGINT;
            v_reservation_calls := (v_reservation->>'calls')::BIGINT;
            v_reservation_tokens := (v_reservation->>'tokens')::BIGINT;
            v_reservation_cost := (v_reservation->>'cost_microunits')::BIGINT;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D08',
                MESSAGE = 'Chronicle capability reservation is outside the supported range';
        END;

        v_capability_lease_id := v_reservation->>'capability_lease_id';
        SELECT capability.*
        INTO v_capability
        FROM ops.chronicle_capability_state AS capability
        WHERE capability.capability_lease_id = v_capability_lease_id
        FOR UPDATE;

        IF NOT FOUND
            OR v_capability.identity_id <> v_identity->>'identity_id'
            OR v_capability.audience <> p_decision->>'audience'
            OR v_capability.runtime_installation_id
                <> v_installation->>'installation_id'
            OR v_capability.generation <> v_reservation_expected_generation
            OR v_capability.expires_at <= v_trusted_time
            OR v_capability.status <> 'active'
            OR v_capability.revoked_at IS NOT NULL
            OR v_reservation_calls > v_budget_max_calls
            OR v_reservation_tokens > v_budget_max_tokens
            OR v_reservation_cost > v_budget_max_cost
            OR v_capability.used_calls + v_reservation_calls
                > v_capability.max_calls
            OR v_capability.used_tokens + v_reservation_tokens
                > v_capability.max_tokens
            OR v_capability.used_cost_microunits + v_reservation_cost
                > v_capability.max_cost_microunits
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P2D08',
                MESSAGE = 'Chronicle capability budget reservation failed';
        END IF;

        v_capability_previous_generation := v_capability.generation;
        v_capability_committed_generation := v_capability.generation + 1;
        UPDATE ops.chronicle_capability_state AS capability
        SET generation = v_capability_committed_generation,
            last_call_index = capability.last_call_index + v_reservation_calls,
            used_calls = capability.used_calls + v_reservation_calls,
            used_tokens = capability.used_tokens + v_reservation_tokens,
            used_cost_microunits =
                capability.used_cost_microunits + v_reservation_cost,
            last_request_id = v_request_id,
            updated_at = v_trusted_time
        WHERE capability.capability_lease_id = v_capability_lease_id;
    END IF;

    -- Materialize the mechanical capability ledger from accepted canonical
    -- records in append order. Semantic authenticity remains platform-infra's
    -- reference/provider responsibility; these checks make replay, budgets,
    -- settlement, and revocation durable and non-bypassable at this boundary.
    FOR v_index IN 1..v_record_count LOOP
        IF p_record_kinds[v_index] NOT IN (
            'CapabilityLease',
            'CapabilityInvocation',
            'CapabilityRevocation'
        ) THEN
            CONTINUE;
        END IF;
        v_record_json := convert_from(
            p_canonical_record_bytes[v_index], 'UTF8'
        )::JSONB;

        IF p_record_kinds[v_index] = 'CapabilityLease' THEN
            IF v_record_json->>'status' IS DISTINCT FROM 'active'
                OR v_record_json->>'lease_id' !~ v_identifier_pattern
                OR v_record_json->>'issuer' !~ v_identifier_pattern
                OR v_record_json->>'nonce' !~ v_uuid_pattern
                OR v_record_json->>'capability_id' !~ v_identifier_pattern
                OR v_record_json->>'audience' !~ v_identifier_pattern
                OR v_record_json->>'runtime_attestation_hash'
                    !~ v_digest_pattern
                OR v_record_json->>'runtime_installation_id'
                    !~ v_identifier_pattern
                OR v_record_json->>'overlay_selection_hash'
                    !~ v_digest_pattern
                OR v_record_json->>'permitted_interface'
                    !~ v_identifier_pattern
                OR v_record_json->>'mode' NOT IN ('read', 'intent')
                OR v_record_json->>'revocation_identity'
                    !~ v_identifier_pattern
                OR v_record_json->'identity'
                    IS DISTINCT FROM (v_identity - 'constitution_hash')
                OR jsonb_typeof(v_record_json->'scope')
                    IS DISTINCT FROM 'object'
                OR jsonb_typeof(v_record_json->'release')
                    IS DISTINCT FROM 'object'
                OR jsonb_typeof(v_record_json->'budget')
                    IS DISTINCT FROM 'object'
                OR NOT v_record_json->'budget' ?& ARRAY[
                    'maximum_calls',
                    'maximum_cost_microunits',
                    'maximum_tokens'
                ]
                OR (v_record_json->'budget') - ARRAY[
                    'maximum_calls',
                    'maximum_cost_microunits',
                    'maximum_tokens'
                ] <> '{}'::JSONB
                OR jsonb_typeof(
                    v_record_json->'budget'->'maximum_calls'
                ) IS DISTINCT FROM 'number'
                OR v_record_json->'budget'->>'maximum_calls'
                    !~ '^[1-9][0-9]*$'
                OR jsonb_typeof(
                    v_record_json->'budget'->'maximum_tokens'
                ) IS DISTINCT FROM 'number'
                OR v_record_json->'budget'->>'maximum_tokens'
                    !~ '^[0-9]+$'
                OR jsonb_typeof(
                    v_record_json->'budget'->'maximum_cost_microunits'
                ) IS DISTINCT FROM 'number'
                OR v_record_json->'budget'->>'maximum_cost_microunits'
                    !~ '^[0-9]+$'
                OR NOT EXISTS (
                    SELECT 1
                    FROM jsonb_array_elements(
                        p_decision->'scope_bindings'
                    ) AS item
                    WHERE item->'scope' = v_record_json->'scope'
                      AND item->'record_hashes'
                            ? p_record_hashes[v_index]
                )
                OR NOT (
                    EXISTS (
                        SELECT 1
                        FROM ops.chronicle_records AS runtime
                        WHERE runtime.record_hash =
                                v_record_json->>'runtime_attestation_hash'
                          AND runtime.record_kind = 'RuntimeAttestation'
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM generate_series(1, v_index - 1) AS prior(index)
                        WHERE p_record_kinds[prior.index]
                                = 'RuntimeAttestation'
                          AND p_record_hashes[prior.index]
                                = v_record_json
                                    ->>'runtime_attestation_hash'
                    )
                )
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D08',
                    MESSAGE = 'Chronicle capability lease binding is invalid';
            END IF;

            BEGIN
                v_capability_calls := (
                    v_record_json->'budget'->>'maximum_calls'
                )::BIGINT;
                v_capability_tokens := (
                    v_record_json->'budget'->>'maximum_tokens'
                )::BIGINT;
                v_capability_cost := (
                    v_record_json->'budget'->>'maximum_cost_microunits'
                )::BIGINT;
                v_capability_started_at :=
                    (v_record_json->>'issued_at')::TIMESTAMPTZ;
                v_capability_recorded_at :=
                    (v_record_json->>'recorded_at')::TIMESTAMPTZ;
                v_capability_completed_at :=
                    (v_record_json->>'expires_at')::TIMESTAMPTZ;
            EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D08',
                    MESSAGE = 'Chronicle capability lease counters or times are invalid';
            END;
            IF v_capability_started_at > v_capability_recorded_at
                OR v_capability_recorded_at >= v_capability_completed_at
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D08',
                    MESSAGE = 'Chronicle capability lease chronology is invalid';
            END IF;

            v_capability_release_bytes := convert_to(
                ops.chronicle_canonical_json_text_v1(
                    v_record_json->'release'
                ),
                'UTF8'
            );
            v_capability_release_sha256 := 'sha256:' || encode(
                sha256(v_capability_release_bytes), 'hex'
            );
            IF EXISTS (
                SELECT 1
                FROM ops.chronicle_capability_state AS existing
                WHERE existing.capability_lease_id =
                        v_record_json->>'lease_id'
                   OR existing.lease_record_hash = p_record_hashes[v_index]
                   OR (
                       existing.issuer = v_record_json->>'issuer'
                       AND existing.issuer_nonce =
                            (v_record_json->>'nonce')::UUID
                   )
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D08',
                    MESSAGE = 'Chronicle capability lease id or issuer nonce was rebound';
            END IF;

            INSERT INTO ops.chronicle_capability_state (
                capability_lease_id,
                lease_record_hash,
                issuer,
                issuer_nonce,
                capability_id,
                identity_id,
                identity_revision,
                identity_epoch,
                audience,
                runtime_attestation_hash,
                runtime_installation_id,
                scope,
                release_bytes,
                release_sha256,
                overlay_selection_hash,
                permitted_interface,
                mode,
                revocation_identity,
                status,
                max_calls,
                max_tokens,
                max_cost_microunits,
                issued_at,
                recorded_at,
                expires_at,
                last_request_id,
                updated_at
            ) VALUES (
                v_record_json->>'lease_id',
                p_record_hashes[v_index],
                v_record_json->>'issuer',
                (v_record_json->>'nonce')::UUID,
                v_record_json->>'capability_id',
                v_record_json->'identity'->>'identity_id',
                (v_record_json->'identity'->>'identity_revision')::BIGINT,
                (v_record_json->'identity'->>'identity_epoch')::BIGINT,
                v_record_json->>'audience',
                v_record_json->>'runtime_attestation_hash',
                v_record_json->>'runtime_installation_id',
                v_record_json->'scope',
                v_capability_release_bytes,
                v_capability_release_sha256,
                v_record_json->>'overlay_selection_hash',
                v_record_json->>'permitted_interface',
                v_record_json->>'mode',
                v_record_json->>'revocation_identity',
                'active',
                v_capability_calls,
                v_capability_tokens,
                v_capability_cost,
                v_capability_started_at,
                v_capability_recorded_at,
                v_capability_completed_at,
                v_request_id,
                v_trusted_time
            );

        ELSIF p_record_kinds[v_index] = 'CapabilityRevocation' THEN
            IF v_record_json->>'revocation_id' !~ v_identifier_pattern
                OR v_record_json->>'target_revocation_identity'
                    !~ v_identifier_pattern
                OR v_record_json->>'overlay_selection_hash'
                    !~ v_digest_pattern
                OR v_record_json->'identity'
                    IS DISTINCT FROM (v_identity - 'constitution_hash')
                OR v_record_json->'provider_rejection_required'
                    IS DISTINCT FROM 'true'::JSONB
                OR v_record_json->>'reactive_profile_state'
                    IS DISTINCT FROM 'deactivated'
                OR v_record_json->'cordis_disposal_is_external_rollback'
                    IS DISTINCT FROM 'false'::JSONB
                OR jsonb_typeof(v_record_json->'release')
                    IS DISTINCT FROM 'object'
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D08',
                    MESSAGE = 'Chronicle capability revocation binding is invalid';
            END IF;
            v_capability_release_bytes := convert_to(
                ops.chronicle_canonical_json_text_v1(
                    v_record_json->'release'
                ),
                'UTF8'
            );
            v_capability_release_sha256 := 'sha256:' || encode(
                sha256(v_capability_release_bytes), 'hex'
            );
            BEGIN
                v_capability_effective_at :=
                    (v_record_json->>'effective_at')::TIMESTAMPTZ;
                v_capability_recorded_at :=
                    (v_record_json->>'recorded_at')::TIMESTAMPTZ;
            EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D08',
                    MESSAGE = 'Chronicle capability revocation time is invalid';
            END;
            IF v_capability_effective_at > v_capability_recorded_at THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D08',
                    MESSAGE = 'Chronicle capability revocation chronology is invalid';
            END IF;
            v_capability_revocation_cause_at := GREATEST(
                v_capability_effective_at,
                v_capability_recorded_at
            );

            SELECT capability.*
            INTO v_capability
            FROM ops.chronicle_capability_state AS capability
            WHERE capability.revocation_identity =
                    v_record_json->>'target_revocation_identity'
              AND capability.release_sha256 =
                    v_capability_release_sha256
              AND capability.release_bytes = v_capability_release_bytes
              AND capability.overlay_selection_hash =
                    v_record_json->>'overlay_selection_hash'
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D08',
                    MESSAGE = 'Chronicle capability revocation has no exact lease binding';
            END IF;

            INSERT INTO ops.chronicle_capability_revocations (
                revocation_id,
                capability_lease_id,
                target_revocation_identity,
                revocation_record_hash,
                release_sha256,
                overlay_selection_hash,
                effective_at,
                recorded_at,
                revocation_cause_at,
                provider_rejection_required,
                reactive_profile_state,
                cordis_disposal_is_external_rollback,
                request_id
            ) VALUES (
                v_record_json->>'revocation_id',
                v_capability.capability_lease_id,
                v_record_json->>'target_revocation_identity',
                p_record_hashes[v_index],
                v_capability_release_sha256,
                v_record_json->>'overlay_selection_hash',
                v_capability_effective_at,
                v_capability_recorded_at,
                v_capability_revocation_cause_at,
                TRUE,
                'deactivated',
                FALSE,
                v_request_id
            );

            UPDATE ops.chronicle_capability_state AS capability
            SET status = 'revoked',
                revoked_at = CASE
                    WHEN capability.revoked_at IS NULL THEN
                        v_capability_revocation_cause_at
                    ELSE LEAST(
                        capability.revoked_at,
                        v_capability_revocation_cause_at
                    )
                END,
                revocation_record_hash = CASE
                    WHEN capability.revoked_at IS NULL
                      OR v_capability_revocation_cause_at
                            < capability.revoked_at
                    THEN p_record_hashes[v_index]
                    ELSE capability.revocation_record_hash
                END,
                last_request_id = v_request_id,
                updated_at = v_trusted_time
            WHERE capability.capability_lease_id =
                    v_capability.capability_lease_id;

        ELSE
            v_capability_invocation_count :=
                v_capability_invocation_count + 1;
            v_capability_lease_hash :=
                v_record_json->>'capability_lease_hash';
            v_capability_usage := v_record_json->'settled_usage';
            v_capability_validations :=
                v_record_json->'provider_validations';

            IF v_record_json->>'invocation_id' !~ v_identifier_pattern
                OR v_record_json->>'call_nonce' !~ v_uuid_pattern
                OR v_capability_lease_hash !~ v_digest_pattern
                OR v_record_json->>'runtime_attestation_hash'
                    !~ v_digest_pattern
                OR v_record_json->'identity'
                    IS DISTINCT FROM (v_identity - 'constitution_hash')
                OR jsonb_typeof(v_capability_usage)
                    IS DISTINCT FROM 'object'
                OR NOT v_capability_usage ?& ARRAY[
                    'calls', 'cost_microunits', 'tokens'
                ]
                OR v_capability_usage - ARRAY[
                    'calls', 'cost_microunits', 'tokens'
                ] <> '{}'::JSONB
                OR v_capability_usage->>'calls' IS DISTINCT FROM '1'
                OR v_capability_usage->>'tokens' !~ '^[0-9]+$'
                OR v_capability_usage->>'cost_microunits' !~ '^[0-9]+$'
                OR v_record_json->>'call_index' !~ '^[1-9][0-9]*$'
                OR jsonb_typeof(v_capability_validations)
                    IS DISTINCT FROM 'array'
                OR jsonb_array_length(v_capability_validations)
                    NOT IN (1, 2)
                OR v_record_json->>'disposition'
                    NOT IN ('succeeded', 'rejected', 'expired', 'revoked')
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D08',
                    MESSAGE = 'Chronicle capability invocation mapping is invalid';
            END IF;

            SELECT capability.*
            INTO v_capability
            FROM ops.chronicle_capability_state AS capability
            WHERE capability.lease_record_hash = v_capability_lease_hash
            FOR UPDATE;
            IF NOT FOUND
                OR v_capability.identity_id
                    <> v_record_json->'identity'->>'identity_id'
                OR v_capability.identity_revision
                    <> (v_record_json->'identity'->>'identity_revision')::BIGINT
                OR v_capability.identity_epoch
                    <> (v_record_json->'identity'->>'identity_epoch')::BIGINT
                OR v_capability.runtime_attestation_hash
                    <> v_record_json->>'runtime_attestation_hash'
                OR v_capability.capability_id
                    <> v_record_json->>'capability_id'
                OR v_capability.permitted_interface
                    <> v_record_json->>'permitted_interface'
                OR v_capability.mode <> v_record_json->>'mode'
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D08',
                    MESSAGE = 'Chronicle invocation is not bound to its durable lease';
            END IF;

            BEGIN
                v_capability_call_index :=
                    (v_record_json->>'call_index')::BIGINT;
                v_capability_calls :=
                    (v_capability_usage->>'calls')::BIGINT;
                v_capability_tokens :=
                    (v_capability_usage->>'tokens')::BIGINT;
                v_capability_cost :=
                    (v_capability_usage->>'cost_microunits')::BIGINT;
                v_capability_started_at :=
                    (v_record_json->>'started_at')::TIMESTAMPTZ;
                v_capability_completed_at :=
                    (v_record_json->>'completed_at')::TIMESTAMPTZ;
                v_capability_recorded_at :=
                    (v_record_json->>'recorded_at')::TIMESTAMPTZ;
            EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D08',
                    MESSAGE = 'Chronicle invocation counters or times are invalid';
            END;

            v_capability_entry_result :=
                v_capability_validations->0->>'result';
            v_capability_before_return_result := CASE
                WHEN jsonb_array_length(v_capability_validations) = 2
                THEN v_capability_validations->1->>'result'
                ELSE NULL
            END;
            v_capability_reservation_candidate :=
                jsonb_typeof(v_reservation) = 'object'
                AND v_capability.capability_lease_id = v_capability_lease_id
                AND v_capability.generation = v_capability_committed_generation
                AND v_capability_call_index = v_capability.last_call_index
                AND v_capability_calls = v_reservation_calls
                AND v_capability_tokens = v_reservation_tokens
                AND v_capability_cost = v_reservation_cost;
            IF (
                    v_capability_reservation_candidate
                    AND v_capability_call_index <> v_capability.last_call_index
                )
                OR (
                    NOT v_capability_reservation_candidate
                    AND v_capability_call_index
                        <> v_capability.last_call_index + 1
                )
                OR (
                    NOT v_capability_reservation_candidate
                    AND v_capability.used_calls + v_capability_calls
                        > v_capability.max_calls
                )
                OR (
                    NOT v_capability_reservation_candidate
                    AND v_capability.used_tokens + v_capability_tokens
                        > v_capability.max_tokens
                )
                OR (
                    NOT v_capability_reservation_candidate
                    AND v_capability.used_cost_microunits + v_capability_cost
                        > v_capability.max_cost_microunits
                )
                OR v_capability_started_at > v_capability_completed_at
                OR v_capability_completed_at > v_capability_recorded_at
                OR v_capability_validations->0->>'phase'
                    IS DISTINCT FROM 'entry'
                OR v_capability_validations->0->>'lease_hash'
                    IS DISTINCT FROM v_capability_lease_hash
                OR v_capability_validations->0->>'attestation_hash'
                    IS DISTINCT FROM v_capability.runtime_attestation_hash
                OR (v_capability_validations->0->>'validated_at')::TIMESTAMPTZ
                    < v_capability_started_at
                OR (v_capability_validations->0->>'validated_at')::TIMESTAMPTZ
                    > v_capability_completed_at
                OR (
                    jsonb_array_length(v_capability_validations) = 2
                    AND (
                        v_capability_validations->1->>'phase'
                            IS DISTINCT FROM 'before_return'
                        OR v_capability_validations->1->>'lease_hash'
                            IS DISTINCT FROM v_capability_lease_hash
                        OR v_capability_validations->1->>'attestation_hash'
                            IS DISTINCT FROM
                                v_capability.runtime_attestation_hash
                        OR (v_capability_validations->1->>'validated_at')::TIMESTAMPTZ
                            < (v_capability_validations->0->>'validated_at')::TIMESTAMPTZ
                        OR (v_capability_validations->1->>'validated_at')::TIMESTAMPTZ
                            > v_capability_completed_at
                    )
                )
                OR (
                    v_record_json->>'disposition' = 'succeeded'
                    AND (
                        jsonb_array_length(v_capability_validations) <> 2
                        OR v_capability_entry_result <> 'accepted'
                        OR v_capability_before_return_result <> 'accepted'
                        OR jsonb_typeof(v_record_json->'result_hash')
                            IS DISTINCT FROM 'string'
                        OR v_record_json->>'result_hash' !~ v_digest_pattern
                        OR v_capability_completed_at >= v_capability.expires_at
                        OR (
                            v_capability.revoked_at IS NOT NULL
                            AND v_capability.revoked_at
                                <= v_capability_completed_at
                        )
                    )
                )
                OR (
                    v_record_json->>'disposition' = 'rejected'
                    AND (
                        jsonb_array_length(v_capability_validations) <> 1
                        OR v_capability_entry_result <> 'rejected'
                        OR jsonb_typeof(v_record_json->'result_hash')
                            IS DISTINCT FROM 'null'
                    )
                )
                OR (
                    v_record_json->>'disposition' = 'expired'
                    AND (
                        jsonb_array_length(v_capability_validations) <> 2
                        OR v_capability_entry_result <> 'accepted'
                        OR v_capability_before_return_result <> 'rejected'
                        OR jsonb_typeof(v_record_json->'result_hash')
                            IS DISTINCT FROM 'null'
                        OR v_capability_completed_at < v_capability.expires_at
                        OR (v_capability_validations->0->>'validated_at')::TIMESTAMPTZ
                            >= v_capability.expires_at
                        OR (v_capability_validations->1->>'validated_at')::TIMESTAMPTZ
                            < v_capability.expires_at
                    )
                )
                OR (
                    v_record_json->>'disposition' = 'revoked'
                    AND (
                        jsonb_array_length(v_capability_validations) <> 2
                        OR v_capability_entry_result <> 'accepted'
                        OR v_capability_before_return_result <> 'rejected'
                        OR jsonb_typeof(v_record_json->'result_hash')
                            IS DISTINCT FROM 'null'
                        OR v_capability.revoked_at IS NULL
                        OR v_capability_started_at >= v_capability.revoked_at
                        OR v_capability.revoked_at
                            > v_capability_completed_at
                        OR (v_capability_validations->0->>'validated_at')::TIMESTAMPTZ
                            >= v_capability.revoked_at
                        OR (v_capability_validations->1->>'validated_at')::TIMESTAMPTZ
                            < v_capability.revoked_at
                    )
                )
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D08',
                    MESSAGE = 'Chronicle invocation settlement or provider validation is invalid';
            END IF;

            IF v_capability_reservation_candidate
                AND v_capability_entry_result = 'accepted'
            THEN
                v_capability_reservation_match_count :=
                    v_capability_reservation_match_count + 1;
            ELSE
                UPDATE ops.chronicle_capability_state AS capability
                SET generation = capability.generation + 1,
                    last_call_index = v_capability_call_index,
                    used_calls = capability.used_calls + v_capability_calls,
                    used_tokens = capability.used_tokens + v_capability_tokens,
                    used_cost_microunits =
                        capability.used_cost_microunits + v_capability_cost,
                    last_request_id = v_request_id,
                    updated_at = v_trusted_time
                WHERE capability.capability_lease_id =
                        v_capability.capability_lease_id;
            END IF;

            INSERT INTO ops.chronicle_capability_invocations (
                invocation_id,
                invocation_record_hash,
                capability_lease_id,
                capability_lease_hash,
                call_nonce,
                call_index,
                runtime_attestation_hash,
                capability_id,
                permitted_interface,
                mode,
                disposition,
                settled_calls,
                settled_tokens,
                settled_cost_microunits,
                entry_result,
                before_return_result,
                started_at,
                completed_at,
                recorded_at,
                request_id
            ) VALUES (
                v_record_json->>'invocation_id',
                p_record_hashes[v_index],
                v_capability.capability_lease_id,
                v_capability_lease_hash,
                (v_record_json->>'call_nonce')::UUID,
                v_capability_call_index,
                v_record_json->>'runtime_attestation_hash',
                v_record_json->>'capability_id',
                v_record_json->>'permitted_interface',
                v_record_json->>'mode',
                v_record_json->>'disposition',
                v_capability_calls,
                v_capability_tokens,
                v_capability_cost,
                v_capability_entry_result,
                v_capability_before_return_result,
                v_capability_started_at,
                v_capability_completed_at,
                v_capability_recorded_at,
                v_request_id
            );
        END IF;
    END LOOP;

    IF jsonb_typeof(v_reservation) = 'object'
        AND v_capability_reservation_match_count <> 1
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D08',
            MESSAGE = 'Chronicle capability reservation is not bound to one committed invocation';
    END IF;

    IF jsonb_typeof(p_decision->'reasoning_cas_preconditions') <> 'array'
        OR jsonb_array_length(p_decision->'reasoning_cas_preconditions') > 6
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D07',
            MESSAGE = 'Chronicle reasoning CAS preconditions must be an array of at most six';
    END IF;
    v_cas_count := jsonb_array_length(p_decision->'reasoning_cas_preconditions');
    reasoning_cas_results := '[]'::JSONB;

    SELECT count(*)
    INTO v_transition_key_count
    FROM (
        SELECT
            record.value->'identity'->>'identity_id' AS identity_id,
            record.value->'scope'->>'scope_type' AS scope_type,
            record.value->'scope'->>'scope_id' AS scope_id
        FROM (
            SELECT convert_from(
                p_canonical_record_bytes[subscript.index], 'UTF8'
            )::JSONB AS value
            FROM generate_subscripts(p_record_hashes, 1) AS subscript(index)
            WHERE p_record_kinds[subscript.index] = 'ReasoningLease'
        ) AS record
        GROUP BY
            record.value->'identity'->>'identity_id',
            record.value->'scope'->>'scope_type',
            record.value->'scope'->>'scope_id'
    ) AS transition_key;

    IF v_transition_key_count <> v_cas_count
        OR EXISTS (
            SELECT 1
            FROM generate_subscripts(p_record_hashes, 1) AS subscript(index)
            WHERE p_record_kinds[subscript.index] = 'ReasoningLease'
              AND convert_from(
                  p_canonical_record_bytes[subscript.index], 'UTF8'
              )::JSONB->>'state'
                    NOT IN ('active', 'released', 'revoked', 'expired')
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D07',
            MESSAGE = 'Chronicle CAS keys must equal ReasoningLease transition keys';
    END IF;

    IF v_cas_count > 0 THEN
        FOR v_index IN 0..v_cas_count - 1 LOOP
            v_cas := (p_decision->'reasoning_cas_preconditions')->v_index;
            IF jsonb_typeof(v_cas) <> 'object'
                OR NOT v_cas ?& ARRAY[
                    'expected_active_reasoning_lease_hash',
                    'expected_generation', 'identity_id',
                    'scope_id', 'scope_type'
                ]
                OR v_cas - ARRAY[
                    'expected_active_reasoning_lease_hash',
                    'expected_generation', 'identity_id',
                    'scope_id', 'scope_type'
                ] <> '{}'::JSONB
                OR v_cas->>'identity_id' !~ v_identifier_pattern
                OR v_cas->>'scope_type'
                    NOT IN ('installation', 'incident', 'journey', 'task')
                OR v_cas->>'scope_id' !~ v_identifier_pattern
                OR jsonb_typeof(v_cas->'expected_generation') <> 'number'
                OR v_cas->>'expected_generation' !~ '^[0-9]+$'
                OR (
                    jsonb_typeof(
                        v_cas->'expected_active_reasoning_lease_hash'
                    ) <> 'null'
                    AND (
                        jsonb_typeof(
                            v_cas->'expected_active_reasoning_lease_hash'
                        ) <> 'string'
                        OR v_cas->>'expected_active_reasoning_lease_hash'
                            !~ v_digest_pattern
                    )
                )
                OR EXISTS (
                    SELECT 1
                    FROM jsonb_array_elements(
                        p_decision->'reasoning_cas_preconditions'
                    ) WITH ORDINALITY AS prior(value, ordinal)
                    WHERE prior.ordinal <= v_index
                      AND prior.value->>'identity_id' = v_cas->>'identity_id'
                      AND prior.value->>'scope_type' = v_cas->>'scope_type'
                      AND prior.value->>'scope_id' = v_cas->>'scope_id'
                )
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D07',
                    MESSAGE = 'Chronicle reasoning CAS precondition is not closed and unique';
            END IF;

            BEGIN
                v_expected_generation :=
                    (v_cas->>'expected_generation')::BIGINT;
            EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D07',
                    MESSAGE = 'Chronicle reasoning CAS generation is outside the supported range';
            END;
            v_expected_active_hash :=
                v_cas->>'expected_active_reasoning_lease_hash';

            SELECT
                count(*) FILTER (WHERE candidate.state = 'active'),
                min(candidate.index) FILTER (WHERE candidate.state = 'active'),
                count(*) FILTER (WHERE candidate.state <> 'active'),
                min(candidate.index) FILTER (WHERE candidate.state <> 'active')
            INTO
                v_target_count,
                v_target_index,
                v_terminal_count,
                v_terminal_index
            FROM (
                SELECT
                    subscript.index,
                    convert_from(
                        p_canonical_record_bytes[subscript.index], 'UTF8'
                    )::JSONB->>'state' AS state
                FROM generate_subscripts(p_record_hashes, 1)
                    AS subscript(index)
                WHERE p_record_kinds[subscript.index] = 'ReasoningLease'
                  AND convert_from(
                      p_canonical_record_bytes[subscript.index], 'UTF8'
                  )::JSONB->'identity'->>'identity_id'
                        = v_cas->>'identity_id'
                  AND convert_from(
                      p_canonical_record_bytes[subscript.index], 'UTF8'
                  )::JSONB->'scope'->>'scope_type'
                        = v_cas->>'scope_type'
                  AND convert_from(
                      p_canonical_record_bytes[subscript.index], 'UTF8'
                  )::JSONB->'scope'->>'scope_id'
                        = v_cas->>'scope_id'
            ) AS candidate;

            IF NOT (
                (v_target_count = 1 AND v_terminal_count IN (0, 1))
                OR (v_target_count = 0 AND v_terminal_count = 1)
            ) OR (
                v_target_count = 1
                AND v_expected_active_hash IS NOT NULL
                AND v_terminal_count <> 1
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D07',
                    MESSAGE = 'Chronicle reasoning CAS replacement requires its exact terminal record';
            END IF;

            v_terminal_hash := NULL;
            v_terminal_json := NULL;
            IF v_terminal_count = 1 THEN
                v_terminal_hash := p_record_hashes[v_terminal_index];
                v_terminal_json := convert_from(
                    p_canonical_record_bytes[v_terminal_index], 'UTF8'
                )::JSONB;
                IF jsonb_typeof(v_terminal_json->'generation')
                        IS DISTINCT FROM 'number'
                    OR v_terminal_json->>'generation' !~ '^[1-9][0-9]*$'
                    OR jsonb_typeof(
                        v_terminal_json->'expected_previous_generation'
                    ) IS DISTINCT FROM 'number'
                    OR v_terminal_json->>'expected_previous_generation'
                        !~ '^[0-9]+$'
                    OR jsonb_typeof(v_terminal_json->'lease_revision')
                        IS DISTINCT FROM 'number'
                    OR v_terminal_json->>'lease_revision' !~ '^[1-9][0-9]*$'
                THEN
                    RAISE EXCEPTION USING
                        ERRCODE = 'P2D07',
                        MESSAGE = 'Chronicle terminal reasoning lease counters are invalid';
                END IF;
                BEGIN
                    v_terminal_generation :=
                        (v_terminal_json->>'generation')::BIGINT;
                    v_terminal_expected_previous_generation :=
                        (v_terminal_json->>'expected_previous_generation')::BIGINT;
                    v_terminal_lease_revision :=
                        (v_terminal_json->>'lease_revision')::BIGINT;
                EXCEPTION WHEN OTHERS THEN
                    RAISE EXCEPTION USING
                        ERRCODE = 'P2D07',
                        MESSAGE = 'Chronicle terminal reasoning lease counters are outside the supported range';
                END;
                IF v_expected_active_hash IS NULL
                    OR v_expected_generation = 0
                    OR v_terminal_generation <> v_expected_generation
                    OR v_terminal_expected_previous_generation
                        <> v_expected_generation - 1
                    OR v_terminal_lease_revision <> 2
                    OR v_terminal_json->>'prior_lease_hash'
                        IS DISTINCT FROM v_expected_active_hash
                    OR (
                        SELECT count(*)
                        FROM jsonb_array_elements(
                            p_decision->'scope_bindings'
                        ) AS item
                        WHERE item->'scope'->>'scope_type'
                                = v_cas->>'scope_type'
                          AND item->'scope'->>'scope_id'
                                = v_cas->>'scope_id'
                          AND item->'record_hashes' ? v_terminal_hash
                    ) <> 1
                THEN
                    RAISE EXCEPTION USING
                        ERRCODE = 'P2D07',
                        MESSAGE = 'Chronicle terminal reasoning transition is invalid';
                END IF;
            END IF;

            IF v_target_count = 1 THEN
                v_target_hash := p_record_hashes[v_target_index];
                v_target_json := convert_from(
                    p_canonical_record_bytes[v_target_index], 'UTF8'
                )::JSONB;
                IF jsonb_typeof(v_target_json->'generation')
                        IS DISTINCT FROM 'number'
                    OR v_target_json->>'generation' !~ '^[1-9][0-9]*$'
                    OR jsonb_typeof(
                        v_target_json->'expected_previous_generation'
                    ) IS DISTINCT FROM 'number'
                    OR v_target_json->>'expected_previous_generation'
                        !~ '^[0-9]+$'
                    OR jsonb_typeof(v_target_json->'lease_revision')
                        IS DISTINCT FROM 'number'
                    OR v_target_json->>'lease_revision' !~ '^[1-9][0-9]*$'
                THEN
                    RAISE EXCEPTION USING
                        ERRCODE = 'P2D07',
                        MESSAGE = 'Chronicle active reasoning lease counters are invalid';
                END IF;
                BEGIN
                    v_target_generation :=
                        (v_target_json->>'generation')::BIGINT;
                    v_target_expected_previous_generation :=
                        (v_target_json->>'expected_previous_generation')::BIGINT;
                    v_target_lease_revision :=
                        (v_target_json->>'lease_revision')::BIGINT;
                EXCEPTION WHEN OTHERS THEN
                    RAISE EXCEPTION USING
                        ERRCODE = 'P2D07',
                        MESSAGE = 'Chronicle active reasoning lease counters are outside the supported range';
                END;
                IF v_target_generation <> v_expected_generation + 1
                    OR v_target_expected_previous_generation
                        <> v_expected_generation
                    OR v_target_lease_revision <> 1
                    OR jsonb_typeof(v_target_json->'prior_lease_hash')
                        IS DISTINCT FROM 'null'
                    OR (
                        v_terminal_count = 1
                        AND v_target_json->>'lease_id'
                            IS NOT DISTINCT FROM v_terminal_json->>'lease_id'
                    )
                    OR (
                        SELECT count(*)
                        FROM jsonb_array_elements(
                            p_decision->'scope_bindings'
                        ) AS item
                        WHERE item->'scope'->>'scope_type'
                                = v_cas->>'scope_type'
                          AND item->'scope'->>'scope_id'
                                = v_cas->>'scope_id'
                          AND item->'record_hashes' ? v_target_hash
                    ) <> 1
                THEN
                    RAISE EXCEPTION USING
                        ERRCODE = 'P2D07',
                        MESSAGE = 'Chronicle active reasoning target is invalid';
                END IF;

                IF v_terminal_count = 1 THEN
                    IF v_record_count <> 6
                        OR p_record_kinds IS DISTINCT FROM ARRAY[
                            'AgentHandoff',
                            'AgentEpisode',
                            'ReasoningLease',
                            'ReasoningLease',
                            'AgentEpisode',
                            'AgentHandoff'
                        ]::TEXT[]
                        OR v_terminal_index <> 3
                        OR v_target_index <> 4
                    THEN
                        RAISE EXCEPTION USING
                            ERRCODE = 'P2D07',
                            MESSAGE = 'Chronicle handoff transfer must use the exact ordered six-record transaction';
                    END IF;

                    v_transfer_pending_handoff := convert_from(
                        p_canonical_record_bytes[1], 'UTF8'
                    )::JSONB;
                    v_transfer_source_episode := convert_from(
                        p_canonical_record_bytes[2], 'UTF8'
                    )::JSONB;
                    v_transfer_target_episode := convert_from(
                        p_canonical_record_bytes[5], 'UTF8'
                    )::JSONB;
                    v_transfer_accepted_handoff := convert_from(
                        p_canonical_record_bytes[6], 'UTF8'
                    )::JSONB;

                    BEGIN
                        IF v_transfer_pending_handoff->>'handoff_revision'
                                IS DISTINCT FROM '1'
                            OR jsonb_typeof(
                                v_transfer_pending_handoff->'prior_handoff_hash'
                            ) IS DISTINCT FROM 'null'
                            OR v_transfer_pending_handoff
                                ->>'terminal_disposition'
                                IS DISTINCT FROM 'pending'
                            OR jsonb_typeof(
                                v_transfer_pending_handoff->'accepted_episode_id'
                            ) IS DISTINCT FROM 'null'
                            OR v_transfer_source_episode
                                ->>'terminal_disposition'
                                IS DISTINCT FROM 'handed_off'
                            OR v_transfer_source_episode->>'episode_id'
                                IS DISTINCT FROM v_transfer_pending_handoff
                                    ->>'source_episode_id'
                            OR v_transfer_source_episode
                                    ->>'reasoning_lease_hash'
                                IS DISTINCT FROM v_expected_active_hash
                            OR v_terminal_json->>'owner_episode_id'
                                IS DISTINCT FROM v_transfer_source_episode
                                    ->>'episode_id'
                            OR v_terminal_json->>'runtime_attestation_hash'
                                IS DISTINCT FROM v_transfer_source_episode
                                    ->>'runtime_attestation_hash'
                            OR v_terminal_json->>'embodiment'
                                IS DISTINCT FROM v_transfer_source_episode
                                    ->>'embodiment'
                            OR v_transfer_pending_handoff
                                    ->>'source_reasoning_lease_hash'
                                IS DISTINCT FROM v_expected_active_hash
                            OR v_target_json->>'owner_episode_id'
                                IS DISTINCT FROM v_transfer_target_episode
                                    ->>'episode_id'
                            OR v_transfer_target_episode->>'episode_revision'
                                IS DISTINCT FROM '1'
                            OR jsonb_typeof(
                                v_transfer_target_episode->'prior_episode_hash'
                            ) IS DISTINCT FROM 'null'
                            OR jsonb_typeof(
                                v_transfer_target_episode
                                    ->'terminal_disposition'
                            ) IS DISTINCT FROM 'null'
                            OR jsonb_typeof(
                                v_transfer_target_episode->'ended_at'
                            ) IS DISTINCT FROM 'null'
                            OR v_transfer_target_episode->>'parent_episode_id'
                                IS DISTINCT FROM v_transfer_source_episode
                                    ->>'episode_id'
                            OR v_transfer_target_episode->>'handoff_id'
                                IS DISTINCT FROM v_transfer_pending_handoff
                                    ->>'handoff_id'
                            OR v_transfer_target_episode
                                    ->>'reasoning_lease_hash'
                                IS DISTINCT FROM v_target_hash
                            OR v_transfer_target_episode
                                    ->>'runtime_attestation_hash'
                                IS DISTINCT FROM v_target_json
                                    ->>'runtime_attestation_hash'
                            OR v_transfer_target_episode->>'embodiment'
                                IS DISTINCT FROM v_target_json->>'embodiment'
                            OR v_transfer_pending_handoff->>'target_embodiment'
                                IS DISTINCT FROM v_target_json->>'embodiment'
                            OR v_transfer_pending_handoff
                                    ->>'target_installation_id'
                                IS DISTINCT FROM v_target_json
                                    ->>'runtime_installation_id'
                            OR v_transfer_accepted_handoff->>'handoff_id'
                                IS DISTINCT FROM v_transfer_pending_handoff
                                    ->>'handoff_id'
                            OR v_transfer_accepted_handoff
                                    ->>'handoff_revision'
                                IS DISTINCT FROM '2'
                            OR v_transfer_accepted_handoff
                                    ->>'prior_handoff_hash'
                                IS DISTINCT FROM p_record_hashes[1]
                            OR v_transfer_accepted_handoff
                                    ->>'terminal_disposition'
                                IS DISTINCT FROM 'accepted'
                            OR v_transfer_accepted_handoff
                                    ->>'accepted_episode_id'
                                IS DISTINCT FROM v_transfer_target_episode
                                    ->>'episode_id'
                            OR (
                                v_transfer_accepted_handoff - ARRAY[
                                    'accepted_episode_id',
                                    'handoff_revision',
                                    'prior_handoff_hash',
                                    'record_hash',
                                    'record_id',
                                    'recorded_at',
                                    'terminal_disposition'
                                ]::TEXT[]
                            ) IS DISTINCT FROM (
                                v_transfer_pending_handoff - ARRAY[
                                    'accepted_episode_id',
                                    'handoff_revision',
                                    'prior_handoff_hash',
                                    'record_hash',
                                    'record_id',
                                    'recorded_at',
                                    'terminal_disposition'
                                ]::TEXT[]
                            )
                            OR v_transfer_source_episode->'identity'
                                IS DISTINCT FROM v_terminal_json->'identity'
                            OR v_transfer_source_episode->'identity'
                                IS DISTINCT FROM v_target_json->'identity'
                            OR v_transfer_source_episode->'identity'
                                IS DISTINCT FROM v_transfer_target_episode
                                    ->'identity'
                            OR v_transfer_source_episode->'identity'
                                IS DISTINCT FROM v_transfer_pending_handoff
                                    ->'identity'
                            OR v_transfer_source_episode->'identity'
                                IS DISTINCT FROM v_transfer_accepted_handoff
                                    ->'identity'
                            OR v_transfer_source_episode->'scope'
                                IS DISTINCT FROM v_terminal_json->'scope'
                            OR v_transfer_source_episode->'scope'
                                IS DISTINCT FROM v_target_json->'scope'
                            OR v_transfer_source_episode->'scope'
                                IS DISTINCT FROM v_transfer_target_episode
                                    ->'scope'
                            OR (v_transfer_pending_handoff->>'issued_at')::TIMESTAMPTZ
                                > (v_transfer_source_episode->>'ended_at')::TIMESTAMPTZ
                            OR (v_transfer_pending_handoff->>'recorded_at')::TIMESTAMPTZ
                                > (v_transfer_source_episode->>'recorded_at')::TIMESTAMPTZ
                            OR (v_transfer_source_episode->>'recorded_at')::TIMESTAMPTZ
                                > (v_terminal_json->>'recorded_at')::TIMESTAMPTZ
                            OR (v_terminal_json->>'recorded_at')::TIMESTAMPTZ
                                > (v_target_json->>'recorded_at')::TIMESTAMPTZ
                            OR (v_target_json->>'recorded_at')::TIMESTAMPTZ
                                > (v_transfer_target_episode->>'recorded_at')::TIMESTAMPTZ
                            OR (v_transfer_target_episode->>'recorded_at')::TIMESTAMPTZ
                                > (v_transfer_accepted_handoff->>'recorded_at')::TIMESTAMPTZ
                            OR (v_transfer_accepted_handoff->>'recorded_at')::TIMESTAMPTZ
                                >= (v_transfer_pending_handoff->>'expires_at')::TIMESTAMPTZ
                        THEN
                            RAISE EXCEPTION USING
                                ERRCODE = 'P2D07',
                                MESSAGE = 'Chronicle six-record handoff binding or causal order is invalid';
                        END IF;
                    EXCEPTION
                        WHEN SQLSTATE 'P2D07' THEN
                            RAISE;
                        WHEN OTHERS THEN
                            RAISE EXCEPTION USING
                                ERRCODE = 'P2D07',
                                MESSAGE = 'Chronicle six-record handoff fields are invalid';
                    END;
                END IF;
                v_committed_generation := v_expected_generation + 1;
                v_committed_active_hash := v_target_hash;
            ELSE
                v_target_hash := NULL;
                v_committed_generation := v_expected_generation;
                v_committed_active_hash := NULL;
            END IF;

            INSERT INTO ops.chronicle_reasoning_leases (
                identity_id,
                scope_type,
                scope_id
            ) VALUES (
                v_cas->>'identity_id',
                v_cas->>'scope_type',
                v_cas->>'scope_id'
            )
            ON CONFLICT (identity_id, scope_type, scope_id) DO NOTHING;

            SELECT lease.*
            INTO v_lease
            FROM ops.chronicle_reasoning_leases AS lease
            WHERE lease.identity_id = v_cas->>'identity_id'
              AND lease.scope_type = v_cas->>'scope_type'
              AND lease.scope_id = v_cas->>'scope_id'
            FOR UPDATE;

            IF v_lease.generation <> v_expected_generation
                OR v_lease.active_reasoning_lease_hash
                    IS DISTINCT FROM v_expected_active_hash
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'P2D07',
                    MESSAGE = 'Chronicle reasoning lease compare-and-swap failed';
            END IF;

            UPDATE ops.chronicle_reasoning_leases AS lease
            SET generation = v_committed_generation,
                active_reasoning_lease_hash = v_committed_active_hash,
                last_request_id = v_request_id,
                updated_at = v_trusted_time
            WHERE lease.identity_id = v_cas->>'identity_id'
              AND lease.scope_type = v_cas->>'scope_type'
              AND lease.scope_id = v_cas->>'scope_id';

            reasoning_cas_results := reasoning_cas_results || jsonb_build_array(
                jsonb_build_object(
                    'identity_id', v_cas->>'identity_id',
                    'scope_type', v_cas->>'scope_type',
                    'scope_id', v_cas->>'scope_id',
                    'previous_generation', v_expected_generation,
                    'committed_generation', v_committed_generation,
                    'previous_active_reasoning_lease_hash',
                        v_expected_active_hash,
                    'committed_active_reasoning_lease_hash',
                        v_committed_active_hash
                )
            );
        END LOOP;
    END IF;

    v_first_append_sequence := v_append_state.chronicle_watermark + 1;
    v_last_append_sequence :=
        v_append_state.chronicle_watermark + v_record_count;
    chronicle_watermark := v_last_append_sequence;
    audit_outbox_watermark := v_append_state.audit_outbox_watermark + 1;

    UPDATE ops.chronicle_append_state AS state
    SET chronicle_watermark = v_last_append_sequence,
        audit_outbox_watermark = chronicle_test_append_v1.audit_outbox_watermark,
        last_request_digest = v_request_digest,
        updated_at = v_trusted_time
    WHERE state.chronicle_id = v_chronicle_id;

    INSERT INTO ops.chronicle_trusted_clock (
        chronicle_id,
        high_water,
        last_request_id,
        updated_at
    ) VALUES (
        v_chronicle_id,
        v_trusted_time,
        v_request_id,
        v_trusted_time
    )
    ON CONFLICT (chronicle_id) DO UPDATE
    SET high_water = EXCLUDED.high_water,
        last_request_id = EXCLUDED.last_request_id,
        updated_at = EXCLUDED.updated_at;

    UPDATE ops.chronicle_replay_sequences AS replay
    SET last_writer_sequence = v_writer_sequence,
        last_envelope_hash = v_request_digest,
        last_request_id = v_request_id,
        updated_at = v_trusted_time
    WHERE replay.writer_id = p_decision->>'writer_id'
      AND replay.writer_key_id = p_decision->>'writer_key_id';

    INSERT INTO ops.chronicle_replay_request_claims (
        request_id,
        request_digest,
        chronicle_id,
        writer_id,
        writer_key_id,
        request_nonce,
        claim_source,
        claimed_at
    ) VALUES (
        v_request_id,
        v_request_digest,
        v_chronicle_id,
        p_decision->>'writer_id',
        p_decision->>'writer_key_id',
        v_request_nonce,
        'committed',
        v_trusted_time
    );

    INSERT INTO ops.chronicle_replay_nonce_claims (
        writer_id,
        request_nonce,
        request_digest,
        chronicle_id,
        writer_key_id,
        request_id,
        claim_source,
        claimed_at
    ) VALUES (
        p_decision->>'writer_id',
        v_request_nonce,
        v_request_digest,
        v_chronicle_id,
        p_decision->>'writer_key_id',
        v_request_id,
        'committed',
        v_trusted_time
    );

    INSERT INTO ops.chronicle_replay_nonces (
        writer_id,
        writer_key_id,
        request_nonce,
        writer_sequence,
        request_id,
        request_digest,
        accepted_at
    ) VALUES (
        p_decision->>'writer_id',
        p_decision->>'writer_key_id',
        v_request_nonce,
        v_writer_sequence,
        v_request_id,
        v_request_digest,
        v_trusted_time
    );

    INSERT INTO ops.chronicle_append_requests (
        request_id,
        api_version,
        kind,
        request_nonce,
        writer_sequence,
        previous_envelope_hash,
        submitted_at,
        expires_at,
        trusted_time,
        chronicle_id,
        identity_id,
        identity_revision,
        identity_epoch,
        constitution_hash,
        audience,
        installation_id,
        embodiment,
        host_class,
        writer_id,
        writer_key_id,
        writer_runtime_attestation_hash,
        writer_session_id,
        source_attestation_hash,
        interface_id,
        mode,
        maximum_calls,
        maximum_tokens,
        maximum_cost_microunits,
        evidence_count,
        authority_effect,
        request_digest,
        signature_bundle_hash,
        canonical_envelope_bytes,
        canonical_envelope_sha256,
        binding_id,
        capability_lease_id,
        capability_previous_generation,
        capability_committed_generation,
        chronicle_watermark,
        first_append_sequence,
        last_append_sequence,
        audit_outbox_watermark,
        record_count,
        committed_at
    ) VALUES (
        v_request_id,
        v_api_version,
        'ChronicleAppendEnvelope',
        v_request_nonce,
        v_writer_sequence,
        v_previous_envelope_hash,
        v_submitted_at,
        v_expires_at,
        v_trusted_time,
        v_chronicle_id,
        v_identity->>'identity_id',
        (v_identity->>'identity_revision')::BIGINT,
        (v_identity->>'identity_epoch')::BIGINT,
        v_identity->>'constitution_hash',
        p_decision->>'audience',
        v_installation->>'installation_id',
        v_installation->>'embodiment',
        v_installation->>'host_class',
        p_decision->>'writer_id',
        p_decision->>'writer_key_id',
        p_decision->>'writer_runtime_attestation_hash',
        v_writer_session_id,
        p_decision->>'source_attestation_hash',
        p_decision->>'interface_id',
        p_decision->>'mode',
        v_budget_max_calls,
        v_budget_max_tokens,
        v_budget_max_cost,
        v_evidence_count,
        p_decision->>'authority_effect',
        v_request_digest,
        p_decision->>'signature_bundle_hash',
        v_canonical_envelope_bytes,
        v_canonical_envelope_sha256,
        v_binding.binding_id,
        v_capability_lease_id,
        v_capability_previous_generation,
        v_capability_committed_generation,
        chronicle_test_append_v1.chronicle_watermark,
        v_first_append_sequence,
        v_last_append_sequence,
        chronicle_test_append_v1.audit_outbox_watermark,
        v_record_count,
        v_trusted_time
    );

    record_commits := '[]'::JSONB;
    FOR v_index IN 1..v_record_count LOOP
        v_record_binding := (p_decision->'record_bindings')->(v_index - 1);
        INSERT INTO ops.chronicle_records (
            record_hash,
            record_id,
            record_kind,
            record_api_version,
            logical_id,
            logical_revision,
            prior_record_hash,
            canonical_record_bytes,
            canonical_bytes_sha256,
            request_id,
            chronicle_id,
            chronicle_watermark,
            append_sequence,
            batch_ordinal,
            committed_at
        ) VALUES (
            p_record_hashes[v_index],
            p_record_ids[v_index]::UUID,
            p_record_kinds[v_index],
            v_record_api_version,
            v_record_binding->>'logical_id',
            (v_record_binding->>'logical_revision')::BIGINT,
            v_record_binding->>'prior_record_hash',
            p_canonical_record_bytes[v_index],
            v_record_binding->>'canonical_bytes_sha256',
            v_request_id,
            v_chronicle_id,
            chronicle_test_append_v1.chronicle_watermark,
            v_first_append_sequence + v_index - 1,
            v_index,
            v_trusted_time
        );

        record_commits := record_commits || jsonb_build_array(
            jsonb_build_object(
                'record_id', p_record_ids[v_index],
                'record_kind', p_record_kinds[v_index],
                'record_hash', p_record_hashes[v_index],
                'append_sequence', v_first_append_sequence + v_index - 1
            )
        );
    END LOOP;

    FOR v_index IN 0..v_evidence_count - 1 LOOP
        INSERT INTO ops.chronicle_append_request_evidence (
            request_id,
            evidence_hash,
            ordinal
        ) VALUES (
            v_request_id,
            (p_decision->'evidence_hashes')->>v_index,
            v_index + 1
        );
    END LOOP;

    FOR v_index IN 0..v_scope_count - 1 LOOP
        v_scope_binding := (p_decision->'scope_bindings')->v_index;
        v_scope := v_scope_binding->'scope';
        INSERT INTO ops.chronicle_append_scopes (
            request_id,
            ordinal,
            scope_type,
            scope_id,
            installation_id,
            resource_type,
            resource_id
        ) VALUES (
            v_request_id,
            v_index + 1,
            v_scope->>'scope_type',
            v_scope->>'scope_id',
            v_scope->>'installation_id',
            v_scope->>'resource_type',
            v_scope->>'resource_id'
        );

        v_inner_index := 0;
        FOR v_runtime_hash IN
            SELECT value
            FROM jsonb_array_elements_text(
                v_scope_binding->'runtime_attestation_hashes'
            )
        LOOP
            v_inner_index := v_inner_index + 1;
            INSERT INTO ops.chronicle_append_scope_runtime_attestations (
                request_id,
                scope_ordinal,
                runtime_attestation_hash,
                ordinal
            ) VALUES (
                v_request_id,
                v_index + 1,
                v_runtime_hash,
                v_inner_index
            );
        END LOOP;

        v_inner_index := 0;
        FOR v_record_hash IN
            SELECT value
            FROM jsonb_array_elements_text(v_scope_binding->'record_hashes')
        LOOP
            v_inner_index := v_inner_index + 1;
            INSERT INTO ops.chronicle_append_scope_records (
                request_id,
                scope_ordinal,
                record_hash,
                ordinal
            ) VALUES (
                v_request_id,
                v_index + 1,
                v_record_hash,
                v_inner_index
            );
        END LOOP;
    END LOOP;

    IF v_cas_count > 0 THEN
        FOR v_index IN 0..v_cas_count - 1 LOOP
            v_cas := reasoning_cas_results->v_index;
            INSERT INTO ops.chronicle_append_request_reasoning_cas (
                request_id,
                ordinal,
                identity_id,
                scope_type,
                scope_id,
                previous_generation,
                previous_active_reasoning_lease_hash,
                committed_generation,
                committed_active_reasoning_lease_hash
            ) VALUES (
                v_request_id,
                v_index + 1,
                v_cas->>'identity_id',
                v_cas->>'scope_type',
                v_cas->>'scope_id',
                (v_cas->>'previous_generation')::BIGINT,
                v_cas->>'previous_active_reasoning_lease_hash',
                (v_cas->>'committed_generation')::BIGINT,
                v_cas->>'committed_active_reasoning_lease_hash'
            );
        END LOOP;
    END IF;

    INSERT INTO ops.chronicle_outbox (
        outbox_id,
        request_id,
        chronicle_id,
        audit_outbox_watermark,
        projection_name,
        request_digest,
        authority_effect,
        outbox_intent_bytes,
        outbox_intent_sha256,
        created_at
    ) VALUES (
        v_outbox_id,
        v_request_id,
        v_chronicle_id,
        chronicle_test_append_v1.audit_outbox_watermark,
        v_outbox->>'projection_name',
        v_outbox->>'request_digest',
        v_outbox->>'authority_effect',
        p_outbox_intent_bytes,
        'sha256:' || encode(sha256(p_outbox_intent_bytes), 'hex'),
        v_trusted_time
    );

    INSERT INTO ops.chronicle_outbox_delivery_state (outbox_id)
    VALUES (v_outbox_id);

    IF jsonb_array_length(record_commits) <> v_record_count
        OR jsonb_array_length(reasoning_cas_results) <> v_cas_count
        OR NOT EXISTS (
            SELECT 1
            FROM jsonb_to_recordset(record_commits) AS committed(
                append_sequence BIGINT
            )
            HAVING count(*) = v_record_count
               AND min(committed.append_sequence) = v_first_append_sequence
               AND max(committed.append_sequence) = v_last_append_sequence
               AND max(committed.append_sequence)
                    - min(committed.append_sequence) + 1 = count(*)
               AND max(committed.append_sequence)
                    = chronicle_test_append_v1.chronicle_watermark
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P2D06',
            MESSAGE = 'Chronicle commit result cardinality or sequence is invalid';
    END IF;

    request_id := v_request_id::TEXT;
    RETURN NEXT;
END
$chronicle_test_append$;

REVOKE ALL PRIVILEGES ON FUNCTION ops.chronicle_test_append_v1(
    JSONB,
    TEXT[],
    TEXT[],
    TEXT[],
    BYTEA[],
    BYTEA
) FROM PUBLIC, dash_ops_reader, dash_ops_indexer, dockhand_ops_writer,
    dash_api_runtime;

GRANT EXECUTE ON FUNCTION ops.chronicle_test_append_v1(
    JSONB,
    TEXT[],
    TEXT[],
    TEXT[],
    BYTEA[],
    BYTEA
) TO dockhand_ops_writer;

REVOKE ALL PRIVILEGES ON FUNCTION ops.chronicle_test_resolve_request_v1(
    TEXT,
    TEXT,
    TEXT,
    UUID,
    UUID
) FROM PUBLIC, dash_ops_reader, dash_ops_indexer, dockhand_ops_writer,
    dash_api_runtime;

GRANT EXECUTE ON FUNCTION ops.chronicle_test_resolve_request_v1(
    TEXT,
    TEXT,
    TEXT,
    UUID,
    UUID
) TO dockhand_ops_writer;

REVOKE ALL PRIVILEGES ON FUNCTION ops.chronicle_test_record_rejection_v1(
    TEXT,
    TEXT,
    TEXT,
    UUID,
    UUID,
    TEXT,
    TEXT,
    TIMESTAMPTZ,
    BOOLEAN
) FROM PUBLIC, dash_ops_reader, dash_ops_indexer, dockhand_ops_writer,
    dash_api_runtime;

GRANT EXECUTE ON FUNCTION ops.chronicle_test_record_rejection_v1(
    TEXT,
    TEXT,
    TEXT,
    UUID,
    UUID,
    TEXT,
    TEXT,
    TIMESTAMPTZ,
    BOOLEAN
) TO dockhand_ops_writer;

DO $chronicle_candidate_relation_denials$
DECLARE
    relation RECORD;
BEGIN
    FOR relation IN
        SELECT class.relname AS relation_name
        FROM pg_class AS class
        JOIN pg_namespace AS namespace
            ON namespace.oid = class.relnamespace
        WHERE namespace.nspname = 'ops'
          AND class.relname LIKE 'chronicle\_%' ESCAPE '\'
          AND class.relkind IN ('r', 'p', 'v', 'm', 'S')
    LOOP
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON ops.%I '
            'FROM dash_ops_reader, dash_ops_indexer, '
            'dockhand_ops_writer, dash_api_runtime',
            relation.relation_name
        );
    END LOOP;
END
$chronicle_candidate_relation_denials$;

GRANT SELECT ON ops.chronicle_audit_projection_v1
    TO dockhand_ops_writer, dash_ops_reader;

COMMENT ON TABLE ops.chronicle_candidate_gate IS
    'Owner-only, default-false enable gate for the unregistered test candidate.';
COMMENT ON FUNCTION ops.chronicle_test_append_v1(
    JSONB,
    TEXT[],
    TEXT[],
    TEXT[],
    BYTEA[],
    BYTEA
) IS
    'Default-disabled test-only atomic Chronicle v1 append/CAS/outbox boundary; not a deployment authorization.';
COMMENT ON FUNCTION ops.chronicle_test_resolve_request_v1(
    TEXT,
    TEXT,
    TEXT,
    UUID,
    UUID
) IS
    'Default-disabled exact durable replay resolver for committed, rejected, and partial-collision state.';
COMMENT ON FUNCTION ops.chronicle_test_record_rejection_v1(
    TEXT,
    TEXT,
    TEXT,
    UUID,
    UUID,
    TEXT,
    TEXT,
    TIMESTAMPTZ,
    BOOLEAN
) IS
    'Default-disabled immutable non-evidence rejection recorder; reserves every unclaimed request-id and writer nonce without Chronicle writes.';
