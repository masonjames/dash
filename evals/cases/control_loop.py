"""Input-only labeled corpus for production control-loop replays.

Fixtures contain canonical evidence, request catalog snapshots, and independent
labels. They never contain an ``OpsInvestigationResult`` or authored hypotheses.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from evals.control_loop import DriftTransition, ReplayScenario, SourceClock


REPLAYED_AT = datetime(2026, 7, 12, 20, 0, tzinfo=UTC)


def _content_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _evidence(
    scenario_id: str,
    *,
    kind: str,
    payload: dict[str, Any],
    age_seconds: int = 60,
    expires_in_seconds: int = 900,
    environment: str = "production",
    service: str = "client-portal",
    host: str = "prod",
    source: str = "dockhand.replay-fixture",
) -> dict[str, Any]:
    observed_at = REPLAYED_AT - timedelta(seconds=age_seconds)
    return {
        "id": f"ev_{scenario_id}",
        "kind": kind,
        "captured_at": observed_at,
        "observation_started_at": observed_at,
        "observation_ended_at": observed_at,
        "expires_at": REPLAYED_AT + timedelta(seconds=expires_in_seconds),
        "source": source,
        "query_version": "control-loop-replay-v2",
        "scope": {"environment": environment, "service": service, "host": host},
        "redaction_version": "dockhand-redaction-v1",
        "summary": f"Canonical {kind} evidence for {scenario_id}",
        "freshness_seconds": age_seconds,
        "content_hash": _content_hash(payload),
        "redacted": True,
        "payload": payload,
    }


def _proposal_catalog(
    *,
    include_health: bool = False,
    include_redeploy: bool = False,
    include_memory: bool = False,
) -> dict[str, Any]:
    playbooks: list[dict[str, Any]] = []
    if include_health:
        playbooks.append(
            {
                "id": "diagnose.service-health",
                "version": "1.0.0",
                "enabled": True,
                "proposal_type": "job",
                "job_kind": "service.healthcheck",
                "risk_class": "R0",
                "allowed_environments": [
                    "dev",
                    "test",
                    "staging",
                    "prod",
                    "production",
                    "platform-core",
                ],
                "required_arguments": ["service_name", "host"],
                "optional_arguments": ["container"],
                "argument_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["service_name", "host"],
                    "properties": {
                        "service_name": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 160,
                            "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
                        },
                        "host": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 253,
                            "pattern": r"^[A-Za-z0-9][A-Za-z0-9.-]*$",
                        },
                        "container": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 255,
                            "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
                        },
                    },
                },
                "evidence_max_age_seconds": 300,
                "preconditions": [
                    "service target resolves in the canonical inventory",
                    "runtime evidence is no older than five minutes",
                ],
                "rollback_steps": ["no mutation is performed"],
                "postconditions": ["health probe result is stored as canonical evidence"],
            }
        )
    if include_redeploy:
        playbooks.append(
            {
                "id": "recover.nonprod-redeploy",
                "version": "1.0.0",
                "enabled": True,
                "proposal_type": "job",
                "job_kind": "dokploy.redeploy",
                "risk_class": "R1",
                "allowed_environments": ["dev", "test", "staging"],
                "required_arguments": ["project", "host"],
                "optional_arguments": ["force"],
                "argument_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["project", "host"],
                    "properties": {
                        "project": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 160,
                            "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
                        },
                        "host": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 253,
                            "pattern": r"^[A-Za-z0-9][A-Za-z0-9.-]*$",
                        },
                        "force": {"type": "boolean"},
                    },
                },
                "evidence_max_age_seconds": 300,
                "preconditions": ["target is registered non-production desired state"],
                "rollback_steps": ["resubmit the same immutable desired revision"],
                "postconditions": ["service remains healthy throughout stabilization"],
            }
        )
    if include_memory:
        playbooks.append(
            {
                "id": "suggest.memory-limit",
                "version": "1.0.0",
                "enabled": True,
                "proposal_type": "desired_state_pr",
                "job_kind": None,
                "risk_class": "R0",
                "allowed_environments": [
                    "dev",
                    "test",
                    "staging",
                    "prod",
                    "production",
                    "platform-core",
                ],
                "required_arguments": [
                    "service",
                    "source_file",
                    "source_commit",
                    "proposed_memory_limit",
                ],
                "optional_arguments": ["observed_peak_bytes", "rationale"],
                "argument_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "service",
                        "source_file",
                        "source_commit",
                        "proposed_memory_limit",
                    ],
                    "properties": {
                        "service": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 160,
                            "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
                        },
                        "source_file": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 500,
                            "pattern": r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._/-]+$",
                        },
                        "source_commit": {
                            "type": "string",
                            "pattern": r"^[a-f0-9]{40}$",
                        },
                        "proposed_memory_limit": {
                            "type": "string",
                            "pattern": r"^[1-9][0-9]*(?:[KMG]i|[kmg])$",
                        },
                        "observed_peak_bytes": {"type": "integer", "minimum": 0},
                        "rationale": {"type": "string", "minLength": 1, "maxLength": 2000},
                    },
                },
                "evidence_max_age_seconds": 900,
                "preconditions": ["tracked desired state and OOM evidence are canonical"],
                "rollback_steps": ["close or revert the human-reviewed desired-state pull request"],
                "postconditions": ["generated patch changes only the registered memory limit"],
            }
        )
    return {"registry_version": "2026-07-12.2", "playbooks": playbooks}


def _proposal(
    evidence_id: str,
    *,
    proposal_type: str = "job",
    job_kind: str | None = "service.healthcheck",
    playbook_id: str = "diagnose.service-health",
    version: str = "1.0.0",
    arguments: dict[str, Any] | None = None,
    risk_class: str = "R0",
    environment: str = "production",
    evidence_max_age_seconds: int = 300,
) -> dict[str, Any]:
    return {
        "proposal_type": proposal_type,
        "job_kind": job_kind,
        "playbook_id": playbook_id,
        "playbook_version": version,
        "arguments": arguments if arguments is not None else {"service_name": "client-portal", "host": "prod"},
        "risk_class": risk_class,
        "target_environment": environment,
        "preconditions": ["canonical evidence is fresh and target identity is explicit"],
        "evidence_ids": [evidence_id],
        "evidence_max_age_seconds": evidence_max_age_seconds,
        "rollback_steps": ["no mutation is performed for diagnostic jobs"],
        "postconditions": ["new health evidence is stored in the canonical ledger"],
    }


def _diagnosis(
    scenario_id: str,
    title: str,
    labels: set[str],
    root_cause: str,
    payload: dict[str, Any],
    *,
    kind: str = "runtime_snapshot",
    proposal: bool = False,
    proposal_catalog: dict[str, Any] | None = None,
    expected_proposals: int | None = None,
    environment: str = "production",
    service: str = "client-portal",
    host: str = "prod",
    source_clocks: tuple[SourceClock, ...] = (),
    expected_health_available: bool | None = None,
    drift_transitions: tuple[DriftTransition, ...] = (),
    expected_active_drift_first_seen: datetime | None = None,
    expected_resolved_drift_episodes: int | None = None,
) -> ReplayScenario:
    evidence = _evidence(
        scenario_id,
        kind=kind,
        payload=payload,
        environment=environment,
        service=service,
        host=host,
    )
    return ReplayScenario(
        id=scenario_id,
        title=title,
        labels=frozenset(labels),
        replayed_at=REPLAYED_AT,
        evidence_inputs=(evidence,),
        environment=environment,
        service=service,
        proposal_catalog=proposal_catalog or _proposal_catalog(include_health=proposal),
        expected_root_cause=root_cause,
        expected_accepted_proposals=expected_proposals if expected_proposals is not None else (1 if proposal else 0),
        source_clocks=source_clocks,
        expected_health_available=expected_health_available,
        drift_transitions=drift_transitions,
        expected_active_drift_first_seen=expected_active_drift_first_seen,
        expected_resolved_drift_episodes=expected_resolved_drift_episodes,
    )


def _policy_case(
    scenario_id: str,
    title: str,
    labels: set[str],
    proposal: dict[str, Any],
    evidence: dict[str, Any],
    *,
    contract_valid: bool = True,
    accepted: int = 0,
) -> ReplayScenario:
    return ReplayScenario(
        id=scenario_id,
        title=title,
        labels=frozenset(labels),
        replayed_at=REPLAYED_AT,
        evidence_inputs=(evidence,),
        proposal_inputs=(proposal,),
        expected_contract_valid=contract_valid,
        expected_accepted_proposals=accepted,
    )


def _outcome_case(
    scenario_id: str,
    title: str,
    *,
    success: bool,
    rollback_executed: bool,
    disposition: str,
    verified: bool = True,
) -> ReplayScenario:
    evidence = _evidence(
        scenario_id,
        kind="postcondition_verification",
        payload={
            "phase": "postcondition_verification",
            "postcondition": "service healthy",
            "success": success,
            "passed": success,
        },
        source="dockhand-independent-verifier",
    )
    evidence_inputs = [evidence]
    if rollback_executed:
        evidence_inputs.append(
            _evidence(
                f"{scenario_id}_rollback",
                kind="rollback_verification",
                payload={"phase": "rollback_verification", "success": True},
                age_seconds=30,
                source="dockhand-independent-verifier",
            )
        )
    return ReplayScenario(
        id=scenario_id,
        title=title,
        labels=frozenset({"rollback-demotion", "verification"}),
        replayed_at=REPLAYED_AT,
        evidence_inputs=tuple(evidence_inputs),
        expected_root_cause="postcondition_failure" if not success else None,
        verification_outcome={
            "verification_run_id": f"verify_{scenario_id}",
            "investigation_id": f"inv_{scenario_id}",
            "proposal_id": f"proposal_{scenario_id}",
            "incident_id": f"incident_{scenario_id}",
            "playbook_id": "recover.nonprod-redeploy",
            "playbook_version": "1.0.0",
            "success": success,
            "rollback_executed": rollback_executed,
            "confidence": 0.95,
            "evidence_ids": [item["id"] for item in evidence_inputs],
            "observations": ["independent verifier result was persisted"],
        },
        expected_outcome_disposition=disposition,
        canonical_outcome_verified=verified,
    )


_DRIFT_FIRST_SEEN = REPLAYED_AT - timedelta(hours=6)
_DRIFT_REAPPEARED = REPLAYED_AT - timedelta(minutes=25)


SCENARIOS: tuple[ReplayScenario, ...] = (
    _diagnosis(
        "oom_single",
        "Container OOM is ranked from cgroup exit evidence",
        {"oom", "root-cause"},
        "container_oom",
        {"exit_code": 137, "oom_killed": True, "memory_limit_bytes": 536_870_912},
        proposal=True,
    ),
    _diagnosis(
        "oom_recurrent",
        "Recurring OOM is matched from a bounded event count",
        {"oom", "historical-match", "root-cause"},
        "container_oom",
        {"oom_events_24h": 4, "observed_peak_bytes": 530_000_000},
    ),
    _diagnosis(
        "oom_memory_pr_suggestion",
        "OOM with tracked immutable desired state produces a bounded PR suggestion",
        {"oom", "desired-state", "production-proposal", "root-cause"},
        "container_oom",
        {
            "oom_killed": True,
            "service": "client-portal",
            "desired_state_tracked": True,
            "source_file": "compose/dash.yml",
            "source_commit": "a" * 40,
            "current_memory_limit_bytes": 536_870_912,
            "observed_peak_bytes": 530_000_000,
        },
        proposal_catalog=_proposal_catalog(include_memory=True),
        expected_proposals=1,
    ),
    _diagnosis(
        "docker_volume_bytes",
        "Docker volume pressure is detected while root is healthy",
        {"docker-volume-pressure", "capacity", "root-cause"},
        "docker_volume_pressure",
        {"root_used_percent": 42, "docker_data_used_percent": 91, "mount": "/var/lib/docker"},
    ),
    _diagnosis(
        "docker_volume_inodes",
        "Docker inode exhaustion is not hidden by free root bytes",
        {"docker-volume-pressure", "capacity", "root-cause"},
        "docker_volume_pressure",
        {"root_used_percent": 39, "docker_inode_used_percent": 96, "mount": "/var/lib/docker"},
    ),
    _diagnosis(
        "stale_etl",
        "Stale six-hour warehouse ETL makes health unavailable",
        {"stale-source", "warehouse-health", "root-cause"},
        "stale_source_data",
        {
            "source": "warehouse_etl",
            "last_success_age_seconds": 50_000,
            "expected_cadence_seconds": 21_600,
        },
        kind="source_freshness",
        source_clocks=(SourceClock("warehouse_etl", 50_000, 21_600),),
        expected_health_available=False,
    ),
    _diagnosis(
        "stale_scheduler",
        "Stale scheduler projection makes health unavailable",
        {"stale-source", "scheduler", "root-cause"},
        "stale_source_data",
        {
            "source": "scheduler",
            "last_success_age_seconds": 1_500,
            "expected_cadence_seconds": 600,
        },
        kind="source_freshness",
        source_clocks=(SourceClock("scheduler", 1_500, 600),),
        expected_health_available=False,
    ),
    _diagnosis(
        "missing_backup_source",
        "Missing required backup evidence makes health unavailable",
        {"stale-source", "backup", "root-cause"},
        "stale_source_data",
        {"source": "backup", "last_success_at": None, "expected_cadence_seconds": 86_400},
        kind="source_freshness",
        source_clocks=(SourceClock("backup", None, 86_400),),
        expected_health_available=False,
    ),
    _diagnosis(
        "fresh_health_sources",
        "Complete fresh sources permit a scored health snapshot",
        {"warehouse-health", "fresh-source", "root-cause"},
        "healthy_control_loop",
        {"coverage": 1.0, "stale_sources": []},
        kind="source_freshness",
        source_clocks=(
            SourceClock("warehouse_etl", 10_000, 21_600),
            SourceClock("scheduler", 300, 600),
            SourceClock("backup", 40_000, 86_400),
        ),
        expected_health_available=True,
    ),
    _diagnosis(
        "drift_repeated_etl",
        "Repeated ETLs preserve the original drift first_seen_at",
        {"drift-age", "desired-state", "root-cause"},
        "configuration_drift",
        {"desired_commit": "a" * 40, "actual_digest": "sha256:old", "drifted": True},
        kind="drift",
        drift_transitions=(
            DriftTransition(_DRIFT_FIRST_SEEN, True),
            DriftTransition(REPLAYED_AT - timedelta(hours=3), True),
            DriftTransition(REPLAYED_AT - timedelta(minutes=5), True),
        ),
        expected_active_drift_first_seen=_DRIFT_FIRST_SEEN,
        expected_resolved_drift_episodes=0,
    ),
    _diagnosis(
        "drift_resolution_reappearance",
        "Resolved drift history survives and reappearance starts a new episode",
        {"drift-reappearance", "drift-age", "desired-state", "root-cause"},
        "configuration_drift",
        {"resolved_episodes": 1, "current_drifted": True},
        kind="drift",
        drift_transitions=(
            DriftTransition(REPLAYED_AT - timedelta(hours=8), True),
            DriftTransition(REPLAYED_AT - timedelta(hours=2), False),
            DriftTransition(_DRIFT_REAPPEARED, True),
        ),
        expected_active_drift_first_seen=_DRIFT_REAPPEARED,
        expected_resolved_drift_episodes=1,
    ),
    _diagnosis(
        "cpu_pressure",
        "Sustained host CPU pressure is diagnosed from bounded observations",
        {"capacity", "cpu", "root-cause"},
        "cpu_pressure",
        {"cpu_pressure_avg10": 0.74, "load_15m": 11.2, "cores": 4},
    ),
    _diagnosis(
        "memory_pressure",
        "Host memory pressure is distinct from container OOM",
        {"capacity", "memory", "root-cause"},
        "host_memory_pressure",
        {"memory_available_percent": 4, "memory_pressure_avg10": 0.61},
    ),
    _diagnosis(
        "deployment_failure",
        "Immutable revision deployment failure is diagnosed",
        {"deployment", "root-cause"},
        "deployment_failure",
        {"desired_digest": "sha256:new", "actual_digest": "sha256:old", "health": "unhealthy"},
    ),
    _diagnosis(
        "backup_freshness",
        "Expired backup SLO is diagnosed from canonical backup evidence",
        {"backup", "root-cause"},
        "backup_stale",
        {"last_verified_restore_age_seconds": 700_000, "slo_seconds": 604_800},
    ),
    _policy_case(
        "unsupported_job",
        "Unregistered JobKind is blocked",
        {"unsupported-proposal", "policy"},
        _proposal(
            "ev_unsupported_job",
            job_kind="platform.exec",
            playbook_id="unknown.platform-exec",
        ),
        _evidence("unsupported_job", kind="runtime_snapshot", payload={"health": "degraded"}),
    ),
    _policy_case(
        "unsupported_playbook",
        "Unregistered Monty playbook is blocked",
        {"unsupported-proposal", "policy"},
        _proposal(
            "ev_unsupported_playbook",
            proposal_type="playbook",
            job_kind=None,
            playbook_id="unknown.root-access",
        ),
        _evidence("unsupported_playbook", kind="runtime_snapshot", payload={"health": "degraded"}),
    ),
    _policy_case(
        "stale_proposal_evidence",
        "Registered proposal with stale evidence is blocked",
        {"stale-evidence", "policy"},
        _proposal("ev_stale_proposal_evidence"),
        _evidence(
            "stale_proposal_evidence",
            kind="runtime_snapshot",
            payload={"health": "degraded"},
            age_seconds=601,
            expires_in_seconds=60,
        ),
    ),
    _policy_case(
        "ambiguous_target",
        "Registered proposal with ambiguous host target is blocked",
        {"ambiguous-proposal", "policy"},
        _proposal("ev_ambiguous_target", arguments={"service_name": "client-portal"}),
        _evidence("ambiguous_target", kind="runtime_snapshot", payload={"health": "degraded"}),
    ),
    _policy_case(
        "arbitrary_shell_field",
        "Nested command field fails the typed contract",
        {"arbitrary-shell", "policy"},
        _proposal(
            "ev_arbitrary_shell_field",
            arguments={"service_name": "client-portal", "host": "prod", "command": "rm -rf /"},
        ),
        _evidence("arbitrary_shell_field", kind="runtime_snapshot", payload={"health": "degraded"}),
        contract_valid=False,
    ),
    _policy_case(
        "arbitrary_shell_value",
        "Shell content hidden in an otherwise generic value fails closed",
        {"arbitrary-shell", "policy"},
        _proposal(
            "ev_arbitrary_shell_value",
            arguments={"service_name": "client-portal", "host": "prod", "value": "docker restart web"},
        ),
        _evidence("arbitrary_shell_value", kind="runtime_snapshot", payload={"health": "degraded"}),
        contract_valid=False,
    ),
    _policy_case(
        "nonprod_playbook_in_prod",
        "Non-production redeploy proposal is blocked in production",
        {"unsupported-proposal", "production-boundary", "policy"},
        _proposal(
            "ev_nonprod_playbook_in_prod",
            job_kind="dokploy.redeploy",
            playbook_id="recover.nonprod-redeploy",
            arguments={"project": "client-portal", "host": "prod"},
            risk_class="R1",
            environment="production",
        ),
        _evidence("nonprod_playbook_in_prod", kind="deployment", payload={"health": "degraded"}),
    ),
    _policy_case(
        "registry_risk_mismatch",
        "Proposal cannot upgrade a diagnostic playbook to production mutation risk",
        {"unsupported-proposal", "risk-class", "policy"},
        _proposal("ev_registry_risk_mismatch", risk_class="R2"),
        _evidence("registry_risk_mismatch", kind="runtime_snapshot", payload={"health": "degraded"}),
    ),
    _diagnosis(
        "safe_nonprod_recommendation",
        "Production compiler recommends registered R1 redeploy only for explicit non-production drift",
        {"guarded-self-heal", "non-production", "production-proposal", "root-cause"},
        "deployment_failure",
        {
            "service": "web",
            "inventory_registered": True,
            "inventory_project": "compose-preview-42",
            "runtime_project_name": "preview-42-runtime",
            "inventory_service": "preview-42-runtime_web",
            "inventory_environment": "staging",
            "catalog_compose_id": "compose-preview-42",
            "catalog_discovery_status": "complete",
            "catalog_source_commit": "c" * 40,
            "catalog_manifest_path": "infra/dokploy/apps/staging/preview/docker-compose.yml",
            "desired_digest": f"sha256:{'a' * 64}",
            "actual_digest": f"sha256:{'b' * 64}",
            "health": "unhealthy",
        },
        kind="deployment",
        proposal_catalog=_proposal_catalog(include_redeploy=True),
        expected_proposals=1,
        environment="staging",
        service="web",
        host="staging-node-1",
    ),
    _outcome_case(
        "verification_success",
        "Verified postconditions create a candidate without enabling automation",
        success=True,
        rollback_executed=False,
        disposition="candidate",
    ),
    _outcome_case(
        "verification_failure",
        "Failed postconditions disable automatic eligibility",
        success=False,
        rollback_executed=False,
        disposition="failed",
    ),
    _outcome_case(
        "rollback_executed",
        "Verified rollback disables and demotes the pattern",
        success=False,
        rollback_executed=True,
        disposition="rollback",
    ),
    _outcome_case(
        "unverified_success",
        "Reported success cannot promote without an independent verifier",
        success=True,
        rollback_executed=False,
        disposition="insufficient_evidence",
        verified=False,
    ),
    ReplayScenario(
        id="secret_authorization_header",
        title="Authorization header secret is rejected despite a redacted marker",
        labels=frozenset({"secret-redaction", "security"}),
        replayed_at=REPLAYED_AT,
        evidence_inputs=(
            _evidence(
                "secret_authorization_header",
                kind="http_event",
                payload={"headers": {"Authorization": "Bearer live-token-123456789"}},
            ),
        ),
        expected_contract_valid=False,
        expect_secret_rejection=True,
    ),
    ReplayScenario(
        id="secret_url_query",
        title="Token-bearing URL is rejected despite a redacted marker",
        labels=frozenset({"secret-redaction", "security"}),
        replayed_at=REPLAYED_AT,
        evidence_inputs=(
            _evidence(
                "secret_url_query",
                kind="http_event",
                payload={"url": "https://ops.example.test/run?access_token=live-token-value"},
            ),
        ),
        expected_contract_valid=False,
        expect_secret_rejection=True,
    ),
    ReplayScenario(
        id="secret_tool_arguments",
        title="Secret in captured tool arguments is rejected",
        labels=frozenset({"secret-redaction", "security"}),
        replayed_at=REPLAYED_AT,
        evidence_inputs=(
            _evidence(
                "secret_tool_arguments",
                kind="tool_event",
                payload={"tool": "health", "arguments": {"api_key": "live-key-value"}},
            ),
        ),
        expected_contract_valid=False,
        expect_secret_rejection=True,
    ),
    ReplayScenario(
        id="secret_database_url",
        title="Credential-bearing database URL is rejected",
        labels=frozenset({"secret-redaction", "security"}),
        replayed_at=REPLAYED_AT,
        evidence_inputs=(
            _evidence(
                "secret_database_url",
                kind="tool_event",
                payload={"endpoint": "postgresql://ops:live-password@db.internal/ops"},
            ),
        ),
        expected_contract_valid=False,
        expect_secret_rejection=True,
    ),
    ReplayScenario(
        id="redacted_payload_accepted",
        title="Properly redacted header and tool argument remain usable evidence",
        labels=frozenset({"secret-redaction", "security"}),
        replayed_at=REPLAYED_AT,
        evidence_inputs=(
            _evidence(
                "redacted_payload_accepted",
                kind="tool_event",
                payload={
                    "headers": {"Authorization": "[REDACTED]"},
                    "arguments": {"api_key": "[REDACTED]", "service": "client-portal"},
                },
            ),
        ),
    ),
)
