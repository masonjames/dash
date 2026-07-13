"""Deterministic, evidence-only diagnosis for private Ops investigations.

Rules in this module recognize a deliberately small set of structured signals.
They do not call models, tools, or networks. Proposal generation is restricted to
request-scoped, HMAC-authenticated Dockhand catalog entries. Unknown or ambiguous
payloads produce no hypotheses or proposals.
"""

from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Iterable

from dash.ops_contract import (
    CauseCode,
    EvidenceReference,
    OpsInvestigationRequest,
    ProposalCatalogEntry,
    RankedHypothesis,
    RemediationProposal,
    RiskClass,
)


DETECTOR_VERSION = "ops-shadow-rules-v2"


@dataclass(frozen=True)
class ShadowDiagnosis:
    summary: str
    summary_evidence_ids: list[str]
    hypotheses: list[RankedHypothesis]
    confidence: float
    root_cause: CauseCode | None


@dataclass(frozen=True)
class _Signal:
    cause_code: CauseCode
    statement: str
    confidence: float
    evidence_ids: tuple[str, ...]

    @property
    def signal_fingerprint(self) -> str:
        identity = f"{DETECTOR_VERSION}:{self.cause_code.value}"
        return hashlib.sha256(identity.encode()).hexdigest()


_REPLICAS_PATTERN = re.compile(r"^\s*(\d+)\s*/\s*(\d+)\s*$")
_PERCENT_PATTERN = re.compile(r"(?<!\d)(\d{1,3}(?:\.\d+)?)%")
_UNHEALTHY_STATES = {"dead", "degraded", "exited", "failed", "restarting", "unhealthy"}


def _normalise_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).casefold()).strip("_")


def _walk_dicts(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from _walk_dicts(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_dicts(nested)


def _structured_oom(payload: dict[str, Any]) -> bool:
    for item in _walk_dicts(payload):
        normalised = {_normalise_key(key): value for key, value in item.items()}
        if normalised.get("oom_killed") is True or normalised.get("oomkilled") is True:
            return True
        if str(normalised.get("oom_killed", "")).casefold() == "true":
            return True
        if str(normalised.get("oomkilled", "")).casefold() == "true":
            return True
        action = str(normalised.get("action", normalised.get("event_action", ""))).casefold()
        event_type = str(normalised.get("event_type", "")).casefold()
        reason = str(normalised.get("reason", "")).casefold()
        if action == "oom" or event_type in {"container.oom", "container_oom"}:
            return True
        if reason in {"oomkilled", "out of memory"}:
            return True
        try:
            if int(normalised.get("oom_events_24h", 0)) > 0:
                return True
        except (TypeError, ValueError):
            pass
    return False


def _df_percent(output: Any) -> float | None:
    if not isinstance(output, str):
        return None
    matches = _PERCENT_PATTERN.findall(output)
    if not matches:
        return None
    value = float(matches[-1])
    return value if 0 <= value <= 100 else None


def _probe_output(state: dict[str, Any], name: str) -> str | None:
    probe = state.get(name)
    if not isinstance(probe, dict) or probe.get("ok") is not True:
        return None
    output = probe.get("output")
    return output if isinstance(output, str) else None


def _capacity_percentages(payload: dict[str, Any]) -> Iterable[tuple[float, float]]:
    try:
        root = float(payload["root_used_percent"])
        docker_value = payload.get("docker_data_used_percent", payload.get("docker_inode_used_percent"))
        if docker_value is None:
            raise ValueError("missing Docker storage percentage")
        docker = float(docker_value)
    except (KeyError, TypeError, ValueError):
        pass
    else:
        if 0 <= root <= 100 and 0 <= docker <= 100:
            yield root, docker

    state = payload.get("state")
    if isinstance(state, dict):
        root_percent = _df_percent(_probe_output(state, "disk"))
        docker_percent = _df_percent(_probe_output(state, "docker_disk"))
        if root_percent is not None and docker_percent is not None:
            yield root_percent, docker_percent

    records = payload.get("records")
    if isinstance(records, list):
        for record in records:
            if not isinstance(record, dict):
                continue
            try:
                root = float(record["disk_usage_pct"])
                docker = float(record["docker_disk_usage_pct"])
            except (KeyError, TypeError, ValueError):
                continue
            if 0 <= root <= 100 and 0 <= docker <= 100:
                yield root, docker


def _json_lines(output: str | None) -> Iterable[dict[str, Any]]:
    if not output:
        return
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(item, dict):
            yield item


def _service_matches_scope(item: dict[str, Any], target_service: str | None) -> bool:
    if not target_service:
        return True
    target = _normalise_key(target_service)
    names = [_normalise_key(item.get(key, "")) for key in ("Name", "name", "service", "service_name", "Names")]
    return any(name == target or name.startswith(f"{target}_") or name.endswith(f"_{target}") for name in names)


def _service_is_unhealthy(item: dict[str, Any], target_service: str | None) -> bool:
    if not _service_matches_scope(item, target_service):
        return False
    replicas = item.get("Replicas", item.get("replicas"))
    if replicas is not None:
        match = _REPLICAS_PATTERN.fullmatch(str(replicas))
        if match and int(match.group(2)) > 0 and int(match.group(1)) < int(match.group(2)):
            return True

    for key in ("State", "state", "Status", "status", "health"):
        value = str(item.get(key, "")).casefold()
        if value in _UNHEALTHY_STATES or "(unhealthy)" in value or value.startswith("restarting"):
            return True
    return False


def _unhealthy_service(payload: dict[str, Any], target_service: str | None) -> bool:
    state = payload.get("state")
    if isinstance(state, dict):
        for probe_name in ("services", "containers"):
            for item in _json_lines(_probe_output(state, probe_name)):
                if _service_is_unhealthy(item, target_service):
                    return True

    records = payload.get("records")
    if isinstance(records, list):
        return any(_service_is_unhealthy(item, target_service) for item in records if isinstance(item, dict))
    return False


def _has_unresolved_drift(evidence: EvidenceReference) -> bool:
    if evidence.kind not in {"configuration_drift", "drift"}:
        return False
    if evidence.payload.get("drifted") is True or evidence.payload.get("current_drifted") is True:
        return True
    records = evidence.payload.get("records")
    if not isinstance(records, list):
        return False
    return any(
        isinstance(record, dict)
        and record.get("resolved_at") is None
        and bool(record.get("category") or record.get("desired_value") or record.get("actual_value"))
        for record in records
    )


def _stale_source(payload: dict[str, Any]) -> bool:
    cadence = payload.get("expected_cadence_seconds")
    if cadence is None:
        return False
    try:
        cadence_seconds = int(cadence)
    except (TypeError, ValueError):
        return False
    if cadence_seconds <= 0:
        return False
    if "last_success_at" in payload and payload.get("last_success_at") is None:
        return True
    try:
        age_seconds = int(payload["last_success_age_seconds"])
    except (KeyError, TypeError, ValueError):
        return False
    return age_seconds > cadence_seconds * 2


def _healthy_control_loop(payload: dict[str, Any]) -> bool:
    try:
        coverage = float(payload["coverage"])
    except (KeyError, TypeError, ValueError):
        return False
    return coverage == 1.0 and payload.get("stale_sources") == []


def _cpu_pressure(payload: dict[str, Any]) -> bool:
    for item in _walk_dicts(payload):
        try:
            pressure = float(item["cpu_pressure_avg10"])
            load = float(item["load_15m"])
            cores = float(item["cores"])
        except (KeyError, TypeError, ValueError):
            continue
        if cores > 0 and pressure >= 0.5 and load >= cores * 2:
            return True
    return False


def _memory_pressure(payload: dict[str, Any]) -> bool:
    for item in _walk_dicts(payload):
        try:
            available = float(item["memory_available_percent"])
            pressure = float(item["memory_pressure_avg10"])
        except (KeyError, TypeError, ValueError):
            continue
        if available <= 10 and pressure >= 0.5:
            return True
    return False


def _deployment_failure(payload: dict[str, Any]) -> bool:
    desired = payload.get("desired_digest")
    actual = payload.get("actual_digest")
    health = str(payload.get("health", "")).casefold()
    return bool(desired and actual and desired != actual and health in _UNHEALTHY_STATES)


def _backup_stale(payload: dict[str, Any]) -> bool:
    try:
        age_seconds = int(payload["last_verified_restore_age_seconds"])
        slo_seconds = int(payload["slo_seconds"])
    except (KeyError, TypeError, ValueError):
        return False
    return slo_seconds > 0 and age_seconds > slo_seconds


def _postcondition_failure(payload: dict[str, Any]) -> bool:
    return bool(payload.get("postcondition")) and payload.get("passed") is False


def _merge_signals(signals: list[_Signal]) -> list[_Signal]:
    merged: dict[CauseCode, _Signal] = {}
    for signal in signals:
        previous = merged.get(signal.cause_code)
        if previous is None:
            merged[signal.cause_code] = signal
            continue
        evidence_ids = tuple(dict.fromkeys((*previous.evidence_ids, *signal.evidence_ids)))
        merged[signal.cause_code] = _Signal(
            signal.cause_code,
            signal.statement,
            max(previous.confidence, signal.confidence),
            evidence_ids,
        )
    return sorted(merged.values(), key=lambda item: (-item.confidence, item.cause_code.value))


def diagnose_evidence(evidence: list[EvidenceReference]) -> ShadowDiagnosis:
    """Recognize allowlisted operational signatures and rank them deterministically."""

    if not evidence:
        return ShadowDiagnosis(
            summary="Insufficient canonical evidence; deterministic shadow diagnosis remains unavailable.",
            summary_evidence_ids=[],
            hypotheses=[],
            confidence=0.0,
            root_cause=None,
        )

    signals: list[_Signal] = []
    for item in evidence:
        if _structured_oom(item.payload):
            signals.append(
                _Signal(
                    CauseCode.CONTAINER_OOM,
                    "root_cause=container_oom; structured lifecycle evidence explicitly reports an OOM kill.",
                    0.98,
                    (item.id,),
                )
            )

        if any(docker >= 85 and root < 70 for root, docker in _capacity_percentages(item.payload)):
            signals.append(
                _Signal(
                    CauseCode.DOCKER_VOLUME_PRESSURE,
                    "root_cause=docker_volume_pressure; Docker data storage is at critical capacity while the root filesystem remains below pressure threshold.",
                    0.96,
                    (item.id,),
                )
            )

        if _has_unresolved_drift(item):
            signals.append(
                _Signal(
                    CauseCode.CONFIGURATION_DRIFT,
                    "root_cause=configuration_drift; canonical desired-versus-actual observations contain unresolved drift.",
                    0.93,
                    (item.id,),
                )
            )

        target_service = item.scope.get("service")
        if _unhealthy_service(
            item.payload,
            target_service if isinstance(target_service, str) else None,
        ):
            signals.append(
                _Signal(
                    CauseCode.SERVICE_UNHEALTHY,
                    "root_cause=service_unhealthy; an observed Docker service or container is below its desired healthy state.",
                    0.91,
                    (item.id,),
                )
            )

        if _stale_source(item.payload):
            signals.append(
                _Signal(
                    CauseCode.STALE_SOURCE_DATA,
                    "root_cause=stale_source_data; a required source is older than twice its declared cadence or has no successful observation.",
                    0.97,
                    (item.id,),
                )
            )

        if _healthy_control_loop(item.payload):
            signals.append(
                _Signal(
                    CauseCode.HEALTHY_CONTROL_LOOP,
                    "root_cause=healthy_control_loop; all declared required sources are fresh with complete coverage.",
                    0.90,
                    (item.id,),
                )
            )

        if _cpu_pressure(item.payload):
            signals.append(
                _Signal(
                    CauseCode.CPU_PRESSURE,
                    "root_cause=cpu_pressure; bounded CPU pressure and load exceed the structured host threshold.",
                    0.94,
                    (item.id,),
                )
            )

        if _memory_pressure(item.payload):
            signals.append(
                _Signal(
                    CauseCode.HOST_MEMORY_PRESSURE,
                    "root_cause=host_memory_pressure; host memory availability and pressure cross the structured threshold.",
                    0.95,
                    (item.id,),
                )
            )

        if _deployment_failure(item.payload):
            signals.append(
                _Signal(
                    CauseCode.DEPLOYMENT_FAILURE,
                    "root_cause=deployment_failure; the unhealthy observed revision differs from the immutable desired digest.",
                    0.96,
                    (item.id,),
                )
            )

        if _backup_stale(item.payload):
            signals.append(
                _Signal(
                    CauseCode.BACKUP_STALE,
                    "root_cause=backup_stale; verified restore freshness exceeds the declared backup SLO.",
                    0.99,
                    (item.id,),
                )
            )

        if _postcondition_failure(item.payload):
            signals.append(
                _Signal(
                    CauseCode.POSTCONDITION_FAILURE,
                    "root_cause=postcondition_failure; an independently recorded postcondition explicitly failed.",
                    0.99,
                    (item.id,),
                )
            )

    ranked = _merge_signals(signals)[:3]
    if not ranked:
        return ShadowDiagnosis(
            summary=(
                "Canonical evidence passed validation, but no allowlisted deterministic failure signature was recognized."
            ),
            summary_evidence_ids=[item.id for item in evidence],
            hypotheses=[],
            confidence=0.0,
            root_cause=None,
        )

    hypotheses = [
        RankedHypothesis(
            rank=rank,
            cause_code=signal.cause_code,
            detector_version=DETECTOR_VERSION,
            signal_fingerprint=signal.signal_fingerprint,
            statement=signal.statement,
            confidence=signal.confidence,
            evidence_ids=list(signal.evidence_ids),
        )
        for rank, signal in enumerate(ranked, 1)
    ]
    summary_evidence_ids = list(dict.fromkeys(evidence_id for signal in ranked for evidence_id in signal.evidence_ids))
    return ShadowDiagnosis(
        summary="Deterministic shadow diagnosis recognized evidence-backed operational failure signals.",
        summary_evidence_ids=summary_evidence_ids,
        hypotheses=hypotheses,
        confidence=ranked[0].confidence,
        root_cause=ranked[0].cause_code,
    )


_SERVICE_HEALTH_PLAYBOOK_ID = "diagnose.service-health"
_SERVICE_HEALTH_JOB_KIND = "service.healthcheck"
_NONPROD_REDEPLOY_PLAYBOOK_ID = "recover.nonprod-redeploy"
_NONPROD_REDEPLOY_JOB_KIND = "dokploy.redeploy"
_MEMORY_LIMIT_PLAYBOOK_ID = "suggest.memory-limit"
_NONPROD_ENVIRONMENTS = {"dev", "test", "staging"}
_DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
_COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")
_MIB = 1024 * 1024
_MAX_MEMORY_RECOMMENDATION = 16 * 1024 * _MIB
_SERVICE_HEALTH_CAUSES = {
    CauseCode.CONTAINER_OOM,
    CauseCode.DOCKER_VOLUME_PRESSURE,
    CauseCode.CONFIGURATION_DRIFT,
    CauseCode.SERVICE_UNHEALTHY,
    CauseCode.CPU_PRESSURE,
    CauseCode.HOST_MEMORY_PRESSURE,
    CauseCode.DEPLOYMENT_FAILURE,
}


def _catalog_definition(
    request: OpsInvestigationRequest,
    *,
    playbook_id: str,
    proposal_type: str,
    job_kind: str | None,
    risk_class: RiskClass,
) -> ProposalCatalogEntry | None:
    definitions = [item for item in request.proposal_catalog.playbooks if item.enabled and item.id == playbook_id]
    if len(definitions) != 1:
        return None
    definition = definitions[0]
    if (
        definition.proposal_type != proposal_type
        or definition.job_kind != job_kind
        or definition.risk_class is not risk_class
    ):
        return None
    return definition


def _cited_current_evidence(
    evidence: list[EvidenceReference],
    diagnosis: ShadowDiagnosis,
    definition: ProposalCatalogEntry,
) -> list[EvidenceReference] | None:
    if not diagnosis.hypotheses:
        return None
    by_id = {item.id: item for item in evidence}
    cited = [by_id.get(evidence_id) for evidence_id in diagnosis.hypotheses[0].evidence_ids]
    if any(item is None for item in cited):
        return None
    concrete = [item for item in cited if item is not None]
    if any(item.freshness_seconds > definition.evidence_max_age_seconds for item in concrete):
        return None
    return concrete


def _scoped_host(
    request: OpsInvestigationRequest,
    cited: list[EvidenceReference],
) -> str | None:
    if any(
        item.scope.get("environment") != request.environment or item.scope.get("service") != request.service
        for item in cited
    ):
        return None
    hosts = {item.scope.get("host") for item in cited if isinstance(item.scope.get("host"), str)}
    return hosts.pop() if len(hosts) == 1 else None


def _proposal_from_definition(
    definition: ProposalCatalogEntry,
    request: OpsInvestigationRequest,
    cited: list[EvidenceReference],
    arguments: dict[str, Any],
) -> RemediationProposal | None:
    if not request.environment or not definition.argument_schema.accepts(arguments):
        return None
    return RemediationProposal(
        proposal_type=definition.proposal_type,
        job_kind=definition.job_kind,
        playbook_id=definition.id,
        playbook_version=definition.version,
        arguments=arguments,
        risk_class=definition.risk_class,
        target_environment=request.environment.casefold(),
        preconditions=list(definition.preconditions),
        evidence_ids=[item.id for item in cited],
        evidence_max_age_seconds=definition.evidence_max_age_seconds,
        rollback_steps=list(definition.rollback_steps),
        postconditions=list(definition.postconditions),
    )


def _build_service_health_proposal(
    request: OpsInvestigationRequest,
    evidence: list[EvidenceReference],
    diagnosis: ShadowDiagnosis,
) -> RemediationProposal | None:
    if diagnosis.root_cause not in _SERVICE_HEALTH_CAUSES or not request.service:
        return None
    definition = _catalog_definition(
        request,
        playbook_id=_SERVICE_HEALTH_PLAYBOOK_ID,
        proposal_type="job",
        job_kind=_SERVICE_HEALTH_JOB_KIND,
        risk_class=RiskClass.R0,
    )
    if (
        definition is None
        or definition.evidence_max_age_seconds > 300
        or set(definition.argument_schema.required) != {"service_name", "host"}
        or set(definition.argument_schema.properties) - {"service_name", "host", "container"}
        or not request.environment
        or request.environment.casefold() not in {value.casefold() for value in definition.allowed_environments}
    ):
        return None
    cited = _cited_current_evidence(evidence, diagnosis, definition)
    if not cited or (host := _scoped_host(request, cited)) is None:
        return None
    arguments: dict[str, Any] = {"service_name": request.service, "host": host}
    containers = {item.scope.get("container") for item in cited if isinstance(item.scope.get("container"), str)}
    if len(containers) == 1 and "container" in definition.argument_schema.properties:
        arguments["container"] = containers.pop()
    return _proposal_from_definition(definition, request, cited, arguments)


def _explicit_unhealthy_deployment(
    payload: dict[str, Any],
    service: str,
    environment: str,
) -> str | None:
    matches: set[str] = set()
    for item in _walk_dicts(payload):
        desired = item.get("desired_digest")
        actual = item.get("actual_digest")
        inventory_project = item.get("inventory_project")
        runtime_project_name = item.get("runtime_project_name")
        catalog_source_commit = item.get("catalog_source_commit")
        catalog_manifest_path = item.get("catalog_manifest_path")
        if (
            item.get("service") == service
            and item.get("inventory_registered") is True
            and isinstance(inventory_project, str)
            and item.get("catalog_compose_id") == inventory_project
            and item.get("catalog_discovery_status") == "complete"
            and isinstance(catalog_source_commit, str)
            and _COMMIT_PATTERN.fullmatch(catalog_source_commit) is not None
            and isinstance(catalog_manifest_path, str)
            and 0 < len(catalog_manifest_path) <= 500
            and not catalog_manifest_path.startswith("/")
            and ".." not in catalog_manifest_path.split("/")
            and isinstance(runtime_project_name, str)
            and item.get("inventory_service") == f"{runtime_project_name}_{service}"
            and item.get("inventory_environment") == environment
            and isinstance(desired, str)
            and _DIGEST_PATTERN.fullmatch(desired)
            and isinstance(actual, str)
            and _DIGEST_PATTERN.fullmatch(actual)
            and desired != actual
            and str(item.get("health", "")).casefold() in _UNHEALTHY_STATES
        ):
            matches.add(inventory_project)
    return matches.pop() if len(matches) == 1 else None


def _build_nonprod_redeploy_proposal(
    request: OpsInvestigationRequest,
    evidence: list[EvidenceReference],
    diagnosis: ShadowDiagnosis,
) -> RemediationProposal | None:
    if (
        diagnosis.root_cause is not CauseCode.DEPLOYMENT_FAILURE
        or not request.environment
        or request.environment.casefold() not in _NONPROD_ENVIRONMENTS
        or not request.service
    ):
        return None
    definition = _catalog_definition(
        request,
        playbook_id=_NONPROD_REDEPLOY_PLAYBOOK_ID,
        proposal_type="job",
        job_kind=_NONPROD_REDEPLOY_JOB_KIND,
        risk_class=RiskClass.R1,
    )
    if (
        definition is None
        or definition.evidence_max_age_seconds > 300
        or set(definition.argument_schema.required) != {"project", "host"}
        or set(definition.argument_schema.properties) - {"project", "host", "force"}
        or request.environment.casefold() not in {value.casefold() for value in definition.allowed_environments}
    ):
        return None
    cited = _cited_current_evidence(evidence, diagnosis, definition)
    if not cited or (host := _scoped_host(request, cited)) is None:
        return None
    inventory_projects = {
        project
        for item in cited
        if (
            project := _explicit_unhealthy_deployment(
                item.payload,
                request.service,
                request.environment,
            )
        )
    }
    if len(inventory_projects) != 1 or any(
        _explicit_unhealthy_deployment(
            item.payload,
            request.service,
            request.environment,
        )
        not in inventory_projects
        for item in cited
    ):
        return None
    return _proposal_from_definition(
        definition,
        request,
        cited,
        {"project": inventory_projects.pop(), "host": host},
    )


def _memory_inputs(
    payload: dict[str, Any],
    service: str,
) -> tuple[str, str, int, int, int] | None:
    candidates: set[tuple[str, str, int, int]] = set()
    for item in _walk_dicts(payload):
        source_file = item.get("source_file")
        source_commit = item.get("source_commit")
        current_value = item.get("current_memory_limit_bytes", item.get("memory_limit_bytes"))
        peak_value = item.get("observed_peak_bytes", item.get("peak_memory_bytes"))
        if (
            item.get("service") != service
            or item.get("desired_state_tracked") is not True
            or not isinstance(source_file, str)
            or not isinstance(source_commit, str)
            or _COMMIT_PATTERN.fullmatch(source_commit) is None
            or current_value is None
            or peak_value is None
            or isinstance(current_value, bool)
            or isinstance(peak_value, bool)
        ):
            continue
        try:
            current = int(current_value)
            peak = int(peak_value)
        except (TypeError, ValueError):
            continue
        if 16 * _MIB <= current <= _MAX_MEMORY_RECOMMENDATION and int(current * 0.80) <= peak:
            candidates.add((source_file, source_commit, current, peak))
    if len(candidates) != 1:
        return None
    source_file, source_commit, current, peak = candidates.pop()
    target = max(current * 2, (peak * 5 + 3) // 4)
    quantum = 64 * _MIB
    proposed = ((target + quantum - 1) // quantum) * quantum
    if proposed <= current or proposed > min(current * 4, _MAX_MEMORY_RECOMMENDATION):
        return None
    return source_file, source_commit, current, peak, proposed


def _build_memory_limit_suggestion(
    request: OpsInvestigationRequest,
    evidence: list[EvidenceReference],
    diagnosis: ShadowDiagnosis,
) -> RemediationProposal | None:
    if diagnosis.root_cause is not CauseCode.CONTAINER_OOM or not request.environment or not request.service:
        return None
    definition = _catalog_definition(
        request,
        playbook_id=_MEMORY_LIMIT_PLAYBOOK_ID,
        proposal_type="desired_state_pr",
        job_kind=None,
        risk_class=RiskClass.R0,
    )
    if (
        definition is None
        or definition.evidence_max_age_seconds > 900
        or set(definition.argument_schema.required)
        != {"service", "source_file", "source_commit", "proposed_memory_limit"}
        or set(definition.argument_schema.properties)
        - {
            "service",
            "source_file",
            "source_commit",
            "proposed_memory_limit",
            "observed_peak_bytes",
            "rationale",
        }
        or request.environment.casefold() not in {value.casefold() for value in definition.allowed_environments}
    ):
        return None
    cited = _cited_current_evidence(evidence, diagnosis, definition)
    if not cited or _scoped_host(request, cited) is None:
        return None
    inputs: set[tuple[str, str, int, int, int]] = set()
    for item in cited:
        if (value := _memory_inputs(item.payload, request.service)) is not None:
            inputs.add(value)
    if len(inputs) != 1:
        return None
    source_file, source_commit, _current, peak, proposed = inputs.pop()
    return _proposal_from_definition(
        definition,
        request,
        cited,
        {
            "service": request.service,
            "source_file": source_file,
            "source_commit": source_commit,
            "proposed_memory_limit": f"{proposed // _MIB}Mi",
            "observed_peak_bytes": peak,
        },
    )


def build_catalog_backed_proposals(
    request: OpsInvestigationRequest,
    evidence: list[EvidenceReference],
    diagnosis: ShadowDiagnosis,
) -> list[RemediationProposal]:
    """Compile evidence-derived intents from Dockhand's closed-world catalog.

    No target, job kind, mutation, source file, or resource value is invented.
    Dockhand recompiles every returned intent and retains all policy/execution
    authority; shadow mode prevents these recommendations from executing.
    """

    builders = (
        _build_service_health_proposal,
        _build_nonprod_redeploy_proposal,
        _build_memory_limit_suggestion,
    )
    return [proposal for builder in builders if (proposal := builder(request, evidence, diagnosis)) is not None]
