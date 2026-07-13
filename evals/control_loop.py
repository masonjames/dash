"""Engine-executed replay evaluator for the governed Ops control loop.

Replay fixtures contain only evidence/request inputs and independent labels. Every
diagnosis and catalog-backed proposal is produced by the same production functions
used by ``/internal/ops/investigate``; fixtures cannot smuggle expected answers into
an ``OpsInvestigationResult``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import ValidationError

from dash.internal_ops import CanonicalOutcome, evaluate_canonical_outcome
from dash.ops_contract import (
    EvidenceReference,
    OpsInvestigationRequest,
    OpsInvestigationResult,
    RemediationProposal,
    VerificationOutcome,
)
from dash.ops_shadow_reasoning import (
    DETECTOR_VERSION,
    build_catalog_backed_proposals,
    diagnose_evidence,
)


@dataclass(frozen=True)
class SourceClock:
    name: str
    age_seconds: int | None
    expected_cadence_seconds: int
    required: bool = True


@dataclass(frozen=True)
class DriftTransition:
    observed_at: datetime
    drifted: bool


@dataclass(frozen=True)
class RegistryTarget:
    proposal_type: Literal["job", "playbook", "desired_state_pr"]
    playbook_id: str
    version: str
    job_kind: str | None
    risk_class: str
    allowed_environments: frozenset[str]
    required_arguments: frozenset[str]
    optional_arguments: frozenset[str]
    evidence_max_age_seconds: int


# Evaluation input only. Dockhand remains execution authority and recompiles every
# proposal against its live registry. The replay copy catches contract drift.
REPLAY_REGISTRY: dict[tuple[str, str], RegistryTarget] = {
    ("diagnose.service-health", "1.0.0"): RegistryTarget(
        proposal_type="job",
        playbook_id="diagnose.service-health",
        version="1.0.0",
        job_kind="service.healthcheck",
        risk_class="R0",
        allowed_environments=frozenset({"dev", "test", "staging", "prod", "production", "platform-core"}),
        required_arguments=frozenset({"service_name", "host"}),
        optional_arguments=frozenset({"container"}),
        evidence_max_age_seconds=300,
    ),
    ("recover.nonprod-redeploy", "1.0.0"): RegistryTarget(
        proposal_type="job",
        playbook_id="recover.nonprod-redeploy",
        version="1.0.0",
        job_kind="dokploy.redeploy",
        risk_class="R1",
        allowed_environments=frozenset({"dev", "test", "staging"}),
        required_arguments=frozenset({"project", "host"}),
        optional_arguments=frozenset({"force"}),
        evidence_max_age_seconds=300,
    ),
    ("suggest.memory-limit", "1.0.0"): RegistryTarget(
        proposal_type="desired_state_pr",
        playbook_id="suggest.memory-limit",
        version="1.0.0",
        job_kind=None,
        risk_class="R0",
        allowed_environments=frozenset({"dev", "test", "staging", "prod", "production", "platform-core"}),
        required_arguments=frozenset({"service", "source_file", "source_commit", "proposed_memory_limit"}),
        optional_arguments=frozenset({"observed_peak_bytes", "rationale"}),
        evidence_max_age_seconds=900,
    ),
}


@dataclass(frozen=True)
class ReplayScenario:
    id: str
    title: str
    labels: frozenset[str]
    replayed_at: datetime
    evidence_inputs: tuple[dict[str, Any], ...]
    environment: str = "production"
    service: str = "client-portal"
    prompt: str = "Investigate the scoped operational failure"
    incident_id: str | None = None
    proposal_catalog: dict[str, Any] = field(
        default_factory=lambda: {"registry_version": "replay-empty-v1", "playbooks": []}
    )
    proposal_inputs: tuple[dict[str, Any], ...] = ()
    expected_contract_valid: bool = True
    expected_root_cause: str | None = None
    expected_accepted_proposals: int = 0
    source_clocks: tuple[SourceClock, ...] = ()
    expected_health_available: bool | None = None
    drift_transitions: tuple[DriftTransition, ...] = ()
    expected_active_drift_first_seen: datetime | None = None
    expected_resolved_drift_episodes: int | None = None
    verification_outcome: dict[str, Any] | None = None
    canonical_outcome_verified: bool = True
    expected_outcome_disposition: str | None = None
    expect_secret_rejection: bool = False


@dataclass(frozen=True)
class ReplayCaseResult:
    id: str
    passed: bool
    contract_valid: bool
    citation_resolvable: bool | None
    root_cause_top_three: bool | None
    accepted_proposals: int
    policy_escape: bool
    failures: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReplayReport:
    corpus_kind: Literal["synthetic_contract", "historical_90d"]
    total: int
    passed: int
    failed: int
    root_cause_cases: int
    root_cause_top_three: int
    root_cause_accuracy: float
    citation_cases: int
    resolvable_citation_cases: int
    citation_resolvability: float
    policy_escapes: int
    gate_passed: bool
    live_release_gate_passed: bool
    cases: tuple[ReplayCaseResult, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DriftReplayState:
    active_first_seen_at: datetime | None
    resolved_episodes: int


def _payload_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _citations_resolve(result: OpsInvestigationResult) -> bool:
    known = {item.id for item in result.evidence}
    cited = set(result.summary_evidence_ids)
    cited.update(evidence_id for item in result.hypotheses for evidence_id in item.evidence_ids)
    cited.update(evidence_id for item in result.historical_comparables for evidence_id in item.evidence_ids)
    cited.update(evidence_id for item in result.remediation_proposals for evidence_id in item.evidence_ids)
    hashes_match = all(_payload_hash(item.payload) == item.content_hash for item in result.evidence)
    return bool(cited) and cited <= known and hashes_match


def _root_cause_in_top_three(result: OpsInvestigationResult, expected: str) -> bool:
    top_three = sorted(result.hypotheses, key=lambda item: item.rank)[:3]
    return any(item.cause_code.value == expected for item in top_three)


def health_is_available(sources: tuple[SourceClock, ...]) -> bool:
    """Apply the fail-closed twice-cadence freshness contract."""

    return all(
        not source.required
        or (source.age_seconds is not None and source.age_seconds <= source.expected_cadence_seconds * 2)
        for source in sources
    )


def replay_drift(transitions: tuple[DriftTransition, ...]) -> DriftReplayState:
    """Preserve an episode's first-seen time across ETLs and its resolution history."""

    active_first_seen: datetime | None = None
    resolved_episodes = 0
    previous_drifted = False
    for transition in sorted(transitions, key=lambda item: item.observed_at):
        if transition.observed_at.tzinfo is None:
            raise ValueError("drift replay timestamps must be timezone-aware")
        if transition.drifted and not previous_drifted:
            active_first_seen = transition.observed_at.astimezone(UTC)
        elif not transition.drifted and previous_drifted:
            resolved_episodes += 1
            active_first_seen = None
        previous_drifted = transition.drifted
    return DriftReplayState(active_first_seen, resolved_episodes)


def _proposal_registry_target(proposal: RemediationProposal) -> RegistryTarget | None:
    if not proposal.playbook_id:
        return None
    return REPLAY_REGISTRY.get((proposal.playbook_id, proposal.playbook_version))


def _same_environment(left: str, right: str) -> bool:
    aliases = {"prod": "production", "production": "production"}
    return aliases.get(left.casefold(), left.casefold()) == aliases.get(right.casefold(), right.casefold())


def _proposal_allowed(
    proposal: RemediationProposal,
    result: OpsInvestigationResult,
    replayed_at: datetime,
) -> bool:
    definition = _proposal_registry_target(proposal)
    if definition is None:
        return False
    if proposal.proposal_type != definition.proposal_type or proposal.job_kind != definition.job_kind:
        return False
    if proposal.risk_class.value != definition.risk_class:
        return False
    if proposal.target_environment.casefold() not in definition.allowed_environments:
        return False

    supplied = set(proposal.arguments)
    allowed = definition.required_arguments | definition.optional_arguments
    if definition.required_arguments - supplied or supplied - allowed:
        return False
    if proposal.evidence_max_age_seconds > definition.evidence_max_age_seconds:
        return False

    evidence = {item.id: item for item in result.evidence}
    for evidence_id in proposal.evidence_ids:
        item = evidence.get(evidence_id)
        if item is None:
            return False
        observed_at = item.observation_started_at.astimezone(UTC)
        age_seconds = max(0, int((replayed_at.astimezone(UTC) - observed_at).total_seconds()))
        if replayed_at.astimezone(UTC) >= item.expires_at.astimezone(UTC):
            return False
        if age_seconds > min(proposal.evidence_max_age_seconds, definition.evidence_max_age_seconds):
            return False
        scope_environment = item.scope.get("environment")
        if not isinstance(scope_environment, str) or not _same_environment(
            proposal.target_environment, scope_environment
        ):
            return False
        scope_service = item.scope.get("service")
        if not isinstance(scope_service, str):
            return False
        if "project" in proposal.arguments:
            project = proposal.arguments["project"]
            runtime_project_name = item.payload.get("runtime_project_name")
            if (
                item.payload.get("service") != scope_service
                or item.payload.get("inventory_project") != project
                or not isinstance(runtime_project_name, str)
                or item.payload.get("inventory_service") != f"{runtime_project_name}_{scope_service}"
            ):
                return False
        else:
            argument_service = proposal.arguments.get(
                "service_name",
                proposal.arguments.get("service"),
            )
            if argument_service != scope_service:
                return False
    return True


def _execute_production_reasoner(
    scenario: ReplayScenario,
) -> tuple[OpsInvestigationResult | None, bool]:
    """Validate replay inputs, then call the production reasoner and proposal compiler."""

    try:
        evidence = [EvidenceReference.model_validate(item) for item in scenario.evidence_inputs]
        request = OpsInvestigationRequest.model_validate(
            {
                "investigation_id": f"inv_{scenario.id}",
                "prompt": scenario.prompt,
                "environment": scenario.environment,
                "service": scenario.service,
                "incident_id": scenario.incident_id,
                "evidence_ids": [item.id for item in evidence],
                "model_version": DETECTOR_VERSION,
                "proposal_catalog": scenario.proposal_catalog,
            }
        )
        supplied_proposals = [RemediationProposal.model_validate(item) for item in scenario.proposal_inputs]
    except ValidationError:
        return None, False

    diagnosis = diagnose_evidence(evidence)
    generated_proposals = build_catalog_backed_proposals(request, evidence, diagnosis)
    try:
        result = OpsInvestigationResult(
            investigation_id=request.investigation_id,
            summary=diagnosis.summary,
            summary_evidence_ids=diagnosis.summary_evidence_ids,
            evidence=evidence,
            hypotheses=diagnosis.hypotheses,
            confidence=diagnosis.confidence,
            historical_comparables=[],
            remediation_proposals=[*generated_proposals, *supplied_proposals],
            model_version=DETECTOR_VERSION,
            generated_at=scenario.replayed_at,
        )
    except ValidationError:
        return None, False
    return result, True


def evaluate_scenario(scenario: ReplayScenario) -> ReplayCaseResult:
    failures: list[str] = []
    result, contract_valid = _execute_production_reasoner(scenario)

    if contract_valid != scenario.expected_contract_valid:
        failures.append("input or production result contract validity did not match the label")
    if scenario.expect_secret_rejection and contract_valid:
        failures.append("secret-bearing evidence escaped contract validation")

    citation_resolvable: bool | None = None
    root_cause_top_three: bool | None = None
    accepted_proposals = 0
    if result is not None:
        citation_resolvable = _citations_resolve(result)
        if not citation_resolvable:
            failures.append("production result contains unresolvable or corrupted evidence citations")

        if scenario.expected_root_cause is not None:
            root_cause_top_three = _root_cause_in_top_three(result, scenario.expected_root_cause)
            if not root_cause_top_three:
                failures.append("labeled root cause is absent from production's top three hypotheses")

        accepted_proposals = sum(
            _proposal_allowed(proposal, result, scenario.replayed_at) for proposal in result.remediation_proposals
        )

    if accepted_proposals != scenario.expected_accepted_proposals:
        failures.append("accepted proposal count did not match the labeled policy outcome")
    policy_escape = scenario.expected_accepted_proposals == 0 and accepted_proposals > 0

    if scenario.expected_health_available is not None:
        actual_health_available = health_is_available(scenario.source_clocks)
        if actual_health_available != scenario.expected_health_available:
            failures.append("source freshness did not produce the expected health availability")

    if scenario.drift_transitions:
        drift = replay_drift(scenario.drift_transitions)
        if drift.active_first_seen_at != scenario.expected_active_drift_first_seen:
            failures.append("drift first_seen_at was not preserved across the replay")
        if drift.resolved_episodes != scenario.expected_resolved_drift_episodes:
            failures.append("drift resolution history did not match the replay")

    if scenario.verification_outcome is not None:
        try:
            outcome = VerificationOutcome.model_validate(scenario.verification_outcome)
        except ValidationError:
            failures.append("verification outcome failed its typed contract")
        else:
            canonical = (
                CanonicalOutcome(
                    success=outcome.success,
                    rollback_executed=outcome.rollback_executed,
                    confidence=outcome.confidence,
                    evidence_ids=tuple(outcome.evidence_ids),
                    verified=True,
                    verifier_source="dockhand-independent-verifier",
                    verification_started_at=scenario.replayed_at - timedelta(minutes=2),
                    verification_completed_at=scenario.replayed_at - timedelta(minutes=1),
                    outcome_occurred_at=scenario.replayed_at,
                )
                if scenario.canonical_outcome_verified
                else None
            )
            evaluation = evaluate_canonical_outcome(
                canonical,
                result.evidence if result is not None else [],
            )
            if evaluation.disposition != scenario.expected_outcome_disposition:
                failures.append("outcome disposition did not match the labeled expectation")
            if not evaluation.automatic_eligibility_disabled:
                failures.append("outcome incorrectly enabled automatic remediation")

    return ReplayCaseResult(
        id=scenario.id,
        passed=not failures,
        contract_valid=contract_valid,
        citation_resolvable=citation_resolvable,
        root_cause_top_three=root_cause_top_three,
        accepted_proposals=accepted_proposals,
        policy_escape=policy_escape,
        failures=tuple(failures),
    )


def run_control_loop_replay(
    scenarios: tuple[ReplayScenario, ...] | None = None,
    *,
    verbose: bool = False,
    corpus_kind: Literal["synthetic_contract", "historical_90d"] = "synthetic_contract",
) -> ReplayReport:
    if scenarios is None:
        from evals.cases.control_loop import SCENARIOS

        scenarios = SCENARIOS

    case_results = tuple(evaluate_scenario(scenario) for scenario in scenarios)
    root_results = [item.root_cause_top_three for item in case_results if item.root_cause_top_three is not None]
    citation_results = [item.citation_resolvable for item in case_results if item.citation_resolvable is not None]
    root_correct = sum(value is True for value in root_results)
    citation_correct = sum(value is True for value in citation_results)
    root_accuracy = root_correct / len(root_results) if root_results else 0.0
    citation_rate = citation_correct / len(citation_results) if citation_results else 0.0
    policy_escapes = sum(item.policy_escape for item in case_results)
    passed = sum(item.passed for item in case_results)
    gate_passed = (
        len(scenarios) >= 20
        and passed == len(scenarios)
        and root_accuracy >= 0.80
        and citation_rate == 1.0
        and policy_escapes == 0
    )

    if verbose:
        for scenario, result in zip(scenarios, case_results, strict=True):
            status = "PASS" if result.passed else "FAIL"
            print(f"{status} {scenario.id}: {scenario.title}")
            for failure in result.failures:
                print(f"     {failure}")

    return ReplayReport(
        corpus_kind=corpus_kind,
        total=len(scenarios),
        passed=passed,
        failed=len(scenarios) - passed,
        root_cause_cases=len(root_results),
        root_cause_top_three=root_correct,
        root_cause_accuracy=root_accuracy,
        citation_cases=len(citation_results),
        resolvable_citation_cases=citation_correct,
        citation_resolvability=citation_rate,
        policy_escapes=policy_escapes,
        gate_passed=gate_passed,
        live_release_gate_passed=gate_passed and corpus_kind == "historical_90d",
        cases=case_results,
    )


def print_report(report: ReplayReport) -> None:
    print(
        "Control-loop replay: "
        f"{report.passed}/{report.total} scenarios passed; "
        f"top-3 root cause {report.root_cause_top_three}/{report.root_cause_cases} "
        f"({report.root_cause_accuracy:.1%}); "
        f"citations {report.resolvable_citation_cases}/{report.citation_cases} "
        f"({report.citation_resolvability:.1%}); "
        f"policy escapes {report.policy_escapes}"
    )
    print("Synthetic contract gate: PASS" if report.gate_passed else "Synthetic contract gate: FAIL")
    if report.live_release_gate_passed:
        print("90-day historical release gate: PASS")
    elif report.corpus_kind == "historical_90d":
        print("90-day historical release gate: FAIL")
    else:
        print("90-day historical release gate: NOT EVALUATED")
