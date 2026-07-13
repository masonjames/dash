"""Strict typed contract between Dockhand and Dash's private Ops service."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from math import isfinite
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ContractModel(BaseModel):
    """Fail closed when independently deployed services disagree on the contract."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RiskClass(StrEnum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"


class CauseCode(StrEnum):
    """Stable machine-readable taxonomy emitted by the production reasoner."""

    CONTAINER_OOM = "container_oom"
    DOCKER_VOLUME_PRESSURE = "docker_volume_pressure"
    CONFIGURATION_DRIFT = "configuration_drift"
    SERVICE_UNHEALTHY = "service_unhealthy"
    STALE_SOURCE_DATA = "stale_source_data"
    HEALTHY_CONTROL_LOOP = "healthy_control_loop"
    CPU_PRESSURE = "cpu_pressure"
    HOST_MEMORY_PRESSURE = "host_memory_pressure"
    DEPLOYMENT_FAILURE = "deployment_failure"
    BACKUP_STALE = "backup_stale"
    POSTCONDITION_FAILURE = "postcondition_failure"


_FORBIDDEN_EXECUTION_KEYS = {
    "args",
    "argv",
    "cmd",
    "code",
    "command",
    "executable",
    "exec",
    "program",
    "script",
    "shell",
    "shellcode",
}
_FORBIDDEN_EXECUTION_MARKERS = (
    "#!/bin/",
    "/bin/bash",
    "/bin/sh",
    "cmd.exe /c",
    "powershell -command",
    "powershell.exe",
    "$(",
    "`",
)
_FORBIDDEN_COMMAND_PATTERN = re.compile(
    r"(?:^|\s)(?:sudo\s+)?(?:bash|chmod|chown|curl|docker|eval|exec|kubectl|node|"
    r"python|reboot|rm|scp|sh|shutdown|ssh|systemctl|touch|wget)\s+",
    re.IGNORECASE,
)
_REDACTED_VALUES = {
    "[redacted]",
    "<redacted>",
    "***redacted***",
    "redacted",
}
_SECRET_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "connection_string",
    "cookie",
    "database_url",
    "db_pass",
    "password",
    "passwd",
    "passphrase",
    "private_key",
    "proxy_authorization",
    "refresh_token",
    "secret",
    "set_cookie",
}
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    re.compile(r"(?i)://[^:/\s]+:[^@\s/]+@"),
    re.compile(
        r"(?i)(?:[?&]|\b)(?:access[_-]?token|api[_-]?key|client[_-]?secret|"
        r"password|passwd|refresh[_-]?token)\s*[=:]\s*[^&\s]+"
    ),
)


def _normalise_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


def _reject_arbitrary_execution(value: Any, path: str = "arguments") -> None:
    """Reject executable material at any nesting depth.

    This is defense in depth. Dockhand remains responsible for resolving proposal
    intent through its closed registry before any execution is possible.
    """

    if isinstance(value, dict):
        for raw_key, nested in value.items():
            key = _normalise_key(str(raw_key))
            if (
                key in _FORBIDDEN_EXECUTION_KEYS
                or key.endswith(("_command", "_script", "_shell", "_code"))
                or key.startswith(("command_", "script_", "shell_"))
            ):
                raise ValueError(f"arbitrary execution field is forbidden at {path}.{raw_key}")
            _reject_arbitrary_execution(nested, f"{path}.{raw_key}")
        return

    if isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_arbitrary_execution(nested, f"{path}[{index}]")
        return

    if isinstance(value, str):
        lowered = value.casefold()
        if (
            any(marker in lowered for marker in _FORBIDDEN_EXECUTION_MARKERS)
            or "\n" in value
            or "\r" in value
            or _FORBIDDEN_COMMAND_PATTERN.search(value)
        ):
            raise ValueError(f"executable content is forbidden at {path}")


def _is_redacted(value: Any) -> bool:
    return isinstance(value, str) and value.strip().casefold() in _REDACTED_VALUES


def _reject_secret_material(value: Any, path: str = "payload") -> None:
    """Reject common credential material even when an upstream redaction flag is wrong.

    This intentionally operates on canonical evidence payloads only. It is not a
    general-purpose secret scanner, but it prevents the high-risk credential forms
    that can otherwise leak through headers, URLs, and captured tool arguments.
    """

    if isinstance(value, dict):
        for raw_key, nested in value.items():
            key = _normalise_key(str(raw_key))
            sensitive_key = key in _SECRET_KEYS or key.endswith(
                ("_api_key", "_password", "_private_key", "_secret", "_token")
            )
            if sensitive_key and not _is_redacted(nested):
                raise ValueError(f"unredacted secret field is forbidden at {path}.{raw_key}")
            _reject_secret_material(nested, f"{path}.{raw_key}")
        return

    if isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_secret_material(nested, f"{path}[{index}]")
        return

    if isinstance(value, str) and not _is_redacted(value):
        if any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS):
            raise ValueError(f"unredacted secret material is forbidden at {path}")


class EvidenceReference(ContractModel):
    id: str = Field(min_length=1, max_length=200)
    kind: str = Field(min_length=1, max_length=100)
    captured_at: datetime
    observation_started_at: datetime
    observation_ended_at: datetime
    expires_at: datetime
    source: str = Field(min_length=1, max_length=200)
    query_version: str = Field(min_length=1, max_length=100)
    scope: dict[str, Any]
    redaction_version: str = Field(min_length=1, max_length=100)
    summary: str = Field(min_length=1, max_length=2000)
    freshness_seconds: int = Field(ge=0)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    redacted: Literal[True] = True
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("payload")
    @classmethod
    def reject_secret_material(cls, value: dict[str, Any]) -> dict[str, Any]:
        _reject_secret_material(value)
        return value

    @model_validator(mode="after")
    def validate_evidence_envelope(self) -> "EvidenceReference":
        # Secrets can leak through labels and provenance just as easily as through
        # the JSON payload. Validate the complete evidence envelope before any
        # factual claim is allowed to cite it.
        _reject_secret_material(
            {
                "source": self.source,
                "query_version": self.query_version,
                "scope": self.scope,
                "summary": self.summary,
            },
            "evidence",
        )
        if any(
            value.tzinfo is None
            for value in (
                self.captured_at,
                self.observation_started_at,
                self.observation_ended_at,
                self.expires_at,
            )
        ):
            raise ValueError("evidence timestamps must be timezone-aware")
        if self.observation_started_at > self.observation_ended_at:
            raise ValueError("evidence observation window is inverted")
        if self.observation_ended_at > self.captured_at:
            raise ValueError("evidence cannot be captured before its observation ends")
        if self.expires_at <= self.observation_ended_at:
            raise ValueError("evidence expiry must follow its observation window")
        return self


class RankedHypothesis(ContractModel):
    rank: int = Field(ge=1)
    cause_code: CauseCode
    detector_version: str = Field(min_length=1, max_length=100)
    signal_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    statement: str = Field(min_length=1, max_length=4000)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(min_length=1, max_length=100)


class HistoricalComparable(ContractModel):
    incident_id: str = Field(min_length=1, max_length=200)
    similarity: float = Field(ge=0, le=1)
    reason: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[str] = Field(min_length=1, max_length=100)


class RemediationProposal(ContractModel):
    proposal_type: Literal["job", "playbook", "desired_state_pr"]
    job_kind: str | None = Field(default=None, min_length=1, max_length=200)
    playbook_id: str | None = Field(default=None, min_length=1, max_length=200)
    playbook_version: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)
    risk_class: RiskClass
    target_environment: str = Field(min_length=1, max_length=100)
    preconditions: list[str] = Field(min_length=1, max_length=100)
    evidence_ids: list[str] = Field(min_length=1, max_length=100)
    evidence_max_age_seconds: int = Field(gt=0)
    rollback_steps: list[str] = Field(min_length=1, max_length=100)
    postconditions: list[str] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_registered_target(self) -> "RemediationProposal":
        if self.proposal_type == "job":
            if not self.job_kind or not self.playbook_id:
                raise ValueError("job proposals require job_kind and the registered playbook_id")
        elif self.proposal_type == "playbook":
            if not self.playbook_id or self.job_kind is not None:
                raise ValueError("playbook proposals require only playbook_id")
        elif not self.playbook_id or self.job_kind is not None:
            raise ValueError("desired-state PR proposals require their registered playbook_id only")

        _reject_arbitrary_execution(self.arguments)
        return self


class ArgumentProperty(ContractModel):
    """Supported, deliberately small JSON-Schema subset for proposal arguments."""

    type: Literal["string", "integer", "number", "boolean"]
    minLength: int | None = Field(default=None, ge=0, le=4000)
    maxLength: int | None = Field(default=None, ge=1, le=4000)
    pattern: str | None = Field(default=None, min_length=1, max_length=500)
    minimum: float | None = None
    maximum: float | None = None

    @model_validator(mode="after")
    def validate_constraints(self) -> "ArgumentProperty":
        string_constraints = self.minLength is not None or self.maxLength is not None or self.pattern is not None
        numeric_constraints = self.minimum is not None or self.maximum is not None
        if self.type != "string" and string_constraints:
            raise ValueError("string constraints require type=string")
        if self.type not in {"integer", "number"} and numeric_constraints:
            raise ValueError("numeric constraints require an integer or number type")
        if self.minLength is not None and self.maxLength is not None and self.minLength > self.maxLength:
            raise ValueError("minLength cannot exceed maxLength")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("minimum cannot exceed maximum")
        if self.pattern is not None:
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError("argument pattern is not a valid regular expression") from exc
        return self

    def accepts(self, value: Any) -> bool:
        if self.type == "string":
            if not isinstance(value, str):
                return False
            if self.minLength is not None and len(value) < self.minLength:
                return False
            if self.maxLength is not None and len(value) > self.maxLength:
                return False
            return self.pattern is None or re.fullmatch(self.pattern, value) is not None
        if self.type == "boolean":
            return isinstance(value, bool)
        if self.type == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                return False
            numeric = float(value)
        else:
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return False
            numeric = float(value)
        if not isfinite(numeric):
            return False
        return (self.minimum is None or numeric >= self.minimum) and (self.maximum is None or numeric <= self.maximum)


class ArgumentSchema(ContractModel):
    """Closed object schema signed by Dockhand as part of the request catalog."""

    type: Literal["object"]
    additionalProperties: Literal[False]
    required: list[str] = Field(default_factory=list, max_length=50)
    properties: dict[str, ArgumentProperty] = Field(default_factory=dict, max_length=50)

    @model_validator(mode="after")
    def validate_object_schema(self) -> "ArgumentSchema":
        if len(self.required) != len(set(self.required)):
            raise ValueError("argument schema required fields must be unique")
        missing = set(self.required) - set(self.properties)
        if missing:
            raise ValueError(f"argument schema required fields are undefined: {sorted(missing)}")
        if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", name) for name in self.properties):
            raise ValueError("argument schema contains an invalid property name")
        return self

    def accepts(self, arguments: dict[str, Any]) -> bool:
        supplied = set(arguments)
        if set(self.required) - supplied or supplied - set(self.properties):
            return False
        return all(self.properties[name].accepts(value) for name, value in arguments.items())


class ProposalCatalogEntry(ContractModel):
    """A request-scoped, HMAC-authenticated view of a Dockhand playbook definition."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]+$", max_length=200)
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$", max_length=100)
    enabled: bool = True
    proposal_type: Literal["job", "playbook", "desired_state_pr"]
    job_kind: str | None = Field(default=None, min_length=1, max_length=200)
    risk_class: RiskClass
    allowed_environments: list[str] = Field(min_length=1, max_length=50)
    required_arguments: list[str] = Field(default_factory=list, max_length=50)
    optional_arguments: list[str] = Field(default_factory=list, max_length=50)
    argument_schema: ArgumentSchema
    evidence_max_age_seconds: int = Field(gt=0, le=86_400)
    preconditions: list[str] = Field(min_length=1, max_length=100)
    rollback_steps: list[str] = Field(min_length=1, max_length=100)
    postconditions: list[str] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_catalog_entry(self) -> "ProposalCatalogEntry":
        if self.proposal_type == "job" and not self.job_kind:
            raise ValueError("job catalog entries require job_kind")
        if self.proposal_type != "job" and self.job_kind is not None:
            raise ValueError("only job catalog entries may declare job_kind")
        if len(self.allowed_environments) != len(set(self.allowed_environments)):
            raise ValueError("catalog allowed_environments must be unique")
        required = set(self.required_arguments)
        optional = set(self.optional_arguments)
        if len(required) != len(self.required_arguments) or len(optional) != len(self.optional_arguments):
            raise ValueError("catalog argument names must be unique")
        if required & optional:
            raise ValueError("catalog required and optional arguments must be disjoint")
        if required != set(self.argument_schema.required):
            raise ValueError("catalog required_arguments must match argument_schema.required")
        if required | optional != set(self.argument_schema.properties):
            raise ValueError("catalog argument lists must exactly match argument_schema.properties")
        return self


class ProposalCatalog(ContractModel):
    """Versioned closed-world catalog supplied by Dockhand for one investigation."""

    registry_version: str = Field(min_length=1, max_length=100)
    playbooks: list[ProposalCatalogEntry] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def reject_duplicate_definitions(self) -> "ProposalCatalog":
        identities = [(item.id, item.version) for item in self.playbooks]
        if len(identities) != len(set(identities)):
            raise ValueError("proposal catalog contains duplicate playbook definitions")
        return self


class OpsInvestigationRequest(ContractModel):
    investigation_id: str = Field(min_length=1, max_length=200)
    prompt: str = Field(min_length=3, max_length=4000)
    environment: str | None = Field(default=None, max_length=100)
    service: str | None = Field(default=None, max_length=200)
    incident_id: str | None = Field(default=None, max_length=200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    model_version: str | None = Field(default=None, max_length=200)
    proposal_catalog: ProposalCatalog

    @field_validator("evidence_ids")
    @classmethod
    def unique_evidence_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("evidence IDs must be unique")
        return value


class OpsInvestigationResult(ContractModel):
    investigation_id: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=4000)
    summary_evidence_ids: list[str] = Field(max_length=100)
    evidence: list[EvidenceReference] = Field(max_length=100)
    hypotheses: list[RankedHypothesis] = Field(max_length=20)
    confidence: float = Field(ge=0, le=1)
    historical_comparables: list[HistoricalComparable] = Field(max_length=20)
    remediation_proposals: list[RemediationProposal] = Field(max_length=20)
    model_version: str = Field(min_length=1, max_length=200)
    generated_at: datetime

    @model_validator(mode="after")
    def validate_citations(self) -> "OpsInvestigationResult":
        known = {item.id for item in self.evidence}
        cited = set(self.summary_evidence_ids)
        for hypothesis in self.hypotheses:
            cited.update(hypothesis.evidence_ids)
        for comparable in self.historical_comparables:
            cited.update(comparable.evidence_ids)
        for proposal in self.remediation_proposals:
            cited.update(proposal.evidence_ids)
        unknown = cited - known
        if unknown:
            raise ValueError(f"unresolvable evidence citations: {sorted(unknown)}")
        if (self.hypotheses or self.remediation_proposals) and not known:
            raise ValueError("claims and proposals require stored evidence")
        return self


class VerificationOutcome(ContractModel):
    verification_run_id: str = Field(min_length=1, max_length=200)
    investigation_id: str = Field(min_length=1, max_length=200)
    proposal_id: str = Field(min_length=1, max_length=200)
    incident_id: str | None = Field(default=None, max_length=200)
    playbook_id: str = Field(min_length=1, max_length=200)
    playbook_version: str = Field(min_length=1, max_length=100)
    success: bool
    rollback_executed: bool = False
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(min_length=1, max_length=100)
    observations: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("evidence_ids")
    @classmethod
    def unique_evidence_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("evidence IDs must be unique")
        return value


class OutcomeEvaluation(ContractModel):
    eligible_candidate: bool
    disposition: Literal["candidate", "failed", "rollback", "insufficient_evidence"]
    learning_summary: str = Field(min_length=1, max_length=4000)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(max_length=100)
    automatic_eligibility_disabled: bool
