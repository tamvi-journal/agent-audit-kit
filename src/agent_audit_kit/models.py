from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any


CONTRACT_VERSION = "1.0"


def _policy_text_tuple(value: Any, *, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, (list, tuple, set)):
        raise ValueError(f"{field_name} must be a string or a list of nonblank strings")

    normalized: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{field_name} must contain only nonblank strings")
        normalized.append(item.strip())
    return tuple(normalized)


def _policy_bool(data: Mapping[str, Any], field_name: str) -> bool:
    if field_name not in data:
        return False
    value = data[field_name]
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")
    return value


def _mapping_copy(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return deepcopy(dict(value))
    return {}


@dataclass(frozen=True)
class Finding:
    kind: str
    message: str
    source: str = ""
    severity: str = "medium"
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "message": self.message,
            "source": self.source,
            "severity": self.severity,
            "details": deepcopy(dict(self.details)),
        }


@dataclass(frozen=True)
class PreflightPolicy:
    allowed_actions: tuple[str, ...] = ()
    approval_required_actions: tuple[str, ...] = ()
    blocked_actions: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    forbidden_tools: tuple[str, ...] = ()
    network_allowed: bool = False
    shell_allowed: bool = False
    external_mutation_allowed: bool = False
    money_touching_allowed: bool = False
    completion_authority: bool = False

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "PreflightPolicy":
        data = dict(value or {})
        return cls(
            allowed_actions=_policy_text_tuple(
                data.get("allowed_actions"), field_name="allowed_actions"
            ),
            approval_required_actions=_policy_text_tuple(
                data.get("approval_required_actions"),
                field_name="approval_required_actions",
            ),
            blocked_actions=_policy_text_tuple(
                data.get("blocked_actions"), field_name="blocked_actions"
            ),
            allowed_tools=_policy_text_tuple(
                data.get("allowed_tools"), field_name="allowed_tools"
            ),
            forbidden_tools=_policy_text_tuple(
                data.get("forbidden_tools"), field_name="forbidden_tools"
            ),
            network_allowed=_policy_bool(data, "network_allowed"),
            shell_allowed=_policy_bool(data, "shell_allowed"),
            external_mutation_allowed=_policy_bool(data, "external_mutation_allowed"),
            money_touching_allowed=_policy_bool(data, "money_touching_allowed"),
            completion_authority=_policy_bool(data, "completion_authority"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": CONTRACT_VERSION,
            "allowed_actions": list(self.allowed_actions),
            "approval_required_actions": list(self.approval_required_actions),
            "blocked_actions": list(self.blocked_actions),
            "allowed_tools": list(self.allowed_tools),
            "forbidden_tools": list(self.forbidden_tools),
            "network_allowed": self.network_allowed,
            "shell_allowed": self.shell_allowed,
            "external_mutation_allowed": self.external_mutation_allowed,
            "money_touching_allowed": self.money_touching_allowed,
            "completion_authority": self.completion_authority,
        }


@dataclass(frozen=True)
class CandidateOutput:
    content: str
    evidence: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "CandidateOutput":
        data = dict(value or {})
        content: str | None = None
        for key in ("content", "output", "text", "summary"):
            if key not in data:
                continue
            item = data[key]
            if not isinstance(item, str):
                raise ValueError(f"{key} must be a string")
            content = item
            break
        if content is None:
            raise ValueError(
                "Candidate packet must contain one of: content, output, text, summary"
            )

        evidence = _mapping_copy(data.get("evidence"))
        if not evidence:
            sources = data.get("claimed_sources") or data.get("sources")
            checks_run = data.get("claimed_checks") or data.get("checks_run")
            artifacts = (
                data.get("evidence_handles")
                or data.get("artifact_handles")
                or data.get("artifacts")
            )
            if sources is not None:
                evidence["sources"] = deepcopy(sources)
            if checks_run is not None:
                evidence["checks_run"] = deepcopy(checks_run)
            if artifacts is not None:
                evidence["artifacts"] = deepcopy(artifacts)

        metadata = _mapping_copy(data.get("metadata"))
        for key in ("worker_id", "agent_id", "worker", "worker_type", "task_id"):
            if key in data and key not in metadata:
                metadata[key] = deepcopy(data[key])

        return cls(content=content, evidence=evidence, metadata=metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": CONTRACT_VERSION,
            "content": self.content,
            "evidence": deepcopy(dict(self.evidence)),
            "metadata": deepcopy(dict(self.metadata)),
        }


CustomGuard = Callable[[CandidateOutput], Finding | Iterable[Finding] | None]
EvidenceVerifier = Callable[[CandidateOutput], Mapping[str, Any] | None]
ArtifactResolver = Callable[[str], bool]


@dataclass(frozen=True)
class PreflightResult:
    status: str
    findings: tuple[Finding, ...] = ()

    @property
    def can_execute(self) -> bool:
        return self.status == "allowed"

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    @property
    def needs_approval(self) -> bool:
        return self.status == "needs_approval"

    @property
    def explanations(self) -> tuple[str, ...]:
        return tuple(
            f"{finding.severity}: {finding.kind} - {finding.message}"
            for finding in self.findings
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": CONTRACT_VERSION,
            "status": self.status,
            "can_execute": self.can_execute,
            "findings": [finding.to_dict() for finding in self.findings],
            "explanations": list(self.explanations),
        }


@dataclass(frozen=True)
class AuditResult:
    status: str
    output: CandidateOutput
    findings: tuple[Finding, ...] = ()
    redacted_content: str | None = None

    @property
    def eligible_for_release(self) -> bool:
        return self.status == "approved_candidate"

    @property
    def passed(self) -> bool:
        return self.eligible_for_release

    @property
    def explanations(self) -> tuple[str, ...]:
        return tuple(
            f"{finding.severity}: {finding.kind} - {finding.message}"
            for finding in self.findings
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": CONTRACT_VERSION,
            "status": self.status,
            "eligible_for_release": self.eligible_for_release,
            "output": self.output.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "redacted_content": self.redacted_content,
            "explanations": list(self.explanations),
        }


@dataclass(frozen=True)
class GuardedTaskResult:
    status: str
    preflight: PreflightResult
    audit: AuditResult | None = None
    worker_ran: bool = False

    @property
    def eligible_for_release(self) -> bool:
        return bool(self.audit and self.audit.eligible_for_release)

    @property
    def explanations(self) -> tuple[str, ...]:
        if self.audit is None:
            return self.preflight.explanations
        return (*self.preflight.explanations, *self.audit.explanations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": CONTRACT_VERSION,
            "status": self.status,
            "eligible_for_release": self.eligible_for_release,
            "worker_ran": self.worker_ran,
            "preflight": self.preflight.to_dict(),
            "audit": self.audit.to_dict() if self.audit is not None else None,
            "explanations": list(self.explanations),
        }


@dataclass(frozen=True)
class AuditConfig:
    policy: PreflightPolicy | None = None
    custom_guards: tuple[CustomGuard, ...] = ()
    verifier: EvidenceVerifier | None = None
    artifact_resolver: ArtifactResolver | None = None
    require_claimed_evidence: bool = True
    require_verified_evidence: bool = True
