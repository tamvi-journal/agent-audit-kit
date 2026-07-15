from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class Finding:
    kind: str
    message: str
    source: str = ""
    severity: str = "medium"
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PreflightPolicy:
    allowed_actions: tuple[str, ...] = ()
    approval_required_actions: tuple[str, ...] = ()
    blocked_actions: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    forbidden_tools: tuple[str, ...] = ()
    network_allowed: bool = False
    completion_authority: bool = False


@dataclass(frozen=True)
class CandidateOutput:
    content: str
    evidence: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)


CustomGuard = Callable[[CandidateOutput], Finding | Iterable[Finding] | None]
EvidenceVerifier = Callable[[CandidateOutput], Mapping[str, Any] | None]


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


@dataclass(frozen=True)
class AuditConfig:
    policy: PreflightPolicy | None = None
    custom_guards: tuple[CustomGuard, ...] = ()
    verifier: EvidenceVerifier | None = None
    require_claimed_evidence: bool = True
    require_verified_evidence: bool = True
