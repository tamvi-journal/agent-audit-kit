from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Callable, Iterable
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


@dataclass(frozen=True)
class AuditResult:
    status: str
    output: CandidateOutput
    findings: tuple[Finding, ...] = ()
    redacted_content: str | None = None

    @property
    def passed(self) -> bool:
        return self.status == "approved_candidate"

    @property
    def explanations(self) -> tuple[str, ...]:
        return tuple(
            f"{finding.severity}: {finding.kind} - {finding.message}"
            for finding in self.findings
        )


@dataclass(frozen=True)
class AuditConfig:
    policy: PreflightPolicy | None = None
    custom_guards: tuple[CustomGuard, ...] = ()
    require_evidence: bool = True
