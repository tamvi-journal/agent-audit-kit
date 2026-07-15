from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class Finding:
    kind: str
    message: str
    source: str = ""
    severity: str = "medium"


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


@dataclass(frozen=True)
class AuditResult:
    status: str
    output: CandidateOutput
    findings: tuple[Finding, ...] = ()
    redacted_content: str | None = None

    @property
    def passed(self) -> bool:
        return self.status == "approved_candidate"
