from __future__ import annotations

from dataclasses import dataclass

from agent_audit_kit.models import CONTRACT_VERSION, Finding


BLOCKING_KINDS = {
    "blocked_action",
    "forbidden_tool",
    "openai_api_key",
    "github_token",
    "aws_access_key_id",
    "slack_token",
    "google_api_key",
    "jwt",
    "bearer_token",
    "database_dsn",
    "private_key_block",
}


@dataclass(frozen=True)
class GateDecision:
    status: str
    findings: tuple[Finding, ...]

    @property
    def approved(self) -> bool:
        return self.status == "approved_candidate"

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_version": CONTRACT_VERSION,
            "status": self.status,
            "approved": self.approved,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def gate_candidate(findings: tuple[Finding, ...]) -> GateDecision:
    """Convert findings into a final candidate status."""

    if any(finding.kind in BLOCKING_KINDS or finding.severity == "high" for finding in findings):
        return GateDecision("blocked_candidate", findings)
    actionable_findings = tuple(finding for finding in findings if finding.kind != "secret_scan_scope")
    if actionable_findings:
        return GateDecision("needs_review", findings)
    return GateDecision("approved_candidate", findings)
