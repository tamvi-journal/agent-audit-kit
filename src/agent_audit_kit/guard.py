from __future__ import annotations

from dataclasses import replace

from agent_audit_kit.models import CandidateOutput, Finding
from agent_audit_kit.secret_scan import scan_text


def guard_candidate_output(output: CandidateOutput) -> tuple[CandidateOutput, tuple[Finding, ...]]:
    """Redact known secret-like patterns and return guard findings.

    The guard is pattern-based. Passing it does not guarantee that output has no
    secrets, and redaction here does not un-leak content already written to logs,
    disk, or git history.
    """

    if not isinstance(output.content, str):
        finding = Finding(
            "invalid_candidate_content",
            "Candidate content must be a string.",
            source="candidate.content",
            severity="high",
        )
        return replace(output, content=""), (finding,)

    scan = scan_text(output.content, source="candidate.content")
    guarded_output = replace(output, content=scan.redacted_text) if scan.has_secret_findings else output
    findings = list(scan.findings)
    if not output.content.strip():
        findings.append(
            Finding(
                "empty_candidate_content",
                "Candidate content must not be blank.",
                source="candidate.content",
            )
        )
    return guarded_output, tuple(findings)
