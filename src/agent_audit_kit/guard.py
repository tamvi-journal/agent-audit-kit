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

    scan = scan_text(output.content, source="candidate.content")
    guarded_output = replace(output, content=scan.redacted_text) if scan.has_secret_findings else output
    return guarded_output, scan.findings
