from __future__ import annotations

from dataclasses import replace

from agent_audit_kit.models import CandidateOutput, Finding
from agent_audit_kit.secret_scan import scan_text


def guard_candidate_output(output: CandidateOutput) -> tuple[CandidateOutput, tuple[Finding, ...]]:
    scan = scan_text(output.content, source="candidate.content")
    guarded_output = replace(output, content=scan.redacted_text) if scan.has_findings else output
    return guarded_output, scan.findings
