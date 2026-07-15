from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_audit_kit.evidence import EvidencePacket, verify_evidence_packet
from agent_audit_kit.gate import gate_candidate
from agent_audit_kit.guard import guard_candidate_output
from agent_audit_kit.models import AuditResult, CandidateOutput, Finding, PreflightPolicy
from agent_audit_kit.preflight import preflight_check


def audit_candidate(
    output: CandidateOutput,
    *,
    envelope: Mapping[str, Any] | None = None,
    policy: PreflightPolicy | None = None,
) -> AuditResult:
    findings: list[Finding] = []

    if envelope is not None and policy is not None:
        findings.extend(preflight_check(envelope, policy))

    guarded_output, guard_findings = guard_candidate_output(output)
    findings.extend(guard_findings)

    evidence = EvidencePacket.from_mapping(guarded_output.evidence)
    findings.extend(verify_evidence_packet(evidence))

    decision = gate_candidate(tuple(findings))
    return AuditResult(
        status=decision.status,
        output=guarded_output,
        findings=tuple(findings),
        redacted_content=guarded_output.content if guard_findings else None,
    )
