from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from agent_audit_kit.evidence import EvidencePacket, verify_evidence_packet
from agent_audit_kit.gate import gate_candidate
from agent_audit_kit.guard import guard_candidate_output
from agent_audit_kit.models import AuditConfig, AuditResult, CandidateOutput, CustomGuard, Finding, PreflightPolicy
from agent_audit_kit.preflight import preflight_check


def _as_findings(value: Finding | tuple[Finding, ...] | list[Finding] | None) -> tuple[Finding, ...]:
    if value is None:
        return ()
    if isinstance(value, Finding):
        return (value,)
    return tuple(value)


def audit_candidate(
    output: CandidateOutput,
    *,
    config: AuditConfig | None = None,
    envelope: Mapping[str, Any] | None = None,
    policy: PreflightPolicy | None = None,
    custom_guards: tuple[CustomGuard, ...] = (),
    review_callback: Callable[[AuditResult], None] | None = None,
) -> AuditResult:
    """Audit one agent output and return an approved, review, or blocked result.

    The default path runs output guardrails, evidence checks, and the final gate.
    Pass a preflight envelope plus policy to check tool/action scope. Pass custom
    guards for domain-specific review rules.
    """

    findings: list[Finding] = []
    active_config = config or AuditConfig()
    active_policy = policy or active_config.policy
    active_guards = (*active_config.custom_guards, *custom_guards)

    if envelope is not None and active_policy is not None:
        findings.extend(preflight_check(envelope, active_policy))

    guarded_output, guard_findings = guard_candidate_output(output)
    findings.extend(guard_findings)

    for guard in active_guards:
        findings.extend(_as_findings(guard(guarded_output)))

    if active_config.require_evidence:
        evidence = EvidencePacket.from_mapping(guarded_output.evidence)
        findings.extend(verify_evidence_packet(evidence))

    decision = gate_candidate(tuple(findings))
    result = AuditResult(
        status=decision.status,
        output=guarded_output,
        findings=tuple(findings),
        redacted_content=guarded_output.content if guard_findings else None,
    )
    if review_callback is not None and not result.passed:
        review_callback(result)
    return result


async def audit_candidate_async(
    output: CandidateOutput,
    *,
    config: AuditConfig | None = None,
    envelope: Mapping[str, Any] | None = None,
    policy: PreflightPolicy | None = None,
    custom_guards: tuple[CustomGuard, ...] = (),
    review_callback: Callable[[AuditResult], None] | None = None,
) -> AuditResult:
    """Async-compatible wrapper around audit_candidate."""

    return audit_candidate(
        output,
        config=config,
        envelope=envelope,
        policy=policy,
        custom_guards=custom_guards,
        review_callback=review_callback,
    )
