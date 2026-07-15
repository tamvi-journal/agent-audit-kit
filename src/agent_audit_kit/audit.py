from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from inspect import isawaitable
from typing import Any

from agent_audit_kit.evidence import EvidencePacket, verify_evidence_packet
from agent_audit_kit.gate import gate_candidate
from agent_audit_kit.guard import guard_candidate_output
from agent_audit_kit.models import (
    AuditConfig,
    AuditResult,
    CandidateOutput,
    CustomGuard,
    Finding,
    GuardedTaskResult,
    PreflightPolicy,
)
from agent_audit_kit.preflight import preflight_check, preflight_task


WorkerFn = Callable[[Mapping[str, Any]], CandidateOutput]
AsyncWorkerFn = Callable[[Mapping[str, Any]], CandidateOutput | Awaitable[CandidateOutput]]
ReviewCallback = Callable[[AuditResult], None]


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
    verified_evidence: Mapping[str, Any] | EvidencePacket | None = None,
    envelope: Mapping[str, Any] | None = None,
    policy: PreflightPolicy | None = None,
    custom_guards: tuple[CustomGuard, ...] = (),
    review_callback: ReviewCallback | None = None,
) -> AuditResult:
    """Audit worker output after execution.

    This function is the output-side audit gate. If `envelope` and `policy` are
    passed, they are checked retrospectively for compatibility with older code,
    but that check does not replace pre-execution `preflight_task()`.

    `approved_candidate` means eligible under the configured checks. It does not
    prove the content is true.
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

    verifier_output = verified_evidence
    if verifier_output is None and active_config.verifier is not None:
        verifier_output = active_config.verifier(guarded_output)

    claimed_packet = EvidencePacket.from_mapping(guarded_output.evidence)
    verified_packet = _coerce_evidence(verifier_output)
    findings.extend(
        verify_evidence_packet(
            claimed_packet,
            verified_packet,
            require_claimed=active_config.require_claimed_evidence,
            require_verified=active_config.require_verified_evidence,
            worker_identity=_worker_identity(guarded_output, envelope),
        )
    )

    decision = gate_candidate(tuple(findings))
    has_secret_redaction = any(finding.kind != "secret_scan_scope" for finding in guard_findings)
    result = AuditResult(
        status=decision.status,
        output=guarded_output,
        findings=tuple(findings),
        redacted_content=guarded_output.content if has_secret_redaction else None,
    )
    if review_callback is not None and not result.eligible_for_release:
        review_callback(result)
    return result


async def audit_candidate_async(
    output: CandidateOutput,
    *,
    config: AuditConfig | None = None,
    verified_evidence: Mapping[str, Any] | EvidencePacket | None = None,
    envelope: Mapping[str, Any] | None = None,
    policy: PreflightPolicy | None = None,
    custom_guards: tuple[CustomGuard, ...] = (),
    review_callback: ReviewCallback | None = None,
) -> AuditResult:
    """Async-compatible wrapper with the same trust-boundary semantics."""

    return audit_candidate(
        output,
        config=config,
        verified_evidence=verified_evidence,
        envelope=envelope,
        policy=policy,
        custom_guards=custom_guards,
        review_callback=review_callback,
    )


def run_guarded_task(
    envelope: Mapping[str, Any],
    policy: PreflightPolicy,
    worker_fn: WorkerFn,
    *,
    config: AuditConfig | None = None,
    verified_evidence: Mapping[str, Any] | EvidencePacket | None = None,
    verifier: Callable[[CandidateOutput], Mapping[str, Any] | None] | None = None,
    review_callback: ReviewCallback | None = None,
) -> GuardedTaskResult:
    """Run preflight before invoking the worker, then audit the candidate output."""

    preflight = preflight_task(envelope, policy)
    if not preflight.can_execute:
        return GuardedTaskResult(preflight.status, preflight, audit=None, worker_ran=False)

    output = worker_fn(envelope)
    active_config = _with_verifier(config or AuditConfig(), verifier)
    audit = audit_candidate(
        output,
        config=active_config,
        verified_evidence=verified_evidence,
        custom_guards=(),
        review_callback=review_callback,
    )
    return GuardedTaskResult(audit.status, preflight, audit=audit, worker_ran=True)


async def run_guarded_task_async(
    envelope: Mapping[str, Any],
    policy: PreflightPolicy,
    worker_fn: AsyncWorkerFn,
    *,
    config: AuditConfig | None = None,
    verified_evidence: Mapping[str, Any] | EvidencePacket | None = None,
    verifier: Callable[[CandidateOutput], Mapping[str, Any] | None] | None = None,
    review_callback: ReviewCallback | None = None,
) -> GuardedTaskResult:
    """Async preflight -> worker -> audit helper."""

    preflight = preflight_task(envelope, policy)
    if not preflight.can_execute:
        return GuardedTaskResult(preflight.status, preflight, audit=None, worker_ran=False)

    maybe_output = worker_fn(envelope)
    output = await maybe_output if isawaitable(maybe_output) else maybe_output
    active_config = _with_verifier(config or AuditConfig(), verifier)
    audit = await audit_candidate_async(
        output,
        config=active_config,
        verified_evidence=verified_evidence,
        custom_guards=(),
        review_callback=review_callback,
    )
    return GuardedTaskResult(audit.status, preflight, audit=audit, worker_ran=True)


def _coerce_evidence(value: Mapping[str, Any] | EvidencePacket | None) -> EvidencePacket | None:
    if value is None:
        return None
    if isinstance(value, EvidencePacket):
        return value
    return EvidencePacket.from_mapping(value)


def _worker_identity(output: CandidateOutput, envelope: Mapping[str, Any] | None) -> str | None:
    for source in (output.metadata, envelope or {}):
        for key in ("worker_id", "worker", "agent_id"):
            value = source.get(key)
            if value:
                return str(value)
    return None


def _with_verifier(
    config: AuditConfig,
    verifier: Callable[[CandidateOutput], Mapping[str, Any] | None] | None,
) -> AuditConfig:
    if verifier is None:
        return config
    return replace(config, verifier=verifier)
