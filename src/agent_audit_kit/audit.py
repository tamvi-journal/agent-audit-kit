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


CandidateLike = CandidateOutput | Mapping[str, Any]
WorkerFn = Callable[[Mapping[str, Any]], CandidateLike]
AsyncWorkerFn = Callable[[Mapping[str, Any]], CandidateLike | Awaitable[CandidateLike]]
ReviewCallback = Callable[[AuditResult], None]


def _as_findings(value: Finding | tuple[Finding, ...] | list[Finding] | None) -> tuple[Finding, ...]:
    if value is None:
        return ()
    if isinstance(value, Finding):
        return (value,)
    return tuple(value)


def audit_candidate(
    output: CandidateLike,
    *,
    config: AuditConfig | None = None,
    verified_evidence: Mapping[str, Any] | EvidencePacket | None = None,
    envelope: Mapping[str, Any] | None = None,
    policy: PreflightPolicy | None = None,
    custom_guards: tuple[CustomGuard, ...] = (),
    review_callback: ReviewCallback | None = None,
) -> AuditResult:
    """Audit worker output after execution.

    Mapping-shaped worker packets are normalized into the shared candidate
    contract. approved_candidate means eligible under configured checks; it
    does not prove the content is true.
    """

    candidate = _coerce_candidate(output)
    findings: list[Finding] = []
    active_config = config or AuditConfig()
    active_policy = policy or active_config.policy
    active_guards = (*active_config.custom_guards, *custom_guards)

    if active_policy is not None and envelope is None:
        raise ValueError("policy requires envelope for audit")
    if envelope is not None and active_policy is not None:
        findings.extend(preflight_check(envelope, active_policy))

    guarded_output, guard_findings = guard_candidate_output(candidate)
    findings.extend(guard_findings)

    for guard in active_guards:
        findings.extend(_as_findings(guard(guarded_output)))

    verifier_output = verified_evidence
    if verifier_output is None and active_config.verifier is not None:
        verifier_output = active_config.verifier(guarded_output)

    worker_identity, identity_mismatch, invalid_identity = _worker_identities(guarded_output, envelope)
    if invalid_identity:
        findings.append(
            Finding(
                "invalid_worker_identity",
                "Worker identity fields must be nonblank strings.",
            )
        )

    claimed_packet = EvidencePacket.from_mapping(guarded_output.evidence)
    verified_packet = _coerce_evidence(verifier_output)
    findings.extend(
        verify_evidence_packet(
            claimed_packet,
            verified_packet,
            require_claimed=active_config.require_claimed_evidence,
            require_verified=active_config.require_verified_evidence,
            worker_identity=worker_identity,
            identity_mismatch=identity_mismatch,
            artifact_resolver=active_config.artifact_resolver,
        )
    )

    decision = gate_candidate(tuple(findings))
    has_secret_redaction = guarded_output.content != candidate.content
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
    output: CandidateLike,
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
        envelope=envelope,
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
        envelope=envelope,
        custom_guards=(),
        review_callback=review_callback,
    )
    return GuardedTaskResult(audit.status, preflight, audit=audit, worker_ran=True)


def _coerce_candidate(value: CandidateLike) -> CandidateOutput:
    if isinstance(value, CandidateOutput):
        return value
    if isinstance(value, Mapping):
        return CandidateOutput.from_mapping(value)
    raise TypeError("Candidate output must be CandidateOutput or a mapping")


def _coerce_evidence(value: Mapping[str, Any] | EvidencePacket | None) -> EvidencePacket | None:
    if value is None:
        return None
    if isinstance(value, EvidencePacket):
        return value
    return EvidencePacket.from_mapping(value)


def _identity_from_mapping(value: Mapping[str, Any] | None) -> tuple[str | None, bool]:
    data = value or {}
    identities: list[str] = []
    invalid = False
    for key in ("worker_id", "worker", "agent_id"):
        if key not in data:
            continue
        item = data.get(key)
        if not isinstance(item, str) or not item.strip():
            invalid = True
            continue
        identities.append(item.strip())

    if len(set(identities)) > 1:
        return None, True
    return (identities[0] if identities else None), invalid


def _worker_identities(
    output: CandidateOutput,
    envelope: Mapping[str, Any] | None,
) -> tuple[str | None, bool, bool]:
    envelope_identity, invalid_envelope_identity = _identity_from_mapping(envelope)
    packet_identity, invalid_packet_identity = _identity_from_mapping(output.metadata)
    worker_identity = envelope_identity or packet_identity
    mismatch = bool(
        envelope_identity
        and packet_identity
        and envelope_identity != packet_identity
    )
    return (
        worker_identity,
        mismatch,
        invalid_envelope_identity or invalid_packet_identity,
    )


def _with_verifier(
    config: AuditConfig,
    verifier: Callable[[CandidateOutput], Mapping[str, Any] | None] | None,
) -> AuditConfig:
    if verifier is None:
        return config
    return replace(config, verifier=verifier)
