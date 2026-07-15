from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from agent_audit_kit.models import Finding


@dataclass(frozen=True)
class EvidencePacket:
    sources: tuple[str, ...] = ()
    checks_run: tuple[str, ...] = ()
    artifacts: tuple[str, ...] = ()
    verifier: str = ""
    missing_fields: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "EvidencePacket":
        data = dict(value or {})
        return cls(
            sources=tuple(str(item) for item in data.get("sources", ()) or ()),
            checks_run=tuple(str(item) for item in data.get("checks_run", ()) or ()),
            artifacts=tuple(str(item) for item in data.get("artifacts", ()) or ()),
            verifier=str(data.get("verifier") or data.get("verified_by") or ""),
            missing_fields=tuple(str(item) for item in data.get("missing_fields", ()) or ()),
            notes=tuple(str(item) for item in data.get("notes", ()) or ()),
        )

    @property
    def has_any_evidence(self) -> bool:
        return bool(self.sources or self.checks_run or self.artifacts or self.verifier or self.notes)


def verify_evidence_packet(
    claimed: EvidencePacket,
    verified: EvidencePacket | None = None,
    *,
    require_claimed: bool = True,
    require_verified: bool = True,
    worker_identity: str | None = None,
) -> tuple[Finding, ...]:
    """Check claimed evidence separately from independently verified evidence."""

    findings: list[Finding] = []

    if require_claimed:
        if not claimed.sources:
            findings.append(Finding("missing_claimed_sources", "Candidate output has no claimed sources"))
        if not claimed.checks_run:
            findings.append(Finding("missing_claimed_checks", "Candidate output has no claimed checks"))

    if claimed.missing_fields:
        findings.append(
            Finding(
                "declared_missing_data",
                "Candidate declares missing fields: " + ", ".join(claimed.missing_fields),
                severity="low",
            )
        )

    if not require_verified:
        return tuple(findings)

    if verified is None or not verified.has_any_evidence:
        findings.append(
            Finding(
                "missing_verified_evidence",
                "Worker-reported evidence is a claim, not proof; no verified evidence was provided.",
            )
        )
        return tuple(findings)

    if not verified.sources:
        findings.append(Finding("missing_verified_sources", "Verified evidence has no external source reference"))
    if not verified.checks_run:
        findings.append(Finding("missing_verified_checks", "Verified evidence has no confirmed checks"))
    if not verified.artifacts:
        findings.append(
            Finding(
                "verifier_artifact_missing",
                "Verified evidence needs an inspectable artifact, log, test result, diff, or review record.",
            )
        )
    if not verified.verifier:
        findings.append(
            Finding(
                "verifier_missing",
                "Verified evidence needs a verifier identity controlled outside the worker.",
            )
        )
    if worker_identity and verified.verifier and verified.verifier == worker_identity:
        findings.append(
            Finding(
                "self_verification",
                "The verifier identity matches the worker identity; workers cannot verify their own output.",
            )
        )

    return tuple(findings)
