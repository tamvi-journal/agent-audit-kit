from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from agent_audit_kit.models import Finding


@dataclass(frozen=True)
class EvidencePacket:
    sources: tuple[str, ...] = ()
    checks_run: tuple[str, ...] = ()
    missing_fields: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "EvidencePacket":
        data = dict(value or {})
        return cls(
            sources=tuple(str(item) for item in data.get("sources", ()) or ()),
            checks_run=tuple(str(item) for item in data.get("checks_run", ()) or ()),
            missing_fields=tuple(str(item) for item in data.get("missing_fields", ()) or ()),
            notes=tuple(str(item) for item in data.get("notes", ()) or ()),
        )


def verify_evidence_packet(packet: EvidencePacket) -> tuple[Finding, ...]:
    """Check whether a candidate declared useful sources and checks."""

    findings: list[Finding] = []
    if not packet.sources:
        findings.append(Finding("missing_sources", "Candidate output has no cited sources"))
    if not packet.checks_run:
        findings.append(Finding("missing_checks", "Candidate output has no declared checks"))
    if packet.missing_fields:
        findings.append(
            Finding(
                "declared_missing_data",
                "Candidate declares missing fields: " + ", ".join(packet.missing_fields),
                severity="low",
            )
        )
    return tuple(findings)
