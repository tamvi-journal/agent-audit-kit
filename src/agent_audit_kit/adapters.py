from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_audit_kit.audit import audit_candidate
from agent_audit_kit.evidence import EvidencePacket
from agent_audit_kit.models import AuditConfig, CandidateOutput, PreflightPolicy


def normalize_candidate_packet(packet: Mapping[str, Any]) -> CandidateOutput:
    """Normalize a worker-specific mapping into the shared candidate contract."""

    return CandidateOutput.from_mapping(packet)


def normalize_policy(policy: Mapping[str, Any]) -> PreflightPolicy:
    """Normalize JSON/YAML-shaped policy data without adding dependencies."""

    return PreflightPolicy.from_mapping(policy)


def audit_agent_packet(
    candidate_packet: Mapping[str, Any],
    *,
    verified_evidence: Mapping[str, Any] | EvidencePacket | None = None,
    envelope: Mapping[str, Any] | None = None,
    policy: PreflightPolicy | Mapping[str, Any] | None = None,
    config: AuditConfig | None = None,
) -> dict[str, Any]:
    """Audit a mapping-shaped packet and return a versioned JSON-safe record."""

    active_policy = (
        PreflightPolicy.from_mapping(policy)
        if isinstance(policy, Mapping)
        else policy
    )
    result = audit_candidate(
        candidate_packet,
        verified_evidence=verified_evidence,
        envelope=envelope,
        policy=active_policy,
        config=config,
    )
    return result.to_dict()
