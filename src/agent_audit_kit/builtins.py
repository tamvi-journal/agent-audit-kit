from __future__ import annotations

from collections.abc import Iterable

from agent_audit_kit.evidence import EvidencePacket
from agent_audit_kit.models import CandidateOutput, CustomGuard, Finding


def max_length_guard(max_chars: int) -> CustomGuard:
    if isinstance(max_chars, bool) or not isinstance(max_chars, int) or max_chars <= 0:
        raise ValueError("max_chars must be a positive integer")

    def guard(output: CandidateOutput):
        if len(output.content) <= max_chars:
            return None
        return Finding(
            "max_length_exceeded",
            f"Candidate content exceeds {max_chars} characters.",
            source="builtins.max_length_guard",
            details={"max_chars": max_chars, "actual_chars": len(output.content)},
        )

    return guard


def forbidden_terms_guard(
    terms: Iterable[str],
    *,
    case_sensitive: bool = False,
) -> CustomGuard:
    items = (terms,) if isinstance(terms, str) else terms
    cleaned = tuple(
        term.strip()
        for term in items
        if isinstance(term, str) and term.strip()
    )
    if not cleaned:
        raise ValueError("terms must contain at least one nonblank string")

    def guard(output: CandidateOutput):
        haystack = output.content if case_sensitive else output.content.casefold()
        matches = [
            term
            for term in cleaned
            if (term if case_sensitive else term.casefold()) in haystack
        ]
        if not matches:
            return None
        return Finding(
            "forbidden_term",
            "Candidate content contains a forbidden term.",
            source="builtins.forbidden_terms_guard",
            details={"matches": matches},
        )

    return guard


def require_sources_guard(output: CandidateOutput):
    evidence = EvidencePacket.from_mapping(output.evidence)
    if evidence.sources:
        return None
    return Finding(
        "required_sources_missing",
        "Candidate output must include at least one claimed source.",
        source="builtins.require_sources_guard",
    )


def require_metadata_fields_guard(*fields: str) -> CustomGuard:
    cleaned = tuple(
        field.strip()
        for field in fields
        if isinstance(field, str) and field.strip()
    )
    if not cleaned:
        raise ValueError("fields must contain at least one nonblank string")

    def guard(output: CandidateOutput):
        missing = [
            field
            for field in cleaned
            if not isinstance(output.metadata.get(field), str)
            or not output.metadata.get(field, "").strip()
        ]
        if not missing:
            return None
        return Finding(
            "required_metadata_missing",
            "Candidate metadata is missing required nonblank string fields.",
            source="builtins.require_metadata_fields_guard",
            details={"missing_fields": missing},
        )

    return guard
