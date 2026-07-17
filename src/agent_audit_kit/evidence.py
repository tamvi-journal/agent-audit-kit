from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agent_audit_kit.models import ArtifactResolver, Finding


INSPECTABLE_ARTIFACT_FIELDS = (
    "path",
    "locator",
    "uri",
    "url",
    "artifact_id",
    "id",
    "sha256",
)


def _first_present(data: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in data:
            return data[key]
    return None


def _clean_text_items(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        items = (value,)
    elif isinstance(value, (list, tuple)):
        items = value
    elif isinstance(value, set):
        items = sorted(value, key=repr)
    else:
        return ()

    cleaned: list[str] = []
    for item in items:
        if not isinstance(item, str):
            continue
        text = item.strip()
        if text and text not in cleaned:
            cleaned.append(text)
    return tuple(cleaned)


def _artifact_locator(value: Any) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if not isinstance(value, Mapping):
        return None
    for field in INSPECTABLE_ARTIFACT_FIELDS:
        item = value.get(field)
        if isinstance(item, str) and item.strip():
            return item.strip()
    return None


def _clean_artifacts(value: Any) -> tuple[str, ...]:
    if isinstance(value, (str, Mapping)):
        items = (value,)
    elif isinstance(value, (list, tuple)):
        items = value
    elif isinstance(value, set):
        items = sorted(value, key=repr)
    else:
        return ()

    cleaned: list[str] = []
    for item in items:
        locator = _artifact_locator(item)
        if locator and locator not in cleaned:
            cleaned.append(locator)
    return tuple(cleaned)


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
        raw_verifier = _first_present(data, ("verifier", "verified_by"))
        verifier = raw_verifier.strip() if isinstance(raw_verifier, str) else ""
        return cls(
            sources=_clean_text_items(
                _first_present(data, ("sources", "source_refs", "verified_sources"))
            ),
            checks_run=_clean_text_items(
                _first_present(data, ("checks_run", "verified_checks"))
            ),
            artifacts=_clean_artifacts(
                _first_present(
                    data,
                    (
                        "artifacts",
                        "evidence_handles",
                        "verified_evidence_handles",
                        "artifact_handles",
                    ),
                )
            ),
            verifier=verifier,
            missing_fields=_clean_text_items(data.get("missing_fields")),
            notes=_clean_text_items(data.get("notes")),
        )

    @property
    def has_any_evidence(self) -> bool:
        return bool(self.sources or self.checks_run or self.artifacts or self.verifier)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sources": list(self.sources),
            "checks_run": list(self.checks_run),
            "artifacts": list(self.artifacts),
            "verifier": self.verifier,
            "missing_fields": list(self.missing_fields),
            "notes": list(self.notes),
        }


def verify_evidence_packet(
    claimed: EvidencePacket,
    verified: EvidencePacket | None = None,
    *,
    require_claimed: bool = True,
    require_verified: bool = True,
    worker_identity: str | None = None,
    identity_mismatch: bool = False,
    artifact_resolver: ArtifactResolver | None = None,
) -> tuple[Finding, ...]:
    """Check claimed evidence separately from independently verified evidence."""

    findings: list[Finding] = []

    if identity_mismatch:
        findings.append(
            Finding(
                "worker_identity_mismatch",
                "Candidate worker identity differs from the trusted envelope identity.",
            )
        )

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
        findings.append(
            Finding(
                "verification_requirement_disabled",
                "Disabling verified evidence cannot grant release eligibility; route this candidate to review.",
            )
        )
        return tuple(findings)

    if verified is None:
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
    if artifact_resolver is not None and verified.artifacts:
        findings.extend(_resolve_verified_artifacts(verified.artifacts, artifact_resolver))
    if worker_identity and verified.verifier and verified.verifier == worker_identity:
        findings.append(
            Finding(
                "self_verification",
                "The verifier identity matches the worker identity; workers cannot verify their own output.",
            )
        )

    return tuple(findings)


def _resolve_verified_artifacts(
    artifacts: tuple[str, ...],
    resolver: ArtifactResolver,
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for artifact_index, locator in enumerate(artifacts):
        safe_details = {"artifact_index": artifact_index}
        try:
            resolved = resolver(locator)
        except Exception:
            findings.append(
                Finding(
                    "artifact_resolver_error",
                    "The caller-provided artifact resolver failed; verified evidence cannot be released automatically.",
                    source="evidence.artifact_resolver",
                    details=safe_details,
                )
            )
            continue

        if not isinstance(resolved, bool):
            findings.append(
                Finding(
                    "artifact_resolver_invalid_result",
                    "The artifact resolver must return a boolean for every verified artifact locator.",
                    source="evidence.artifact_resolver",
                    details=safe_details,
                )
            )
        elif not resolved:
            findings.append(
                Finding(
                    "verifier_artifact_unresolved",
                    "A verified artifact locator could not be resolved by the caller-provided resolver.",
                    source="evidence.artifact_resolver",
                    details=safe_details,
                )
            )
    return tuple(findings)
