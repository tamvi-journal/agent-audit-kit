from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_audit_kit.models import Finding, PreflightPolicy, PreflightResult


BLOCKING_PREFLIGHT_KINDS = {
    "blocked_action",
    "forbidden_tool",
    "invalid_envelope_field",
    "completion_authority_forbidden",
}


def _text_items(value: Any, *, field: str) -> tuple[tuple[str, ...], tuple[Finding, ...]]:
    if value is None:
        return (), ()
    if isinstance(value, str):
        values = (value,)
    elif isinstance(value, (list, tuple, set)):
        values = tuple(value)
    else:
        return (), (
            Finding(
                "invalid_envelope_field",
                f"{field} must be a string or a collection of nonblank strings.",
                severity="high",
                details={"field": field},
            ),
        )

    cleaned: list[str] = []
    invalid = False
    for item in values:
        if not isinstance(item, str) or not item.strip():
            invalid = True
            continue
        text = item.strip()
        if text not in cleaned:
            cleaned.append(text)

    findings: tuple[Finding, ...] = ()
    if invalid:
        findings = (
            Finding(
                "invalid_envelope_field",
                f"{field} contains a non-string or blank value.",
                severity="high",
                details={"field": field},
            ),
        )
    return tuple(cleaned), findings


def _validate_identity_fields(envelope: Mapping[str, Any]) -> tuple[Finding, ...]:
    identities: list[str] = []
    findings: list[Finding] = []
    for field in ("worker_id", "worker", "agent_id"):
        if field not in envelope:
            continue
        value = envelope.get(field)
        if not isinstance(value, str) or not value.strip():
            findings.append(
                Finding(
                    "invalid_envelope_field",
                    f"{field} must be a nonblank string.",
                    severity="high",
                    details={"field": field},
                )
            )
            continue
        identities.append(value.strip())

    if len(set(identities)) > 1:
        findings.append(
            Finding(
                "invalid_envelope_field",
                "Envelope worker identity fields disagree.",
                severity="high",
                details={"fields": ["worker_id", "worker", "agent_id"]},
            )
        )
    return tuple(findings)


def preflight_check(envelope: Mapping[str, Any], policy: PreflightPolicy) -> tuple[Finding, ...]:
    """Return policy findings for a task envelope without executing the task."""

    findings: list[Finding] = []
    requested_actions, action_findings = _text_items(
        envelope.get("requested_actions"),
        field="requested_actions",
    )
    requested_tools, tool_findings = _text_items(
        envelope.get("requested_tools"),
        field="requested_tools",
    )
    findings.extend(action_findings)
    findings.extend(tool_findings)
    findings.extend(_validate_identity_fields(envelope))

    for tool in requested_tools:
        if tool in policy.forbidden_tools:
            findings.append(Finding("forbidden_tool", f"Tool is forbidden: {tool}", severity="high"))
        elif policy.allowed_tools and tool not in policy.allowed_tools:
            findings.append(Finding("tool_outside_allowlist", f"Tool is outside allowlist: {tool}"))

    for action in requested_actions:
        if action in policy.blocked_actions:
            findings.append(Finding("blocked_action", f"Action is blocked: {action}", severity="high"))
        elif action in policy.approval_required_actions:
            findings.append(Finding("approval_required", f"Action requires approval: {action}"))
        elif policy.allowed_actions and action not in policy.allowed_actions:
            findings.append(Finding("action_outside_allowlist", f"Action is outside allowlist: {action}"))

    risk_flags = (
        ("network_access", policy.network_allowed, "network_requires_approval", "Network access is not auto-allowed"),
        ("shell_access", policy.shell_allowed, "shell_requires_approval", "Shell access is not auto-allowed"),
        (
            "external_mutation",
            policy.external_mutation_allowed,
            "external_mutation_requires_approval",
            "External mutation is not auto-allowed",
        ),
        (
            "money_touching",
            policy.money_touching_allowed,
            "money_touching_requires_approval",
            "Money-touching work is not auto-allowed",
        ),
    )
    for field, allowed, kind, message in risk_flags:
        if field not in envelope:
            continue
        value = envelope.get(field)
        if not isinstance(value, bool):
            findings.append(
                Finding(
                    "invalid_envelope_field",
                    f"{field} must be a boolean.",
                    severity="high",
                    details={"field": field},
                )
            )
        elif value and not allowed:
            findings.append(Finding(kind, message))

    if "completion_authority" in envelope:
        value = envelope.get("completion_authority")
        if not isinstance(value, bool):
            findings.append(
                Finding(
                    "invalid_envelope_field",
                    "completion_authority must be a boolean.",
                    severity="high",
                    details={"field": "completion_authority"},
                )
            )
        elif value and not policy.completion_authority:
            findings.append(
                Finding(
                    "completion_authority_forbidden",
                    "Worker completion authority is forbidden by policy.",
                    severity="high",
                )
            )

    return tuple(findings)


def preflight_task(envelope: Mapping[str, Any], policy: PreflightPolicy) -> PreflightResult:
    """Decide whether a task may execute before the worker is called."""

    findings = preflight_check(envelope, policy)
    if any(finding.severity == "high" or finding.kind in BLOCKING_PREFLIGHT_KINDS for finding in findings):
        return PreflightResult("blocked", findings)
    if findings:
        return PreflightResult("needs_approval", findings)
    return PreflightResult("allowed", ())
