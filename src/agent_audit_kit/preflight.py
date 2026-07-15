from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_audit_kit.models import Finding, PreflightPolicy


def _as_text_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        return tuple(str(item) for item in value)
    return ()


def preflight_check(envelope: Mapping[str, Any], policy: PreflightPolicy) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    requested_actions = _as_text_tuple(envelope.get("requested_actions"))
    requested_tools = _as_text_tuple(envelope.get("requested_tools"))

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

    if bool(envelope.get("network_access")) and not policy.network_allowed:
        findings.append(Finding("network_requires_approval", "Network access is not auto-allowed"))

    return tuple(findings)
