from agent_audit_kit import CandidateOutput, PreflightPolicy, audit_candidate


policy = PreflightPolicy(
    allowed_tools=("filesystem_read", "filesystem_write", "terminal"),
    forbidden_tools=("network", "browser", "package_install"),
    allowed_actions=("read_input", "write_output", "run_tests"),
    approval_required_actions=("network", "package_install", "git_push"),
    blocked_actions=("read_secret", "print_secret"),
)

candidate = CandidateOutput(
    content="Worker completed the task and ran tests.",
    evidence={
        "sources": ["tests/test_agent_audit_kit.py"],
        "checks_run": ["pytest"],
        "missing_fields": [],
    },
)

result = audit_candidate(
    candidate,
    envelope={
        "requested_tools": ["filesystem_read", "terminal"],
        "requested_actions": ["read_input", "run_tests"],
        "network_access": False,
    },
    policy=policy,
)

print(result.status)
for finding in result.findings:
    print(f"- {finding.severity}: {finding.kind} - {finding.message}")
