from agent_audit_kit import CandidateOutput, PreflightPolicy, run_guarded_task


policy = PreflightPolicy(
    allowed_tools=("filesystem_read", "filesystem_write", "terminal"),
    forbidden_tools=("network", "browser", "package_install"),
    allowed_actions=("read_input", "write_output", "run_tests"),
    approval_required_actions=("network", "package_install", "git_push"),
    blocked_actions=("read_secret", "print_secret"),
)

envelope = {
    "requested_tools": ["filesystem_read", "terminal"],
    "requested_actions": ["read_input", "run_tests"],
    "network_access": False,
}


def worker(_envelope):
    return CandidateOutput(
        content="Worker completed a draft candidate.",
        evidence={
            "sources": ["worker-output"],
            "checks_run": ["claimed-pytest"],
            "missing_fields": [],
        },
    )


def verifier(_candidate):
    return {
        "sources": ["tests/test_agent_audit_kit.py"],
        "checks_run": ["pytest"],
        "artifacts": ["local pytest output"],
        "verifier": "caller",
    }


result = run_guarded_task(envelope, policy, worker, verifier=verifier)

print(result.status)
for explanation in result.explanations:
    print(explanation)
