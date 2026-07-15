from agent_audit_kit import CandidateOutput, PreflightPolicy, audit_candidate


def toy_agent(prompt: str) -> CandidateOutput:
    return CandidateOutput(
        content=f"Draft response for: {prompt}",
        evidence={
            "sources": ["toy_agent prompt"],
            "checks_run": ["manual-smoke-test"],
            "missing_fields": [],
        },
    )


policy = PreflightPolicy(
    allowed_tools=("filesystem_read", "filesystem_write"),
    forbidden_tools=("network", "browser", "package_install"),
    allowed_actions=("draft_response",),
    blocked_actions=("read_secret", "print_secret"),
)

candidate = toy_agent("Write a safe summary.")
result = audit_candidate(
    candidate,
    envelope={
        "requested_tools": ["filesystem_read"],
        "requested_actions": ["draft_response"],
        "network_access": False,
    },
    policy=policy,
)

print(result.status)
for explanation in result.explanations:
    print(explanation)
