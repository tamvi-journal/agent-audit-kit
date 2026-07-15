from agent_audit_kit import CandidateOutput, PreflightPolicy, run_guarded_task


def toy_agent(prompt: str) -> CandidateOutput:
    return CandidateOutput(
        content=f"Draft response for: {prompt}",
        evidence={
            "sources": ["toy_agent prompt"],
            "checks_run": ["draft-created"],
            "missing_fields": [],
        },
    )


policy = PreflightPolicy(
    allowed_tools=("filesystem_read", "filesystem_write"),
    forbidden_tools=("network", "browser", "package_install"),
    allowed_actions=("draft_response",),
    blocked_actions=("read_secret", "print_secret"),
)

envelope = {
    "requested_tools": ["filesystem_read"],
    "requested_actions": ["draft_response"],
    "network_access": False,
}


def worker(_envelope):
    return toy_agent("Write a safe summary.")


def verifier(_candidate):
    return {
        "sources": ["manual-review"],
        "checks_run": ["read-output"],
        "artifacts": ["review-note"],
        "verifier": "caller",
    }


result = run_guarded_task(envelope, policy, worker, verifier=verifier)

print(result.status)
for explanation in result.explanations:
    print(explanation)
