from agent_audit_kit import CandidateOutput, PreflightPolicy, preflight_task, audit_candidate


policy = PreflightPolicy(
    allowed_tools=("filesystem_read",),
    forbidden_tools=("network", "browser"),
    allowed_actions=("write_summary",),
    blocked_actions=("read_secret", "print_secret"),
)

task = {
    "requested_tools": ["filesystem_read"],
    "requested_actions": ["write_summary"],
    "network_access": False,
}

preflight = preflight_task(task, policy)
if not preflight.can_execute:
    print("Do not run the worker:", preflight.status)
    raise SystemExit(1)

# The worker runs only after preflight passes.
candidate = CandidateOutput(
    content="Summary draft ready.",
    evidence={"sources": ["worker-note"], "checks_run": ["draft-created"]},
)

# A separate caller, test, log, or human verifies the evidence.
verified_evidence = {
    "sources": ["review-note"],
    "checks_run": ["human-review"],
    "artifacts": ["review-note.md"],
    "verifier": "human-reviewer",
}

result = audit_candidate(candidate, verified_evidence=verified_evidence)
print(result.status)
