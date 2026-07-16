from agent_audit_kit import PreflightPolicy, run_guarded_task


policy = PreflightPolicy(
    allowed_tools=("filesystem_read",),
    allowed_actions=("draft_response",),
)

envelope = {
    "worker_id": "example-worker",
    "requested_tools": ["filesystem_read"],
    "requested_actions": ["draft_response"],
    "network_access": False,
}


def worker(_envelope):
    return {
        "worker_id": "example-worker",
        "content": "Candidate created from a mapping-shaped worker packet.",
        "sources": ["worker-log"],
        "checks_run": ["claimed-read"],
        "evidence_handles": [{"path": "artifacts/claimed.txt"}],
    }


verified_evidence = {
    "verified_by": "mainbrain",
    "sources": ["review-log"],
    "verified_checks": ["readback"],
    "evidence_handles": [{"path": "artifacts/readback.log"}],
}

result = run_guarded_task(
    envelope,
    policy,
    worker,
    verified_evidence=verified_evidence,
)

print(result.to_dict())
