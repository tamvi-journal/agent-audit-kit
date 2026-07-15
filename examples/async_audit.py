import asyncio

from agent_audit_kit import CandidateOutput, PreflightPolicy, run_guarded_task_async


policy = PreflightPolicy(
    allowed_tools=("filesystem_read",),
    allowed_actions=("draft_response",),
    forbidden_tools=("network",),
)

envelope = {
    "requested_tools": ["filesystem_read"],
    "requested_actions": ["draft_response"],
    "network_access": False,
}


async def worker(_envelope):
    return CandidateOutput(
        content="Async worker produced a candidate.",
        evidence={"sources": ["async-worker-log"], "checks_run": ["draft-created"]},
    )


def verifier(_candidate):
    return {
        "sources": ["async-test-log"],
        "checks_run": ["async-smoke-test"],
        "artifacts": ["async-smoke-test.log"],
        "verifier": "caller",
    }


async def main():
    result = await run_guarded_task_async(envelope, policy, worker, verifier=verifier)
    print(result.status)


asyncio.run(main())
