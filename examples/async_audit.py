import asyncio

from agent_audit_kit import CandidateOutput, audit_candidate_async


async def run_agent_task() -> CandidateOutput:
    return CandidateOutput(
        content="Async worker produced a candidate.",
        evidence={"sources": ["async-worker-log"], "checks_run": ["unit-test"]},
    )


async def main():
    candidate = await run_agent_task()
    result = await audit_candidate_async(candidate)
    print(result.status)


asyncio.run(main())
