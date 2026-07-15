from agent_audit_kit import CandidateOutput, audit_candidate


def audit_text_from_any_agent(text: str, *, verified_log_path: str):
    """Wrap text from LangChain, LlamaIndex, CrewAI, or a custom agent.

    Keep framework dependencies outside this repo. The important part is that
    verification comes from the caller, not from the worker text itself.
    """

    candidate = CandidateOutput(
        content=text,
        evidence={
            "sources": ["agent-output"],
            "checks_run": ["claimed-generation"],
        },
    )
    return audit_candidate(
        candidate,
        verified_evidence={
            "sources": [verified_log_path],
            "checks_run": ["caller-reviewed-output"],
            "artifacts": [verified_log_path],
            "verifier": "caller",
        },
    )


# Example:
# raw = chain.invoke({"question": "..."})
# result = audit_text_from_any_agent(raw["output"], verified_log_path="logs/review.txt")
# if result.eligible_for_release:
#     return result.output.content
# raise RuntimeError(result.explanations)
