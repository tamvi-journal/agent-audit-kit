from agent_audit_kit import CandidateOutput, audit_candidate


def audit_text_from_any_agent(text: str, *, source_name: str = "agent-output"):
    """Wrap text from LangChain, LlamaIndex, CrewAI, or a custom agent."""

    candidate = CandidateOutput(
        content=text,
        evidence={
            "sources": [source_name],
            "checks_run": ["agent-audit-kit"],
        },
    )
    return audit_candidate(candidate)


# Example:
# raw = chain.invoke({"question": "..."})
# result = audit_text_from_any_agent(raw["output"], source_name="langchain-chain")
# if result.status == "approved_candidate":
#     return result.output.content
# raise RuntimeError(result.explanations)
