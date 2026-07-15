from agent_audit_kit import AuditConfig, CandidateOutput, Finding, audit_candidate


def citation_guard(output: CandidateOutput):
    if "according to" in output.content.lower() and not output.evidence.get("sources"):
        return Finding(
            kind="citation_needed",
            message="The candidate makes a sourced-style claim without sources.",
            severity="medium",
        )
    return None


config = AuditConfig(custom_guards=(citation_guard,))

candidate = CandidateOutput(
    content="According to the policy, this is allowed.",
    evidence={"checks_run": ["citation_guard"]},
)

result = audit_candidate(
    candidate,
    config=config,
    verified_evidence={
        "sources": ["review-note"],
        "checks_run": ["citation_guard"],
        "artifacts": ["review-note.md"],
        "verifier": "caller",
    },
)

print(result.status)
for explanation in result.explanations:
    print(explanation)
