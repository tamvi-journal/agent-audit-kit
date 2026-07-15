# Extending Agent Audit Kit

Agent Audit Kit is intentionally small. The main extension point is a custom guard: a function that receives a `CandidateOutput` and returns one or more `Finding` objects.

## Custom Guard

```python
from agent_audit_kit import CandidateOutput, Finding


def citation_guard(output: CandidateOutput):
    if "according to" in output.content.lower() and not output.evidence.get("sources"):
        return Finding(
            kind="citation_needed",
            message="The candidate makes a sourced-style claim without sources.",
            severity="medium",
        )
    return None
```

Then pass it into `audit_candidate`:

```python
from agent_audit_kit import AuditConfig, audit_candidate

config = AuditConfig(custom_guards=(citation_guard,))
result = audit_candidate(candidate, config=config)
```

## Verified Evidence Callback

Use a verifier when evidence comes from outside the worker, such as a log, test result, artifact, or human review.

```python
def verifier(candidate):
    return {
        "sources": ["ci-log"],
        "checks_run": ["pytest"],
        "artifacts": ["ci/pytest.log"],
        "verifier": "ci",
    }


config = AuditConfig(verifier=verifier)
result = audit_candidate(candidate, config=config)
```

Worker-reported evidence is a claim, not proof. A verifier should be controlled by the caller, not by the worker being audited.

## Review Callback

Use a review callback when you want to route blocked or review-needed candidates to a human queue, log, UI, or issue tracker.

```python
def send_to_review(result):
    print(result.status)
    print(result.explanations)


result = audit_candidate(candidate, review_callback=send_to_review)
```

The callback only runs when the result is not `approved_candidate`.

## Async Wrapper

For async agent code:

```python
result = await run_guarded_task_async(envelope, policy, worker, verifier=verifier)
```

The async API keeps the same trust-boundary semantics as the sync API.
