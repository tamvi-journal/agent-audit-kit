# Non-Tech Guide

TamVi Agent Gate is for people who use AI tools to build things but do not want to blindly trust every AI-generated answer, file, command, or report.

The core idea is simple:

1. The task is checked before the AI worker runs.
2. The AI worker does not produce truth.
3. The AI worker produces a candidate.
4. The worker can claim evidence, but a claim is not proof.
5. Evidence must be verified outside the worker.
6. A gate decides whether the candidate is blocked, needs review, or is eligible for release.

## The Five Questions

Use these questions even without code:

1. What did the agent ask permission to do?
2. Should the agent run at all?
3. What evidence did the worker claim?
4. What evidence was independently verified?
5. Is this safe to release, or should it stay a candidate?

## Useful Words

- **Preflight**: check the request before running the agent.
- **Guard**: block or redact risky output.
- **Claimed evidence**: what the worker says supports the output.
- **Verified evidence**: what a separate check, artifact, log, or reviewer confirms.
- **Release gate**: the final decision layer.
- **Candidate**: an output that is not trusted yet.

## A Good Rule

Never let an agent's first output go directly to a user, a commit, a production system, or a payment action.

Make it pass through preflight and a release gate first.
