# Non-Tech Guide

Agent Audit Kit is for people who use AI tools to build things but do not want to blindly trust every AI-generated answer, file, command, or report.

The core idea is simple:

1. The AI worker does not produce truth.
2. The AI worker produces a candidate.
3. The candidate must show evidence.
4. The candidate is scanned for risky content.
5. A gate decides whether it is blocked, needs review, or can be treated as an approved candidate.

## The Five Questions

Use these questions even without code:

1. What did the agent ask permission to do?
2. What tools or actions did it use?
3. What evidence did it provide?
4. Did the output include secrets, credentials, or unsupported claims?
5. Is this safe to approve, or should it stay a candidate?

## Useful Words

- **Preflight**: check the request before running the agent.
- **Guard**: block or redact risky output.
- **Evidence packet**: the sources and checks the agent claims support its output.
- **Verification**: test whether the output is backed by evidence.
- **Gate**: the final decision layer.
- **Candidate**: an output that is not trusted yet.

## A Good Rule

Never let an agent's first output go directly to a user, a commit, a production system, or a payment action.

Make it pass through a gate first.
