<p align="center">
  <img src="assets/agent-audit-kit-hero.svg" alt="Agent Audit Kit pipeline: worker output passes through preflight, guard, evidence, verification, and gate before becoming an approved candidate." width="100%">
</p>

# Agent Audit Kit

**Stop trusting agent output. Start auditing it.**

Agent Audit Kit is a small, practical safety layer for AI agents, vibe-coded workers, and automation scripts. It turns an agent's first answer into a **candidate** that must pass preflight checks, guardrails, evidence review, verification, and a final gate.

> Worker output is not truth. It is a candidate until it passes the gate.

## Why This Exists

Many AI workflows fail in quiet ways:

- A worker claims it finished, but no checks were run.
- A report looks confident, but has no sources.
- A script prints an API key into a log or markdown file.
- An agent asks for a tool it should not have.
- A generated patch is treated as safe before anyone audits it.

Agent Audit Kit gives builders a simple pattern for catching those failures before they reach a user, a commit, a production system, or an external action.

## The Pattern

```text
Worker output
    |
    v
Preflight policy
    |
    v
Guard and secret scan
    |
    v
Evidence packet
    |
    v
Verification
    |
    v
Gate decision
    |
    v
approved_candidate | needs_review | blocked_candidate
```

## Quick Start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
```

```python
from agent_audit_kit import CandidateOutput, audit_candidate

candidate = CandidateOutput(
    content="Created the requested draft and ran tests.",
    evidence={
        "sources": ["local-test-log"],
        "checks_run": ["pytest"],
    },
)

result = audit_candidate(candidate)

print(result.status)
# approved_candidate
```

## Secret Leak Example

```python
from agent_audit_kit import CandidateOutput, audit_candidate

fake_key = "sk-proj-" + "abcdefghijklmnopqrstuvwxyz1234567890"

result = audit_candidate(
    CandidateOutput(
        content="OPENAI_API_KEY=" + fake_key,
        evidence={"sources": ["unit-test"], "checks_run": ["secret-scan"]},
    )
)

print(result.status)
# blocked_candidate

print(result.output.content)
# OPENAI_API_KEY=[REDACTED_OPENAI_API_KEY]
```

## What It Checks

- **Preflight**: did the agent request allowed tools and actions?
- **Guard**: does output contain secret-like material?
- **Evidence packet**: did the candidate include sources and checks?
- **Verification**: does the candidate declare what was checked and what is missing?
- **Gate**: should the output be approved, reviewed, or blocked?

## For Non-Technical Builders

You can use the idea even before using the code:

1. Treat every AI answer as a candidate.
2. Ask what evidence supports it.
3. Scan for secrets before sharing or committing.
4. Require checks before accepting completion claims.
5. Put a final approval gate between the agent and the real world.

See [docs/NON_TECH_GUIDE.md](docs/NON_TECH_GUIDE.md).

## Feedback

The first public version is intentionally small. If you test it, the most useful feedback is whether the gate feels too strict, too loose, or confusing.

See [docs/FEEDBACK_GUIDE.md](docs/FEEDBACK_GUIDE.md).

## Public Boundary

This repo intentionally shares only the generic audit pattern. It does not include private project architecture, credentials, prompts, memory, or logs.

See [docs/PUBLIC_BOUNDARY.md](docs/PUBLIC_BOUNDARY.md).

## Status

This is an early public kit. The goal is feedback from builders, non-technical operators, vibe coders, and agent developers who want safer AI workflows without needing a full platform.

## License

MIT
