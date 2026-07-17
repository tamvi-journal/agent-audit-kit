<p align="center">
  <img src="assets/tamvi-agent-gate-hero.svg" alt="TamVi Agent Gate pipeline: task passes through preflight, worker execution, guard, evidence verification, and release gate." width="100%">
</p>

# TamVi Agent Gate

**A small, versioned preflight and candidate-release gate shared across AI agents.**

TamVi Agent Gate is the generic governance kernel extracted from a larger agent runtime. It stays separate from every agent's identity, memory, orchestration, and domain logic.

> Worker-reported evidence is a claim, not proof.

> `approved_candidate` means eligible under configured checks; not proven true.

## Stable trust boundary

```text
trusted envelope -> preflight -> worker -> output guard -> external evidence check -> release gate
```

- Preflight must run before the worker.
- The trusted envelope identity is authoritative.
- Candidate metadata cannot override envelope identity.
- A worker cannot verify its own output.
- Verified evidence needs a different verifier principal and an inspectable artifact.
- Disabling verified evidence can only route to review; it cannot grant release eligibility.
- Secret scanning is pattern-based and does not replace sandboxing, IAM, secret managers, or repository-history cleanup.

### Enforcement boundary

**TamVi Agent Gate evaluates declarations; it does not enforce capabilities.** Preflight checks the trusted envelope supplied by the caller. The runtime must separately enforce actual network, shell, tool, filesystem, and external-mutation permissions. A worker that declares `network_access: false` but is still given network access cannot be detected or stopped by this kernel.

The caller/MainBrain is the trust root. Verified-evidence packets are structurally validated, but the kernel does not authenticate the caller or verifier. If that trust root is compromised, fabricated envelopes and evidence are outside this gate's protection.

## Install for development

The distribution name is `tamvi-agent-gate`; the import namespace remains `agent_audit_kit` for compatibility.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The project is prepared for packaging but is not published yet. The unrelated `agent-audit-kit` name is already used on PyPI, so this project must not publish under that name.

## Python API

Mapping-shaped worker packets can be passed directly:

```python
from agent_audit_kit import PreflightPolicy, run_guarded_task

policy = PreflightPolicy(
    allowed_tools=("filesystem_read",),
    allowed_actions=("draft_response",),
)

envelope = {
    "worker_id": "research-worker",
    "requested_tools": ["filesystem_read"],
    "requested_actions": ["draft_response"],
    "network_access": False,
}

def worker(_envelope):
    return {
        "worker_id": "research-worker",
        "content": "Candidate report.",
        "sources": ["worker-log"],
        "checks_run": ["claimed-read"],
        "evidence_handles": [{"path": "artifacts/claimed.txt"}],
    }

verified = {
    "verified_by": "mainbrain",
    "sources": ["ci-log"],
    "verified_checks": ["pytest"],
    "evidence_handles": [{"path": "artifacts/pytest.log"}],
}

result = run_guarded_task(
    envelope,
    policy,
    worker,
    verified_evidence=verified,
)

print(result.status)
print(result.to_dict())
```

## JSON CLI

The CLI audits data. It deliberately does not execute arbitrary agent scripts.

```bash
tamvi-agent-gate preflight --envelope envelope.json --policy policy.json

tamvi-agent-gate audit \
  --candidate candidate.json \
  --verified verified.json \
  --envelope envelope.json \
  --policy policy.json
```

For `audit`, `--policy` requires `--envelope`; the CLI rejects a policy it cannot evaluate.

| Exit | Meaning |
|---:|---|
| `0` | allowed / approved candidate |
| `2` | needs approval / needs review |
| `3` | blocked |
| `4` | invalid JSON or input contract |

Decision and invalid-input records emitted by the subcommands are versioned JSON with `contract_version: "1.0"`; `--version` remains plain text.

## Optional built-in guards

Built-in guards are opt-in and dependency-free:

```python
from agent_audit_kit import (
    AuditConfig,
    forbidden_terms_guard,
    max_length_guard,
    require_metadata_fields_guard,
)

config = AuditConfig(
    custom_guards=(
        max_length_guard(20_000),
        forbidden_terms_guard(["internal-only"]),
        require_metadata_fields_guard("worker_id", "task_id"),
    )
)
```

Domain-specific truth checks should remain outside this kernel and attach verified evidence through the caller-controlled envelope.

## Optional artifact resolution

A caller can require every verified artifact locator to resolve before automatic release:

```python
from pathlib import Path

from agent_audit_kit import AuditConfig

artifact_root = Path("audit-artifacts").resolve()

def artifact_exists(locator: str) -> bool:
    candidate = (artifact_root / locator).resolve()
    return candidate.is_relative_to(artifact_root) and candidate.is_file()

config = AuditConfig(artifact_resolver=artifact_exists)
```

Resolver exceptions, non-boolean results, and unresolved locators fail closed to `needs_review`. The hook improves artifact reachability checks only; it does not authenticate the verifier, prove artifact integrity, or protect against a compromised caller. Stronger assurance requires a separate trust domain, signed attestations, or an independently controlled verifier.

## Audit-record persistence

The kernel returns versioned records and intentionally does not persist them. See [docs/AUDIT_RECORDS.md](docs/AUDIT_RECORDS.md) for an external JSON Lines/ledger pattern, retention cautions, and sink-failure guidance.

## Shared-agent integration

Each agent should add only a thin adapter:

1. Map its worker packet to `CandidateOutput` fields.
2. Pass the trusted invocation envelope separately.
3. Keep worker evidence claimed-only.
4. Let MainBrain, CI, a human, or another independent principal attach verified evidence.
5. Consume the versioned audit record and honor the release status.

See [docs/SHARED_AGENT_CONTRACT.md](docs/SHARED_AGENT_CONTRACT.md) and [examples/shared_mapping_agent.py](examples/shared_mapping_agent.py).

## What this is not

TamVi Agent Gate is not:

- an agent manager or MainBrain;
- a sandbox, permission system, or credential vault;
- a static code scanner or compliance suite;
- a factual truth oracle;
- agent identity, memory, personality, or private architecture;
- an LLM self-critique loop.

## Extension points

- Custom guards: [docs/EXTENDING.md](docs/EXTENDING.md)
- Public boundary: [docs/PUBLIC_BOUNDARY.md](docs/PUBLIC_BOUNDARY.md)
- Security reporting: [SECURITY.md](SECURITY.md)
- Non-technical mental model: [docs/NON_TECH_GUIDE.md](docs/NON_TECH_GUIDE.md)

## Status

Version `0.2.1` implements shared contract `1.0`. Keep agent-specific policies and adapters in the consuming agent repositories.

## License

MIT
