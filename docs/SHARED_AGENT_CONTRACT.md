# Shared Agent Contract v1

Contract version: `1.0`

This document defines the generic boundary shared by TamVi agents. It does not define any agent's identity, memory, domain policy, orchestration, or final authority.

## 1. Principals

- **Caller / MainBrain** owns the trusted invocation envelope and release decision.
- **Worker** produces a candidate packet and claimed evidence.
- **Verifier** is a different principal controlled outside the worker.
- **Gate** classifies the candidate under configured checks; it does not prove truth.

## 2. Invocation order

```text
construct trusted envelope
-> preflight_task(envelope, policy)
-> only if allowed: invoke worker
-> normalize candidate packet
-> guard output
-> attach caller-controlled verified evidence
-> audit and release decision
```

Calling `audit_candidate()` retrospectively does not repair a skipped preflight.

## 3. Trusted envelope

Common fields:

```json
{
  "worker_id": "research-worker",
  "requested_tools": ["filesystem_read"],
  "requested_actions": ["draft_response"],
  "network_access": false,
  "shell_access": false,
  "external_mutation": false,
  "money_touching": false,
  "completion_authority": false
}
```

Identity fields (`worker_id`, `worker`, `agent_id`) must be nonblank strings. If multiple identity fields exist, they must agree. Malformed or conflicting identity blocks preflight.

Sensitive capability flags must be booleans. A true flag requires explicit policy permission; completion authority is blocked by default.

Policy mappings are parsed strictly. Action/tool collections must contain only nonblank strings and capability permissions must be booleans. Malformed policy data is invalid input; it never falls back to a looser policy. Every audit API rejects a policy when no envelope is available to evaluate it.

## 4. Candidate packet

Canonical shape:

```json
{
  "content": "Candidate text",
  "evidence": {
    "sources": ["worker-log"],
    "checks_run": ["claimed-check"],
    "artifacts": ["artifacts/claimed.log"]
  },
  "metadata": {
    "worker_id": "research-worker",
    "task_id": "task-123"
  }
}
```

Mapping adapters also accept top-level `output`, `text`, or `summary`; top-level `sources`, `checks_run`, `evidence_handles`, `artifact_handles`, and `artifacts`; and top-level worker/task identity fields.

Exactly one supported content field is selected by priority and it must be a string. Blank content is not release eligible. Candidate evidence is always claimed evidence.

## 5. Verified evidence

Canonical shape:

```json
{
  "verifier": "mainbrain",
  "sources": ["ci-log"],
  "checks_run": ["pytest"],
  "artifacts": ["artifacts/pytest.log"]
}
```

Accepted aliases are `verified_by`, `verified_sources`, `source_refs`, `verified_checks`, `evidence_handles`, `verified_evidence_handles`, and `artifact_handles`.

Artifact entries may be:

- a nonblank string; or
- a mapping containing a nonblank string in `path`, `locator`, `uri`, `url`, `artifact_id`, `id`, or `sha256`.

Containers, booleans, numbers, `null`, blank strings, empty mappings, and metadata-only mappings do not count as inspectable artifacts.

Verifier identity must be a nonblank string. A worker cannot verify itself. If trusted envelope identity and candidate identity disagree, the candidate is not release eligible.

## 6. Stable statuses

| Stage | Statuses |
|---|---|
| Preflight | `allowed`, `needs_approval`, `blocked` |
| Audit | `approved_candidate`, `needs_review`, `blocked_candidate` |

`approved_candidate` means eligible under configured checks, not proven true and not automatically executed.

## 7. Versioned records

`Finding`, `PreflightResult`, `AuditResult`, and `GuardedTaskResult` expose `to_dict()`. Records contain `contract_version: "1.0"`.

Consumers must:

- reject unknown major contract versions;
- preserve structured findings rather than only limitation text;
- keep top-level release status authoritative;
- avoid treating logs or observability records as approval.

## 8. Agent adapter rule

Keep the adapter inside each consuming agent repository. The shared kernel must not import agent-specific prompts, memory, skills, credentials, private paths, or identity rules.

Recommended rollout:

1. Add adapter and contract tests in the agent repository.
2. Run in shadow mode and compare decisions.
3. Enable preflight and audit enforcement.
4. Remove duplicated local gate code only after parity is verified.

## 9. Anti-patterns

- Worker supplies both candidate and verified evidence.
- Worker metadata overrides the trusted envelope.
- Preflight runs after the worker.
- Free-text LLM approval counts as verification.
- Audit output directly triggers external mutation.
- `allow-unverified` is treated as release permission.
- Agent-specific domain logic is added to the shared kernel.
