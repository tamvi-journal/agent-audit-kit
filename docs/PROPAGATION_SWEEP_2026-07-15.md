# Propagation Sweep — 2026-07-15

Scope: harden the secret-scan warning and verifier constraints from Agent Audit Kit across known local repos that use or mirror the pattern.

## agent-audit-kit

- Status: changed.
- Branch: `fix/guard-verifier-hardening`.
- PR: https://github.com/tamvi-journal/agent-audit-kit/pull/2
- Changes:
  - `secret_scan_scope` info finding on clean secret-scan passes.
  - Info findings no longer force `needs_review`.
  - Verified evidence now requires non-empty verifier identity and inspectable artifacts.
  - Worker self-verification is downgraded to `needs_review` when worker identity is supplied.
  - README and `docs/EXTENDING.md` document verifier constraints and redaction limits at point of use.
- Verification:
  - `python3 -m pytest` → 19 passed.
  - `python3 -m compileall -q src tests` → passed.
  - Patch secret scan → 0 findings.

## tamvi-journal/Tracey-hybrid-Hermes

- Status: changed.
- Branch: `fix/guard-verifier-hardening`.
- PR: https://github.com/tamvi-journal/Tracey-hybrid-Hermes/pull/43
- Changes:
  - Runtime secret scanner now carries a pattern-limited `scope_note` without changing allow/block decisions.
  - Repo diff and worker payload scan results propagate the scope note.
  - Worker evidence gate now requires an external verifier plus inspectable evidence handle/artifact for release eligibility.
  - Worker self-verification is not release eligible.
  - Runtime README documents verifier and redaction limits.
- Verification:
  - `PYTHONDONTWRITEBYTECODE=1 python3 -B runtime/run_tests.py` → 235 passed.
  - `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_*.py' -t .` → 235 passed.
  - Tracey patch secret scan → 0 findings.

## Tracey-Projects/coin-scan-worker

- Status: changed locally; not pushed.
- Reason not pushed: local repo has no configured remote and already had uncommitted/untracked worker guard files.
- Changes:
  - `worker_runtime/security/secret_scan.py` adds pattern-limited scope note.
  - `worker_runtime/security/repo_diff_guard.py` propagates `scope_note`.
  - `worker_runtime/security/worker_io_guard.py` includes allow-path `secret_guard` scope note without blocking clean output.
  - `tests/test_anti_leak_guard.py` covers clean output and clean diff scope notes.
  - `worker_runtime/ANTI_LEAK_GUARD.md` documents pattern limits and redaction limits.
- Verification:
  - `python3 -m pytest` → 18 passed.
  - Patch secret scan → 0 findings.

## Tracey-Projects/finance-scan-worker

- Status: changed locally; not pushed.
- Reason not pushed: local repo has no configured remote and has no initial git commit.
- Changes:
  - Same local guard hardening as `coin-scan-worker`.
- Verification:
  - `python3 -m pytest` → 24 passed.
  - Patch secret scan → 0 findings.

## Aux-Projects/seyn-runtime

- Status: checked — no change.
- Finding: repo has evidence/gate language for Seyn's own graph promotion model, but does not consume Agent Audit Kit evidence packets or mirror the worker secret-scan guard implementation.

## tamvi-journal/state-memory-agent

- Status: not changed.
- Finding: no local checkout named `state-memory-agent` was found under `/Users/pinksilkpham` during this sweep, so there was no repo to inspect or patch locally.

