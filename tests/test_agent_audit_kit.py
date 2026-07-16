import asyncio

from agent_audit_kit import (
    AuditConfig,
    CandidateOutput,
    Finding,
    PreflightPolicy,
    audit_candidate,
    audit_candidate_async,
    preflight_task,
    redact_text,
    run_guarded_task,
    run_guarded_task_async,
)


VERIFIED = {
    "sources": ["unit-test-log"],
    "checks_run": ["pytest"],
    "artifacts": ["pytest-output"],
    "verifier": "unit-test",
}


def _policy() -> PreflightPolicy:
    return PreflightPolicy(
        allowed_tools=("filesystem_read",),
        forbidden_tools=("network",),
        allowed_actions=("draft_response",),
        blocked_actions=("read_secret", "print_secret"),
    )


def _allowed_envelope():
    return {
        "requested_tools": ["filesystem_read"],
        "requested_actions": ["draft_response"],
        "network_access": False,
    }


def test_blocked_preflight_does_not_call_worker_callback():
    called = []

    def worker(_envelope):
        called.append(True)
        return CandidateOutput(content="should not run")

    result = run_guarded_task(
        {"requested_tools": ["network"], "requested_actions": ["draft_response"]},
        _policy(),
        worker,
        verified_evidence=VERIFIED,
    )

    assert result.status == "blocked"
    assert result.preflight.blocked
    assert not result.worker_ran
    assert called == []


def test_preflight_task_exposes_can_execute_and_status():
    result = preflight_task(_allowed_envelope(), _policy())

    assert result.status == "allowed"
    assert result.can_execute
    assert result.findings == ()


def test_claimed_evidence_without_verified_evidence_needs_review():
    output = CandidateOutput(
        content="Worker says tests passed.",
        evidence={"sources": ["worker-log"], "checks_run": ["claimed-pytest"]},
    )

    result = audit_candidate(output)

    assert result.status == "needs_review"
    assert not result.eligible_for_release
    assert any(finding.kind == "missing_verified_evidence" for finding in result.findings)


def test_verified_evidence_allows_eligible_candidate_when_clean():
    output = CandidateOutput(
        content="Created the requested draft and ran unit tests.",
        evidence={"sources": ["worker-log"], "checks_run": ["claimed-pytest"]},
    )

    result = audit_candidate(output, verified_evidence=VERIFIED)

    assert result.status == "approved_candidate"
    assert result.eligible_for_release
    assert [finding.kind for finding in result.findings] == ["secret_scan_scope"]
    assert result.findings[0].severity == "info"
    assert result.redacted_content is None


def test_secret_scan_scope_note_is_present_on_clean_pass_without_blocking():
    output = CandidateOutput(
        content="No synthetic secrets here.",
        evidence={"sources": ["worker-log"], "checks_run": ["claimed-pytest"]},
    )

    result = audit_candidate(output, verified_evidence=VERIFIED)

    assert result.status == "approved_candidate"
    assert result.eligible_for_release
    assert any(finding.kind == "secret_scan_scope" for finding in result.findings)
    assert not any(finding.kind == "openai_api_key" for finding in result.findings)


def test_secret_like_output_is_redacted_and_blocked_even_with_verified_evidence():
    fake_key = "sk-proj-" + "abcdefghijklmnopqrstuvwxyz1234567890"
    output = CandidateOutput(
        content="OPENAI_API_KEY=" + fake_key,
        evidence={"sources": ["unit-test"], "checks_run": ["secret-scan"]},
    )

    result = audit_candidate(output, verified_evidence=VERIFIED)

    assert result.status == "blocked_candidate"
    assert fake_key not in result.output.content
    assert "[REDACTED_OPENAI_API_KEY]" in result.output.content
    assert any(finding.kind == "openai_api_key" for finding in result.findings)


def test_missing_verified_evidence_is_not_approved():
    output = CandidateOutput(
        content="The task appears complete.",
        evidence={"sources": ["worker"], "checks_run": ["claimed-check"]},
    )

    result = audit_candidate(output)

    assert result.status == "needs_review"
    assert not result.passed


def test_verified_evidence_without_artifact_needs_review():
    output = CandidateOutput(
        content="The task appears complete.",
        evidence={"sources": ["worker"], "checks_run": ["claimed-check"]},
    )
    verified = {
        "sources": ["review-note"],
        "checks_run": ["manual-review"],
        "verifier": "human-reviewer",
    }

    result = audit_candidate(output, verified_evidence=verified)

    assert result.status == "needs_review"
    assert not result.eligible_for_release
    assert any(finding.kind == "verifier_artifact_missing" for finding in result.findings)


def test_verified_evidence_without_verifier_needs_review():
    output = CandidateOutput(
        content="The task appears complete.",
        evidence={"sources": ["worker"], "checks_run": ["claimed-check"]},
    )
    verified = {
        "sources": ["ci-log"],
        "checks_run": ["pytest"],
        "artifacts": ["ci/pytest.log"],
    }

    result = audit_candidate(output, verified_evidence=verified)

    assert result.status == "needs_review"
    assert not result.eligible_for_release
    assert any(finding.kind == "verifier_missing" for finding in result.findings)


def test_self_verification_needs_review_when_worker_identity_matches():
    output = CandidateOutput(
        content="Worker says tests passed.",
        evidence={"sources": ["worker-log"], "checks_run": ["claimed-pytest"]},
        metadata={"worker_id": "repo-worker"},
    )
    verified = {
        "sources": ["worker-log"],
        "checks_run": ["pytest"],
        "artifacts": ["logs/pytest.log"],
        "verifier": "repo-worker",
    }

    result = audit_candidate(output, verified_evidence=verified)

    assert result.status == "needs_review"
    assert not result.eligible_for_release
    assert any(finding.kind == "self_verification" for finding in result.findings)


def test_missing_claimed_evidence_needs_review_even_with_verified_evidence():
    output = CandidateOutput(content="The task appears complete.")

    result = audit_candidate(output, verified_evidence=VERIFIED)

    assert result.status == "needs_review"
    assert {"missing_claimed_sources", "missing_claimed_checks"}.issubset(
        {finding.kind for finding in result.findings}
    )


def test_redact_text_does_not_return_database_url():
    dsn = "postgres://" + "user:pass@example.com:5432/app"
    redacted = redact_text("DATABASE_URL=" + dsn)

    assert dsn not in redacted
    assert "[REDACTED_DATABASE_DSN]" in redacted


def test_secret_finding_includes_explainable_location_details():
    fake_key = "sk-proj-" + "abcdefghijklmnopqrstuvwxyz1234567890"
    output = CandidateOutput(
        content="line one\nOPENAI_API_KEY=" + fake_key,
        evidence={"sources": ["unit-test"], "checks_run": ["secret-scan"]},
    )

    result = audit_candidate(output, verified_evidence=VERIFIED)
    finding = next(item for item in result.findings if item.kind == "openai_api_key")

    assert finding.details["line"] == 2
    assert finding.details["column"] == len("OPENAI_API_KEY=") + 1
    assert any("openai_api_key" in line for line in result.explanations)


def test_custom_guard_can_mark_output_for_review():
    def no_completion_claims(output: CandidateOutput):
        if "definitely complete" in output.content.lower():
            return Finding(
                kind="overconfident_completion_claim",
                message="The candidate claims completion too strongly.",
                severity="medium",
            )
        return None

    result = audit_candidate(
        CandidateOutput(
            content="This is definitely complete.",
            evidence={"sources": ["unit-test"], "checks_run": ["custom-guard"]},
        ),
        verified_evidence=VERIFIED,
        custom_guards=(no_completion_claims,),
    )

    assert result.status == "needs_review"
    assert any(finding.kind == "overconfident_completion_claim" for finding in result.findings)


def test_disabling_verified_evidence_cannot_grant_release_eligibility():
    result = audit_candidate(
        CandidateOutput(
            content="Draft only, verified evidence disabled.",
            evidence={"sources": ["caller"], "checks_run": ["manual"]},
        ),
        config=AuditConfig(require_verified_evidence=False),
    )

    assert result.status == "needs_review"
    assert not result.eligible_for_release
    assert any(
        finding.kind == "verification_requirement_disabled"
        for finding in result.findings
    )


def test_review_callback_receives_non_passing_result():
    reviewed = []

    def review_callback(result):
        reviewed.append(result.status)

    audit_candidate(
        CandidateOutput(content="Needs evidence."),
        review_callback=review_callback,
    )

    assert reviewed == ["needs_review"]


def test_async_api_keeps_sync_semantics_for_verified_evidence():
    async def run():
        return await audit_candidate_async(
            CandidateOutput(
                content="Async candidate.",
                evidence={"sources": ["unit-test"], "checks_run": ["async-audit"]},
            ),
            verified_evidence=VERIFIED,
        )

    result = asyncio.run(run())

    assert result.status == "approved_candidate"
    assert result.eligible_for_release


def test_async_guarded_task_does_not_call_worker_when_preflight_blocks():
    called = []

    async def worker(_envelope):
        called.append(True)
        return CandidateOutput(content="should not run")

    async def run():
        return await run_guarded_task_async(
            {"requested_tools": ["network"], "requested_actions": ["draft_response"]},
            _policy(),
            worker,
            verified_evidence=VERIFIED,
        )

    result = asyncio.run(run())

    assert result.status == "blocked"
    assert not result.worker_ran
    assert called == []


def test_run_guarded_task_runs_worker_after_allowed_preflight():
    called = []

    def worker(_envelope):
        called.append(True)
        return CandidateOutput(
            content="Worker output.",
            evidence={"sources": ["worker"], "checks_run": ["claimed-check"]},
        )

    result = run_guarded_task(_allowed_envelope(), _policy(), worker, verified_evidence=VERIFIED)

    assert called == [True]
    assert result.worker_ran
    assert result.eligible_for_release


def test_envelope_identity_overrides_spoofed_candidate_metadata():
    output = CandidateOutput(
        content="Worker says tests passed.",
        evidence={"sources": ["worker-log"], "checks_run": ["claimed-pytest"]},
        metadata={"worker_id": "spoofed-worker"},
    )
    verified = {
        "sources": ["worker-log"],
        "checks_run": ["pytest"],
        "artifacts": ["logs/pytest.log"],
        "verifier": "trusted-worker",
    }

    result = audit_candidate(
        output,
        verified_evidence=verified,
        envelope={"worker_id": "trusted-worker"},
    )

    assert result.status == "needs_review"
    assert any(finding.kind == "self_verification" for finding in result.findings)


def test_run_guarded_task_catches_self_verification_from_envelope_identity():
    envelope = {**_allowed_envelope(), "worker_id": "trusted-worker"}

    def worker(_envelope):
        return CandidateOutput(
            content="Worker output.",
            evidence={"sources": ["worker"], "checks_run": ["claimed-check"]},
        )

    verified = {
        "sources": ["worker-log"],
        "checks_run": ["pytest"],
        "artifacts": ["logs/pytest.log"],
        "verifier": "trusted-worker",
    }

    result = run_guarded_task(envelope, _policy(), worker, verified_evidence=verified)

    assert result.worker_ran
    assert result.status == "needs_review"
    assert result.audit is not None
    assert any(finding.kind == "self_verification" for finding in result.audit.findings)


def test_run_guarded_task_async_catches_self_verification_from_envelope_identity():
    envelope = {**_allowed_envelope(), "worker_id": "trusted-worker"}

    async def worker(_envelope):
        return CandidateOutput(
            content="Worker output.",
            evidence={"sources": ["worker"], "checks_run": ["claimed-check"]},
        )

    verified = {
        "sources": ["worker-log"],
        "checks_run": ["pytest"],
        "artifacts": ["logs/pytest.log"],
        "verifier": "trusted-worker",
    }

    async def run():
        return await run_guarded_task_async(envelope, _policy(), worker, verified_evidence=verified)

    result = asyncio.run(run())

    assert result.worker_ran
    assert result.status == "needs_review"
    assert result.audit is not None
    assert any(finding.kind == "self_verification" for finding in result.audit.findings)


def test_blocking_kind_with_info_severity_still_blocks():
    def bad_guard(_output):
        return Finding(
            kind="openai_api_key",
            message="Blocking kind must remain blocking regardless of severity.",
            severity="info",
        )

    result = audit_candidate(
        CandidateOutput(
            content="No synthetic secrets here.",
            evidence={"sources": ["unit-test"], "checks_run": ["custom-guard"]},
        ),
        verified_evidence=VERIFIED,
        custom_guards=(bad_guard,),
    )

    assert result.status == "blocked_candidate"


def test_secret_scan_scope_is_the_only_non_actionable_info_finding():
    result = audit_candidate(
        CandidateOutput(
            content="No synthetic secrets here.",
            evidence={"sources": ["unit-test"], "checks_run": ["secret-scan"]},
        ),
        verified_evidence=VERIFIED,
    )

    assert result.status == "approved_candidate"
    assert [finding.kind for finding in result.findings] == ["secret_scan_scope"]
