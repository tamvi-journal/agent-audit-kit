import asyncio

from agent_audit_kit import AuditConfig, CandidateOutput, Finding, PreflightPolicy, audit_candidate, audit_candidate_async, redact_text


def test_secret_like_output_is_redacted_and_blocked():
    fake_key = "sk-proj-" + "abcdefghijklmnopqrstuvwxyz1234567890"
    output = CandidateOutput(
        content="OPENAI_API_KEY=" + fake_key,
        evidence={"sources": ["unit-test"], "checks_run": ["secret-scan"]},
    )

    result = audit_candidate(output)

    assert result.status == "blocked_candidate"
    assert fake_key not in result.output.content
    assert "[REDACTED_OPENAI_API_KEY]" in result.output.content
    assert any(finding.kind == "openai_api_key" for finding in result.findings)


def test_missing_evidence_needs_review():
    output = CandidateOutput(content="The task appears complete.")

    result = audit_candidate(output)

    assert result.status == "needs_review"
    assert {finding.kind for finding in result.findings} == {"missing_sources", "missing_checks"}


def test_preflight_blocks_forbidden_tool():
    output = CandidateOutput(
        content="I searched the web.",
        evidence={"sources": ["unit-test"], "checks_run": ["policy-check"]},
    )
    policy = PreflightPolicy(
        allowed_tools=("filesystem_read",),
        forbidden_tools=("network",),
    )

    result = audit_candidate(
        output,
        envelope={"requested_tools": ["network"], "requested_actions": []},
        policy=policy,
    )

    assert result.status == "blocked_candidate"
    assert any(finding.kind == "forbidden_tool" for finding in result.findings)


def test_safe_candidate_can_pass():
    output = CandidateOutput(
        content="Created the requested draft and ran unit tests.",
        evidence={"sources": ["local-test-log"], "checks_run": ["pytest"]},
    )

    result = audit_candidate(output)

    assert result.passed
    assert result.findings == ()


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

    result = audit_candidate(output)
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
        custom_guards=(no_completion_claims,),
    )

    assert result.status == "needs_review"
    assert any(finding.kind == "overconfident_completion_claim" for finding in result.findings)


def test_config_can_disable_evidence_requirement_for_lightweight_use():
    result = audit_candidate(
        CandidateOutput(content="Draft only, no evidence required."),
        config=AuditConfig(require_evidence=False),
    )

    assert result.status == "approved_candidate"


def test_review_callback_receives_non_passing_result():
    reviewed = []

    def review_callback(result):
        reviewed.append(result.status)

    audit_candidate(
        CandidateOutput(content="Needs evidence."),
        review_callback=review_callback,
    )

    assert reviewed == ["needs_review"]


def test_async_audit_candidate_matches_sync_api():
    async def run():
        return await audit_candidate_async(
            CandidateOutput(
                content="Async candidate.",
                evidence={"sources": ["unit-test"], "checks_run": ["async-audit"]},
            )
        )

    result = asyncio.run(run())

    assert result.status == "approved_candidate"
