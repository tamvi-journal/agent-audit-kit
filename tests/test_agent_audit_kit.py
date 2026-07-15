from agent_audit_kit import CandidateOutput, PreflightPolicy, audit_candidate, redact_text


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
