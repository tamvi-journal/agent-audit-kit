import json

from agent_audit_kit import (
    CandidateOutput,
    audit_candidate,
    forbidden_terms_guard,
    max_length_guard,
    require_metadata_fields_guard,
    require_sources_guard,
)
from agent_audit_kit.cli import (
    EXIT_BLOCKED,
    EXIT_INVALID_INPUT,
    EXIT_OK,
    EXIT_REVIEW,
    main,
)


def test_builtin_guards_are_opt_in_and_explainable():
    output = CandidateOutput(
        content="internal only",
        evidence={},
        metadata={},
    )
    findings = (
        max_length_guard(5)(output),
        forbidden_terms_guard(["internal"])(output),
        require_sources_guard(output),
        require_metadata_fields_guard("worker_id")(output),
    )

    assert {finding.kind for finding in findings if finding is not None} == {
        "max_length_exceeded",
        "forbidden_term",
        "required_sources_missing",
        "required_metadata_missing",
    }


def test_extended_secret_formats_block_and_redact():
    cases = (
        ("aws_access_key_id", "AK" + "IA" + "ABCDEFGHIJKLMNOP"),
        ("slack_token", "xo" + "xb-" + "1234567890ABCDEF-"),
        ("google_api_key", "AI" + "za" + "A" * 34 + "_"),
        ("jwt", "ey" + "Jheader.payloadpart.signaturepart_"),
    )
    verified = {
        "sources": ["unit-test"],
        "checks_run": ["secret-scan"],
        "artifacts": ["artifacts/secret-scan.log"],
        "verifier": "unit-test",
    }

    for expected_kind, synthetic_secret in cases:
        result = audit_candidate(
            CandidateOutput(
                content="value=" + synthetic_secret,
                evidence={"sources": ["unit-test"], "checks_run": ["secret-scan"]},
            ),
            verified_evidence=verified,
        )

        assert result.status == "blocked_candidate"
        assert any(finding.kind == expected_kind for finding in result.findings)
        assert synthetic_secret not in result.output.content


def test_cli_preflight_emits_versioned_json(tmp_path, capsys):
    envelope = tmp_path / "envelope.json"
    policy = tmp_path / "policy.json"
    envelope.write_text(
        json.dumps(
            {
                "requested_tools": ["filesystem_read"],
                "requested_actions": ["draft_response"],
                "network_access": False,
            }
        ),
        encoding="utf-8",
    )
    policy.write_text(
        json.dumps(
            {
                "allowed_tools": ["filesystem_read"],
                "allowed_actions": ["draft_response"],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "preflight",
            "--envelope",
            str(envelope),
            "--policy",
            str(policy),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == EXIT_OK
    assert payload["contract_version"] == "1.0"
    assert payload["status"] == "allowed"


def test_cli_audit_uses_mapping_contract(tmp_path, capsys):
    candidate = tmp_path / "candidate.json"
    verified = tmp_path / "verified.json"
    envelope = tmp_path / "envelope.json"
    candidate.write_text(
        json.dumps(
            {
                "worker_id": "worker-a",
                "content": "Candidate.",
                "sources": ["worker"],
                "checks_run": ["claimed"],
            }
        ),
        encoding="utf-8",
    )
    verified.write_text(
        json.dumps(
            {
                "sources": ["ci"],
                "checks_run": ["pytest"],
                "artifacts": ["artifacts/pytest.log"],
                "verifier": "mainbrain",
            }
        ),
        encoding="utf-8",
    )
    envelope.write_text(
        json.dumps({"worker_id": "worker-a"}),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "audit",
            "--candidate",
            str(candidate),
            "--verified",
            str(verified),
            "--envelope",
            str(envelope),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == EXIT_OK
    assert payload["status"] == "approved_candidate"
    assert payload["eligible_for_release"] is True


def test_cli_allow_unverified_still_routes_to_review(tmp_path, capsys):
    candidate = tmp_path / "candidate.json"
    candidate.write_text(
        json.dumps(
            {
                "content": "Draft.",
                "sources": ["worker"],
                "checks_run": ["claimed"],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "audit",
            "--candidate",
            str(candidate),
            "--allow-unverified",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == EXIT_REVIEW
    assert payload["status"] == "needs_review"


def test_cli_secret_finding_returns_blocked_exit(tmp_path, capsys):
    candidate = tmp_path / "candidate.json"
    verified = tmp_path / "verified.json"
    fake_key = "sk-proj-" + "abcdefghijklmnopqrstuvwxyz1234567890"
    candidate.write_text(
        json.dumps(
            {
                "content": "OPENAI_API_KEY=" + fake_key,
                "sources": ["worker"],
                "checks_run": ["claimed"],
            }
        ),
        encoding="utf-8",
    )
    verified.write_text(
        json.dumps(
            {
                "sources": ["ci"],
                "checks_run": ["scan"],
                "artifacts": ["artifacts/scan.log"],
                "verifier": "mainbrain",
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "audit",
            "--candidate",
            str(candidate),
            "--verified",
            str(verified),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == EXIT_BLOCKED
    assert payload["status"] == "blocked_candidate"
    assert fake_key not in payload["output"]["content"]


def test_cli_rejects_malformed_policy_instead_of_relaxing_it(tmp_path, capsys):
    envelope = tmp_path / "envelope.json"
    policy = tmp_path / "policy.json"
    envelope.write_text(
        json.dumps({"requested_tools": ["shell"]}),
        encoding="utf-8",
    )
    policy.write_text(
        json.dumps({"allowed_tools": [{}]}),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "preflight",
            "--envelope",
            str(envelope),
            "--policy",
            str(policy),
        ]
    )
    payload = json.loads(capsys.readouterr().err)

    assert exit_code == EXIT_INVALID_INPUT
    assert payload["contract_version"] == "1.0"
    assert payload["status"] == "invalid_input"
    assert "allowed_tools" in payload["error"]


def test_forbidden_terms_guard_treats_string_as_one_term():
    guard = forbidden_terms_guard("internal only")

    finding = guard(CandidateOutput(content="internal only"))

    assert finding is not None
    assert finding.details["matches"] == ["internal only"]


def test_cli_audit_rejects_policy_without_envelope(tmp_path, capsys):
    candidate = tmp_path / "candidate.json"
    policy = tmp_path / "policy.json"
    candidate.write_text(
        json.dumps(
            {
                "content": "Candidate.",
                "sources": ["worker"],
                "checks_run": ["claimed"],
            }
        ),
        encoding="utf-8",
    )
    policy.write_text(
        json.dumps({"allowed_tools": ["filesystem_read"]}),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "audit",
            "--candidate",
            str(candidate),
            "--policy",
            str(policy),
        ]
    )
    payload = json.loads(capsys.readouterr().err)

    assert exit_code == EXIT_INVALID_INPUT
    assert payload["status"] == "invalid_input"
    assert payload["error"] == "--policy requires --envelope for audit"
