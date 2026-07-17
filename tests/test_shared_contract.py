import pytest

from agent_audit_kit import (
    CONTRACT_VERSION,
    AuditConfig,
    CandidateOutput,
    PreflightPolicy,
    audit_agent_packet,
    audit_candidate,
    preflight_task,
    run_guarded_task,
)


VERIFIED_ALIASES = {
    "sources": ["ci-log"],
    "verified_checks": ["pytest"],
    "evidence_handles": [{"path": "artifacts/pytest.log"}],
    "verified_by": "mainbrain",
}


def allowed_policy():
    return PreflightPolicy(
        allowed_tools=("filesystem_read",),
        allowed_actions=("draft_response",),
    )


def allowed_envelope():
    return {
        "worker_id": "worker-a",
        "requested_tools": ["filesystem_read"],
        "requested_actions": ["draft_response"],
        "network_access": False,
        "shell_access": False,
        "external_mutation": False,
        "money_touching": False,
        "completion_authority": False,
    }


def mapping_candidate():
    return {
        "worker_id": "worker-a",
        "content": "Candidate packet.",
        "sources": ["worker-log"],
        "checks_run": ["claimed-check"],
        "evidence_handles": [{"path": "artifacts/claimed.log"}],
    }


def test_mapping_packet_and_aliases_use_shared_contract():
    result = audit_candidate(
        mapping_candidate(),
        verified_evidence=VERIFIED_ALIASES,
        envelope=allowed_envelope(),
    )

    assert result.status == "approved_candidate"
    assert result.output.metadata["worker_id"] == "worker-a"
    assert result.to_dict()["contract_version"] == CONTRACT_VERSION


@pytest.mark.parametrize(
    "invalid_handle",
    [{}, {"path": {}}, {"path": []}, {"path": "  "}, 1, True, None],
)
def test_malformed_verified_artifact_handles_are_rejected(invalid_handle):
    verified = {
        "sources": ["ci-log"],
        "checks_run": ["pytest"],
        "artifacts": [invalid_handle],
        "verifier": "mainbrain",
    }

    result = audit_candidate(
        mapping_candidate(),
        verified_evidence=verified,
        envelope=allowed_envelope(),
    )

    assert result.status == "needs_review"
    assert any(
        finding.kind == "verifier_artifact_missing"
        for finding in result.findings
    )


@pytest.mark.parametrize("invalid_verifier", [{}, [], True, 1, None, "  "])
def test_malformed_verifier_identity_is_rejected(invalid_verifier):
    verified = {
        "sources": ["ci-log"],
        "checks_run": ["pytest"],
        "artifacts": ["artifacts/pytest.log"],
        "verifier": invalid_verifier,
    }

    result = audit_candidate(
        mapping_candidate(),
        verified_evidence=verified,
        envelope=allowed_envelope(),
    )

    assert result.status == "needs_review"
    assert any(finding.kind == "verifier_missing" for finding in result.findings)


def test_envelope_packet_identity_mismatch_is_not_release_eligible():
    packet = mapping_candidate()
    packet["worker_id"] = "spoofed-worker"

    result = audit_candidate(
        packet,
        verified_evidence=VERIFIED_ALIASES,
        envelope=allowed_envelope(),
    )

    assert result.status == "needs_review"
    assert any(
        finding.kind == "worker_identity_mismatch"
        for finding in result.findings
    )


@pytest.mark.parametrize("invalid_identity", [{}, [], True, 1, None, "  "])
def test_malformed_worker_identity_is_not_release_eligible(invalid_identity):
    envelope = allowed_envelope()
    envelope["worker_id"] = invalid_identity

    result = audit_candidate(
        mapping_candidate(),
        verified_evidence=VERIFIED_ALIASES,
        envelope=envelope,
    )

    assert result.status == "needs_review"
    assert any(
        finding.kind == "invalid_worker_identity"
        for finding in result.findings
    )


def test_guarded_task_accepts_mapping_worker_output():
    result = run_guarded_task(
        allowed_envelope(),
        allowed_policy(),
        lambda _envelope: mapping_candidate(),
        verified_evidence=VERIFIED_ALIASES,
    )

    assert result.worker_ran
    assert result.status == "approved_candidate"
    assert result.to_dict()["contract_version"] == CONTRACT_VERSION


def test_serialized_records_do_not_alias_candidate_metadata():
    candidate = CandidateOutput(
        content="Candidate.",
        evidence={"sources": ["worker"], "checks_run": ["claimed"]},
        metadata={"worker_id": "worker-a"},
    )
    result = audit_candidate(
        candidate,
        verified_evidence=VERIFIED_ALIASES,
        envelope=allowed_envelope(),
    )

    record = result.to_dict()
    record["output"]["metadata"]["worker_id"] = "mutated"

    assert candidate.metadata["worker_id"] == "worker-a"
    assert result.output.metadata["worker_id"] == "worker-a"


def test_adapter_returns_versioned_json_record():
    record = audit_agent_packet(
        mapping_candidate(),
        verified_evidence=VERIFIED_ALIASES,
        envelope=allowed_envelope(),
    )

    assert record["contract_version"] == CONTRACT_VERSION
    assert record["status"] == "approved_candidate"
    assert record["eligible_for_release"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("requested_tools", [{}]),
        ("requested_actions", [""]),
        ("network_access", "false"),
        ("worker_id", {}),
    ],
)
def test_malformed_preflight_fields_block_before_worker(field, value):
    envelope = allowed_envelope()
    envelope[field] = value

    result = preflight_task(envelope, allowed_policy())

    assert result.status == "blocked"
    assert any(
        finding.kind == "invalid_envelope_field"
        for finding in result.findings
    )


@pytest.mark.parametrize(
    "field",
    ["network_access", "shell_access", "external_mutation", "money_touching"],
)
def test_sensitive_capability_flags_require_approval_by_default(field):
    envelope = allowed_envelope()
    envelope[field] = True

    result = preflight_task(envelope, allowed_policy())

    assert result.status == "needs_approval"


def test_completion_authority_is_blocked_by_default():
    envelope = allowed_envelope()
    envelope["completion_authority"] = True

    result = preflight_task(envelope, allowed_policy())

    assert result.status == "blocked"
    assert any(
        finding.kind == "completion_authority_forbidden"
        for finding in result.findings
    )


def test_disabling_verification_only_creates_review_mode():
    result = audit_candidate(
        mapping_candidate(),
        envelope=allowed_envelope(),
        config=AuditConfig(require_verified_evidence=False),
    )

    assert result.status == "needs_review"
    assert not result.eligible_for_release


@pytest.mark.parametrize(
    "policy",
    [
        {"allowed_tools": [{}]},
        {"allowed_tools": [""]},
        {"allowed_actions": 1},
        {"network_allowed": "false"},
        {"completion_authority": 1},
    ],
)
def test_malformed_policy_mapping_fails_closed(policy):
    with pytest.raises(ValueError):
        PreflightPolicy.from_mapping(policy)


@pytest.mark.parametrize("packet", [{}, {"content": {}}, {"output": []}])
def test_mapping_candidate_requires_string_content(packet):
    with pytest.raises(ValueError):
        audit_candidate(packet, verified_evidence=VERIFIED_ALIASES)


def test_blank_candidate_content_is_not_release_eligible():
    packet = mapping_candidate()
    packet["content"] = "  "

    result = audit_candidate(
        packet,
        verified_evidence=VERIFIED_ALIASES,
        envelope=allowed_envelope(),
    )

    assert result.status == "needs_review"
    assert any(
        finding.kind == "empty_candidate_content"
        for finding in result.findings
    )


def test_non_string_typed_candidate_content_is_blocked():
    candidate = CandidateOutput(
        content=1,  # type: ignore[arg-type]
        evidence={"sources": ["worker"], "checks_run": ["claimed"]},
    )

    result = audit_candidate(candidate, verified_evidence=VERIFIED_ALIASES)

    assert result.status == "blocked_candidate"
    assert result.output.content == ""
    assert any(
        finding.kind == "invalid_candidate_content"
        for finding in result.findings
    )


def test_conflicting_envelope_identity_fields_are_not_release_eligible():
    envelope = allowed_envelope()
    envelope["agent_id"] = "different-worker"

    result = audit_candidate(
        mapping_candidate(),
        verified_evidence=VERIFIED_ALIASES,
        envelope=envelope,
    )

    assert result.status == "needs_review"
    assert any(
        finding.kind == "invalid_worker_identity"
        for finding in result.findings
    )


def test_artifact_resolver_accepts_reachable_verified_artifact():
    resolved = []

    def resolver(locator):
        resolved.append(locator)
        return True

    result = audit_candidate(
        mapping_candidate(),
        verified_evidence=VERIFIED_ALIASES,
        envelope=allowed_envelope(),
        config=AuditConfig(artifact_resolver=resolver),
    )

    assert result.status == "approved_candidate"
    assert resolved == ["artifacts/pytest.log"]


def test_artifact_resolver_rejects_unreachable_verified_artifact():
    result = audit_candidate(
        mapping_candidate(),
        verified_evidence=VERIFIED_ALIASES,
        envelope=allowed_envelope(),
        config=AuditConfig(artifact_resolver=lambda _locator: False),
    )

    assert result.status == "needs_review"
    assert any(
        finding.kind == "verifier_artifact_unresolved"
        for finding in result.findings
    )


def test_artifact_resolver_error_fails_closed_without_leaking_exception():
    def resolver(_locator):
        raise RuntimeError("private resolver detail")

    result = audit_candidate(
        mapping_candidate(),
        verified_evidence=VERIFIED_ALIASES,
        envelope=allowed_envelope(),
        config=AuditConfig(artifact_resolver=resolver),
    )

    assert result.status == "needs_review"
    assert any(
        finding.kind == "artifact_resolver_error"
        for finding in result.findings
    )
    assert "private resolver detail" not in " ".join(result.explanations)


def test_artifact_resolver_requires_boolean_result():
    result = audit_candidate(
        mapping_candidate(),
        verified_evidence=VERIFIED_ALIASES,
        envelope=allowed_envelope(),
        config=AuditConfig(artifact_resolver=lambda _locator: "yes"),
    )

    assert result.status == "needs_review"
    assert any(
        finding.kind == "artifact_resolver_invalid_result"
        for finding in result.findings
    )


def test_adapter_rejects_policy_without_envelope():
    with pytest.raises(ValueError, match="policy requires envelope"):
        audit_agent_packet(
            mapping_candidate(),
            verified_evidence=VERIFIED_ALIASES,
            policy=allowed_policy(),
        )


def test_config_policy_cannot_be_ignored_without_envelope():
    with pytest.raises(ValueError, match="policy requires envelope"):
        audit_candidate(
            mapping_candidate(),
            verified_evidence=VERIFIED_ALIASES,
            config=AuditConfig(policy=allowed_policy()),
        )
