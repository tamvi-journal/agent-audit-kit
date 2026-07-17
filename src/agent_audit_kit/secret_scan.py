from __future__ import annotations

from dataclasses import dataclass
import re

from agent_audit_kit.models import Finding


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "openai_api_key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        "[REDACTED_OPENAI_API_KEY]",
    ),
    (
        "github_token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"),
        "[REDACTED_GITHUB_TOKEN]",
    ),
    (
        "aws_access_key_id",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "[REDACTED_AWS_ACCESS_KEY_ID]",
    ),
    (
        "slack_token",
        re.compile(
            r"(?<![A-Za-z0-9-])xox(?:a|b|c|e|o|p|r|s)-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])"
        ),
        "[REDACTED_SLACK_TOKEN]",
    ),
    (
        "google_api_key",
        re.compile(r"(?<![0-9A-Za-z_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
        "[REDACTED_GOOGLE_API_KEY]",
    ),
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\."
            r"[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])"
        ),
        "[REDACTED_JWT]",
    ),
    (
        "bearer_token",
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{24,}\b", re.IGNORECASE),
        "Bearer [REDACTED_TOKEN]",
    ),
    (
        "database_dsn",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"<>]+", re.IGNORECASE),
        "[REDACTED_DATABASE_DSN]",
    ),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PRIVATE )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA |PRIVATE )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
)


@dataclass(frozen=True)
class SecretScan:
    findings: tuple[Finding, ...]
    redacted_text: str

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def has_secret_findings(self) -> bool:
        return any(finding.kind != "secret_scan_scope" for finding in self.findings)


def scan_text(text: str | None, *, source: str = "candidate_output") -> SecretScan:
    """Run a pattern-limited secret scan.

    This catches known token/key formats only. A clean result is not a guarantee
    that no secret exists, and it does not replace secret managers, pre-commit
    scanners, or repository-history cleanup.
    """

    value = text or ""
    findings: list[Finding] = [
        Finding(
            kind="secret_scan_scope",
            message=(
                "Pattern-based secret scan only checks known key formats; "
                "a pass is not a guarantee that no secret exists."
            ),
            source=source,
            severity="info",
            details={"pattern_count": len(SECRET_PATTERNS)},
        )
    ]
    redacted = value

    for kind, pattern, redaction in SECRET_PATTERNS:
        for match in pattern.finditer(value):
            line, column = _line_column(value, match.start())
            findings.append(
                Finding(
                    kind=kind,
                    message=f"{kind} detected and redacted",
                    source=source,
                    severity="high",
                    details={
                        "line": line,
                        "column": column,
                        "start": match.start(),
                        "end": match.end(),
                        "redaction": redaction,
                    },
                )
            )
        redacted = pattern.sub(redaction, redacted)

    return SecretScan(findings=tuple(findings), redacted_text=redacted)


def redact_text(text: str | None, *, source: str = "candidate_output") -> str:
    return scan_text(text, source=source).redacted_text


def _line_column(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    line_start = text.rfind("\n", 0, index)
    column = index + 1 if line_start < 0 else index - line_start
    return line, column
