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


def scan_text(text: str | None, *, source: str = "candidate_output") -> SecretScan:
    value = text or ""
    findings: list[Finding] = []
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
