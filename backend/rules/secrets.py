import re
from typing import Optional
from backend.models.schemas import Finding

SECRET_PATTERNS = [
    (
        r"(?:password|passwd|pwd)\s*[:=]\s*['\"](?!\$\{|\$\(|os\.getenv|process\.env|dotenv)([^'\"]{3,})['\"]",
        "critical", "SAFECODE-SEC-001",
        "Hardcoded password found in source code",
        "Move credentials to environment variables or a secrets manager."
    ),
    (
        r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "critical", "SAFECODE-SEC-002",
        "Hardcoded API key/secret found",
        "Use environment variables or a vault for API keys."
    ),
    (
        r"(?:secret[_-]?key|secretkey|secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "critical", "SAFECODE-SEC-003",
        "Hardcoded secret key found",
        "Store secrets in environment variables or a secrets manager."
    ),
    (
        r"(?:access[_-]?token|auth[_-]?token|jwt[_-]?secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "critical", "SAFECODE-SEC-004",
        "Hardcoded access token or JWT secret",
        "Use environment variables with proper access controls."
    ),
    (
        r"(?:private[_-]?key|privkey)\s*[:=]\s*['\"]?-----BEGIN",
        "critical", "SAFECODE-SEC-005",
        "Private key embedded in source code",
        "Never store private keys in source code. Use a key management service."
    ),
    (
        r"AKIA[0-9A-Z]{16}",
        "critical", "SAFECODE-SEC-006",
        "AWS Access Key ID found",
        "Use IAM roles or environment variables instead of hardcoded AWS keys."
    ),
    (
        r"(?:github|gitlab|ghp)_[a-zA-Z0-9]{20,}",
        "critical", "SAFECODE-SEC-007",
        "GitHub/GitLab token found in code",
        "Use the git credential helper or environment variables."
    ),
    (
        r"(?:connection[_-]?string|conn[_-]?str|database[_-]?url)\s*[:=]\s*['\"]([^'\"]+@[^'\"]+)['\"]",
        "high", "SAFECODE-SEC-008",
        "Database connection string with credentials in code",
        "Use environment variables or a connection string builder with secrets injection."
    ),
    (
        r"(?:ssh[_-]?key|id_rsa|id_ed25519|id_ecdsa)",
        "high", "SAFECODE-SEC-009",
        "Reference to SSH private key file",
        "Ensure SSH keys are stored outside the project directory and not committed."
    ),
    (
        r"(?:encryption[_-]?key|aes[_-]?key|cipher[_-]?key)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "high", "SAFECODE-SEC-010",
        "Hardcoded encryption key",
        "Use a key derivation function or key management service."
    ),
]


def check_secrets(code: str, lines: list[str]) -> list[Finding]:
    findings = []
    for pattern, severity, rule_id, message, recommendation in SECRET_PATTERNS:
        for i, line in enumerate(lines):
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                line_num = i + 1
                findings.append(Finding(
                    severity=severity,
                    rule_id=rule_id,
                    message=message,
                    line=line_num,
                    snippet=line.strip(),
                    recommendation=recommendation,
                ))
    return findings
