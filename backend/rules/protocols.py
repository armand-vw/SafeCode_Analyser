import re
from backend.models.schemas import Finding

PROTOCOL_CHECKS = [
    (
        r"http://[^\s\"'`]+",
        "medium", "SAFECODE-PROTO-001",
        "HTTP (unencrypted) URL found — use HTTPS",
        "Replace http:// with https:// to encrypt data in transit."
    ),
    (
        r"ftp://[^\s\"'`]+",
        "high", "SAFECODE-PROTO-002",
        "FTP (unencrypted) URL found — use FTPS or SFTP",
        "FTP transmits credentials and data in plaintext. Use SFTP or FTPS."
    ),
    (
        r"telnet://[^\s\"'`]+",
        "high", "SAFECODE-PROTO-003",
        "Telnet URL found — use SSH instead",
        "Telnet sends all data unencrypted. Replace with SSH."
    ),
    (
        r"ws://[^\s\"'`]+",
        "medium", "SAFECODE-PROTO-004",
        "Insecure WebSocket (ws://) found — use wss://",
        "Use wss:// for encrypted WebSocket connections."
    ),
    (
        r"ldap://[^\s\"'`]+",
        "medium", "SAFECODE-PROTO-005",
        "Unencrypted LDAP found — use LDAPS",
        "LDAP without TLS exposes directory data. Use ldaps:// instead."
    ),
    (
        r"smtp://[^\s\"'`]+",
        "medium", "SAFECODE-PROTO-006",
        "Unencrypted SMTP found — use SMTPS or STARTTLS",
        "Use port 587 with STARTTLS or port 465 with SSL/TLS."
    ),
    (
        r"ssl\.PROTOCOL_",
        "low", "SAFECODE-PROTO-007",
        "Explicit SSL protocol version specified — use auto-negotiation",
        "Avoid pinning specific SSL/TLS versions. Use the defaults of a modern TLS library."
    ),
    (
        r"verify\s*=\s*False",
        "high", "SAFECODE-PROTO-008",
        "TLS certificate verification disabled",
        "Removing certificate verification enables man-in-the-middle attacks."
    ),
    (
        r"check_hostname\s*=\s*False",
        "medium", "SAFECODE-PROTO-009",
        "Hostname verification disabled in TLS",
        "Disabling hostname verification allows spoofing."
    ),
]


def check_protocols(code: str, lines: list[str]) -> list[Finding]:
    findings = []
    for pattern, severity, rule_id, message, recommendation in PROTOCOL_CHECKS:
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
