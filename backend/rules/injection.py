import re
from backend.models.schemas import Finding

SQL_INJECTION_PATTERNS = [
    (
        r"(?:execute|exec|query|raw)\s*\([^)]*\+[^)]*\)",
        "high", "SAFECODE-INJ-001",
        "Potential SQL injection — string concatenation in query",
        "Use parameterized queries or an ORM with proper escaping."
    ),
    (
        r"\.format\s*\(\s*.*\)\s*.*(?:execute|exec|query)",
        "high", "SAFECODE-INJ-002",
        "Potential SQL injection — .format() used in query string",
        "Use parameterized queries with ? or %s placeholders."
    ),
    (
        r"f['\"].*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b",
        "medium", "SAFECODE-INJ-003",
        "f-string used to build SQL query — injection risk",
        "Never use f-strings with SQL. Use parameterized queries."
    ),
    (
        r"(?:SELECT|INSERT|UPDATE|DELETE)\b.*\+\s*['\"]",
        "medium", "SAFECODE-INJ-004",
        "String concatenation in SQL statement",
        "Use prepared statements or query builders."
    ),
]

XSS_PATTERNS = [
    (
        r"\.innerHTML\s*=",
        "high", "SAFECODE-INJ-010",
        "innerHTML assignment — potential XSS vector",
        "Use textContent or sanitize with DOMPurify before setting innerHTML."
    ),
    (
        r"dangerouslySetInnerHTML",
        "high", "SAFECODE-INJ-011",
        "React dangerouslySetInnerHTML used — XSS risk",
        "Avoid dangerouslySetInnerHTML. Use safe React rendering or sanitize input."
    ),
    (
        r"document\.write\s*\(",
        "high", "SAFECODE-INJ-012",
        "document.write() used — XSS risk",
        "Avoid document.write(). Use DOM manipulation methods instead."
    ),
    (
        r"eval\s*\(",
        "high", "SAFECODE-INJ-013",
        "eval() used — code injection risk",
        "Avoid eval(). Use JSON.parse() for data or safer alternatives."
    ),
]

COMMAND_INJECTION_PATTERNS = [
    (
        r"os\.system\s*\(\s*['\"].*\+",
        "high", "SAFECODE-INJ-020",
        "Potential command injection with os.system()",
        "Use subprocess.run() with a list of arguments, not a shell string."
    ),
    (
        r"subprocess\..*\(.*shell\s*=\s*True",
        "high", "SAFECODE-INJ-021",
        "subprocess with shell=True — command injection risk",
        "Avoid shell=True. Pass arguments as a list instead."
    ),
    (
        r"Runtime\.getRuntime\(\)\.exec\s*\(",
        "high", "SAFECODE-INJ-022",
        "Runtime.exec() — command injection risk in Java",
        "Use ProcessBuilder with a list of arguments."
    ),
    (
        r"exec\s*\(\s*['\"].*\+",
        "critical", "SAFECODE-INJ-023",
        "exec() with dynamic string — arbitrary code execution risk",
        "Avoid exec() entirely. Use safer alternatives."
    ),
    (
        r"pickle\.(?:loads?|dump)",
        "high", "SAFECODE-INJ-024",
        "pickle deserialization — arbitrary code execution risk",
        "Use JSON or a safe serialization format instead of pickle."
    ),
    (
        r"yaml\.load\b(?!er)",
        "high", "SAFECODE-INJ-025",
        "Unsafe YAML load — arbitrary code execution risk",
        "Use yaml.safe_load() instead of yaml.load()."
    ),
]

PATH_TRAVERSAL_PATTERNS = [
    (
        r"os\.path\.join\s*\(\s*.*request\..*\b(?:GET|POST|args|form|params|body)\b",
        "high", "SAFECODE-INJ-030",
        "User input used in file path construction — path traversal risk",
        "Validate and sanitize file paths. Use a whitelist of allowed directories."
    ),
]


def check_injection(code: str, lines: list[str]) -> list[Finding]:
    findings = []
    all_patterns = SQL_INJECTION_PATTERNS + XSS_PATTERNS + COMMAND_INJECTION_PATTERNS + PATH_TRAVERSAL_PATTERNS
    for pattern, severity, rule_id, message, recommendation in all_patterns:
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
