import re
from typing import Optional
from backend.models.schemas import Finding, SeverityLevel

class BaseAnalyzer:
    language: str = "generic"

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split("\n")

    def find_line(self, pattern: str, start: int = 0) -> Optional[int]:
        for i, line in enumerate(self.lines[start:], start=start):
            if re.search(pattern, line):
                return i + 1
        return None

    def find_all_matches(self, pattern: str) -> list[tuple[int, str]]:
        results = []
        for i, line in enumerate(self.lines):
            m = re.search(pattern, line)
            if m:
                results.append((i + 1, line.strip()))
        return results

    def make_finding(self, severity: SeverityLevel, rule_id: str, message: str,
                     line: Optional[int] = None, column: Optional[int] = None,
                     snippet: Optional[str] = None, recommendation: Optional[str] = None) -> Finding:
        return Finding(
            severity=severity,
            rule_id=rule_id,
            message=message,
            line=line,
            column=column,
            snippet=snippet,
            recommendation=recommendation,
        )

    def analyze(self) -> list[Finding]:
        raise NotImplementedError
