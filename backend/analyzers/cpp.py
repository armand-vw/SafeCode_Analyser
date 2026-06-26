import re
from backend.analyzers.base import BaseAnalyzer
from backend.rules.secrets import check_secrets
from backend.rules.protocols import check_protocols
from backend.rules.crypto import check_crypto
from backend.rules.injection import check_injection
from backend.models.schemas import Finding

CPP_UNSAFE_CHECKS = [
    (r"\bgets\s*\(", "critical", "SAFECODE-CPP-001",
     "gets() used — buffer overflow vulnerability (removed from C11/C++14)",
     "Use fgets() or std::getline() instead."),
    (r"\bstrcpy\s*\(", "high", "SAFECODE-CPP-002",
     "strcpy() used — no bounds checking, buffer overflow risk",
     "Use strncpy(), strlcpy(), or std::string instead."),
    (r"\bstrcat\s*\(", "high", "SAFECODE-CPP-003",
     "strcat() used — no bounds checking, buffer overflow risk",
     "Use strncat(), strlcat(), or std::string concatenation."),
    (r"\bsprintf\s*\(", "high", "SAFECODE-CPP-004",
     "sprintf() used — no bounds checking, buffer overflow risk",
     "Use snprintf() instead."),
    (r"\bvsprintf\s*\(", "high", "SAFECODE-CPP-005",
     "vsprintf() used — no bounds checking, buffer overflow risk",
     "Use vsnprintf() instead."),
    (r"\bscanf\s*\(\s*\"[^\"]*%s", "high", "SAFECODE-CPP-006",
     "scanf() with %s — no width specifier, buffer overflow risk",
     "Specify a maximum width (e.g., %99s) or use fgets + sscanf."),
    (r"\bgets_s\s*\(", "medium", "SAFECODE-CPP-007",
     "gets_s() used — better than gets() but still not recommended",
     "Prefer fgets() or std::getline() for portability."),
    (r"\brealloc\s*\(", "low", "SAFECODE-CPP-008",
     "realloc() used — potential memory leak on failure",
     "Assign to a temporary pointer first, check for NULL before overwriting original."),
    (r"\bmalloc\s*\([^)]*\)\s*;.*\b(?!free)", "medium", "SAFECODE-CPP-009",
     "malloc() without visible free() — potential memory leak",
     "Ensure every malloc()/calloc() has a corresponding free(). Use RAII in C++."),
    (r"\bnew\b(?!.*\bdelete\b|.*unique_ptr|.*shared_ptr|.*make_unique|.*make_shared)",
     "low", "SAFECODE-CPP-010",
     "new without visible delete or smart pointer — potential memory leak",
     "Use std::unique_ptr or std::shared_ptr instead of raw new/delete."),
    (r"\bprintf\s*\([^)]*%s[^)]*\)",
     "low", "SAFECODE-CPP-011",
     "printf() with %s format string — ensure null-terminated input",
     "Consider using std::cout which is type-safe and avoids format string issues."),
    (r"(?:system|popen)\s*\(",
     "high", "SAFECODE-CPP-012",
     "system() or popen() used — command injection risk",
     "Avoid executing shell commands. If necessary, use exec family with explicit args."),
    (r"\bexec[lv][pe]?\s*\(",
     "high", "SAFECODE-CPP-013",
     "exec*() family used — ensure args are fixed, not user-controlled",
     "Validate all arguments to exec functions against a whitelist."),
    (r"\bfopen\s*\(.*\"[wa]\"\)",
     "low", "SAFECODE-CPP-014",
     "File opened for writing — TOCTOU race condition risk",
     "Use O_CREAT|O_EXCL or fopen with 'wx' flag to prevent overwriting."),
    (r"\bassert\s*\(",
     "low", "SAFECODE-CPP-015",
     "assert() — removed in release builds, don't use for security checks",
     "Use proper error handling, not assert(), for security-relevant validation."),
    (r"std::rand\s*\(",
     "medium", "SAFECODE-CPP-016",
     "std::rand() used — not cryptographically secure",
     "Use std::random_device or a cryptographic library for secure randomness."),
    (r"ato[ifl]\s*\(",
     "low", "SAFECODE-CPP-017",
     "atoi/atol/atof used — undefined behavior on error",
     "Use strtol(), strtod() with error checking, or std::stoi()."),
    (r"\balloca\s*\(",
     "medium", "SAFECODE-CPP-018",
     "alloca() used — stack allocation, potential stack overflow",
     "Use heap allocation (malloc/std::vector) or fixed-size stack arrays."),
    (r"strlen\s*\([^)]*\)\s*\+\s*\d+\s*>\s*sizeof",
     "high", "SAFECODE-CPP-019",
     "Manual buffer size calculation — error-prone, possible overflow",
     "Use bounded string functions or std::string to avoid manual size math."),
    (r"memcpy\s*\([^)]*strlen",
     "medium", "SAFECODE-CPP-020",
     "memcpy() with strlen() — may copy without null terminator",
     "Use strncpy() or ensure the destination includes space for null terminator."),
]


CPP_BUG_CHECKS = [
    (r"\b(?:NULL|nullptr)\s*->",
     "high", "SAFECODE-CPP-B001",
     "Potential null pointer dereference via ->",
     "Check pointer is not null before dereferencing."),
    (r"=\s*(?:NULL|0|nullptr)\s*;.*->",
     "medium", "SAFECODE-CPP-B002",
     "Pointer assigned null then dereferenced on same line — likely bug",
     "Verify the pointer is initialized before use."),
    (r"(?:delete|free)\s*\(?\s*\w+\s*\)?\s*;.{0,50}(?:delete|free)\s*\(?\s*\1\s*\)?",
     "high", "SAFECODE-CPP-B003",
     "Double free detected — same pointer freed twice",
     "Set pointer to nullptr after freeing to prevent double-free."),
    (r"switch\s*\([^)]*\)\s*\{[^}]*\}(?!.*default)",
     "low", "SAFECODE-CPP-B004",
     "switch without default case — missing default handling",
     "Add a default case to handle unexpected values."),
    (r"/\s*0\b(?!\.)", "medium", "SAFECODE-CPP-B005",
     "Division by literal zero — runtime crash",
     "Add a guard check: if (denominator != 0) before division."),
    (r"int\s+\w+\s*=\s*[-+]?\d+;\s*(?:if|while)?.*\/\s*\1",
     "low", "SAFECODE-CPP-B006",
     "Potential integer division where float expected",
     "Cast to float/double if fractional result is needed: float(x) / y."),
    (r"#ifdef\b(?!.*#else|.*#endif)", "low", "SAFECODE-CPP-B007",
     "#ifdef without visible #endif — potential preprocessor bug",
     "Ensure all #ifdef/#ifndef have matching #endif."),
]


class CppAnalyzer(BaseAnalyzer):
    language = "cpp"

    def analyze(self) -> list[Finding]:
        findings = []
        findings.extend(check_secrets(self.code, self.lines))
        findings.extend(check_protocols(self.code, self.lines))
        findings.extend(check_crypto(self.code, self.lines))
        findings.extend(check_injection(self.code, self.lines))
        findings.extend(self._run_checks(CPP_UNSAFE_CHECKS))
        return findings

    def find_bugs(self) -> list[Finding]:
        return self._run_checks(CPP_BUG_CHECKS)

    def _run_checks(self, checks: list) -> list[Finding]:
        findings = []
        for pattern, severity, rule_id, message, recommendation in checks:
            for i, line in enumerate(self.lines):
                m = re.search(pattern, line)
                if m:
                    findings.append(self.make_finding(
                        severity=severity, rule_id=rule_id, message=message,
                        line=i + 1, snippet=line.strip(), recommendation=recommendation,
                    ))
        return findings
