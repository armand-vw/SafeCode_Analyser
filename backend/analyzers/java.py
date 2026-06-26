import re
from backend.analyzers.base import BaseAnalyzer
from backend.rules.secrets import check_secrets
from backend.rules.protocols import check_protocols
from backend.rules.crypto import check_crypto
from backend.rules.injection import check_injection
from backend.models.schemas import Finding

JAVA_UNSAFE_CHECKS = [
    (r"Runtime\.getRuntime\(\)\.exec\s*\(",
     "high", "SAFECODE-JAVA-001",
     "Runtime.exec() used — command injection risk",
     "Use ProcessBuilder with a List<String> of arguments instead."),
    (r"new\s+ProcessBuilder\s*\([^)]*\+",
     "high", "SAFECODE-JAVA-002",
     "ProcessBuilder with string concatenation — injection risk",
     "Use a List<String> for command arguments, never string concatenation."),
    (r"Statement\s+\w+\s*=\s*\w+\.createStatement\s*\(\s*\)",
     "high", "SAFECODE-JAVA-003",
     "Plain Statement used instead of PreparedStatement — SQL injection risk",
     "Use PreparedStatement with ? parameter placeholders."),
    (r"\.executeQuery\s*\([^)]*\+[^)]*\)",
     "high", "SAFECODE-JAVA-004",
     "String concatenation in SQL query — injection risk",
     "Use PreparedStatement with parameter placeholders."),
    (r"\.executeUpdate\s*\([^)]*\+[^)]*\)",
     "high", "SAFECODE-JAVA-005",
     "String concatenation in SQL update — injection risk",
     "Use PreparedStatement with parameter placeholders."),
    (r"MessageDigest\.getInstance\s*\(\s*\"MD5\"",
     "high", "SAFECODE-JAVA-006",
     "MD5 hashing — cryptographically broken",
     "Use MessageDigest.getInstance(\"SHA-256\") instead."),
    (r"MessageDigest\.getInstance\s*\(\s*\"SHA-?1\"",
     "medium", "SAFECODE-JAVA-007",
     "SHA-1 hashing — deprecated for security use",
     "Use SHA-256 or SHA-512 for security-sensitive hashing."),
    (r"Cipher\.getInstance\s*\(\s*\"DES\"",
     "high", "SAFECODE-JAVA-008",
     "DES cipher — key size too small",
     "Use Cipher.getInstance(\"AES/GCM/NoPadding\") instead."),
    (r"Cipher\.getInstance\s*\(\s*\"RC4\"",
     "high", "SAFECODE-JAVA-009",
     "RC4 cipher — cryptographically broken",
     "Use AES-GCM or ChaCha20-Poly1305 instead."),
    (r"Cipher\.getInstance\s*\([^)]*ECB",
     "medium", "SAFECODE-JAVA-010",
     "ECB cipher mode — leaks data patterns",
     "Use GCM or CBC mode instead. ECB is not semantically secure."),
    (r"SecureRandom\.getInstance\s*\(\s*\"SHA1PRNG\"",
     "low", "SAFECODE-JAVA-011",
     "SHA1PRNG SecureRandom — preferred algorithm, but verify seed source",
     "Consider using NativePRNG or the default SecureRandom() constructor."),
    (r"new\s+Random\s*\(",
     "medium", "SAFECODE-JAVA-012",
     "java.util.Random used — not cryptographically secure",
     "Use java.security.SecureRandom for security-sensitive randomness."),
    (r"ObjectInputStream(?!.*validated|.*whitelist|.*setObjectInputFilter)",
     "high", "SAFECODE-JAVA-013",
     "ObjectInputStream without input validation — deserialization attack risk",
     "Set an ObjectInputFilter to whitelist allowed classes."),
    (r"XMLReader\s+.*=.*XMLReaderFactory|SAXParser\s+.*=.*SAXParserFactory(?!.*setFeature.*disallow-doctype|.*FEATURE_SECURE_PROCESSING)",
     "high", "SAFECODE-JAVA-014",
     "XML parser without XXE protection",
     "Disable DOCTYPE declarations and external entities in the XML parser config."),
    (r"\.printStackTrace\s*\(",
     "low", "SAFECODE-JAVA-015",
     "printStackTrace() — leaks stack traces to stdout, may expose internals",
     "Use a proper logging framework and avoid printing stack traces to stdout."),
    (r"System\.out\.println\s*\(.*(?:password|secret|token|key)",
     "medium", "SAFECODE-JAVA-016",
     "Credentials printed to stdout — information leak",
     "Never log credentials. Use a logger with appropriate redaction."),
    (r"logger\.(?:info|debug|warn|error)\s*\(.*(?:password|secret|token)",
     "medium", "SAFECODE-JAVA-017",
     "Credentials passed to logger — may be stored in log files",
     "Redact or omit credentials from log output."),
    (r"\.equals\s*\(\s*\w+\s*\)\s*(?:&&|if)\s*\w+\.equals\s*\(",
     "low", "SAFECODE-JAVA-018",
     "Chained .equals() calls — potential NPE if first object is null",
     "Use Objects.equals(a, b) to avoid NullPointerException."),
    (r"FileInputStream|FileOutputStream|FileReader|FileWriter\b(?!.*try-with-resources|.*try\s*\()",
     "low", "SAFECODE-JAVA-019",
     "File IO without try-with-resources — potential resource leak",
     "Use try-with-resources to ensure the stream is closed."),
    (r"new\s+Socket\s*\(\s*\"[^\"]*\",\s*\d+\s*\)(?!.*setSoTimeout)",
     "low", "SAFECODE-JAVA-020",
     "Socket created without timeout — may hang indefinitely",
     "Call setSoTimeout() or use the connect() method with a timeout."),
    (r"@RequestMapping|@GetMapping|@PostMapping(?!.*@PreAuthorize|.*@RolesAllowed|.*\.authenticated)",
     "low", "SAFECODE-JAVA-021",
     "Spring endpoint without explicit authorization annotation",
     "Add @PreAuthorize or configure method security for this endpoint."),
]

JAVA_BUG_CHECKS = [
    (r"catch\s*\(\s*Exception\s+\w+\s*\)\s*\{[^}]*\}(?!.*throw|.*log)",
     "medium", "SAFECODE-JAVA-B001",
     "Exception caught but not handled — swallowed silently",
     "Log the exception and handle it appropriately."),
    (r"catch\s*\([^)]*\)\s*\{\s*\}",
     "high", "SAFECODE-JAVA-B002",
     "Empty catch block — exception silently swallowed",
     "At minimum log the exception. Empty catches hide bugs."),
    (r"\.equals\s*\(\s*null\s*\)",
     "low", "SAFECODE-JAVA-B003",
     "Calling .equals(null) — always returns false, probably a bug",
     "Check for null before calling equals(), or use Objects.equals()."),
    (r"null\s*\.equals\s*\(",
     "high", "SAFECODE-JAVA-B004",
     "null.equals() — will throw NullPointerException",
     "Check for null first or use Objects.equals(a, b)."),
    (r"\w+\s*==\s*\"[^\"]*\"",
     "medium", "SAFECODE-JAVA-B005",
     "String comparison with == instead of .equals() — reference comparison",
     "Use .equals() or .equalsIgnoreCase() for string value comparison."),
    (r"\.size\(\)\s*>\s*0",
     "low", "SAFECODE-JAVA-B006",
     "size() > 0 check — use .isEmpty() instead",
     "Use .isEmpty() which is more readable and potentially optimized."),
    (r"new\s+ArrayList\s*<\s*\w+\s*>\s*\(\s*\)\s*;",
     "low", "SAFECODE-JAVA-B007",
     "ArrayList allocated without initial capacity — resizing overhead",
     "Specify an initial capacity if the expected size is known."),
    (r"SimpleDateFormat\s+\w+\s*=\s*new\s+SimpleDateFormat",
     "low", "SAFECODE-JAVA-B008",
     "SimpleDateFormat not thread-safe — use DateTimeFormatter in Java 8+",
     "Use java.time.format.DateTimeFormatter which is thread-safe."),
    (r"Float\.(?:compare|equals)|Double\.(?:compare|equals)",
     "low", "SAFECODE-JAVA-B009",
     "Float/Double comparison — precision issues possible",
     "Use BigDecimal for exact decimal comparisons."),
]


class JavaAnalyzer(BaseAnalyzer):
    language = "java"

    def analyze(self) -> list[Finding]:
        findings = []
        findings.extend(check_secrets(self.code, self.lines))
        findings.extend(check_protocols(self.code, self.lines))
        findings.extend(check_crypto(self.code, self.lines))
        findings.extend(check_injection(self.code, self.lines))
        findings.extend(self._run_checks(JAVA_UNSAFE_CHECKS))
        return findings

    def find_bugs(self) -> list[Finding]:
        return self._run_checks(JAVA_BUG_CHECKS)

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
