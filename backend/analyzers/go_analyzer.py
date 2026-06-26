import re
from backend.analyzers.base import BaseAnalyzer
from backend.rules.secrets import check_secrets
from backend.rules.protocols import check_protocols
from backend.rules.crypto import check_crypto
from backend.rules.injection import check_injection
from backend.models.schemas import Finding

GO_UNSAFE_CHECKS = [
    (r"crypto/md5", "high", "SAFECODE-GO-001",
     "MD5 imported — cryptographically broken",
     "Use crypto/sha256 instead of MD5."),
    (r"crypto/sha1", "medium", "SAFECODE-GO-002",
     "SHA-1 imported — deprecated for security use",
     "Use crypto/sha256 or crypto/sha512 for new systems."),
    (r"crypto/des", "high", "SAFECODE-GO-003",
     "DES imported — key size too small",
     "Use crypto/aes with a 256-bit key instead."),
    (r"crypto/rc4", "high", "SAFECODE-GO-004",
     "RC4 imported — cryptographically broken",
     "Use crypto/aes with GCM mode or x/crypto/chacha20poly1305."),
    (r"math/rand", "medium", "SAFECODE-GO-005",
     "math/rand imported — not cryptographically secure",
     "Use crypto/rand for any security-sensitive randomness."),
    (r"fmt\.Sprintf\s*\([^)]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b",
     "high", "SAFECODE-GO-006",
     "SQL query built with fmt.Sprintf — SQL injection risk",
     "Use placeholders with db.Query/Exec: db.Query('SELECT ... WHERE x = ?', val)."),
    (r"db\.(?:Query|Exec)\s*\(\s*[^?]+\+\s*\w+",
     "high", "SAFECODE-GO-007",
     "String concatenation in SQL query — injection risk",
     "Use parameterized queries with ? placeholders."),
    (r"os/exec.*Cmd\s*\{[^}]*bash|os/exec.*Cmd\s*\{[^}]*sh\b",
     "high", "SAFECODE-GO-008",
     "Shell command via os/exec — command injection risk",
     "Specify the executable and arguments separately, not via shell."),
    (r"exec\.Command\s*\(\s*['\"`].*\$",
     "high", "SAFECODE-GO-009",
     "exec.Command with shell variables — injection risk",
     "Use exec.Command with explicit arguments, not shell interpolation."),
    (r"html/template.*\.Execute\s*\(\s*\w+,\s*\w+\)(?!.*\.(?:HTMLEscape|JS))",
     "medium", "SAFECODE-GO-010",
     "html/template output without explicit escaping — potential XSS",
     "html/template auto-escapes by type, but verify the context is correct."),
    (r"text/template",
     "medium", "SAFECODE-GO-011",
     "text/template used — no auto-escaping for HTML/JS contexts",
     "Use html/template instead of text/template when rendering HTML."),
    (r"net/http.*ListenAndServe\s*\(\s*\"(?!.*TLS)",
     "low", "SAFECODE-GO-012",
     "HTTP server without TLS — consider ListenAndServeTLS",
     "Use ListenAndServeTLS or put a reverse proxy with TLS in front."),
    (r"net/http.*ListenAndServeTLS\s*\(\s*\"[^\"]*\",\s*\"(?:cert|server)\.pem\"",
     "low", "SAFECODE-GO-013",
     "Hardcoded TLS certificate path — consider environment variables",
     "Use environment variables or a config file for certificate paths."),
    (r"http\.Get\s*\(\s*\"http://",
     "medium", "SAFECODE-GO-014",
     "HTTP GET to insecure endpoint — use HTTPS",
     "Use https:// URLs for outgoing HTTP requests."),
    (r"json\.NewDecoder\s*\(\s*\w+\.Body\s*\)\.Decode\b(?!.*DisallowUnknownFields)",
     "low", "SAFECODE-GO-015",
     "JSON decode without DisallowUnknownFields — extra fields silently ignored",
     "Add .DisallowUnknownFields() to the decoder to reject unexpected fields."),
    (r"ioutil\.ReadAll|ioutil\.ReadFile|ioutil\.WriteFile",
     "low", "SAFECODE-GO-016",
     "Deprecated ioutil functions — use io.ReadAll / os.ReadFile",
     "Replace ioutil with io and os package functions (Go 1.16+)."),
    (r"\.(?:Set|Get)\s*\(\s*['\"]Set-Cookie['\"]",
     "low", "SAFECODE-GO-017",
     "Manual cookie header manipulation — risk of missing security flags",
     "Use http.SetCookie() which auto-applies SameSite and other defaults."),
    (r"defer\s+resp\.Body\.Close\(\)\s*\n\s*(?:if|return|resp)",
     "low", "SAFECODE-GO-018",
     "defer resp.Body.Close() before nil check — may panic",
     "Check err before deferring Body.Close() on a nil response."),
    (r"crypto/aes.*ECB",
     "medium", "SAFECODE-GO-019",
     "AES in ECB mode — leaks data patterns",
     "Use AES-GCM (AEAD) or AES-CBC with proper IV handling."),
    (r"gob\.NewDecoder|gob\.NewEncoder",
     "medium", "SAFECODE-GO-020",
     "gob encoding used — not safe for untrusted input",
     "Use JSON, protobuf, or another vetted serialization format."),
]

GO_BUG_CHECKS = [
    (r"if\s+err\s*!=\s*nil\s*\{[^}]*\}", "low", "SAFECODE-GO-B001",
     "Error check without return or meaningful handling",
     "Return the error or log it meaningfully, don't silently swallow."),
    (r"if\s+err\s*!=\s*nil\s*\{[^}]*\}\s*\n\s*_",
     "low", "SAFECODE-GO-B002",
     "Error assigned to blank identifier _ after being checked — likely lost",
     "Use the value returned alongside the error."),
    (r"defer\s+\w+\.(?:Close|Unlock|Rollback)\(\)\s*\n.{,100}(?:Close|Unlock|Rollback)",
     "medium", "SAFECODE-GO-B003",
     "Resource closed both in defer and explicitly — potential double-close",
     "Remove the explicit close; defer handles it."),
    (r"for\s+range\s+\w+\s*\{.*\b(?:&|pointer)",
     "low", "SAFECODE-GO-B004",
     "Taking address of range loop variable — all pointers reference same memory",
     "Assign the loop variable to a new variable inside the loop body."),
    (r"go\s+func\s*\([^)]*\)\s*\{.*\b(?:&|pointer)",
     "low", "SAFECODE-GO-B005",
     "Goroutine closure capturing loop variable by reference — race condition",
     "Pass the variable as an argument to the goroutine closure."),
    (r"sync\.Mutex(?!.*Lock|.*Unlock)",
     "medium", "SAFECODE-GO-B006",
     "sync.Mutex declared but no Lock/Unlock calls — unused or unsafe",
     "Ensure the mutex is properly used with Lock() and Unlock()."),
    (r"\.Lock\(\)\s*\n(?!.*defer.*Unlock|.*\.Unlock)",
     "medium", "SAFECODE-GO-B007",
     "Lock() without visible Unlock() — potential deadlock",
     "Use defer mu.Unlock() immediately after Lock()."),
    (r"var\s+\w+\s+\w+\s*\n(?!.*make|.*\[\])",
     "low", "SAFECODE-GO-B008",
     "Uninitialized variable — nil map/slice/channel will panic on use",
     "Initialize with make() or composite literal."),
    (r"fmt\.(?:Sprintf|Fprintf|Printf)\s*\([^)]*%[^sdvtxX]",
     "low", "SAFECODE-GO-B009",
     "Potentially incorrect format verb in fmt.Printf",
     "Verify the format verb matches the argument type."),
]


class GoAnalyzer(BaseAnalyzer):
    language = "go"

    def analyze(self) -> list[Finding]:
        findings = []
        findings.extend(check_secrets(self.code, self.lines))
        findings.extend(check_protocols(self.code, self.lines))
        findings.extend(check_crypto(self.code, self.lines))
        findings.extend(check_injection(self.code, self.lines))
        findings.extend(self._run_checks(GO_UNSAFE_CHECKS))
        return findings

    def find_bugs(self) -> list[Finding]:
        return self._run_checks(GO_BUG_CHECKS)

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
