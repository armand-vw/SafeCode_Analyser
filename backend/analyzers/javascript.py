import re
from backend.analyzers.base import BaseAnalyzer
from backend.rules.secrets import check_secrets
from backend.rules.protocols import check_protocols
from backend.rules.crypto import check_crypto
from backend.rules.injection import check_injection
from backend.models.schemas import Finding

JS_UNSAFE_CHECKS = [
    (r"\beval\s*\(", "critical", "SAFECODE-JS-001",
     "eval() used — arbitrary code execution risk",
     "Avoid eval(). Use JSON.parse() for JSON data."),
    (r"\bFunction\s*\(", "critical", "SAFECODE-JS-002",
     "Function() constructor used — equivalent to eval()",
     "Avoid the Function constructor. Use proper function definitions."),
    (r"\bsetTimeout\s*\(\s*['\"`]", "medium", "SAFECODE-JS-003",
     "setTimeout with string argument — equivalent to eval()",
     "Pass a function reference to setTimeout, never a string."),
    (r"\bsetInterval\s*\(\s*['\"`]", "medium", "SAFECODE-JS-004",
     "setInterval with string argument — equivalent to eval()",
     "Pass a function reference to setInterval, never a string."),
    (r"\.innerHTML\s*=", "high", "SAFECODE-JS-005",
     "innerHTML assignment — potential XSS vector",
     "Use textContent or sanitize with DOMPurify before setting innerHTML."),
    (r"\.outerHTML\s*=", "high", "SAFECODE-JS-006",
     "outerHTML assignment — potential XSS vector",
     "Avoid direct outerHTML assignment. Use DOM manipulation methods."),
    (r"document\.write\s*\(", "high", "SAFECODE-JS-007",
     "document.write() used — XSS risk, blocks parser",
     "Use DOM manipulation methods like createElement and appendChild."),
    (r"document\.writeln\s*\(", "high", "SAFECODE-JS-008",
     "document.writeln() used — XSS risk",
     "Use DOM manipulation methods instead."),
    (r"\bexecScript\s*\(", "critical", "SAFECODE-JS-009",
     "execScript() used — Internet Explorer code execution",
     "Refactor to avoid execScript entirely."),
    (r"dangerouslySetInnerHTML", "high", "SAFECODE-JS-010",
     "React dangerouslySetInnerHTML — XSS risk",
     "Use safe React rendering or sanitize input with DOMPurify."),
    (r"__html\s*:", "medium", "SAFECODE-JS-011",
     "__html property used — potential XSS in template",
     "Ensure the HTML content is properly sanitized before injection."),
    (r"bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)", "high", "SAFECODE-JS-012",
     "Angular bypassSecurityTrust* — explicitly bypasses security",
     "Use Angular's DomSanitizer only when absolutely necessary and after manual review."),
    (r"new\s+Script\s*\(", "critical", "SAFECODE-JS-013",
     "new Script() in Node.js — executes arbitrary code",
     "Avoid creating scripts from dynamic strings. Use vm module only with trusted code."),
    (r"require\s*\(\s*['\"`].*\+", "medium", "SAFECODE-JS-014",
     "Dynamic require() with concatenation — code injection risk",
     "Use a static import or validate against a whitelist of allowed modules."),
    (r"child_process\.(?:exec|spawn|fork)\s*\(", "high", "SAFECODE-JS-015",
     "child_process execution — command injection risk",
     "Use execFile() with fixed arguments or validate all user input."),
    (r"(?:exec|spawn|fork)\s*\([^)]*\+\s*\w+", "high", "SAFECODE-JS-016",
     "Dynamic command construction in child_process — injection risk",
     "Use execFile() with array arguments, never construct commands with +."),
    (r"Math\.random\s*\(", "medium", "SAFECODE-JS-017",
     "Math.random() used — not cryptographically secure",
     "Use crypto.getRandomValues() or crypto.randomBytes() for security."),
    (r"JSON\.parse\s*\(\s*\w+\.(?:params|query|body|data)", "low", "SAFECODE-JS-018",
     "JSON.parse() on user input — validate structure first",
     "Wrap in try/catch and validate the parsed object structure."),
    (r"new\s+WebSocket\s*\(\s*['\"]ws://", "medium", "SAFECODE-JS-019",
     "WebSocket using ws:// — use wss:// for encryption",
     "Change to wss:// to encrypt WebSocket traffic."),
    (r"process\.env\.\w+\s*(?:&&|if|:)",
     "low", "SAFECODE-JS-020",
     "Environment variable used without fallback — may crash on missing var",
     "Provide a default value: process.env.VAR || 'default'"),
    (r"\.replace\s*\(\s*/.*/g\s*,\s*['\"`][^'\"`]*['\"`]\s*\).*\.replace",
     "low", "SAFECODE-JS-021",
     "Chained .replace() for sanitization — may be incomplete",
     "Use a proper sanitization library like DOMPurify for HTML."),
    (r"\.split\s*\(\s*['\"`]\s*['\"`]",
     "low", "SAFECODE-JS-022",
     "split('') used for string processing — fragile",
     "Use Array.from(), spread operator, or a proper string library."),
    (r"crypto\.createHash\s*\(\s*['\"]md5['\"]",
     "high", "SAFECODE-JS-023",
     "MD5 hash in Node.js crypto — cryptographically broken",
     "Use SHA-256 or SHA-512 via crypto.createHash('sha256')."),
    (r"@ts-ignore|@ts-nocheck",
     "low", "SAFECODE-JS-024",
     "TypeScript ignore directive — bypasses type checking",
     "Fix the type error instead of silencing it."),
    (r"as\s+any\b",
     "low", "SAFECODE-JS-025",
     "TypeScript 'as any' cast — bypasses type safety",
     "Use a more specific type or a type guard function."),
    (r"localStorage\.setItem|sessionStorage\.setItem",
     "medium", "SAFECODE-JS-026",
     "Sensitive data stored in browser storage — accessible to XSS",
     "Never store tokens or secrets in localStorage/sessionStorage."),
    (r"console\.(?:log|dir|error)\(.*(?:password|token|secret|key)",
     "medium", "SAFECODE-JS-027",
     "Credentials logged to console — will appear in browser devtools",
     "Remove or mask credentials before logging."),
]

JS_BUG_CHECKS = [
    (r"==\s*null\b", "low", "SAFECODE-JS-B001",
     "== null comparison — matches both null and undefined",
     "Use === null or === undefined explicitly to avoid coercion."),
    (r"!=\s*null\b", "low", "SAFECODE-JS-B002",
     "!= null comparison — matches both null and undefined",
     "Use !== null and !== undefined for explicit checks."),
    (r"==\s*undefined\b", "low", "SAFECODE-JS-B003",
     "== undefined — use === undefined or typeof check",
     "Use === undefined for explicit undefined checks."),
    (r"(?:^|[^=!])=(?!=)\s*(?:true|false|\d+|['\"])", "low", "SAFECODE-JS-B004",
     "Assignment in condition expression — may be intentional but suspicious",
     "Wrap assignment in extra parentheses if intentional: if ((x = y))"),
    (r"async\s+function.*\bawait\b(?!.*\bcatch\b|.*\.catch\b)",
     "medium", "SAFECODE-JS-B005",
     "await without error handling — unhandled promise rejection",
     "Wrap await in try/catch or chain .catch() on the promise."),
    (r"Promise\s*\(\s*function\s*\(|new\s+Promise\s*\(.*\b(?:async|try)",
     "low", "SAFECODE-JS-B006",
     "Unnecessary Promise constructor wrapping an async function",
     "The async function already returns a promise, no need to wrap."),
    (r"\.forEach\s*\(\s*async\b",
     "low", "SAFECODE-JS-B007",
     "async function in forEach — promises are not awaited",
     "Use a for...of loop with await instead of forEach with async."),
    (r"\.map\s*\(\s*async\b.*\)(?!\s*\.\s*Promise\.all)",
     "low", "SAFECODE-JS-B008",
     "async map() without Promise.all — may not resolve as expected",
     "Use Promise.all(array.map(async ...)) to await all promises."),
    (r"delete\s+\w+\.\w+",
     "low", "SAFECODE-JS-B009",
     "delete on object property — mutates shape, slows V8 optimization",
     "Set the property to undefined or null instead of using delete."),
    (r"with\s*\(",
     "medium", "SAFECODE-JS-B010",
     "'with' statement — ambiguous scope, forbidden in strict mode",
     "Explicitly reference the object properties instead of using with."),
    (r"console\.(?:log|dir|warn|error)\s*\(.*(?:TODO|FIXME|HACK)",
     "low", "SAFECODE-JS-B011",
     "Debug logging with TODO/FIXME/HACK marker left in code",
     "Clean up debug logging before committing."),
]


class JavaScriptAnalyzer(BaseAnalyzer):
    language = "javascript"

    def analyze(self) -> list[Finding]:
        findings = []
        findings.extend(check_secrets(self.code, self.lines))
        findings.extend(check_protocols(self.code, self.lines))
        findings.extend(check_crypto(self.code, self.lines))
        findings.extend(check_injection(self.code, self.lines))
        findings.extend(self._run_checks(JS_UNSAFE_CHECKS))
        return findings

    def find_bugs(self) -> list[Finding]:
        return self._run_checks(JS_BUG_CHECKS)

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
