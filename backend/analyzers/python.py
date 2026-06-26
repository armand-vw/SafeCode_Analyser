import re
from backend.analyzers.base import BaseAnalyzer
from backend.rules.secrets import check_secrets
from backend.rules.protocols import check_protocols
from backend.rules.crypto import check_crypto
from backend.rules.injection import check_injection
from backend.models.schemas import Finding

PYTHON_UNSAFE_CHECKS = [
    (r"\beval\s*\(", "critical", "SAFECODE-PY-001",
     "eval() used — arbitrary code execution risk",
     "Avoid eval(). Use ast.literal_eval() for safe evaluation of literals."),
    (r"\bexec\s*\(", "critical", "SAFECODE-PY-002",
     "exec() used — arbitrary code execution risk",
     "Avoid exec(). If you must run dynamic code, use a sandboxed environment."),
    (r"\bcompile\s*\(", "medium", "SAFECODE-PY-003",
     "compile() used — code injection risk if input is untrusted",
     "Ensure input to compile() is trusted and never from user input."),
    (r"input\s*\(\s*\)", "medium", "SAFECODE-PY-004",
     "input() used — in Python 2 this is equivalent to eval(raw_input())",
     "In Python 3 this is safe, but verify you are not on Python 2."),
    (r"os\.system\s*\(", "high", "SAFECODE-PY-005",
     "os.system() used — command injection risk",
     "Use subprocess.run() with a list of arguments instead of a shell string."),
    (r"os\.popen\s*\(", "high", "SAFECODE-PY-006",
     "os.popen() used — command injection risk",
     "Use subprocess.run() or subprocess.Popen() with list arguments."),
    (r"commands\.getoutput|commands\.getstatusoutput", "high", "SAFECODE-PY-007",
     "Deprecated commands module used — command injection risk",
     "Use subprocess module instead."),
    (r"shell\s*=\s*True", "high", "SAFECODE-PY-008",
     "subprocess with shell=True — command injection risk",
     "Avoid shell=True. Pass arguments as a list to subprocess.run()."),
    (r"pickle\.(?:loads?|dump)", "high", "SAFECODE-PY-009",
     "pickle (de)serialization used — arbitrary code execution risk",
     "Use JSON, msgpack, or protobuf for safe serialization."),
    (r"marshal\.loads?\s*\(", "high", "SAFECODE-PY-010",
     "marshal.loads() used — unsafe deserialization",
     "marshal is not secure against malicious data. Use JSON."),
    (r"yaml\.load\b(?!er|_all)", "high", "SAFECODE-PY-011",
     "Unsafe yaml.load() used — arbitrary code execution risk",
     "Use yaml.safe_load() or yaml.safe_load_all() instead."),
    (r"xml\.etree\.ElementTree\.parse\b(?!.*defusedxml)", "low", "SAFECODE-PY-012",
     "Standard XML parser used — vulnerable to XXE/billion laughs",
     "Use defusedxml library for parsing untrusted XML."),
    (r"etree\.fromstring\b(?!.*defusedxml)", "low", "SAFECODE-PY-013",
     "XML fromstring without safe parser — XXE risk",
     "Use defusedxml.ElementTree.fromstring() instead."),
    (r"assert\s", "low", "SAFECODE-PY-014",
     "assert statement used — assertions are stripped with -O flag",
     "Use explicit if/raise for validation logic, not assert."),
    (r"__import__\s*\(", "medium", "SAFECODE-PY-015",
     "__import__() used — dynamic imports can be dangerous",
     "Use importlib.import_module() which is more explicit."),
    (r"\bgetattr\s*\(\s*\w+\s*,\s*['\"][^'\"]+['\"]\s*\)", "low", "SAFECODE-PY-016",
     "getattr() with string attribute — potential attribute injection",
     "Validate the attribute name against a whitelist before using getattr()."),
    (r"md5\s*\(|[Hh]ashlib.*md5", "high", "SAFECODE-PY-017",
     "MD5 hashing detected — cryptographically broken",
     "Use hashlib.sha256() instead of MD5."),
    (r"random\.(?:random|randint|choice|shuffle|uniform|randrange)", "medium", "SAFECODE-PY-018",
     "Insecure random number generator — not for security use",
     "Use secrets module or os.urandom() for cryptographic purposes."),
    (r"str\.format\s*\(.*password|password.*\.format", "medium", "SAFECODE-PY-019",
     "Password used with .format() — may appear in logs or error messages",
     "Avoid formatting passwords into strings that may be logged."),
    (r"print\s*\(.*password|logging\..*password", "medium", "SAFECODE-PY-020",
     "Password potentially printed or logged",
     "Never log or print passwords. Mask or omit credentials in logs."),
    (r"requests\.(?:get|post|put|patch|delete).*verify\s*=\s*False", "high", "SAFECODE-PY-021",
     "TLS certificate verification disabled in requests",
     "Never set verify=False in production. Use proper certificates."),
    (r"ssl\._create_unverified_context", "high", "SAFECODE-PY-022",
     "Unverified SSL context created",
     "Use a proper SSL context with certificate verification enabled."),
    (r"DEBUG\s*=\s*True", "high", "SAFECODE-PY-023",
     "DEBUG=True in production config",
     "Set DEBUG=False in production to prevent information leakage."),
    (r"SECRET_KEY\s*=\s*['\"]\s*['\"]", "critical", "SAFECODE-PY-024",
     "Empty or placeholder SECRET_KEY",
     "Generate a strong, random SECRET_KEY and store it in an environment variable."),
    (r"ALLOWED_HOSTS\s*=\s*\[[\s'\"]*[*][\s'\"]*\]", "high", "SAFECODE-PY-025",
     "ALLOWED_HOSTS set to wildcard '*' — host header attack risk",
     "Specify the exact list of allowed hostnames."),
    (r"open\s*\([^)]*['\"][wa][^\'\"]*['\"]", "low", "SAFECODE-PY-026",
     "File opened for writing without explicit encoding",
     "Specify encoding='utf-8' explicitly when opening files."),
    (r"\bimport\s+imp\b", "low", "SAFECODE-PY-027",
     "Deprecated 'imp' module imported — use importlib instead",
     "Replace imp with importlib for module loading."),
]

PYTHON_BUG_CHECKS = [
    (r"except\s*:\s*$", "medium", "SAFECODE-PY-B001",
     "Bare except clause — catches SystemExit and KeyboardInterrupt",
     "Catch specific exceptions instead of using a bare except."),
    (r"except\s+Exception\s*:", "low", "SAFECODE-PY-B002",
     "Overly broad except Exception — may hide unexpected errors",
     "Catch only the specific exceptions you expect."),
    (r"except.*:\s*pass\s*$", "high", "SAFECODE-PY-B003",
     "Exception caught and silently ignored with 'pass'",
     "At minimum log the exception. Silently ignoring errors hides bugs."),
    (r"except.*:\s*#\s*TODO", "low", "SAFECODE-PY-B004",
     "TODO in exception handler — error handling not implemented",
     "Implement proper error handling instead of leaving a TODO."),
    (r"=\s*\[.*\]\s*\*\s*\d+", "low", "SAFECODE-PY-B005",
     "List multiplication with mutable objects — may share references",
     "Use a list comprehension to create independent copies for nested structures."),
    (r"def\s+\w+\s*\([^)]*=\[\]", "medium", "SAFECODE-PY-B006",
     "Mutable default argument (empty list) — shared across calls",
     "Use None as default and initialize inside the function body."),
    (r"def\s+\w+\s*\([^)]*=\{\}", "medium", "SAFECODE-PY-B007",
     "Mutable default argument (empty dict) — shared across calls",
     "Use None as default and initialize inside the function body."),
    (r"\bfile\s*=\s*open\(", "medium", "SAFECODE-PY-B008",
     "open() called without context manager — resource leak risk",
     "Use 'with open(...) as f:' to ensure the file is closed."),
    (r"\btime\.sleep\(", "low", "SAFECODE-PY-B009",
     "time.sleep() in potentially sync code — may block event loops",
     "Use asyncio.sleep() in async code or consider refactoring."),
    (r"if\s+\w+\s*(?:is|==)\s*(?:True|False|None)\s*:", "low", "SAFECODE-PY-B010",
     "Explicit comparison to True/False/None — use truthiness",
     "Use 'if x:' or 'if x is None:' instead of 'if x == True:'."),
    (r"range\s*\(\s*len\s*\(", "low", "SAFECODE-PY-B011",
     "range(len(...)) pattern — unpythonic",
     "Use enumerate() or iterate directly over the sequence."),
]


class PythonAnalyzer(BaseAnalyzer):
    language = "python"

    def analyze(self) -> list[Finding]:
        findings = []
        findings.extend(check_secrets(self.code, self.lines))
        findings.extend(check_protocols(self.code, self.lines))
        findings.extend(check_crypto(self.code, self.lines))
        findings.extend(check_injection(self.code, self.lines))
        findings.extend(self._run_checks(PYTHON_UNSAFE_CHECKS))
        return findings

    def find_bugs(self) -> list[Finding]:
        findings = []
        findings.extend(self._run_checks(PYTHON_BUG_CHECKS))
        return findings

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
