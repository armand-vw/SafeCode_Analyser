import pytest
from backend.analyzers.python import PythonAnalyzer
from backend.analyzers.javascript import JavaScriptAnalyzer
from backend.analyzers.cpp import CppAnalyzer
from backend.analyzers.go_analyzer import GoAnalyzer
from backend.analyzers.java import JavaAnalyzer
from backend.rules.secrets import check_secrets
from backend.rules.protocols import check_protocols
from backend.rules.crypto import check_crypto
from backend.rules.injection import check_injection


def _lines(code):
    return code.strip().split("\n")


class TestSecretDetection:
    def test_hardcoded_password(self):
        code = 'password = "supersecret123"'
        findings = check_secrets(code, _lines(code))
        assert len(findings) >= 1
        assert any("password" in f.message.lower() for f in findings)

    def test_api_key(self):
        code = 'API_KEY = "sk-abc123def456ghi789"'
        findings = check_secrets(code, _lines(code))
        assert len(findings) >= 1
        assert any("api key" in f.message.lower() for f in findings)

    def test_aws_key(self):
        code = "access_key = 'AKIAIOSFODNN7EXAMPLE'"
        findings = check_secrets(code, _lines(code))
        assert any("AWS" in f.message for f in findings)

    def test_env_var_ok(self):
        code = 'password = os.getenv("DB_PASSWORD")'
        findings = check_secrets(code, _lines(code))
        assert len(findings) == 0

    def test_placeholder_no_match(self):
        code = 'password = "${DB_PASS}"'
        findings = check_secrets(code, _lines(code))
        assert len(findings) == 0

    def test_db_connection_string(self):
        code = 'DATABASE_URL = "postgresql://user:pass@localhost/db"'
        findings = check_secrets(code, _lines(code))
        assert any("connection string" in f.message.lower() for f in findings)


class TestProtocolDetection:
    def test_http_url(self):
        code = 'url = "http://example.com/api"'
        findings = check_protocols(code, _lines(code))
        assert any("http" in f.message.lower() for f in findings)

    def test_ftp_url(self):
        code = 'ftp_url = "ftp://files.example.com"'
        findings = check_protocols(code, _lines(code))
        assert any("ftp" in f.message.lower() for f in findings)

    def test_https_ok(self):
        code = 'url = "https://example.com/api"'
        findings = check_protocols(code, _lines(code))
        assert len(findings) == 0

    def test_tls_verify_disabled(self):
        code = "response = requests.get(url, verify=False)"
        findings = check_protocols(code, _lines(code))
        assert any("certificate verification" in f.message.lower() for f in findings)


class TestCryptoDetection:
    def test_md5_hash(self):
        code = "hasher = hashlib.md5()"
        findings = check_crypto(code, _lines(code))
        assert any("md5" in f.message.lower() for f in findings)

    def test_sha1_hash(self):
        code = "hasher = hashlib.sha1()"
        findings = check_crypto(code, _lines(code))
        assert any("sha-1" in f.message.lower() or "sha1" in f.message.lower() for f in findings)

    def test_des_cipher(self):
        code = 'Cipher.getInstance("DES")'
        findings = check_crypto(code, _lines(code))
        assert any("des" in f.message.lower() for f in findings)

    def test_insecure_random(self):
        code = "x = random.randint(1, 100)"
        findings = check_crypto(code, _lines(code))
        assert any("random" in f.message.lower() for f in findings)

    def test_sha256_ok(self):
        code = "hasher = hashlib.sha256()"
        findings = check_crypto(code, _lines(code))
        assert len(findings) == 0


class TestInjectionDetection:
    def test_sql_concatenation(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        findings = check_injection(code, _lines(code))
        assert any("sql injection" in f.message.lower() for f in findings)

    def test_shell_true(self):
        code = "subprocess.run(cmd, shell=True)"
        findings = check_injection(code, _lines(code))
        assert any("shell=true" in f.message.lower() for f in findings)

    def test_eval_used(self):
        code = "result = eval(user_input)"
        findings = check_injection(code, _lines(code))
        assert any("eval" in f.message.lower() for f in findings)

    def test_innerhtml(self):
        code = "element.innerHTML = userInput;"
        findings = check_injection(code, _lines(code))
        assert any("innerhtml" in f.message.lower() for f in findings)

    def test_pickle_load(self):
        code = "data = pickle.loads(user_data)"
        findings = check_injection(code, _lines(code))
        assert any("pickle" in f.message.lower() for f in findings)


class TestPythonAnalyzer:
    def test_eval_detected(self):
        a = PythonAnalyzer("x = eval(user_input)")
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-PY-001" in rule_ids

    def test_shell_true_detected(self):
        a = PythonAnalyzer("subprocess.run(cmd, shell=True)")
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert any("shell" in str(r).lower() for r in rule_ids) or "SAFECODE-PY-008" in rule_ids

    def test_debug_true_detected(self):
        a = PythonAnalyzer("DEBUG = True")
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-PY-023" in rule_ids

    def test_secret_key_empty(self):
        a = PythonAnalyzer("SECRET_KEY = ''")
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-PY-024" in rule_ids

    def test_mutable_default_arg_bug(self):
        a = PythonAnalyzer("def foo(items=[]):\n    pass")
        bugs = a.find_bugs()
        rule_ids = [f.rule_id for f in bugs]
        assert "SAFECODE-PY-B006" in rule_ids

    def test_bare_except_bug(self):
        a = PythonAnalyzer("try:\n    risky()\nexcept:\n    pass")
        bugs = a.find_bugs()
        rule_ids = [f.rule_id for f in bugs]
        assert "SAFECODE-PY-B001" in rule_ids


class TestJavaScriptAnalyzer:
    def test_eval_js(self):
        a = JavaScriptAnalyzer("eval(userData)")
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-JS-001" in rule_ids

    def test_innerhtml_js(self):
        a = JavaScriptAnalyzer("document.getElementById('x').innerHTML = data;")
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-JS-005" in rule_ids

    def test_math_random(self):
        a = JavaScriptAnalyzer("const x = Math.random();")
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-JS-017" in rule_ids

    def test_dangerously_insert_html(self):
        a = JavaScriptAnalyzer('<div dangerouslySetInnerHTML={{__html: content}} />')
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-JS-010" in rule_ids

    def test_console_log_password(self):
        a = JavaScriptAnalyzer('console.log("password:", pwd);')
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert any("SAFECODE-JS-027" in rid or "SAFECODE-JS" in rid for rid in rule_ids)


class TestCppAnalyzer:
    def test_gets_detected(self):
        a = CppAnalyzer("gets(buffer);")
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-CPP-001" in rule_ids

    def test_strcpy_detected(self):
        a = CppAnalyzer("strcpy(dest, src);")
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-CPP-002" in rule_ids

    def test_system_detected(self):
        a = CppAnalyzer('system("rm -rf /" + user_path);')
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-CPP-012" in rule_ids


class TestGoAnalyzer:
    def test_md5_import(self):
        a = GoAnalyzer('import "crypto/md5"')
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-GO-001" in rule_ids

    def test_math_rand(self):
        a = GoAnalyzer('import "math/rand"')
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-GO-005" in rule_ids

    def test_sql_sprintf(self):
        a = GoAnalyzer('query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)')
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-GO-006" in rule_ids

    def test_text_template_html(self):
        a = GoAnalyzer('import "text/template"')
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-GO-011" in rule_ids


class TestJavaAnalyzer:
    def test_runtime_exec(self):
        a = JavaAnalyzer("Runtime.getRuntime().exec(userCmd);")
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-JAVA-001" in rule_ids

    def test_plain_statement(self):
        a = JavaAnalyzer("Statement stmt = conn.createStatement();")
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-JAVA-003" in rule_ids

    def test_md5_java(self):
        a = JavaAnalyzer('MessageDigest.getInstance("MD5")')
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-JAVA-006" in rule_ids

    def test_util_random(self):
        a = JavaAnalyzer("Random rng = new Random();")
        findings = a.analyze()
        rule_ids = [f.rule_id for f in findings]
        assert "SAFECODE-JAVA-012" in rule_ids

    def test_string_equals_bug(self):
        a = JavaAnalyzer('if (name == "admin") {')
        bugs = a.find_bugs()
        rule_ids = [f.rule_id for f in bugs]
        assert "SAFECODE-JAVA-B005" in rule_ids

    def test_empty_catch(self):
        a = JavaAnalyzer("try { risky(); } catch (IOException e) { }")
        bugs = a.find_bugs()
        rule_ids = [f.rule_id for f in bugs]
        assert "SAFECODE-JAVA-B002" in rule_ids
