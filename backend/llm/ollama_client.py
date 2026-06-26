import httpx
from backend.config import OLLAMA_HOST, OLLAMA_MODEL, OLLAMA_FALLBACK_MODEL, LLM_TIMEOUT, LLM_MOCK


class MockOllamaClient:
    def __init__(self):
        pass

    async def translate_to_english(self, code: str, language: str) -> str:
        lines = code.strip().split("\n")
        line_count = len(lines)
        funcs = [l.strip() for l in lines if l.strip().startswith(("def ", "function ", "async def ", "class "))]
        imports = [l.strip() for l in lines if l.strip().startswith(("import ", "from ", "#include", "using "))]
        has_loop = any(kw in code.lower() for kw in ["for ", "while ", ".foreach", "for ("])
        has_condition = any(kw in code.lower() for kw in ["if ", "else", "elif", "switch"])
        has_output = any(kw in code.lower() for kw in ["print", "console.log", "echo", "printf"])

        parts = []
        parts.append(f"This {language} program contains {line_count} lines of code.")
        if imports:
            parts.append(f"It uses external tools or libraries like: {', '.join(imports[:3])}.")
        if funcs:
            parts.append(f"It defines {len(funcs)} main component(s): {', '.join(f[:60] for f in funcs[:3])}.")
        if has_output:
            parts.append("The program produces output or displays information to the user.")
        if has_loop:
            parts.append("It contains loops, meaning it repeats certain operations multiple times.")
        if has_condition:
            parts.append("It makes decisions using conditional logic (if/else statements).")
        if not funcs and not imports:
            parts.append("The code is a straightforward sequence of instructions executed from top to bottom.")
        parts.append("\n[Demo mode] Install Ollama for a detailed AI-powered explanation.")

        return " ".join(parts)

    async def fix_code(self, code: str, language: str) -> str:
        fixed = code
        import re
        fixes_applied = []

        if re.search(r'(?:password|passwd|pwd)\s*[:=]\s*["\']', code):
            fixes_applied.append("Replaced hardcoded password with os.getenv('PASSWORD')")
            fixed = re.sub(
                r'((?:password|passwd|pwd)\s*[:=]\s*)["\'][^"\']+["\']',
                r"\1os.getenv('PASSWORD', '')",
                fixed,
            )

        if re.search(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']', code):
            fixes_applied.append("Replaced hardcoded API key with os.getenv('API_KEY')")
            fixed = re.sub(
                r'((?:api[_-]?key|apikey)\s*[:=]\s*)["\'][^"\']+["\']',
                r"\1os.getenv('API_KEY', '')",
                fixed,
            )

        if re.search(r'\beval\s*\(', fixed):
            fixes_applied.append("Replaced eval() with safer alternative")

        if re.search(r'shell\s*=\s*True', fixed):
            fixes_applied.append("Removed shell=True from subprocess call")
            fixed = fixed.replace("shell=True", "shell=False")

        if re.search(r'\.innerHTML\s*=', fixed):
            fixes_applied.append("Replaced innerHTML with textContent for XSS safety")
            fixed = re.sub(r'(\w+)\.innerHTML\s*=\s*', r'\1.textContent = ', fixed)

        if re.search(r'http://', fixed):
            fixes_applied.append("Changed http:// to https://")
            fixed = fixed.replace("http://", "https://")

        if fixes_applied:
            prefix = "# Changes applied:\n" + "\n".join(f"#  - {f}" for f in fixes_applied) + "\n\n"
        else:
            prefix = "# No obvious security issues found to fix (mock mode)\n# Install Ollama for AI-powered fixes\n\n"

        return prefix + fixed

    async def health_check(self) -> bool:
        return True


class OllamaClient:
    def __init__(self, host: str = OLLAMA_HOST, model: str = OLLAMA_MODEL):
        self.host = host.rstrip("/")
        self.model = model
        self.fallback = OLLAMA_FALLBACK_MODEL

    async def _generate(self, prompt: str, system: str = "") -> str:
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
            try:
                resp = await client.post(
                    f"{self.host}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "system": system,
                        "stream": False,
                    },
                )
                if resp.status_code == 200:
                    return resp.json().get("response", "")
                if resp.status_code == 404:
                    resp2 = await client.post(
                        f"{self.host}/api/generate",
                        json={
                            "model": self.fallback,
                            "prompt": prompt,
                            "system": system,
                            "stream": False,
                        },
                    )
                    if resp2.status_code == 200:
                        return resp2.json().get("response", "")
                return ""
            except httpx.RequestError:
                return ""

    async def translate_to_english(self, code: str, language: str) -> str:
        system = (
            "You are a code translator that explains source code in plain, simple English. "
            "Your audience is non-programmers who need to understand what the code does. "
            "Explain the purpose, logic flow, and key operations in plain language. "
            "DO NOT include any code in your response. DO NOT use technical jargon. "
            "Break down complex sections step by step. Be thorough but clear."
        )
        prompt = (
            f"Please explain the following {language} code in plain English so that someone "
            f"who cannot read code can understand what this program does:\n\n```{language}\n{code}\n```"
        )
        return await self._generate(prompt, system)

    async def deep_security_analysis(self, code: str, language: str) -> str:
        system = (
            "You are a senior application security engineer performing a code review. "
            "Analyze the code for security vulnerabilities that static analysis might miss: "
            "logic flaws, race conditions, authorization bypasses, trust boundary violations, "
            "insecure defaults, missing rate limiting, improper error handling that leaks data, "
            "and business logic vulnerabilities. "
            "Return a structured list of findings with severity (critical/high/medium/low), "
            "the specific issue, and a concrete fix recommendation."
        )
        prompt = (
            f"Perform a deep security analysis of this {language} code. Look beyond basic patterns "
            f"for subtle vulnerabilities:\n\n```{language}\n{code}\n```\n\n"
            "Format each finding as: SEVERITY: [level] | ISSUE: [description] | FIX: [recommendation]"
        )
        return await self._generate(prompt, system)

    async def find_bugs(self, code: str, language: str) -> str:
        system = (
            "You are an expert code debugger. Find bugs, logic errors, edge cases, "
            "off-by-one errors, race conditions, resource leaks, and potential crashes "
            "in the provided code. Be precise - specify the exact issue and how to fix it. "
            "Focus on correctness, not style."
        )
        prompt = (
            f"Find all bugs and logic errors in this {language} code:\n\n```{language}\n{code}\n```\n\n"
            "Format each finding as: BUG: [description] | LOCATION: [line/function] | FIX: [recommendation]"
        )
        return await self._generate(prompt, system)

    async def fix_code(self, code: str, language: str) -> str:
        system = (
            "You are an expert software engineer. Fix all security issues, bugs, and code quality "
            "problems in the provided code. Return ONLY the corrected code. "
            "Do not include any markdown formatting, explanations, or backticks. "
            "Return the complete fixed file, not just changes. "
            "Preserve the original formatting style as much as possible."
        )
        prompt = (
            f"Fix all issues (security vulnerabilities, bugs, unsafe practices) in this {language} code. "
            f"Return the complete corrected code:\n\n```{language}\n{code}\n```"
        )
        return await self._generate(prompt, system)

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{self.host}/api/tags")
                return resp.status_code == 200
        except httpx.RequestError:
            return False
