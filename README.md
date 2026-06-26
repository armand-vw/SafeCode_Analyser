# SafeCode Analyzer

**Security-first static code analyzer.** Paste code, find vulnerabilities, squash bugs, translate to plain English, and auto-fix issues — across 8 languages. Fully local. No data ever leaves your machine.

![Languages](https://img.shields.io/badge/languages-8-blue) ![Python](https://img.shields.io/badge/python-3.10%2B-green) ![License](https://img.shields.io/badge/license-MIT-yellow)

---

## Why SafeCode?

Most security tools audit code after it's written. SafeCode is designed for **security by design** — you catch vulnerabilities while you write, not months later in a penetration test. Every check, every rule, every piece of this tool was built with the philosophy that code should be secure from the first line.

The tool also bridges the gap between developers and non-technical stakeholders by translating code into plain English, so anyone can understand what a program does.

---

## Features

### 🔒 Analyse Security
Scans your code for common security vulnerabilities using a hybrid rule engine. Catches what linters miss.

**Checks performed:**
- Hardcoded passwords, API keys, tokens, and secrets
- Insecure protocols (HTTP, FTP, Telnet, bare WebSocket)
- Weak cryptography (MD5, SHA-1, DES, RC4, ECB mode)
- SQL injection patterns and unsafe query construction
- Command injection, XSS vectors, unsafe deserialization
- Language-specific dangerous functions (`eval`, `shell=True`, `strcpy`, `gets`, etc.)
- Disabled TLS verification and certificate validation
- Debug mode left enabled, empty secret keys, wildcard hosts

### 🐛 Find Bugs
Detects logic errors and common anti-patterns before they hit production.

**Checks performed:**
- Swallowed exceptions and bare except clauses
- Mutable default arguments in function signatures
- Null pointer risks and resource leaks
- Async/await without error handling
- String comparison with `==` instead of `.equals()`
- Race conditions in goroutines and unlocked mutexes
- Uninitialized variables and double-free bugs
- Loop variable capture in closures

### 📖 Translate Code
Explains what your code does in plain, simple English — designed for non-programmers, project managers, or anyone who needs to understand what's happening behind the scenes without reading code.

### 🔧 Fix Code
Generates corrected code with all detected security issues and bugs resolved. Shows the fixed version ready to use.

---

## Supported Languages

| Language | Security Checks | Bug Checks | Auto-Detect |
|----------|:---:|:---:|:---:|
| Python   | 27 rules | 11 rules | ✅ |
| JavaScript | 27 rules | 11 rules | ✅ |
| TypeScript | 27 rules | 11 rules | ✅ |
| C         | 20 rules | 7 rules  | ✅ |
| C++       | 20 rules | 7 rules  | ✅ |
| Go        | 20 rules | 9 rules  | ✅ |
| Java      | 21 rules | 9 rules  | ✅ |
| Kotlin    | 21 rules | 9 rules  | ✅ |

Language is auto-detected if you leave the selector on "Auto Detect".

---

## Quick Start

### Prerequisites
- Python 3.10 or higher
- `uv` package manager (installed automatically with `pip install uv`)

### Installation

```bash
git clone git@github.com:armand-vw/SafeCode_Analyser.git
cd SafeCode_Analyser
./run.sh
```

Open **http://localhost:8844** in your browser.

The first run creates a virtual environment and installs dependencies automatically.

---

## AI Features (Optional)

SafeCode integrates with [Ollama](https://ollama.com) to power the Translation and Fix features. Everything else works completely offline with no AI required.

### Setup

```bash
# 1. Install Ollama (one-time)
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull a code model
ollama pull codellama

# 3. Start SafeCode with LLM enabled
SAFECODE_LLM_ENABLED=true ./run.sh
```

### Supported Models

Any Ollama-compatible model works. Recommended:
- `codellama` — Meta's code-specialized model (default)
- `deepseek-coder` — Strong alternative, auto-used as fallback
- `llama3` — General purpose, works well for translation

### Mock Mode (No Ollama Required)

Get a taste of the AI features without installing anything:

```bash
SAFECODE_LLM_MOCK=true ./run.sh
```

The mock mode analyzes code structure and returns a realistic simulation. Useful for demos, development, and testing.

---

## Configuration

All configuration is done through environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SAFECODE_LLM_ENABLED` | `false` | Enable Ollama-powered AI features |
| `SAFECODE_LLM_MOCK` | `false` | Use mock AI responses (overrides LLM) |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API address |
| `OLLAMA_MODEL` | `codellama` | Primary model to use |
| `OLLAMA_FALLBACK_MODEL` | `deepseek-coder` | Fallback if primary model not found |
| `SAFECODE_LLM_TIMEOUT` | `120` | LLM request timeout in seconds |
| `SAFECODE_MAX_CODE_LENGTH` | `50000` | Maximum code length in characters |
| `SAFECODE_RATE_LIMIT` | `30` | Max requests per window |
| `SAFECODE_RATE_WINDOW` | `60` | Rate limit window in seconds |
| `PORT` | `8844` | Server port |
| `HOST` | `0.0.0.0` | Server bind address |

---

## API Reference

The backend exposes a REST API at `http://localhost:8844/api/`.

### `POST /api/analyze/security`

Analyze code for security vulnerabilities.

```json
{
  "code": "password = \"hunter2\"\neval(user_input)",
  "language": "python"
}
```

**Response:**
```json
{
  "language": "python",
  "findings": [
    {
      "severity": "critical",
      "rule_id": "SAFECODE-SEC-001",
      "message": "Hardcoded password found in source code",
      "line": 1,
      "snippet": "password = \"hunter2\"",
      "recommendation": "Move credentials to environment variables or a secrets manager."
    }
  ],
  "total_count": 2,
  "critical_count": 2,
  "high_count": 0,
  "medium_count": 0,
  "low_count": 0
}
```

### `POST /api/analyze/bugs`

Find bugs and logic errors. Same request/response format as above.

### `POST /api/translate`

Translate code to plain English. Requires LLM enabled or mock mode.

```json
{
  "code": "print(\"Hello World\")",
  "language": "python"
}
```

**Response:**
```json
{
  "language": "python",
  "plain_english": "This Python program contains 1 line of code...",
  "llm_used": true
}
```

### `POST /api/fix`

Auto-fix security issues and bugs. Requires LLM enabled or mock mode.

```json
{
  "code": "password = \"secret123\"",
  "language": "python"
}
```

**Response:**
```json
{
  "language": "python",
  "original_code": "password = \"secret123\"",
  "fixed_code": "# Changes applied:\n...\npassword = os.getenv('PASSWORD', '')",
  "llm_used": true
}
```

### `GET /api/health`

Server and LLM health check.

```json
{
  "status": "ok",
  "llm": "disabled",
  "llm_enabled": false
}
```

---

## Architecture

```
SafeCode_Analyser/
├── backend/
│   ├── analyzers/           # Per-language scanners
│   │   ├── base.py          # Shared result builder + line matcher
│   │   ├── python.py        # 27 security + 11 bug detection rules
│   │   ├── javascript.py    # 27 security + 11 bug detection rules
│   │   ├── cpp.py           # 20 security + 7 bug detection rules
│   │   ├── go_analyzer.py   # 20 security + 9 bug detection rules
│   │   └── java.py          # 21 security + 9 bug detection rules
│   ├── rules/               # Cross-language rule engine
│   │   ├── secrets.py       # Password, API key, token detection
│   │   ├── protocols.py     # HTTP, FTP, Telnet, TLS checks
│   │   ├── crypto.py        # Weak hash and cipher detection
│   │   └── injection.py     # SQL, XSS, command injection patterns
│   ├── llm/                 # AI integration (optional)
│   │   ├── ollama_client.py # Ollama API client + mock implementation
│   │   └── prompts.py       # LLM prompt templates
│   ├── routers/             # API route handlers
│   │   ├── analyze.py       # Security and bug analysis endpoints
│   │   ├── translate.py     # Code translation endpoint
│   │   └── fix.py           # Auto-fix endpoint
│   ├── models/schemas.py    # Pydantic request/response models
│   ├── config.py            # Environment-based configuration
│   └── main.py              # FastAPI app with security middleware
├── frontend/
│   ├── index.html           # Single-page application shell
│   ├── css/style.css        # Dark theme with severity color coding
│   └── js/
│       ├── api.js           # Fetch-based API client
│       ├── app.js           # UI logic, result rendering, event handling
│       └── editor.js        # Code editor with line numbers + tab support
├── tests/
│   └── test_analyzers.py    # 44 tests covering all analyzers + rules
├── run.sh                   # One-command startup script
└── requirements.txt         # Python dependencies
```

---

## Security by Design

SafeCode practices what it preaches. The tool itself is built with security-first principles:

- **Zero persistence** — All code is processed in memory. Nothing is written to disk. No logs of your code.
- **Fully local** — No external API calls. The only outbound network request is to localhost Ollama, and only if you enable it.
- **Security headers** — CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy enforced on every response.
- **Rate limiting** — 30 requests per 60 seconds per IP address, with proper `Retry-After` headers.
- **Input validation** — Maximum code length enforced. Request body size limited. All input is Pydantic-validated.
- **Opt-in AI only** — Ollama integration is disabled by default. You control when and if AI touches your code.
- **No telemetry** — No analytics, no tracking, no phone-home. This is a tool, not a service.

---

## Development

### Running Tests

```bash
source .venv/bin/activate
python -m pytest tests/ -v
```

### Adding a New Language Check

1. Add patterns to the relevant `backend/analyzers/{language}.py` file
2. Follow the existing tuple format: `(regex, severity, rule_id, message, recommendation)`
3. Add test cases to `tests/test_analyzers.py`
4. Run the test suite to verify

### Adding a New Shared Rule

1. Create a new module in `backend/rules/`
2. Implement a `check_*` function that takes `(code, lines)` and returns `list[Finding]`
3. Call it from the base analyzer or individual language analyzers
4. Add tests

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend framework | FastAPI (Python 3.10+) |
| Data validation | Pydantic |
| ASGI server | Uvicorn |
| Frontend | Vanilla JavaScript, CSS (no framework) |
| Package manager | uv |
| AI (optional) | Ollama (local) |
| Testing | pytest |

---

## License

MIT
