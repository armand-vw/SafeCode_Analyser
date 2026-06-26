import os

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "codellama")
OLLAMA_FALLBACK_MODEL = os.getenv("OLLAMA_FALLBACK_MODEL", "deepseek-coder")

LLM_ENABLED = os.getenv("SAFECODE_LLM_ENABLED", "false").lower() == "true"
LLM_MOCK = os.getenv("SAFECODE_LLM_MOCK", "false").lower() == "true"
LLM_TIMEOUT = int(os.getenv("SAFECODE_LLM_TIMEOUT", "120"))

MAX_CODE_LENGTH = int(os.getenv("SAFECODE_MAX_CODE_LENGTH", "50000"))
MAX_REQUEST_SIZE = int(os.getenv("SAFECODE_MAX_REQUEST_SIZE", str(1024 * 1024)))

RATE_LIMIT_REQUESTS = int(os.getenv("SAFECODE_RATE_LIMIT", "30"))
RATE_LIMIT_WINDOW = int(os.getenv("SAFECODE_RATE_WINDOW", "60"))
