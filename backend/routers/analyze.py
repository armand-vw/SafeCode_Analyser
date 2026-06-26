from fastapi import APIRouter, HTTPException
from backend.models.schemas import CodeRequest, AnalysisResponse, SUPPORTED_LANGUAGES
from backend.config import LLM_ENABLED, MAX_CODE_LENGTH

router = APIRouter(prefix="/analyze", tags=["analyze"])

ANALYZER_MAP = {
    "python": "backend.analyzers.python.PythonAnalyzer",
    "javascript": "backend.analyzers.javascript.JavaScriptAnalyzer",
    "typescript": "backend.analyzers.javascript.JavaScriptAnalyzer",
    "c": "backend.analyzers.cpp.CppAnalyzer",
    "cpp": "backend.analyzers.cpp.CppAnalyzer",
    "go": "backend.analyzers.go_analyzer.GoAnalyzer",
    "java": "backend.analyzers.java.JavaAnalyzer",
    "kotlin": "backend.analyzers.java.JavaAnalyzer",
}

LANGUAGE_DETECTION = [
    (r"\bdef\s+\w+\s*\(|import\s+\w+|from\s+\w+\s+import|class\s+\w+.*:|print\s*\(", "python"),
    (r"\bconst\s+\w+\s*=|let\s+\w+\s*=|var\s+\w+\s*=|function\s+\w+\s*\(|=>\s*\{|export\s+(?:default\s+)?", "javascript"),
    (r"\binterface\s+\w+\s*\{|:\s*(?:string|number|boolean|void)\b|as\s+\w+", "typescript"),
    (r"\bpackage\s+\w+;|import\s+java\.|public\s+class\s+\w+|System\.out\.", "java"),
    (r"\bpackage\s+\w+\s*\n|func\s+\w+\s*\(|import\s+\(\s*\n", "go"),
    (r"\b#include\s*<|int\s+main\s*\(|printf\s*\(|scanf\s*\(|malloc\s*\(", "c"),
]


def detect_language(code: str) -> str:
    for pattern, lang in LANGUAGE_DETECTION:
        import re
        if re.search(pattern, code):
            if lang == "javascript":
                if re.search(r":\s*(?:string|number|boolean|void)\b|interface\s+\w+\s*\{", code):
                    return "typescript"
            return lang
    return "python"


def get_analyzer(language: str, code: str):
    import importlib

    if language == "auto":
        language = detect_language(code)

    module_path = ANALYZER_MAP.get(language)
    if not module_path:
        raise HTTPException(status_code=400, detail=f"Unsupported language: {language}")

    module_name, class_name = module_path.rsplit(".", 1)
    module = importlib.import_module(module_name)
    analyzer_class = getattr(module, class_name)
    return analyzer_class(code), language


@router.post("/security", response_model=AnalysisResponse)
async def analyze_security(req: CodeRequest):
    if len(req.code) > MAX_CODE_LENGTH:
        raise HTTPException(status_code=413, detail="Code exceeds maximum length")

    analyzer, detected_lang = get_analyzer(req.language, req.code)
    findings = analyzer.analyze()

    findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[f.severity])

    return AnalysisResponse(
        language=detected_lang,
        findings=findings,
        total_count=len(findings),
        critical_count=sum(1 for f in findings if f.severity == "critical"),
        high_count=sum(1 for f in findings if f.severity == "high"),
        medium_count=sum(1 for f in findings if f.severity == "medium"),
        low_count=sum(1 for f in findings if f.severity == "low"),
    )


@router.post("/bugs", response_model=AnalysisResponse)
async def analyze_bugs(req: CodeRequest):
    if len(req.code) > MAX_CODE_LENGTH:
        raise HTTPException(status_code=413, detail="Code exceeds maximum length")

    analyzer, detected_lang = get_analyzer(req.language, req.code)

    if hasattr(analyzer, "find_bugs"):
        findings = analyzer.find_bugs()
    else:
        findings = []

    findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[f.severity])

    return AnalysisResponse(
        language=detected_lang,
        findings=findings,
        total_count=len(findings),
        critical_count=sum(1 for f in findings if f.severity == "critical"),
        high_count=sum(1 for f in findings if f.severity == "high"),
        medium_count=sum(1 for f in findings if f.severity == "medium"),
        low_count=sum(1 for f in findings if f.severity == "low"),
    )
