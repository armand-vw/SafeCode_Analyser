from pydantic import BaseModel, Field
from typing import Literal, Optional

SUPPORTED_LANGUAGES = Literal["python", "javascript", "typescript", "c", "cpp", "go", "java", "kotlin", "auto"]

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]

class CodeRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=50000)
    language: SUPPORTED_LANGUAGES = "auto"

class Finding(BaseModel):
    severity: SeverityLevel
    rule_id: str
    message: str
    line: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None
    recommendation: Optional[str] = None

class AnalysisResponse(BaseModel):
    language: str
    findings: list[Finding]
    total_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

class TranslateResponse(BaseModel):
    language: str
    plain_english: str
    llm_used: bool = False
    error: Optional[str] = None

class FixResponse(BaseModel):
    language: str
    original_code: str
    fixed_code: Optional[str] = None
    changes: list[dict] = []
    explanation: Optional[str] = None
    llm_used: bool = False
    error: Optional[str] = None

class ErrorResponse(BaseModel):
    detail: str
