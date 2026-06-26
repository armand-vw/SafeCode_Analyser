from fastapi import APIRouter, HTTPException
from backend.models.schemas import CodeRequest, FixResponse
from backend.config import LLM_ENABLED, LLM_MOCK, MAX_CODE_LENGTH
from backend.llm.ollama_client import OllamaClient, MockOllamaClient

router = APIRouter(prefix="/fix", tags=["fix"])


@router.post("", response_model=FixResponse)
async def fix_code(req: CodeRequest):
    if len(req.code) > MAX_CODE_LENGTH:
        raise HTTPException(status_code=413, detail="Code exceeds maximum length")

    if not LLM_ENABLED and not LLM_MOCK:
        return FixResponse(
            language=req.language,
            original_code=req.code,
            llm_used=False,
            error="LLM features are disabled. Set SAFECODE_LLM_ENABLED=true to enable code fixing.",
        )

    from backend.routers.analyze import detect_language
    if req.language == "auto":
        language = detect_language(req.code)
    else:
        language = req.language

    if LLM_MOCK:
        client = MockOllamaClient()
        result = await client.fix_code(req.code, language)
        return FixResponse(
            language=language,
            original_code=req.code,
            fixed_code=result,
            llm_used=True,
        )

    client = OllamaClient()
    healthy = await client.health_check()

    if not healthy:
        return FixResponse(
            language=language,
            original_code=req.code,
            llm_used=False,
            error="Ollama is not running. Start Ollama and ensure the model is available.",
        )

    result = await client.fix_code(req.code, language)

    if not result:
        return FixResponse(
            language=language,
            original_code=req.code,
            llm_used=True,
            error="The model returned an empty response. Try a different model or check Ollama logs.",
        )

    return FixResponse(
        language=language,
        original_code=req.code,
        fixed_code=result,
        llm_used=True,
    )
