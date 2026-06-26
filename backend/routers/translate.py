from fastapi import APIRouter, HTTPException
from backend.models.schemas import CodeRequest, TranslateResponse
from backend.config import LLM_ENABLED, LLM_MOCK, MAX_CODE_LENGTH
from backend.llm.ollama_client import OllamaClient, MockOllamaClient

router = APIRouter(prefix="/translate", tags=["translate"])


@router.post("", response_model=TranslateResponse)
async def translate_code(req: CodeRequest):
    if len(req.code) > MAX_CODE_LENGTH:
        raise HTTPException(status_code=413, detail="Code exceeds maximum length")

    if not LLM_ENABLED and not LLM_MOCK:
        return TranslateResponse(
            language=req.language,
            plain_english="",
            llm_used=False,
            error="LLM features are disabled. Set SAFECODE_LLM_ENABLED=true to enable code translation.",
        )

    from backend.routers.analyze import detect_language
    if req.language == "auto":
        language = detect_language(req.code)
    else:
        language = req.language

    if LLM_MOCK:
        client = MockOllamaClient()
        result = await client.translate_to_english(req.code, language)
        return TranslateResponse(
            language=language,
            plain_english=result,
            llm_used=True,
        )

    client = OllamaClient()
    healthy = await client.health_check()

    if not healthy:
        return TranslateResponse(
            language=language,
            plain_english="",
            llm_used=False,
            error="Ollama is not running. Start Ollama and ensure the model is available.",
        )

    result = await client.translate_to_english(req.code, language)

    if not result:
        return TranslateResponse(
            language=language,
            plain_english="",
            llm_used=True,
            error="The model returned an empty response. Try a different model or check Ollama logs.",
        )

    return TranslateResponse(
        language=language,
        plain_english=result,
        llm_used=True,
    )
