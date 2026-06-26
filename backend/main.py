import time
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from contextlib import asynccontextmanager
import os

from backend.routers import analyze, translate, fix
from backend.config import RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")

_rate_limit_store: dict[str, list[float]] = {}


def _clean_rate_limits():
    now = time.time()
    expired = []
    for ip, timestamps in _rate_limit_store.items():
        _rate_limit_store[ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
        if not _rate_limit_store[ip]:
            expired.append(ip)
    for ip in expired:
        del _rate_limit_store[ip]


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="SafeCode Analyzer",
    description="Secure-by-design static code analysis tool",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self' http://localhost:*; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@app.middleware("http")
async def rate_limiter(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        now = time.time()
        client_ip = request.client.host if request.client else "unknown"

        _clean_rate_limits()

        timestamps = _rate_limit_store.get(client_ip, [])
        timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]

        if len(timestamps) >= RATE_LIMIT_REQUESTS:
            retry_after = int(RATE_LIMIT_WINDOW - (now - timestamps[0]))
            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded. Retry in {retry_after}s."},
                headers={"Retry-After": str(retry_after)},
            )

        timestamps.append(now)
        _rate_limit_store[client_ip] = timestamps

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_REQUESTS)
        response.headers["X-RateLimit-Remaining"] = str(RATE_LIMIT_REQUESTS - len(timestamps))
        return response
    return await call_next(request)


app.include_router(analyze.router, prefix="/api")
app.include_router(translate.router, prefix="/api")
app.include_router(fix.router, prefix="/api")


@app.get("/api/health")
async def health():
    from backend.config import LLM_ENABLED, LLM_MOCK
    llm_status = "disabled"
    if LLM_MOCK:
        llm_status = "mock"
    elif LLM_ENABLED:
        from backend.llm.ollama_client import OllamaClient
        client = OllamaClient()
        try:
            ok = await client.health_check()
            llm_status = "connected" if ok else "unreachable"
        except Exception:
            llm_status = "error"
    return {
        "status": "ok",
        "llm": llm_status,
        "llm_enabled": LLM_ENABLED or LLM_MOCK,
    }


@app.get("/")
async def index():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
