"""FastAPI application for RuleSentry AI."""
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .ai_review import explain_rule
from .models import (
    ExplainRequest,
    ExplainResponse,
    TestRequest,
    TestResponse,
    ValidateRequest,
    ValidateResponse,
)
from .sigma_engine import test_rule, validate_rule

app = FastAPI(
    title="RuleSentry AI",
    description="AI-assisted Sigma-style rule validation and local event testing.",
    version="0.1.0",
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "RULESENTRY_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "rulesentry-ai"}


@app.post("/api/v1/rules/validate", response_model=ValidateResponse)
async def validate(request: ValidateRequest) -> ValidateResponse:
    return validate_rule(request.rule)


@app.post("/api/v1/rules/test", response_model=TestResponse)
async def test(request: TestRequest) -> TestResponse:
    return test_rule(request.rule, request.events)


@app.post("/api/v1/rules/explain", response_model=ExplainResponse)
async def explain(request: ExplainRequest) -> ExplainResponse:
    try:
        explanation, model = await explain_rule(request.rule, request.question)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AI provider request failed.") from exc
    return ExplainResponse(available=True, model=model, explanation=explanation)


# In production the Docker image includes the compiled Vite app. Mounting it
# after the API routes keeps /health and /api/* handled by FastAPI.
frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if frontend_dist.is_dir():
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="dashboard")
