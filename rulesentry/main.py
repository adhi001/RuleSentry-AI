"""FastAPI application for RuleSentry AI."""
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

from .ai_review import explain_rule
from .engine import ENGINE_REGISTRY
from .models import (
    AttackCoverageRequest,
    AttackCoverageResponse,
    AttackMappingResponse,
    ExplainRequest,
    ExplainResponse,
    TestRequest,
    TestResponse,
    ValidateRequest,
    ValidateResponse,
)
from .sigma_engine import attack_coverage, map_attack_tags

app = FastAPI(
    title="RuleSentry AI",
    description="AI-assisted Sigma-style rule validation and local event testing.",
    version="0.3.0",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "rulesentry-ai"}


@app.post("/api/v1/rules/validate", response_model=ValidateResponse)
async def validate(request: ValidateRequest) -> ValidateResponse:
    return ENGINE_REGISTRY.get("sigma").validate(request.rule)


@app.post("/api/v1/rules/test", response_model=TestResponse)
async def test(request: TestRequest) -> TestResponse:
    return ENGINE_REGISTRY.get("sigma").test(request.rule, request.events)


@app.post("/api/v1/rules/attack-mapping", response_model=AttackMappingResponse)
async def attack_mapping(request: ValidateRequest) -> AttackMappingResponse:
    return map_attack_tags(request.rule)


@app.post("/api/v1/attack/coverage", response_model=AttackCoverageResponse)
async def attack_coverage_report(request: AttackCoverageRequest) -> AttackCoverageResponse:
    return attack_coverage(request.rules)


@app.post("/api/v1/rules/explain", response_model=ExplainResponse)
async def explain(request: ExplainRequest) -> ExplainResponse:
    try:
        explanation, model = await explain_rule(request.rule, request.question)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AI provider request failed.") from exc
    return ExplainResponse(available=True, model=model, explanation=explanation)


# Serve the browser workbench after API routes so /api/* and /health remain API endpoints.
_frontend = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/", StaticFiles(directory=_frontend, html=True), name="dashboard")
