"""Typed API contracts."""
from pydantic import BaseModel, Field


class ValidateRequest(BaseModel):
    rule: str = Field(min_length=1, max_length=200_000)


class Diagnostic(BaseModel):
    severity: str
    code: str
    message: str


class ValidateResponse(BaseModel):
    valid: bool
    title: str | None = None
    rule_id: str | None = None
    diagnostics: list[Diagnostic] = Field(default_factory=list)


class TestRequest(ValidateRequest):
    events: list[dict[str, object]] = Field(min_length=1, max_length=500)


class EventResult(BaseModel):
    index: int
    matched: bool | None
    reason: str


class TestResponse(BaseModel):
    supported: bool
    matched_count: int
    total_events: int
    results: list[EventResult]
    diagnostics: list[Diagnostic] = Field(default_factory=list)


class ExplainRequest(ValidateRequest):
    question: str = Field(default="Explain the rule's intent and likely limitations.", max_length=2000)


class ExplainResponse(BaseModel):
    available: bool
    model: str | None = None
    explanation: str
