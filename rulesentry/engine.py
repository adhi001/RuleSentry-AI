"""Rule-engine contracts and registry.

The registry keeps API orchestration independent from individual detection formats.
New engines should implement RuleEngine and register under a stable format name.
"""
from __future__ import annotations

from typing import Protocol

from .models import TestResponse, ValidateResponse


class RuleEngine(Protocol):
    """Common interface implemented by detection-rule engines."""

    format_name: str

    def validate(self, source: str) -> ValidateResponse:
        """Validate a rule without evaluating events."""

    def test(self, source: str, events: list[dict[str, object]]) -> TestResponse:
        """Evaluate a rule against events, reporting unsupported evaluation."""


class EngineRegistry:
    """In-memory registry of available rule engines."""

    def __init__(self) -> None:
        self._engines: dict[str, RuleEngine] = {}

    def register(self, engine: RuleEngine, *, replace: bool = False) -> None:
        name = engine.format_name.strip().lower()
        if not name:
            raise ValueError("Engine format_name must not be empty.")
        if name in self._engines and not replace:
            raise ValueError(f"A rule engine for '{name}' is already registered.")
        self._engines[name] = engine

    def get(self, format_name: str) -> RuleEngine:
        name = format_name.strip().lower()
        try:
            return self._engines[name]
        except KeyError as exc:
            available = ", ".join(self.available_formats()) or "none"
            raise ValueError(
                f"Unsupported rule format '{format_name}'. Available formats: {available}."
            ) from exc

    def available_formats(self) -> tuple[str, ...]:
        return tuple(sorted(self._engines))


class SigmaSubsetEngine:
    """Adapter exposing the existing Sigma-subset functions via RuleEngine."""

    format_name = "sigma"

    def validate(self, source: str) -> ValidateResponse:
        from .sigma_engine import validate_rule

        return validate_rule(source)

    def test(self, source: str, events: list[dict[str, object]]) -> TestResponse:
        from .sigma_engine import test_rule

        return test_rule(source, events)


def create_default_registry() -> EngineRegistry:
    """Build the application registry with the currently supported engine."""
    registry = EngineRegistry()
    registry.register(SigmaSubsetEngine())
    return registry


ENGINE_REGISTRY = create_default_registry()
