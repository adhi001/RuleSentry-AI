# Rule engine architecture

## Current architecture

The API depends on a small engine contract rather than importing a format-specific
implementation directly.

```text
FastAPI routes
    |
    v
EngineRegistry  -- format name ("sigma")
    |
    v
RuleEngine protocol
    |
    v
SigmaSubsetEngine adapter
    |
    v
sigma_engine.py (existing parser, validator and event matcher)
```

## Contract

Every engine exposes:

- `format_name`: stable registry key.
- `validate(source)`: returns the shared `ValidateResponse`.
- `test(source, events)`: returns the shared `TestResponse`.

The registry normalizes format names, rejects accidental duplicate registration,
and provides an explicit `replace=True` escape hatch for controlled replacement.
Unknown formats produce an actionable error listing registered formats.

## Compatibility and boundaries

- The existing `sigma_engine.py` implementation and its public functions remain
  unchanged. `SigmaSubsetEngine` delegates to those functions.
- Existing API endpoints continue to select Sigma by default, so request and
  response payloads do not change in this milestone.
- The current engine remains a documented Sigma subset, not full Sigma support.
- Future formats can implement `RuleEngine` and register themselves without
  changing the API route logic.
- Engine registration is currently in-process and static at application startup;
  dynamic third-party plugin discovery and per-request format selection are
  intentionally deferred.

## Adding another engine

1. Implement the `RuleEngine` protocol.
2. Register the implementation in `create_default_registry()` (or a future
   application-specific registry factory).
3. Add engine-specific validation and evaluation tests.
4. Add an explicit API format-selection contract before exposing the format to
   clients. Do not infer a format from untrusted rule contents.
