# Contributing to RuleSentry AI

Thanks for helping improve RuleSentry AI.

## Before you start

- Open an issue to discuss substantial changes.
- Keep the project focused on defensive detection engineering.
- Never commit API keys, credentials, customer data, or sensitive telemetry.
- Clearly document any Sigma syntax supported or intentionally unsupported.

## Development setup

Use Python 3.11 or newer:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
```

## Pull requests

1. Keep changes focused and include tests.
2. Explain behavior changes and compatibility impact.
3. Update documentation for new endpoints, settings, or supported syntax.
4. Ensure tests and lint checks pass.
5. Do not present AI-generated analysis as authoritative detection validation.

For contribution enquiries, contact **astromediasnet16@gmail.com**.
