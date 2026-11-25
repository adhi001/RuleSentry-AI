# RuleSentry AI

**AI-assisted Sigma detection engineering, with deterministic validation and transparent event tests.**

RuleSentry AI is an open-source workbench for detection engineers and security analysts. It validates Sigma-style YAML rules, tests them against sample JSON events, and can optionally request an AI-assisted explanation through OpenRouter.

> **Scope and safety:** The initial local engine supports a documented subset of Sigma syntax; it is not a complete Sigma implementation. AI output is advisory and can be wrong. Do not send secrets, customer data, or sensitive telemetry to an external AI provider.

## Features

- YAML parsing and structural rule validation.
- Local event matching for supported field comparisons and simple conditions.
- Per-event match results and explicit unsupported-syntax diagnostics.
- Optional OpenRouter rule explanation; the core validator works without an API key.
- Browser dashboard for editing rules, validation diagnostics, event testing, and optional AI explanations.
- FastAPI API, tests, Dockerfile, and contributor/security guidance.

## Quick start

Requires Python 3.11+.

```bash
git clone https://github.com/adhi001/RuleSentry-AI.git
cd RuleSentry-AI
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
uvicorn rulesentry.main:app --reload
```

Open **http://127.0.0.1:8000** for the RuleSentry dashboard, or **http://127.0.0.1:8000/docs** for interactive API documentation.

The dashboard is served by the FastAPI application and calls its same-origin API routes. It includes a sample Sigma rule, validation diagnostics, JSON event input and per-event match outcomes, plus an optional AI explanation panel. The AI panel requires `OPENROUTER_API_KEY` on the backend; validation and event testing do not.

## API examples

### Validate a rule

`POST /api/v1/rules/validate`

```json
{
  "rule": "title: Detect whoami\\nid: 11111111-1111-4111-8111-111111111111\\nstatus: experimental\\ndescription: Detect whoami execution\\nlogsource:\\n  category: process_creation\\ndetection:\\n  selection:\\n    Image|endswith: whoami.exe\\n  condition: selection\\n"
}
```

### Test events

`POST /api/v1/rules/test`

```json
{
  "rule": "title: Detect whoami\\nid: 11111111-1111-4111-8111-111111111111\\nstatus: experimental\\ndescription: Detect whoami execution\\nlogsource:\\n  category: process_creation\\ndetection:\\n  selection:\\n    Image|endswith: whoami.exe\\n  condition: selection\\n",
  "events": [{"Image": "C:\\\\Windows\\\\System32\\\\whoami.exe"}]
}
```

Supported initial subset: exact values, lists, and `contains`, `startswith`, `endswith`, and `re` modifiers; simple `and`, `or`, `not`, parentheses; and `1 of them`, `all of them`, or wildcard selection groups. Unsupported constructs are reported as not evaluated, not silently treated as non-matches.

### Optional AI explanation

Set `OPENROUTER_API_KEY` and optionally `OPENROUTER_MODEL`, then use the dashboard's AI explanation action or call `POST /api/v1/rules/explain`. The rule text is sent to OpenRouter. Use sanitized, non-sensitive content only.

## Configuration

Copy `.env.example` to `.env`.

| Variable | Purpose | Default |
|---|---|---|
| `OPENROUTER_API_KEY` | Optional AI review key | unset |
| `OPENROUTER_MODEL` | OpenRouter model identifier | `openrouter/auto` |
| `OPENROUTER_BASE_URL` | OpenRouter API base URL | `https://openrouter.ai/api/v1` |
| `APP_ENV` | Environment label | `development` |

Never commit `.env`, API keys, credentials, or production logs.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Roadmap

- Full Sigma support using pySigma and backend plugins.
- ATT&CK technique mapping and coverage views.
- Detection-quality heuristics and false-positive review workflows.
- Analyst report export.
- Persistent rule library, authentication, and team collaboration.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Contribution enquiries: **astromediasnet16@gmail.com**.

## Security

See [SECURITY.md](SECURITY.md). Do not include secrets, customer data, or unredacted telemetry in public issues.

## License

MIT. See [LICENSE](LICENSE).
