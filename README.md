# RuleSentry AI

**AI-assisted Sigma detection engineering, with deterministic validation and transparent event tests.**

RuleSentry AI is an open-source workbench for detection engineers and security analysts. It validates Sigma-style YAML rules, tests them against sample JSON events, and can optionally request an AI-assisted explanation through OpenRouter.

> **Scope and safety:** The initial local engine supports a documented subset of Sigma syntax; it is not a complete Sigma implementation. AI output is advisory and can be wrong. Do not send secrets, customer data, or sensitive telemetry to an external AI provider.

## Features

- YAML parsing and structural rule validation.
- Local event matching for supported field comparisons and simple conditions.
- Per-event match results and explicit unsupported-syntax diagnostics.
- Sigma `attack.*` tag extraction for ATT&CK techniques and tactics.
- Batch ATT&CK coverage reports across caller-supplied rule collections.
- Optional OpenRouter rule explanation; the core validator works without an API key.
- FastAPI API, tests, Dockerfile, and contributor/security guidance.

## Quick start

Requires Python 3.11+.

```bash
git clone https://github.com/adhi001/RuleSentry-AI.git
cd RuleSentry-AI
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
uvicorn rulesentry.main:app --reload
```

Open http://127.0.0.1:8000/docs for interactive API documentation.

## API examples

### Validate a rule

`POST /api/v1/rules/validate`

```json
{
  "rule": "title: Detect whoami\nid: 11111111-1111-4111-8111-111111111111\nstatus: experimental\ndescription: Detect whoami execution\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: whoami.exe\n  condition: selection\n"
}
```

### Test events

`POST /api/v1/rules/test`

```json
{
  "rule": "title: Detect whoami\nid: 11111111-1111-4111-8111-111111111111\nstatus: experimental\ndescription: Detect whoami execution\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: whoami.exe\n  condition: selection\n",
  "events": [{"Image": "C:\\\\Windows\\\\System32\\\\whoami.exe"}]
}
```

Supported initial subset: exact values, lists, and `contains`, `startswith`, `endswith`, and `re` modifiers; simple `and`, `or`, `not`, parentheses; and `1 of them`, `all of them`, or wildcard selection groups. Unsupported constructs are reported as not evaluated, not silently treated as non-matches.

### MITRE ATT&CK mapping and coverage

RuleSentry reads ATT&CK identifiers from a Sigma rule's `tags` list. Technique tags such as `attack.t1059` and `attack.t1059.001` are normalized to uppercase technique IDs; tactic tags such as `attack.execution` are reported as tactic slugs. Non-ATT&CK tags are ignored. Malformed `attack.*` tags and invalid tag structures produce warnings.

Map one rule with `POST /api/v1/rules/attack-mapping`:

```json
{
  "rule": "title: Detect PowerShell\ntags:\n  - attack.execution\n  - attack.t1059\n  - attack.t1059.001\n"
}
```

Aggregate coverage with `POST /api/v1/attack/coverage`, supplying the rule collection in the request. The response reports how many rules were analyzed and mapped, plus each technique and tactic's rule count and contributing rule titles:

```json
{
  "rules": [
    "title: Detect PowerShell\ntags:\n  - attack.execution\n  - attack.t1059\n",
    "title: Detect Script Interpreter\ntags:\n  - attack.execution\n  - attack.t1059.001\n"
  ]
}
```

Coverage is calculated only from the rules supplied in that request; this initial release does not persist a rule library or infer mappings from rule logic. It reports tag-based coverage, not proof that a technique is comprehensively detected. Technique names, tactic descriptions, and live ATT&CK catalogue metadata are not yet enriched.

### Optional AI explanation

Set `OPENROUTER_API_KEY` and optionally `OPENROUTER_MODEL`, then call `POST /api/v1/rules/explain`. The rule text is sent to OpenRouter. Use sanitized, non-sensitive content only.

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
- Expand ATT&CK metadata enrichment and coverage visualization.
- Detection-quality heuristics and false-positive review workflows.
- Analyst report export and a React frontend.
- Persistent rule library, authentication, and team collaboration.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Contribution enquiries: **astromediasnet16@gmail.com**.

## Security

See [SECURITY.md](SECURITY.md). Do not include secrets, customer data, or unredacted telemetry in public issues.

## License

MIT. See [LICENSE](LICENSE).


## Dashboard concept preview

The image below is a **proposed dashboard design**, not a screenshot of a running frontend. The current release is a FastAPI backend; a React dashboard is still on the roadmap.

![RuleSentry AI dashboard concept preview](docs/dashboard-preview.svg)

### How the dashboard is intended to work

1. **Open the workbench:** The analyst pastes a Sigma-style YAML rule or selects one from a future rule library.
2. **Validate:** The dashboard sends the rule to `POST /api/v1/rules/validate`. The backend parses the YAML and returns validity, rule metadata, and diagnostics.
3. **Test events:** The analyst supplies sample JSON events. The dashboard calls `POST /api/v1/rules/test` and displays each event as a match, non-match, or not evaluated when the syntax is unsupported.
4. **Review results:** A results panel shows validation diagnostics, event match counts, and per-event reasons. Unsupported Sigma syntax is surfaced rather than silently treated as a non-match.
5. **Optional AI explanation:** The analyst can ask for an explanation through `POST /api/v1/rules/explain`. This requires an OpenRouter API key; AI output is advisory, while deterministic validation and event testing remain authoritative.

### What is implemented today

- FastAPI backend endpoints for health, validation, event testing, ATT&CK mapping/coverage, and optional AI explanation.
- A documented, intentionally limited Sigma-style syntax subset.
- Automated test files and a GitHub Actions workflow configuration.

### What is not implemented yet

- The visual dashboard shown above.
- Browser-based rule editing, file upload, saved rule library, and interactive result panels.
- User accounts, persistent rule storage, team collaboration, and a visual ATT&CK coverage dashboard.

The dashboard is a planned frontend layer over the existing API. The preview uses illustrative sample values and does not represent live telemetry or actual execution results.
