# Security Policy

## Reporting a vulnerability

Please do not report exploitable vulnerabilities in public issues. Contact **astromediasnet16@gmail.com** with a concise description, impact, and safe reproduction steps. Avoid sending real secrets or sensitive customer data.

## Data handling

- RuleSentry's local validation and event testing run in the application process.
- The optional AI explanation endpoint sends the submitted rule and question to the configured OpenRouter endpoint.
- Do not submit secrets, personal data, customer logs, or confidential detection content to external AI providers unless your organization has explicitly approved that processing.
- Treat AI responses as untrusted suggestions; review them before operational use.

## Supported scope

The first release implements only a subset of Sigma syntax. An unsupported expression must not be interpreted as proof that an event is benign or that a rule is ineffective.
