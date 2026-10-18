# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| Latest release (`v0.x`) | Yes |
| `main` | Yes (pre-release) |
| Older tags | Best effort only |

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems**, and do not include working exploit details against Kunari itself in public discussions.

Prefer one of these channels:

1. [GitHub Private Vulnerability Reporting](https://github.com/jimididit/kunari/security/advisories/new) (recommended)
2. Contact the repository maintainer privately via their GitHub profile

Please include:

- Affected version or commit
- Component (`hub`, `sentinel`, `forge`, sinks, CI, etc.)
- Impact summary and reproduction steps sufficient to verify
- Whether you plan a public write-up (coordinate timing if so)

You should receive an acknowledgment when the report is seen. Fixes are prioritized by severity and exploitability.

## Operational notes

- Deploy Kunari only on systems you own or are authorized to monitor.
- Keep `ingest.secret`, `api.token`, and signing keys out of forged artifacts and public repos.
- SSE `?token=` is for browser `EventSource` clients only; tokens in query strings can appear in reverse-proxy access logs. Prefer `Authorization: Bearer` when the client can set headers.
- Put the hub behind TLS (reverse proxy). Use `--trusted-proxy` only for terminators you control.
