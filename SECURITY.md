# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| Latest release (`v0.x`) | Yes |
| `main` | Yes (pre-release) |
| Older tags | Best effort only |

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems**, and do not include working exploit details against Kunari itself in public discussions.

### Preferred channel (after the repo is public)

On a **public** repository, enable and use GitHub Private Vulnerability Reporting:

1. Repo **Settings** → sidebar **Security and quality** → **Advanced Security**
2. Enable **Private vulnerability reporting**
3. Researchers use **Security** → **Advisories** → **Report a vulnerability**, or:  
   https://github.com/jimididit/kunari/security/advisories/new

That settings page is often missing or limited while the repository is still **private** on a free plan. Private Vulnerability Reporting is a free feature for public repos; it is not the same as paid Code Security / Advanced Security for private repos.

### Always available

Contact the repository maintainer privately via their [GitHub profile](https://github.com/jimididit).

Please include:

- Affected version or commit
- Component (`hub`, `sentinel`, `forge`, sinks, CI, etc.)
- Impact summary and reproduction steps sufficient to verify
- Whether you plan a public write-up (coordinate timing if so)

Fixes are prioritized by severity and exploitability.

## Operational notes

- Deploy Kunari only on systems you own or are authorized to monitor.
- Keep `ingest.secret`, `api.token`, and signing keys out of forged artifacts and public repos.
- SSE `?token=` is for browser `EventSource` clients only; tokens in query strings can appear in reverse-proxy access logs. Prefer `Authorization: Bearer` when the client can set headers.
- Put the hub behind TLS (reverse proxy). Use `--trusted-proxy` only for terminators you control.
