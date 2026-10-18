# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| Latest release (`v0.x`) | Yes |
| `main` | Yes (pre-release) |
| Older tags | Best effort only |

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems**, and do not include working exploit details against Kunari itself in public discussions.

### Preferred channel

Enable and use GitHub Private Vulnerability Reporting (free on public repos):

1. Repo **Settings** → sidebar **Security and quality** (or **Code security**) → **Advanced Security**
2. Enable **Private vulnerability reporting**
3. Researchers use **Security** → **Advisories** → **Report a vulnerability**, or:  
   https://github.com/jimididit/kunari/security/advisories/new

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
- SSE `?token=` is for legacy `EventSource` clients only; tokens in query strings can appear in reverse-proxy access logs. Prefer `Authorization: Bearer` when the client can set headers. The embedded hub `/ui/` console streams SSE with Bearer via `fetch` (no query token).
- Put the hub behind TLS (reverse proxy). Use `--trusted-proxy` only for terminators you control.

## Sentinel OPSEC (local attackers)

Kunari is a **defensive tripwire**, not a stealth agent. A local attacker who can list processes and read files can usually discover that a sentinel is running and, if `sentinel.json` is readable, learn the watched paths.

**Assume:**

- Process name / argv (`kunari sentinel run --config …`) is visible
- A world-readable config discloses targets, hub URL, and secret paths
- Killing the sentinel process is possible for a privileged attacker

**Do:**

- Keep `sentinel.json`, `hub_secret_file`, and `data_dir` private (`0600` / `0700` on Unix; restrictive NTFS ACLs on Windows). `kunari sentinel run` chmod`s config/secret files to `0600` when needed and refuses to start if `data_dir` is group/other-accessible.
- Run under a dedicated low-privilege service account (`kunari sentinel install-hints` sketches this).
- Prefer forge `--detect both` so HTTPS/DNS beacons still fire if the sentinel is stopped.
- Place decoys among believable paths; do not put the only copy of real secrets in a canary.

**Do not expect:** invisibility from a determined local admin. Further anti-enumeration research is tracked on the internal roadmap; it will stay within authorized defensive OPSEC (not rootkit / offensive hiding techniques).
