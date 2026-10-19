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
- Put the hub behind TLS (reverse proxy). Use `--trusted-proxy` only for terminators you control. See [examples/tls-hub](examples/tls-hub/README.md) for Caddy and nginx recipes.
- For beacon-max (decoy-only) collectors, forge with a public `https://` hostname that hits that terminator - not the hub's loopback listen address.

## Beacon vs sentinel

- **Beacon-max / beacon-only:** decoy files on the endpoint; alerts depend on a network fetch to your hub. Not a substitute for filesystem watching.
- **Agent / sentinel:** local `kunari sentinel` (or `kunari package agent`) required for open/read/modify (per OS tier). Prefer `--detect both` so beacons remain if the sentinel is stopped.
- Do not describe beacon-only deployments as providing sentinel-equivalent coverage.

## Sentinel and local attackers

Kunari is a defensive tripwire, not a stealth agent. Optimize for **resilience and private config**, not invisibility.

| Local adversary | What to expect |
|---|---|
| Unprivileged user | Must not read `sentinel.json`, `ingest.secret`, or a world-accessible `data_dir`. Starts harden/fail-closed on those modes (Unix permission bits; Windows NTFS ACL for owner + current process user + SYSTEM + Administrators, rejecting World/Authenticated Users/Builtin Users Allow ACEs). |
| Local admin / root | Can list processes, services/tasks, and override ACLs. They can find and stop the agent. Plan for that. |

Practical guidance:

- Process name and argv are visible in process listings. Prefer `KUNARI_SENTINEL_CONFIG` (agent pack units/tasks do) so the config path is not on argv.
- Persistence names (`kunari-sentinel.service`, scheduled task `KunariSentinel`, LaunchDaemon label) are enumerable.
- A world-readable config discloses targets, hub URL, and secret paths - keep `sentinel.json`, `hub_secret_file`, and `data_dir` private (`0600` / `0700` on Unix; owner/current-user/SYSTEM/Administrators NTFS ACL on Windows). On start, Kunari hardens those paths and refuses to run if they remain broadly readable (Unix group/other bits; Windows Allow ACEs for World, Authenticated Users, or Builtin Users). If Windows lacks WRITE_DAC, an already-private ACL is accepted; a still-broad ACL fails closed. The current process user is always granted so a dedicated service account is not locked out when it is not the file owner.
- Prefer a dedicated low-privilege service account (`kunari sentinel install-hints` / agent pack under `/opt`).
- Prefer forge `--detect both` (dual-layer): HTTPS/DNS beacons can still fire if the sentinel process is killed. Avoid agent-only when the threat includes a hostile local admin.
- Beacon-max (decoy only, no agent) has the smallest process footprint but does not watch the filesystem - see [examples/tls-hub](examples/tls-hub/README.md).
- Do not rename the binary to impersonate OS components (`svchost`, `systemd`, …). That is out of scope and harms incident response clarity.
- Do not expect invisibility from a determined local admin.
