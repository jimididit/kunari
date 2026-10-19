# Kunari

*(pronounced kun-NAR-ee)*

[![CI](https://github.com/jimididit/kunari/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jimididit/kunari/actions/workflows/ci.yml)
[![Security](https://github.com/jimididit/kunari/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/jimididit/kunari/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/jimididit/kunari)](https://github.com/jimididit/kunari/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/jimididit/kunari)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Cross-platform **canary / tripwire toolkit** for DFIR and defensive monitoring.

Kunari helps you plant decoy files, watch them for unauthorized touch, collect signed evidence, and alert through a self-hosted hub - using DNS or HTTPS beacons only (no NTLM-leaking UNC/SMB paths).

> **Authorized use only.** Deploy Kunari only on systems you own or have written authorization to monitor. Do not use it for unauthorized access, harassment, stalking, or offensive operations. Generated manifests include an authorization-reference field for operational accountability.

## Features

- **Forge** decoy artifacts with signed manifests and install notes
- **Sentinel** on-host sensors with honest detection tiers (Linux / Windows / macOS)
- **Hub** HTTPS (+ optional DNS) collector with HMAC ingest from sentinels
- **Evidence** hash-chained, Ed25519-signed event logs (`kunari verify`)
- **Alerts** disk-backed queue - sink failures are surfaced, never silently disabled
- **Operator API + UI** authenticated event pull, live SSE, and a thin hub console at `/ui/`

## Install

Pick one:

| Method | When to use |
|---|---|
| **Release archive** | Recommended for operators - no Go toolchain required |
| **`go install`** | Fastest if you already have Go; installs into your `GOBIN`/`GOPATH/bin` |
| **Clone + build** | Development / hacking on the tree |
| **Docker** | Hub-only lab collector ([examples/docker](examples/docker/README.md)) |

**Release binaries** (recommended): download the archive for your OS/arch from [Releases](https://github.com/jimididit/kunari/releases), extract, and put `kunari` on your `PATH`. Verify with `checksums.txt` (Syft SBOMs + cosign signature on the checksum file are attached to the same release).

**With Go** (Go 1.26.9+; cross-platform):

```bash
go install github.com/jimididit/kunari/cmd/kunari@latest
kunari self-test
```

Pin a release if you prefer: `go install github.com/jimididit/kunari/cmd/kunari@v0.4.0`.

**From a clone** (local `bin/` keeps the binary out of the repo root; that directory is gitignored):

```bash
git clone https://github.com/jimididit/kunari.git
cd kunari
go build -o bin/kunari ./cmd/kunari
./bin/kunari self-test
```

Package managers (Homebrew, Scoop, winget) are not published yet. Until then, release archives or `go install` are the supported paths.

## Quick start

Examples below assume `kunari` is on your `PATH` (or substitute `./bin/kunari` after a local build).

```bash
# 1) Forge a decoy (beacon + sentinel)
mkdir -p dist data
kunari forge --type env --name app-secrets --detect both \
  --collector http://127.0.0.1:8080 \
  --memo "lab only" --authz-ref "LAB-001" \
  --out ./dist --key ./data/signing.key --registry ./data/registry.db

# 2) Run the hub (creates ingest.secret + api.token under ./data)
kunari hub --listen 127.0.0.1:8080 --data ./data
# Optional: open http://127.0.0.1:8080/ui/ and paste the contents of ./data/api.token

# 3) Arm a sentinel (share the hub ingest secret; never put it in the decoy)
kunari sentinel init-config \
  --path ./dist/app-secrets.env \
  --token "$(jq -r .token_id ./dist/app-secrets.manifest.json)" \
  --hub-url http://127.0.0.1:8080 \
  --hub-secret-file ./data/ingest.secret \
  --out ./sentinel.json
kunari sentinel run --config ./sentinel.json
```

Touch the decoy (`cat ./dist/app-secrets.env`). Watch hub health and events:

```bash
curl -s http://127.0.0.1:8080/healthz

curl -s -H "Authorization: Bearer $(tr -d '\n' < ./data/api.token)" \
  'http://127.0.0.1:8080/api/v1/events?after_seq=0&limit=50'
```

More detail: [examples/lab-hub](examples/lab-hub/README.md), [examples/docker](examples/docker/README.md), [examples/tls-hub](examples/tls-hub/README.md) (Caddy/nginx in front of the hub).

## Commands

| Command | Role |
|---|---|
| `kunari forge` | Generate tripwire artifacts + signed manifests |
| `kunari package agent` | Build a per-OS endpoint bundle (decoy + sentinel config + install script) |
| `kunari lint` | Scan artifacts for static fingerprint tells |
| `kunari verify` | Verify hash-chained, signed event logs |
| `kunari hub` | Beacon collector, ingest, operator API |
| `kunari sentinel` | On-host sensor (best available OS tier) |
| `kunari self-test` | Offline forge + lint + evidence-chain smoke check |

## Hub API (operator)

Secrets live under the hub `--data` directory (`ingest.secret`, `api.token`). Never embed them in forged artifacts.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /` → `/ui/` | none | Operator console (API token entered in-browser; sessionStorage only) |
| `GET /healthz` | none | Liveness + hit counters |
| `GET\|HEAD /b/{token}` | none | HTTPS beacon |
| `POST /api/v1/ingest` | HMAC (`X-Kunari-*`) | Sentinel event push |
| `GET /api/v1/status` | Bearer / `X-Kunari-API-Key` | Hits, last seq, queue depth, sink names |
| `GET /api/v1/events` | Bearer / `X-Kunari-API-Key` | Paginated pull (`after_seq`, `limit`) |
| `GET /api/v1/events/stream` | Bearer or `?token=` | Live SSE |
| `GET /api/v1/tokens` | Bearer / `X-Kunari-API-Key` | Registry inventory (no signatures) |
| `POST /api/v1/tokens/{id}/revoke` | Bearer / `X-Kunari-API-Key` | Revoke a forged token |

Behind a TLS terminator (required for realistic off-host HTTPS beacons):

```bash
kunari hub --listen 127.0.0.1:8080 --data ./data \
  --trusted-proxy 127.0.0.1/32 --client-ip-header X-Forwarded-For
```

Copy-paste Caddy and nginx configs: [examples/tls-hub](examples/tls-hub/README.md).

## How detection works

Kunari has two layers. You can use either or both on an authorized host.

| Deploy model | On the endpoint | What you get |
|---|---|---|
| **Beacon-max** | Decoy file(s) only | Alerts when something fetches the embedded HTTPS/DNS lure. No local FS watcher. |
| **Agent** | Decoy + `kunari package agent` / sentinel | Best-effort open/read/modify (tier varies by OS and privilege), plus beacons if forged with `--detect both`. |

1. **Beacon** - A forged decoy that contacts your hub over HTTPS or DNS when something uses it in a way that triggers the embedded beacon. The decoy file can sit alone on the endpoint; forge and hub stay on your infrastructure. This does not see every filesystem touch - only those network fetches.
2. **Sentinel** - An on-host `kunari sentinel` process that watches decoy paths with the best available OS mechanism (tier varies by platform and privilege). Forge with `--detect both` if you want beacon and sentinel together.

Placing a decoy without a sentinel is not the same as running a sentinel. For production beacons, point `--collector` at a reachable HTTPS hub hostname (not `127.0.0.1`) and terminate TLS in front of the hub ([examples/tls-hub](examples/tls-hub/README.md)). Keep `ingest.secret`, `api.token`, and signing keys out of forged artifacts.

To stage an authorized **agent** install (sentinel + decoy + install script for linux/windows/darwin), use `kunari package agent` after forging; put a matching release binary in the package `bin/` directory, then run the generated install script on the endpoint. Linux defaults to `/opt/kunari-agent` (not under `/home`). Windows registers a SYSTEM scheduled task - `kunari.exe` is not a Windows Service binary.

Operational hardening and reporting guidance: [SECURITY.md](SECURITY.md).

## Status

**v0.4.0** is the current release: `kunari package agent` (per-OS endpoint bundle), TLS reverse-proxy recipes for beacon-max collectors ([examples/tls-hub](examples/tls-hub/README.md)), plus the v0.3 hub UI / operator APIs and sentinel OPSEC basics.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Use feature branches and pull requests against `main`. Do not contribute exploit payloads, persistence mechanisms, or credential-stealing beacons.

## Security

See [SECURITY.md](SECURITY.md) for supported versions and how to report vulnerabilities privately.

## License

[Apache-2.0](LICENSE)
