# Contributing

## Workflow

1. Branch from `main`: `feature/<short-name>` or `fix/<short-name>`.
2. Keep commits focused; include tests with behavior changes.
3. Open a pull request against `main`. Do not push directly to `main` once the repo is shared.
4. CI must be green on Linux, Windows, and macOS runners.

## Authorized use

Kunari is for defensive / DFIR deployment on systems you are authorized to monitor. Do not contribute:

- Exploit payloads, persistence, or hack-back behavior
- UNC/SMB/WebDAV beacons that can leak NTLM credentials
- Link-shortener / personal IP-logger features
- Code copied from GPL/AGPL prior art (study patterns; write original code)

## What is not in git

Local research, planning, and capability matrices live under paths listed in `.gitignore` (`docs/`, `PLAN.md`, etc.). Do not force-add them. Public documentation belongs in `README.md` and future curated `doc/` pages when we publish them intentionally.

## Development

```bash
go test ./...
go build -o bin/kunari ./cmd/kunari
```
