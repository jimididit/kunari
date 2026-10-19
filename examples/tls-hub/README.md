# TLS in front of the Kunari hub

Authorized use only. These recipes terminate TLS on a reverse proxy and forward to a hub listening on localhost. The hub itself still speaks plain HTTP on the loopback address.

Beacon-max (decoy-only) deploys need a **reachable HTTPS hostname** in `--collector`. Pointing forge at `http://127.0.0.1` only proves the lab loop; clients off that host will never hit your collector.

This does **not** add filesystem watching. Beacons fire only when something fetches the embedded HTTPS/DNS lure. Use `kunari package agent` (or a local sentinel) when you need on-host open/read/modify detection.

## Topology

```text
Internet / LAN clients
        |  HTTPS :443
   Caddy or nginx (TLS)
        |  only /b/*, /healthz, POST /api/v1/ingest
        v
   kunari hub --listen 127.0.0.1:8080 --data ./data \
     --trusted-proxy 127.0.0.1/32 --client-ip-header X-Forwarded-For

Operator UI / pull API
        |  SSH tunnel or VPN to 127.0.0.1:8080 (not on the public vhost)
```

Use `--trusted-proxy` only for the terminator you control. Without it, the hub ignores `X-Forwarded-For` and records the proxy as the client IP.

## Public surface vs operator surface

The example configs **do not** publish `/ui/` or the Bearer-protected operator APIs (`/api/v1/events`, `/status`, `/tokens`, …) on the public hostname. Those stay on loopback.

| Path | Public HTTPS vhost | Notes |
|---|---|---|
| `/b/{token}` | yes | HTTPS beacons |
| `/healthz` | yes | Liveness |
| `POST /api/v1/ingest` | yes | Sentinel HMAC push (still requires ingest secret) |
| `/ui/`, other `/api/v1/*` | no (default) | Use an SSH tunnel or uncomment the optional `@ops` allowlist in the Caddyfile |

Operator via tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 user@hub-host
# then open http://127.0.0.1:8080/ui/ and paste ./data/api.token
```

## Hub (behind the proxy)

```bash
mkdir -p data
kunari hub --listen 127.0.0.1:8080 --data ./data \
  --trusted-proxy 127.0.0.1/32 --client-ip-header X-Forwarded-For
```

Secrets land under `./data` (`ingest.secret`, `api.token`). Never embed them in forged decoys.

## Client IP (`X-Forwarded-For`)

The hub, when the peer is a trusted proxy, records the **leftmost** `X-Forwarded-For` IP. The proxy must **overwrite** that header with the TCP client address (`$remote_addr` / Caddy `{remote_host}`). Do not use nginx `$proxy_add_x_forwarded_for` on the edge: a client-supplied header would become leftmost and spoof the logged source.

## Caddy

Requires [Caddy](https://caddyserver.com/) with automatic HTTPS (public DNS name recommended).

1. Edit [`Caddyfile`](Caddyfile) in this directory: replace `beacon.example.com` with your hostname.
2. Run Caddy from this directory (or `caddy run --config Caddyfile`).
3. Confirm: `curl -sS https://beacon.example.com/healthz`
4. Confirm UI is not public: `curl -sS -o /dev/null -w '%{http_code}\n' https://beacon.example.com/ui/` (expect `404`).

## nginx

Requires certificates you already have (Let's Encrypt, internal CA, etc.).

1. Copy the snippet from this same directory: [`nginx.conf.snippet`](./nginx.conf.snippet) (path: `examples/tls-hub/nginx.conf.snippet`).
2. Set `server_name`, `ssl_certificate`, and `ssl_certificate_key`.
3. Reload nginx. Confirm `/healthz` over HTTPS and that `/ui/` returns 404 on the public vhost.

## Forge for beacon-max

Use the public HTTPS origin (not the loopback listen address). Place only the forged artifact on the endpoint. Keep hub data, signing keys, and `ingest.secret` on infrastructure you control.

| Type | HTTPS `--collector` | DNS `--collector-dns` | Lure shape |
|---|---|---|---|
| `env` | optional if DNS set | optional if HTTPS set | `HEALTHCHECK_URL` / `METRICS_HOST` |
| `svg` / `html` | required | not embedded | zero-size image / 1x1 img |
| `docx` / `xlsx` | required | not embedded | OOXML external image relationship |
| `pdf` | optional if DNS set | optional if HTTPS set | link annotation; DNS-only uses `https://<name>/` |
| `folder` | optional if DNS set | optional if HTTPS set | zip of decoy dir + `secrets.env`; no UNC `desktop.ini` (use sentinel) |
| `stub-exe` | required | not used | zip of harmless per-OS stubs that GET the beacon once (needs Go on the forge host) |

Env (secrets-looking lure):

```bash
kunari forge --type env --name app-secrets --detect beacon \
  --collector https://beacon.example.com \
  --memo "authorized lab" --authz-ref "LAB-BEACON-001" \
  --out ./dist --key ./data/signing.key --registry ./data/registry.db
```

Office document (external image fetch when the client resolves it):

```bash
kunari forge --type docx --name q3-budget --detect beacon \
  --collector https://beacon.example.com \
  --memo "authorized lab" --authz-ref "LAB-BEACON-002" \
  --out ./dist --key ./data/signing.key --registry ./data/registry.db
```

PDF link annotation:

```bash
kunari forge --type pdf --name vendor-invoice --detect beacon \
  --collector https://beacon.example.com \
  --memo "authorized lab" --authz-ref "LAB-BEACON-003" \
  --out ./dist --key ./data/signing.key --registry ./data/registry.db
```

Folder decoy (extract + sentinel; optional inner beacon file):

```bash
kunari forge --type folder --name hr-archive --detect both \
  --collector https://beacon.example.com \
  --memo "authorized lab" --authz-ref "LAB-BEACON-004" \
  --out ./dist --key ./data/signing.key --registry ./data/registry.db
```

Harmless stub binaries (forge host needs Go; zip contains per-OS stubs):

```bash
kunari forge --type stub-exe --name healthcheck --detect beacon \
  --platform windows,linux --collector https://beacon.example.com \
  --memo "authorized lab" --authz-ref "LAB-BEACON-005" \
  --out ./dist --key ./data/signing.key --registry ./data/registry.db
```

Optional DNS channel: set `--collector-dns` to a zone you control and wire the hub with `--dns-listen` / `--dns-zone`. See [../dns-hub](../dns-hub/README.md). That path is separate from this TLS proxy.

## Smoke checks

```bash
curl -sS https://beacon.example.com/healthz
# Expect JSON with "ok": true

curl -sS -o /dev/null -w '%{http_code}\n' https://beacon.example.com/ui/
# Expect 404 with the default recipe

# Operator events (via SSH tunnel to loopback, not the public vhost):
curl -sS -H "Authorization: Bearer $(tr -d '\n' < ./data/api.token)" \
  'http://127.0.0.1:8080/api/v1/events?after_seq=0&limit=20'
```

## What this example is not

- Not mTLS for ingest (HMAC remains; put mTLS on the proxy if you need it).
- Not a substitute for `kunari package agent` / sentinel filesystem tiers.
- Not a claim that every open of a decoy file will beacon - only fetches that hit the embedded lure.
- Not a recommendation to put the operator console on the public Internet.
