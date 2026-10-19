# TLS in front of the Kunari hub

Authorized use only. These recipes terminate TLS on a reverse proxy and forward to a hub listening on localhost. The hub itself still speaks plain HTTP on the loopback address.

Beacon-max (decoy-only) deploys need a **reachable HTTPS hostname** in `--collector`. Pointing forge at `http://127.0.0.1` only proves the lab loop; clients off that host will never hit your collector.

This does **not** add filesystem watching. Beacons fire only when something fetches the embedded HTTPS/DNS lure. Use `kunari package agent` (or a local sentinel) when you need on-host open/read/modify detection.

## Topology

```text
Internet / LAN clients
        |  HTTPS :443
   Caddy or nginx (TLS + optional HSTS)
        |  HTTP 127.0.0.1:8080
   kunari hub --listen 127.0.0.1:8080 --data ./data \
     --trusted-proxy 127.0.0.1/32 --client-ip-header X-Forwarded-For
```

Use `--trusted-proxy` only for the terminator you control. Without it, the hub ignores `X-Forwarded-For` and records the proxy as the client IP.

## Hub (behind the proxy)

```bash
mkdir -p data
kunari hub --listen 127.0.0.1:8080 --data ./data \
  --trusted-proxy 127.0.0.1/32 --client-ip-header X-Forwarded-For
```

Secrets land under `./data` (`ingest.secret`, `api.token`). Never embed them in forged decoys.

Operator UI: `https://beacon.example.com/ui/` (paste `api.token` in-browser).

## Caddy

Requires [Caddy](https://caddyserver.com/) with automatic HTTPS (public DNS name recommended).

1. Edit [`Caddyfile`](Caddyfile): replace `beacon.example.com` with your hostname.
2. Run Caddy from this directory (or point `caddy run --config` at the file).
3. Confirm: `curl -sS https://beacon.example.com/healthz`

## nginx

Requires certificates you already have (Let's Encrypt, internal CA, etc.).

1. Copy [`nginx.conf.snippet`](nginx.conf.snippet) into a site config.
2. Set `server_name`, `ssl_certificate`, and `ssl_certificate_key`.
3. Reload nginx. Confirm `/healthz` over HTTPS.

## Forge for beacon-max

Use the public HTTPS origin (not the loopback listen address):

```bash
kunari forge --type env --name app-secrets --detect beacon \
  --collector https://beacon.example.com \
  --memo "authorized lab" --authz-ref "LAB-BEACON-001" \
  --out ./dist --key ./data/signing.key --registry ./data/registry.db
```

Optional DNS beacons: set `--collector-dns` to a zone you control that resolves queries into the hub DNS collector (separate from this TLS proxy).

Place only the forged artifact on the endpoint. Keep hub data, signing keys, and `ingest.secret` on infrastructure you control.

## Smoke checks

```bash
curl -sS https://beacon.example.com/healthz
# Expect JSON with "ok": true

# After a client fetch of the decoy's beacon URL:
curl -sS -H "Authorization: Bearer $(tr -d '\n' < ./data/api.token)" \
  'https://beacon.example.com/api/v1/events?after_seq=0&limit=20'
```

## What this example is not

- Not mTLS for ingest (HMAC remains; put mTLS on the proxy if you need it).
- Not a substitute for `kunari package agent` / sentinel filesystem tiers.
- Not a claim that every open of a decoy file will beacon - only fetches that hit the embedded lure.
