# Docker example: hub only

Runs the Kunari hub in a container for lab collection. Authorized use only.

```bash
docker compose -f examples/docker/docker-compose.yml up --build
```

Hub listens on `127.0.0.1:8443`. Forge decoys with `--collector https://host.docker.internal:8443` (or your lab hostname) from the host.

For a public hostname with real TLS certificates, prefer [../tls-hub](../tls-hub/README.md) (Caddy/nginx in front of a localhost hub) over exposing the container port directly.
