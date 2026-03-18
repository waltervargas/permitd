#!/bin/bash
set -euo pipefail

PERMITD_UID=$(id -u permitd)
export XDG_RUNTIME_DIR="/run/user/${PERMITD_UID}"

echo "=== Starting dozzle under permitd user ==="

# Create apps network if it doesn't exist
podman network exists apps 2>/dev/null || podman network create apps

# Remove old dozzle container if exists
podman rm -f dozzle 2>/dev/null || true

podman run -d \
  --name dozzle \
  --restart unless-stopped \
  -v "${XDG_RUNTIME_DIR}/podman/podman.sock:/var/run/docker.sock:ro" \
  --network apps \
  --label traefik.enable=true \
  --label "traefik.http.routers.dozzle.rule=Host(\`logs.walt3r.dev\`)" \
  --label traefik.http.routers.dozzle.entrypoints=web \
  --label traefik.http.services.dozzle.loadbalancer.server.port=8080 \
  docker.io/amir20/dozzle:latest

echo "=== Dozzle started ==="
podman ps --filter name=dozzle
