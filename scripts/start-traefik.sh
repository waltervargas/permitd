#!/bin/bash
set -euo pipefail

PERMITD_UID=$(id -u permitd)
export XDG_RUNTIME_DIR="/run/user/${PERMITD_UID}"

echo "=== Starting traefik under permitd user ==="

# Create apps network if it doesn't exist
podman network exists apps 2>/dev/null || podman network create apps

# Remove old traefik container if exists
podman rm -f traefik 2>/dev/null || true

podman run -d \
  --name traefik \
  --restart unless-stopped \
  -p 8080:8080 \
  -v "${XDG_RUNTIME_DIR}/podman/podman.sock:/run/podman/podman.sock:ro" \
  -v /home/permitd/traefik/traefik.yml:/etc/traefik/traefik.yml:ro \
  -v /home/permitd/traefik/dynamic:/etc/traefik/dynamic:ro \
  --network apps \
  docker.io/library/traefik:v3

echo "=== Traefik started ==="
podman ps --filter name=traefik
