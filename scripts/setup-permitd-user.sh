#!/bin/bash
set -euo pipefail

PERMITD_HOME="/home/permitd"
PERMITD_SRC="/home/walter/workspace/permitd"
PERMITD_UID=$(id -u permitd)

echo "=== Setting up permitd user config ==="

# Copy routes and schema
cp "$PERMITD_SRC/examples/routes.podman.toml" "$PERMITD_HOME/config/"
cp "$PERMITD_SRC/schema.cedarschema" "$PERMITD_HOME/config/"

# Copy policies
cp "$PERMITD_SRC/run/policies/"*.cedar "$PERMITD_HOME/config/policies/"

# Copy traefik dynamic config
cp "$PERMITD_SRC/infra/traefik/dynamic/permitd.yml" "$PERMITD_HOME/traefik/dynamic/"

# Traefik static config
cat > "$PERMITD_HOME/traefik/traefik.yml" << 'EOF'
api:
  dashboard: false

entryPoints:
  web:
    address: ":8080"

providers:
  docker:
    endpoint: "unix:///run/podman/podman.sock"
    exposedByDefault: false
    network: apps
  file:
    directory: "/etc/traefik/dynamic"
    watch: true

log:
  level: INFO
EOF

# permitd config
cat > "$PERMITD_HOME/config/config.toml" << EOF
[server]
listen_addr = "0.0.0.0:8081"

[upstream]
socket_path = "/run/user/${PERMITD_UID}/podman/podman.sock"

[oidc]
issuer = "https://token.actions.githubusercontent.com"
audience = "permitd"
jwks_cache_ttl_secs = 3600

[cedar]
schema_path = "${PERMITD_HOME}/config/schema.cedarschema"
policy_dir = "${PERMITD_HOME}/config/policies/"

[routes]
mapping_file = "${PERMITD_HOME}/config/routes.podman.toml"

[logging]
format = "text"
level = "info"
log_authorized = true
log_denied = true
EOF

# systemd user service
cat > "$PERMITD_HOME/.config/systemd/user/permitd.service" << 'EOF'
[Unit]
Description=permitd - OIDC Authorization Gateway
After=network-online.target podman.socket
Wants=network-online.target
Requires=podman.socket

[Service]
Type=simple
ExecStart=/usr/local/bin/permitd serve --config /home/permitd/config/config.toml
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
EOF

# Fix ownership
chown -R permitd:permitd "$PERMITD_HOME/"

echo "=== Done ==="
echo "Files installed:"
find "$PERMITD_HOME" -type f | sort
