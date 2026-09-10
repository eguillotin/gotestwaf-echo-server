#!/bin/bash
# =============================================================================
# EC2 user-data: bootstrap the GoTestWAF echo server (origin) on Amazon Linux 2023
# =============================================================================
# Paste this into the EC2 "User data" field (or `--user-data file://`) when
# launching the instance. It installs Docker + compose v2, clones this repo,
# and starts the echo server. `restart: unless-stopped` (in docker-compose.yml)
# keeps it up across reboots.
#
# The instance is the ORIGIN. Do NOT give it a 0.0.0.0/0 security group — this
# server reflects every payload and trusts everyone by design. Lock inbound to
# your WAF vendors' egress ranges + your admin IP. See deploy/DEPLOY.md.
#
# Override the repo/branch with instance tags or by editing REPO_URL below.
# =============================================================================
set -euxo pipefail

REPO_URL="${REPO_URL:-https://github.com/eguillotin/gotestwaf-echo-server.git}"
REPO_DIR="/opt/gotestwaf-echo-server"

dnf install -y docker git
systemctl enable --now docker
usermod -aG docker ec2-user

# Docker Compose v2 as a CLI plugin
install -d /usr/libexec/docker/cli-plugins
ARCH="$(uname -m)"
curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${ARCH}" \
  -o /usr/libexec/docker/cli-plugins/docker-compose
chmod +x /usr/libexec/docker/cli-plugins/docker-compose

# Clone (or refresh) and launch
if [ ! -d "$REPO_DIR/.git" ]; then
  git clone "$REPO_URL" "$REPO_DIR"
else
  git -C "$REPO_DIR" pull --ff-only
fi
cd "$REPO_DIR"

# Ports must stay numeric (Node parsePort strips a stray leading colon, but keep
# them clean). 8080 = HTTP/REST/GraphQL, 50051 = gRPC.
docker compose up -d --build

# Sanity check into the boot log (journalctl -u cloud-final)
sleep 5
curl -fsS http://localhost:8080/health || echo "WARN: health check did not pass yet"
