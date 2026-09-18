#!/bin/bash
# =============================================================================
# EC2 bootstrap for the GoTestWAF echo server (origin) on Amazon Linux 2023
# =============================================================================
# Works two ways:
#
#   1. As EC2 "User data" at launch — cloud-init runs it as root, fully
#      automated. Paste the file contents into the User data field (or
#      `--user-data file://deploy/ec2-userdata.sh`).
#
#   2. By hand on a running instance — `bash deploy/ec2-userdata.sh` as the
#      default login user (e.g. ec2-user). Privileged steps are re-run through
#      sudo automatically, so you don't need to be root or prefix anything.
#
# It installs Docker + compose v2, clones this repo, and starts the echo
# server. `restart: unless-stopped` (in docker-compose.yml) keeps it up across
# reboots.
#
# The instance is the ORIGIN. Do NOT give it a 0.0.0.0/0 security group — this
# server reflects every payload and trusts everyone by design. Lock inbound to
# your WAF vendors' egress ranges + your admin IP. See deploy/DEPLOY.md.
#
# Override the clone source/target with REPO_URL / REPO_DIR env vars.
# =============================================================================
set -euxo pipefail

REPO_URL="${REPO_URL:-https://github.com/eguillotin/gotestwaf-echo-server.git}"
REPO_DIR="${REPO_DIR:-/opt/gotestwaf-echo-server}"

# Run privileged steps directly when already root (cloud-init), or via sudo when
# invoked by hand as a normal user. The default ec2-user has passwordless sudo
# on Amazon Linux, so no prompt appears.
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

# The unprivileged user that should own the checkout and be able to run docker
# on future logins. When run under sudo, SUDO_USER is the real caller; otherwise
# it's the current user (root under cloud-init).
LOGIN_USER="${SUDO_USER:-$(id -un)}"

# --- Install Docker + git + openssl ------------------------------------------
$SUDO dnf install -y docker git openssl
$SUDO systemctl enable --now docker

# Add the login user to the docker group (takes effect on next login; we still
# use $SUDO for docker below because the group isn't active in this shell yet).
if [ "$LOGIN_USER" != "root" ]; then
  $SUDO usermod -aG docker "$LOGIN_USER"
fi

# --- Docker CLI plugins: Compose v2 + Buildx ---------------------------------
# Amazon Linux 2023's `docker` package ships neither plugin. Compose v2
# delegates image building to Buildx, so `compose up --build` fails without it
# ("compose build requires buildx 0.17.0 or later"). Install both.
$SUDO install -d /usr/libexec/docker/cli-plugins

# Compose release assets are named with uname's arch (x86_64 / aarch64).
ARCH="$(uname -m)"
$SUDO curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${ARCH}" \
  -o /usr/libexec/docker/cli-plugins/docker-compose
$SUDO chmod +x /usr/libexec/docker/cli-plugins/docker-compose

# Buildx assets embed the version in the filename and use Go arch names
# (amd64 / arm64), so resolve the latest tag and map the arch. Override the
# pin with BUILDX_VERSION if you don't want "latest".
BUILDX_VERSION="${BUILDX_VERSION:-$(curl -fsSL -o /dev/null -w '%{url_effective}' \
  https://github.com/docker/buildx/releases/latest | sed 's#.*/tag/##')}"
case "$ARCH" in
  x86_64)  BUILDX_ARCH=amd64 ;;
  aarch64) BUILDX_ARCH=arm64 ;;
  *)       BUILDX_ARCH=amd64 ;;
esac
$SUDO curl -fsSL "https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}/buildx-${BUILDX_VERSION}.linux-${BUILDX_ARCH}" \
  -o /usr/libexec/docker/cli-plugins/docker-buildx
$SUDO chmod +x /usr/libexec/docker/cli-plugins/docker-buildx

# --- Prepare the checkout dir and hand it to the login user ------------------
# /opt is root-owned, so create it with sudo then chown to the login user so git
# clone/pull (and re-runs) work without sudo. Re-running by hand after a root
# cloud-init clone self-heals ownership here.
$SUDO mkdir -p "$REPO_DIR"
if [ "$LOGIN_USER" != "root" ]; then
  $SUDO chown -R "$LOGIN_USER":"$LOGIN_USER" "$REPO_DIR"
fi

# --- Clone (or refresh) and launch -------------------------------------------
if [ ! -d "$REPO_DIR/.git" ]; then
  git clone "$REPO_URL" "$REPO_DIR"
else
  git -C "$REPO_DIR" pull --ff-only
fi
cd "$REPO_DIR"

# --- TLS cert for HTTPS on 443 -----------------------------------------------
# docker-compose publishes HTTPS (443) and mounts ./certs; server.js starts
# HTTPS only when both cert files exist. Generate a self-signed pair if none is
# present. A real cert dropped into certs/ is left untouched. Override the
# subject CN with CERT_CN (e.g. your hostname).
CERT_CN="${CERT_CN:-echo-server}"
if [ ! -f certs/fullchain.pem ] || [ ! -f certs/privkey.pem ]; then
  mkdir -p certs
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout certs/privkey.pem -out certs/fullchain.pem \
    -days 365 -subj "/CN=${CERT_CN}"
  chmod 644 certs/*.pem
fi

# Ports must stay numeric (Node parsePort strips a stray leading colon, but keep
# them clean). 443 = HTTPS/REST/GraphQL (from container 8443), 50051 = gRPC.
$SUDO docker compose up -d --build

# --- Sanity check ------------------------------------------------------------
# (In cloud-init this lands in /var/log/cloud-init-output.log.) Self-signed
# cert, so -k. Give the container a moment to build/start first.
sleep 10
curl -fsSk https://localhost:443/health || echo "WARN: HTTPS health check did not pass yet"
