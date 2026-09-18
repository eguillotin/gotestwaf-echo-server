# Deploying the echo server on AWS EC2 (Docker) behind multiple WAFs

This is the **origin** for a multi-WAF GoTestWAF comparison (Imperva, Cloudflare,
Akamai, F5, Fortinet, Google, Microsoft, AWS). Stand up **one** origin EC2 and point
every WAF tenant at it — identical origin behind each WAF gives an apples-to-apples
comparison (one report per WAF, same target).

> ⚠️ This server reflects every payload verbatim, has open CORS, no auth, and
> introspection/reflection enabled. It only *echoes* strings, but never give it a
> `0.0.0.0/0` security group. Lock inbound to your WAF vendors' egress ranges and
> your own IPs.

## 1. Launch the instance

- Amazon Linux 2023, `t3.small` is plenty.
- Paste [`ec2-userdata.sh`](./ec2-userdata.sh) into **User data**. It installs Docker,
  Compose v2, and **Buildx** (AL2023's `docker` package ships none of these), clones
  this repo, generates a self-signed TLS cert if none exists, and runs
  `docker compose up -d --build`.
- Verify on the box (self-signed cert, so `-k`):
  `curl -k https://localhost/health` → `{"status":"healthy",...}`.

The container serves:

| Host port | Proto | Purpose |
|-----------|-------|---------|
| `443/tcp`   | HTTPS | REST + GraphQL + WebSocket echo (published from the container's `8443` — it runs as non-root and can't bind `443` directly) |
| `50051/tcp` | HTTP/2 (h2c) | gRPC echo |

Plain HTTP (`8080`) runs **inside** the container for the healthcheck only and is not
published. Uncomment the `8080:8080` line in `docker-compose.yml` if you want a
plain-HTTP baseline exposed too.

### TLS certificate

HTTPS starts only when `certs/fullchain.pem` + `certs/privkey.pem` exist (mounted
read-only into the container). The user-data script auto-generates a **self-signed**
pair — fine for a WAF origin (the WAF/scanner connects to the origin and ignores cert
validation; direct clients use `-k`). To use a real cert, drop your own
`fullchain.pem`/`privkey.pem` into `certs/` and restart — the script won't overwrite an
existing pair. Regenerate the self-signed one with:

```bash
mkdir -p certs && openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/privkey.pem -out certs/fullchain.pem \
  -days 365 -subj "/CN=aw.waaplabs.com" && chmod 644 certs/*.pem
```

### Running the script by hand / Buildx

`ec2-userdata.sh` also runs cleanly by hand (`bash deploy/ec2-userdata.sh`) — it
auto-`sudo`s the privileged steps. If you build manually **without** the script and hit
`compose build requires buildx 0.17.0 or later`, install Buildx into the system plugin
dir (visible to `sudo docker`):

```bash
case "$(uname -m)" in x86_64) A=amd64;; aarch64) A=arm64;; esac
sudo curl -fsSL "https://github.com/docker/buildx/releases/download/v0.37.1/buildx-v0.37.1.linux-${A}" \
  -o /usr/libexec/docker/cli-plugins/docker-buildx
sudo chmod +x /usr/libexec/docker/cli-plugins/docker-buildx
sudo docker buildx version   # confirm >= 0.17
```

## 2. Ports to open (security group)

| Port | Source | Why |
|------|--------|-----|
| `443/tcp`   | Union of WAF egress CIDRs **+** your tester IP (for the no-WAF baseline) | HTTPS/REST/GraphQL origin |
| `50051/tcp` | Same union | gRPC origin (plaintext h2c forwarded by the WAF/LB) |
| `22/tcp`    | Your admin IP **/32 only** | SSH |

**Never** open `443`/`50051` to `0.0.0.0/0`.

For **AWS WAF**, don't use egress CIDRs: put an **ALB in the same VPC** (443 listener,
gRPC + HTTPS target groups → `50051`/`443`), attach AWS WAF to the ALB, and have the
EC2 security group **reference the ALB's security group** instead of CIDRs.

Vendor egress ranges change — pull them at test time, don't hardcode:

| Vendor | Where to get egress/forwarding ranges |
|--------|----------------------------------------|
| Cloudflare | `https://www.cloudflare.com/ips/` |
| AWS | `ip-ranges.json` (or just use the ALB SG reference) |
| Google | GCLB ranges `35.191.0.0/16`, `130.211.0.0/22` |
| Microsoft Azure | Service tags: `AzureFrontDoor.Backend` / App Gateway subnet |
| Imperva | Published in the Imperva console |
| Akamai | SiteShield / edge server ranges |
| Fortinet FortiWeb Cloud | Published range list |
| F5 (Distributed Cloud) | Published range list; self-managed BIG-IP = its own IP |

## 3. gRPC through each WAF

gRPC is HTTP/2-over-TLS. A WAF only *tests* gRPC if it parses HTTP/2 gRPC at L7.
Serve gRPC to the public over **443/TLS** (terminated at the WAF/LB); the WAF forwards
gRPC to the origin's plaintext `:50051` inside the trusted segment. The container is
unchanged.

| WAF | gRPC path | Notes |
|-----|-----------|-------|
| AWS WAF | ALB (native gRPC/HTTP2 target) | Cleanest — same VPC |
| Google Cloud Armor | External Application LB (HTTP/2) | Good |
| Azure | **Application Gateway WAF v2** (has gRPC/HTTP2), not Front Door | Use App Gateway |
| F5 | BIG-IP / F5 Distributed Cloud (full proxy) | Full proxy |
| Fortinet FortiWeb | Recent versions inspect gRPC | Verify version |
| Imperva | 443/h2 | Limited — use `--skipGRPCCheck` |
| Cloudflare | gRPC on paid plans, 443/TLS | Managed-rule body coverage limited |
| Akamai | Limited on standard App & API Protector | Verify per contract |

For the "limited/verify" tier, the GoTestWAF gRPC **availability pre-check** will fail
even when payloads still flow — run with `--skipGRPCCheck` (this repo's patch) to skip
the pre-check and send payloads anyway. Where a WAF genuinely can't carry gRPC, mark
that protocol N/A for that vendor in the report rather than chasing it.

## 4. Run GoTestWAF against each WAF

Use the patched tool (see the repo README — it adds `--skipGRPCCheck` /
`--skipGraphQLCheck`). Point `--url` / `--graphqlURL` / gRPC at each **WAF hostname**,
not the origin:

```bash
./gotestwaf \
  --url=https://app-behind-<vendor>.example.com \
  --graphqlURL=https://app-behind-<vendor>.example.com/graphql --skipGraphQLCheck \
  --grpcPort=443 --skipGRPCCheck \
  --blockStatusCodes=403 --blockConnReset --followCookies --renewSession \
  --nonBlockedAsPassed --ignoreUnresolved --reportFormat=pdf --reportName=<vendor>
```

Run once per vendor (swap the hostname + `--reportName`) to produce one comparable
report each. Add a `baseline` run straight at the origin (no WAF) for the control row —
see `waf-targets.conf.example`.
