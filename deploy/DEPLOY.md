# Deploying the echo server on AWS EC2 (Docker) behind multiple WAFs

This is the **origin** for a multi-WAF GoTestWAF comparison (Imperva, Cloudflare,
Akamai, F5, Fortinet, Google, Microsoft, AWS). Stand up **one** origin EC2 and point
every WAF tenant at it — identical origin behind each WAF gives an apples-to-apples
comparison (one report per WAF, same target).

> ⚠️ This server reflects every payload verbatim, has open CORS, no auth, and
> introspection/reflection enabled. It only *echoes* strings, but never give it a
> `0.0.0.0/0` security group. Lock inbound to your WAF vendors' egress ranges and
> your own IPs.

> **Two deployment shapes:** the generic model below (§1–5) publishes HTTPS on 443 and
> gRPC on 50051 separately — use it when the WAF/LB can forward gRPC on its own port.
> When the proxy only forwards on 443 (e.g. Imperva's AWS vPOP), use the **nginx
> sidecar** that multiplexes HTTP + gRPC on a single 443 — see **§6** and
> [`docker-compose.nginx.yml`](./docker-compose.nginx.yml).

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
| Imperva (SaaS Cloud WAF) | 443/h2 | Custom-port listener (e.g. 50051) available |
| Imperva (AWS vPOP) | **gRPC not viable** | vPOP only forwards on 80/443 **and** hangs on unary gRPC request bodies — see §6 |
| Cloudflare | gRPC on paid plans, 443/TLS | Managed-rule body coverage limited |
| Akamai | Limited on standard App & API Protector | Verify per contract |

For the "limited/verify" tier, the GoTestWAF gRPC **availability pre-check** will fail
even when payloads still flow — run with `--skipGRPCCheck` (this repo's patch) to skip
the pre-check and send payloads anyway. Where a WAF genuinely can't carry gRPC, mark
that protocol N/A for that vendor in the report rather than chasing it.

## 4. Run GoTestWAF against each WAF

Use upstream GoTestWAF **v0.5.10+** (all needed fixes are merged — see the repo README;
no patches). Point `--url` / `--graphqlURL` / gRPC at each **WAF hostname**, not the
origin:

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

If GoTestWAF stops with **"WAF was not detected"**, its auto block-check didn't
recognize a block. Add `--skipWAFBlockCheck` to run all tests anyway, and tune block
detection to how the WAF actually signals a block. For **Imperva**, blocks come back as
an Incapsula page, so add a regex:

```bash
  --skipWAFBlockCheck \
  --blockStatusCodes=403,406,429 \
  --blockRegex='Incapsula|_Incapsula_Resource|incident'
```

"WAF not detected" with a plain `200`+echo on an attack probe means the WAF isn't
blocking (monitor/count mode, or rules disabled) — fix that in the WAF console before a
run is meaningful. Sanity-check with:
`curl -sk -o /dev/null -w '%{http_code}\n' "https://<host>/?q=<script>alert(1)</script>"`.

## 6. Real-world topology: CloudFront → Imperva AWS vPOP → origin

This is the concrete setup used for `aw.waaplabs.com` (Imperva behind CloudFront). It
differs from the generic "WAF in front of origin" model because of two hard limits of
the **Imperva AWS vPOP** integration discovered in testing:

1. **The vPOP only forwards to the origin on 80/443** — no custom-port (50051) listener,
   unlike the SaaS Cloud WAF. So the origin must serve **HTTP and gRPC on the same 443**.
2. **The vPOP hangs on unary gRPC request bodies.** Reflection (bodyless) passes, but a
   unary call with a protobuf body never completes (the body-inspecting proxy doesn't
   return gRPC trailers). So gRPC **cannot** be Imperva-inspected through this vPOP.

### Origin: nginx sidecar multiplexes HTTP + gRPC on 443

Because the vPOP forwards everything to origin:443, the origin serves both protocols on
443 via an **nginx reverse proxy** (Express and grpc-js can't share a port in-process).
Use the behind-WAF compose file instead of the repo-root one:

```bash
docker compose -f deploy/docker-compose.nginx.yml up -d --build
```

nginx terminates TLS on 443 and path-routes: gRPC service paths
(`/encoder.ServiceFooBar/*`, `/echo.EchoService/*`, `/grpc.reflection.*`) →
grpc-js:50051 (h2c); everything else → Express:8080. The echo-server is internal-only.
See [`nginx.conf`](./nginx.conf). Needs a cert in `../certs` (Let's Encrypt for the
origin hostname in prod). `50051` is no longer published to the host — it's internal.

### CloudFront: two origins, HTTP via Imperva, gRPC bypasses Imperva

Since Imperva can't carry unary gRPC, gRPC is routed **around** Imperva straight to the
origin, while HTTP/GraphQL stay Imperva-inspected:

```
                         ┌─ default *                  → Imperva vPOP:443 → EC2:443 [nginx]  (HTTP/GraphQL, WAF-inspected)
client ─443─▶ CloudFront ┤
                         └─ /encoder.ServiceFooBar/*    → origin (EC2):443 → EC2:443 [nginx]  (gRPC, bypasses Imperva)
```

CloudFront origins:
- **Imperva origin** (`*.origins.<region>.vpop.imperva.com`, HTTPS 443) — default behavior.
- **`ec2-direct`** (`origin.waaplabs.com`, HTTPS 443, real cert) — the `/encoder.ServiceFooBar/*`
  behavior, **gRPC toggle Enabled**, CachingDisabled, AllViewer.

Every behavior needs **CachingDisabled + AllViewer** (a cached/response-buffering
behavior eats gRPC trailers and stops payloads reaching the origin). Distribution must
have **HTTP/2 enabled** (gRPC is h2). Use the real ACM/wildcard cert for the viewer
domain; the `ec2-direct` origin needs a **publicly-trusted** cert (self-signed → 502).

### Origin cert (Let's Encrypt, no ALB/IAM)

The `ec2-direct` origin must present a trusted cert or CloudFront 502s. Issue one on the
EC2 with certbot HTTP-01 (needs port 80 reachable at issuance; no AWS IAM):

```bash
sudo dnf install -y python3 python3-pip augeas-libs openssl
sudo python3 -m venv /opt/certbot && sudo /opt/certbot/bin/pip install certbot
sudo ln -sf /opt/certbot/bin/certbot /usr/bin/certbot
sudo certbot certonly --standalone -d origin.waaplabs.com \
  --agree-tos -m you@example.com --non-interactive
sudo cp /etc/letsencrypt/live/origin.waaplabs.com/{fullchain,privkey}.pem certs/
sudo chmod 644 certs/*.pem && docker compose -f deploy/docker-compose.nginx.yml restart
```

### Security group for this topology

| Port | Source | Why |
|------|--------|-----|
| `443/tcp` | Imperva egress ranges | HTTP/GraphQL via the vPOP |
| `443/tcp` | prefix list `com.amazonaws.global.cloudfront.origin-facing` | gRPC direct from CloudFront (`ec2-direct`) |
| `22/tcp`  | Your admin IP /32 | SSH |

`50051` is **not** exposed publicly here — it's internal to the Docker network.

### GoTestWAF against this topology

```bash
./gotestwaf \
  --url=https://aw.waaplabs.com \
  --graphqlURL=https://aw.waaplabs.com/graphql --skipGraphQLCheck \
  --grpcPort=443 --skipGRPCCheck --skipWAFBlockCheck \
  --blockStatusCodes=403,406,429 --blockRegex='Incapsula|_Incapsula_Resource|incident' \
  --blockConnReset --followCookies --renewSession \
  --nonBlockedAsPassed --ignoreUnresolved --reportFormat=pdf,json --reportName=imperva-full
```

**Result attribution:** HTTP/REST/GraphQL = Imperva-inspected. gRPC = CloudFront-only
(bypasses Imperva). Record **gRPC as N/A for Imperva**, reason: *AWS vPOP hangs on unary
gRPC request bodies (reflection passes, method calls don't)*.

### Verifying each hop (bottom-up)

`/tmp/service.proto` = GoTestWAF's proto (`package encoder; service ServiceFooBar { rpc foo(Request) returns (Response); }`).

```bash
# origin direct (bypass CloudFront+Imperva) — proves nginx routes gRPC:
grpcurl -insecure -import-path /tmp -proto service.proto \
  -d '{"value":"x"}' origin.waaplabs.com:443 encoder.ServiceFooBar/foo   # -> Unimplemented
# full chain via CloudFront (gRPC bypasses Imperva):
grpcurl -import-path /tmp -proto service.proto \
  -d '{"value":"x"}' aw.waaplabs.com:443 encoder.ServiceFooBar/foo       # -> Unimplemented
# HTTP through Imperva:
curl -s https://aw.waaplabs.com/health
```
`Unimplemented` = routed correctly (the origin implements `echo.EchoService`, not
`encoder.ServiceFooBar`, so it rejects the method with proper gRPC trailers). A **hang**
or **"server closed the stream without sending trailers"** = a hop above nginx is
mangling gRPC (wrong origin, gRPC toggle off, or the Imperva vPOP on the gRPC path).
