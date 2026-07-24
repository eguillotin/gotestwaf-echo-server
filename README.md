# GoTestWAF Multi-Protocol Echo Server

A Docker-based echo server supporting all protocols required for comprehensive WAF testing with [Wallarm GoTestWAF](https://github.com/wallarm/gotestwaf).

## Supported Protocols

| Protocol | Port | Endpoint |
|----------|------|----------|
| HTTP | 8080 | `/*` (catch-all) |
| HTTPS | 8443 | `/*` (catch-all) |
| REST API | 8080/8443 | `/api/*`, `/rest/*` |
| GraphQL | 8080/8443 | `/graphql` |
| WebSocket | 8080/8443 | `/ws` |
| gRPC | 50051 | `EchoService` |

## Quick Start

### Build and Run (HTTP only)

```bash
# Build the image
docker build -t gotestwaf-echo-server .

# Run the echo server
docker run -d -p 8080:8080 -p 50051:50051 --name echo-server gotestwaf-echo-server

# Verify it's running
curl http://localhost:8080/health
```

### Run with HTTPS (SSL/TLS)

```bash
# Run with SSL certificates
docker run -d --name echo-server \
  -v $(pwd)/fullchain.pem:/app/fullchain.pem \
  -v $(pwd)/privkey.pem:/app/privkey.pem \
  -p 80:8080 \
  -p 443:8443 \
  -p 50051:50051 \
  gotestwaf-echo-server

# Test HTTP
curl http://localhost/health

# Test HTTPS (use -k to skip certificate verification for self-signed certs)
curl https://localhost/health -k
```

### Using Docker Compose

```bash
# Build and run
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f
```

## Testing with GoTestWAF

### Basic WAF Test (HTTP)

```bash
docker run --rm -it \
  --network host \
  wallarm/gotestwaf \
  --url http://localhost:8080
```

### Full Protocol Test

```bash
docker run --rm -it \
  --network host \
  -v $(pwd)/reports:/reports \
  wallarm/gotestwaf \
  --url http://localhost:8080 \
  --grpcPort 50051 \
  --graphqlURL http://localhost:8080/graphql \
  --openapiFile http://localhost:8080/openapi.json \
  --reportFormat html,json \
  --reportPath /reports
```

### Testing Against a WAF

Place your WAF in front of the echo server and test against the WAF's URL:

```bash
# Example: Testing Cloudflare WAF
docker run --rm -it \
  -v $(pwd)/reports:/reports \
  wallarm/gotestwaf \
  --url https://your-domain-behind-cloudflare.com \
  --grpcPort 443 \
  --graphqlURL https://your-domain-behind-cloudflare.com/graphql \
  --reportFormat html,json,pdf \
  --reportPath /reports
```

## Testing Behind a WAF (Pre-check Gotchas)

When the echo server sits behind a real WAF (e.g. Imperva Cloud WAF), GoTestWAF's
GraphQL and gRPC **pre-checks** can fail before any test runs — even though the
endpoints work. These are WAF/topology issues, not echo-server bugs:

| Symptom | Cause | Fix |
|---------|-------|-----|
| `gRPC pre-check connection="not available"` | Cloud WAF only proxies 80/443, not the gRPC port (e.g. 50051) | Test gRPC **direct to the origin** (`--url=http://<origin>:<port>`), or front gRPC with a gRPC-capable proxy |
| `GraphQL pre-check ... couldn't send request` | WAF issues a session/redirect challenge (e.g. Imperva `307` + `incap_ses` cookies) the pre-check client doesn't complete | `--followCookies --renewSession`, or exempt the test source IP from the session challenge |
| `GraphQL pre-check connection="not available"` (instant) | WAF blocks the pre-check probe `GET /graphql?query={__typename}` (introspection-like) | Narrow WAF exception (below), or the patched flags (below) |

### The GraphQL pre-check request (for a narrow WAF exception)

GoTestWAF probes availability with exactly:

```
GET /graphql?query={__typename}
```

Success = HTTP `200` with a JSON body containing `data.__typename`. To let *only*
this probe through Imperva without whitelisting the whole endpoint, scope an
exception to: **source IP + URL `/graphql` + query string `query={__typename}`**.
The actual attack payloads are `POST` with JSON bodies, so they still get fully
inspected.

### Option: skip the pre-checks in GoTestWAF

This repo ships three GoTestWAF patches, all applied together:

- `gotestwaf-skip-checks.patch` — adds `--skipGraphQLCheck` and `--skipGRPCCheck`,
  which skip the pre-check probe entirely and proceed straight to sending payloads
  (which the WAF still inspects) — no WAF exception needed.
- `gotestwaf-grpc-availability-bugfix.patch` — fixes the GraphQL pre-check
  clobbering the gRPC-availability flag.
- `gotestwaf-graphql-get-double-encode.patch` — fixes the GraphQL GET placeholder
  double-URL-encoding already-encoded payloads.

Their absolute paths in this repo are `<repo>/gotestwaf-*.patch` (substitute your
own checkout path below).

#### Build the patched tool — pick one

**A. Apply to an existing gotestwaf clone**
```bash
cd <your-gotestwaf-clone>
# --3way survives minor upstream drift; resolve any <<<< markers if they appear.
# Order doesn't matter — they touch different lines and apply cleanly either way.
git apply --3way /path/to/gotestwaf-grpc-availability-bugfix.patch
git apply --3way /path/to/gotestwaf-skip-checks.patch
git apply --3way /path/to/gotestwaf-graphql-get-double-encode.patch
go build -o gotestwaf ./cmd/gotestwaf
./gotestwaf --help | grep -i skip        # confirm --skipGraphQLCheck / --skipGRPCCheck
```

**B. Fresh clone**
```bash
git clone https://github.com/wallarm/gotestwaf.git && cd gotestwaf
git apply --3way /path/to/gotestwaf-grpc-availability-bugfix.patch
git apply --3way /path/to/gotestwaf-skip-checks.patch
git apply --3way /path/to/gotestwaf-graphql-get-double-encode.patch
go build -o gotestwaf ./cmd/gotestwaf
```

**C. Docker** — `gotestwaf-patched.Dockerfile` clones + patches + builds for you:
```bash
docker build -f gotestwaf-patched.Dockerfile -t gotestwaf-patched .
docker run --rm gotestwaf-patched --help | grep -i skip   # verify
```

#### Run it (through the WAF, GraphQL pre-check skipped)

```bash
# local binary (options A/B)
./gotestwaf --url=https://your-domain-behind-waf.com \
  --graphqlURL=https://your-domain-behind-waf.com/graphql --skipGraphQLCheck \
  --blockStatusCodes=403 --blockConnReset --followCookies --renewSession \
  --nonBlockedAsPassed --ignoreUnresolved --reportFormat=pdf

# Docker equivalent (option C)
docker run --rm -v "$(pwd)/reports:/app/reports" gotestwaf-patched \
  --url=https://your-domain-behind-waf.com \
  --graphqlURL=https://your-domain-behind-waf.com/graphql --skipGraphQLCheck \
  --nonBlockedAsPassed --ignoreUnresolved --reportFormat=pdf --reportPath=/app/reports
```

The log should read `GraphQL pre-check status=skipped connection="assumed available"`.
gRPC through a Cloud WAF still won't work (port not proxied) — test gRPC direct to the
origin. The full PR write-up for upstreaming these flags is in `gotestwaf-skip-checks-PR.md`.

> Note: the echo server sets Apollo `csrfPrevention: false` so scanners probing
> `/graphql` via `GET` or non-JSON content types aren't rejected with HTTP 400.

## Endpoints Reference

### HTTP Echo (Classic WAF Testing)

```bash
# Basic echo
curl http://localhost:8080/echo

# With attack payload (will be echoed back)
curl "http://localhost:8080/search?q=<script>alert(1)</script>"

# POST with body
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"user": "admin", "pass": "' OR 1=1--"}'
```

### REST API

```bash
# List users
curl http://localhost:8080/api/v1/users

# Get user with injection attempt
curl "http://localhost:8080/api/v1/users/1%20OR%201=1"

# Create user
curl -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"name": "<img src=x onerror=alert(1)>", "email": "test@test.com"}'

# Search with SQLi
curl "http://localhost:8080/api/v1/search?q=test'%20UNION%20SELECT%20*%20FROM%20users--"
```

### GraphQL

```bash
# Query
curl -X POST http://localhost:8080/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ echo(message: \"<script>alert(1)</script>\") { message timestamp } }"}'

# Mutation
curl -X POST http://localhost:8080/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { createEcho(message: \"test' OR '1'='1\") { message } }"}'

# Introspection (often blocked by WAFs)
curl -X POST http://localhost:8080/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

### gRPC

```bash
# Using grpcurl
grpcurl -plaintext -d '{"message": "<script>alert(1)</script>"}' \
  localhost:50051 echo.EchoService/Echo

# List services
grpcurl -plaintext localhost:50051 list

# Describe service
grpcurl -plaintext localhost:50051 describe echo.EchoService
```

## GoTestWAF Options Reference

| Option | Description |
|--------|-------------|
| `--url` | Target URL (required) |
| `--grpcPort` | gRPC port (default: none) |
| `--graphqlURL` | GraphQL endpoint URL |
| `--openapiFile` | OpenAPI/Swagger spec URL or file |
| `--reportFormat` | Output formats: html, json, pdf, none |
| `--reportPath` | Directory for reports |
| `--workers` | Concurrent workers (default: 5) |
| `--sendDelay` | Delay between requests in ms |
| `--proxy` | HTTP proxy for requests |
| `--skipWAFBlockCheck` | Don't verify WAF blocks |
| `--testCase` | Specific test case to run |
| `--testSet` | Specific test set to run |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Echo Server Container                    │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  HTTP/HTTPS │  │   GraphQL   │  │       gRPC          │ │
│  │   Handler   │  │   Handler   │  │      Server         │ │
│  │  (Express)  │  │  (Apollo)   │  │                     │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                     │            │
│         └────────────────┴─────────────────────┘            │
│                          │                                  │
│                    Echo Response                            │
│              (Returns all input data)                       │
│                                                             │
│  Port 8080: HTTP/REST/GraphQL/WebSocket                     │
│  Port 8443: HTTPS/REST/GraphQL/WebSocket (SSL)              │
│  Port 50051: gRPC                                           │
└─────────────────────────────────────────────────────────────┘
```

## Testing Multiple WAFs

Create a simple script to test multiple WAF configurations:

```bash
#!/bin/bash

WAFS=(
  "https://app-behind-cloudflare.example.com"
  "https://app-behind-akamai.example.com"
  "https://app-behind-imperva.example.com"
  "https://app-behind-f5.example.com"
  "https://app-behind-aws-waf.example.com"
)

for WAF_URL in "${WAFS[@]}"; do
  WAF_NAME=$(echo $WAF_URL | sed 's/.*behind-\(.*\)\.example.*/\1/')
  echo "Testing $WAF_NAME..."
  
  docker run --rm \
    -v $(pwd)/reports:/reports \
    wallarm/gotestwaf \
    --url "$WAF_URL" \
    --graphqlURL "$WAF_URL/graphql" \
    --reportFormat html,json \
    --reportPath "/reports/$WAF_NAME"
done
```

## Response Format

All endpoints echo back request details in JSON:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "method": "POST",
  "path": "/api/v1/users",
  "protocol": "HTTP/1.1",
  "headers": {
    "Content-Type": ["application/json"],
    "User-Agent": ["curl/7.68.0"]
  },
  "query_params": {
    "filter": ["active"]
  },
  "body": "{\"name\": \"test\"}",
  "remote_addr": "172.17.0.1:54321",
  "host": "localhost:8080"
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_PORT` | `8080` | HTTP server port |
| `HTTPS_PORT` | `8443` | HTTPS server port |
| `GRPC_PORT` | `50051` | gRPC server port |
| `SSL_CERT_PATH` | `/app/fullchain.pem` | Path to SSL certificate |
| `SSL_KEY_PATH` | `/app/privkey.pem` | Path to SSL private key |

### Adding Custom Endpoints

Modify `server.js` to add custom endpoints for specific testing scenarios:

```javascript
app.all('/custom/endpoint', echoHandler);
```

## License

MIT License - Use freely for WAF testing and security research.