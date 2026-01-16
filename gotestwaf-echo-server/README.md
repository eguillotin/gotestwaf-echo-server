# GoTestWAF Multi-Protocol Echo Server

A Docker-based echo server supporting all protocols required for comprehensive WAF testing with [Wallarm GoTestWAF](https://github.com/wallarm/gotestwaf).

## Supported Protocols

| Protocol | Port | Endpoint |
|----------|------|----------|
| HTTP/HTTPS | 8080 | `/*` (catch-all) |
| REST API | 8080 | `/api/v1/*`, `/api/v2/*` |
| GraphQL | 8080 | `/graphql` |
| gRPC | 50051 | `EchoService` |

## Quick Start

### Build and Run

```bash
# Build the image
docker-compose build

# Run the echo server
docker-compose up -d

# Verify it's running
curl http://localhost:8080/health
```

### Standalone Docker

```bash
# Build
docker build -t gotestwaf-echo-server .

# Run
docker run -d -p 8080:8080 -p 50051:50051 --name echo-server gotestwaf-echo-server
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
│                    Echo Server Container                     │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   HTTP      │  │   GraphQL   │  │       gRPC          │ │
│  │   Handler   │  │   Handler   │  │      Server         │ │
│  │  (Mux)      │  │             │  │                     │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                     │            │
│         └────────────────┴─────────────────────┘            │
│                          │                                  │
│                    Echo Response                            │
│              (Returns all input data)                       │
│                                                             │
│  Port 8080: HTTP/REST/GraphQL                               │
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

## Customization

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_PORT` | `:8080` | HTTP server port |
| `GRPC_PORT` | `:50051` | gRPC server port |

### Adding Custom Endpoints

Modify `main.go` to add custom endpoints for specific testing scenarios:

```go
router.HandleFunc("/custom/endpoint", func(w http.ResponseWriter, r *http.Request) {
    // Custom logic
    echoHandler(w, r)
}).Methods("GET", "POST")
```

## License

MIT License - Use freely for WAF testing and security research.
