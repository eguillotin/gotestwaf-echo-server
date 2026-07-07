# CLAUDE.md

Guidance for working in this repo. Read this before "fixing" anything.

## What this project is

A **multi-protocol echo server used as a test target for [Wallarm GoTestWAF](https://github.com/wallarm/gotestwaf)**. Its entire job is to **reflect incoming requests back to the client** (across HTTP/REST, GraphQL, gRPC, and WebSocket) so GoTestWAF can measure what the WAF *in front of it* blocks. The origin must always respond `200` and echo the payload — that's how GoTestWAF attributes any blocking to the WAF rather than the origin.

## ⚠️ The "vulnerabilities" are intentional — do NOT fix them

This server deliberately looks insecure. The following are **required behavior**, not bugs:

- Endpoints like `/exec`, `/eval`, `/cmd`, `/upload`, `/admin/*`, `/file/*` and GraphQL `exec`/`file`/`executeCommand` resolvers.
- Reflecting attacker payloads (SQLi, XSS, RCE strings, path traversal) verbatim in responses.
- Wide-open `CORS *`, GraphQL introspection enabled, gRPC reflection enabled, no auth.
- Apollo `csrfPrevention: false` — the endpoint must accept GET and any content-type
  so scanners (GoTestWAF's GraphQL availability pre-check uses GET) aren't rejected
  with HTTP 400. Do not re-enable it.

**Do not lock any of this down** — it breaks the tool. These endpoints only *echo strings*; none of them actually execute commands, read user-specified files, or make outbound requests (verified: no `child_process`, `eval`, `fs` reads of request input, or SSRF). That is the correct and safe design for a WAF test target.

## What IS worth fixing

Genuine defects only — crashes, things that don't build, config that breaks startup, or code that would *actually* execute a payload (there is currently none). When in doubt, ask whether a change would reduce the server's ability to reflect requests; if so, don't make it.

## Active implementation

- **`server.js` (Node/Express + Apollo + @grpc/grpc-js + ws) is the only server.** The `Dockerfile` and `docker-compose.yml` build and run it.
- `proto/echo.proto` is loaded by the Node gRPC server at runtime — keep it.
- There is no Go server. A broken, non-compiling Go implementation (`main.go` + `go.mod`) was removed; don't re-add a second implementation unless explicitly asked.

## Ports gotcha

The Node server expects **plain numeric ports** (`HTTP_PORT=8080`, `GRPC_PORT=50051`). Go-style `:8080` breaks Node's `listen()` (coerces to `NaN` → random port) and gRPC bind. `server.js` now strips a leading colon defensively (`parsePort`), but keep env values numeric. This was the one real bug that stopped `docker compose up` from being reachable.

## Deployment rule

Run only on an **isolated/test network**. This box trusts everyone by design — never expose it to the public internet.

## Run / test

```bash
docker compose up -d                 # starts the Node echo server
curl http://localhost:8080/health    # sanity check
# then point GoTestWAF at it (see README.md for full command)
```
