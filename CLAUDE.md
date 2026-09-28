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
- `/graphql` JSON parser uses `express.json({ type: () => true })` — parses the body
  as JSON regardless of Content-Type. GoTestWAF POSTs GraphQL payloads with **no**
  Content-Type header; the default parser skips them and Apollo returns HTTP 400.
  Keep the `type: () => true`.

**Do not lock any of this down** — it breaks the tool. These endpoints only *echo strings*; none of them actually execute commands, read user-specified files, or make outbound requests (verified: no `child_process`, `eval`, `fs` reads of request input, or SSRF). That is the correct and safe design for a WAF test target.

## What IS worth fixing

Genuine defects only — crashes, things that don't build, config that breaks startup, or code that would *actually* execute a payload (there is currently none). When in doubt, ask whether a change would reduce the server's ability to reflect requests; if so, don't make it.

## Active implementation

- **`server.js` (Node/Express + Apollo + @grpc/grpc-js + ws) is the only server.** The `Dockerfile` and `docker-compose.yml` build and run it.
- `proto/echo.proto` is loaded by the Node gRPC server at runtime — keep it.
- There is no Go server. A broken, non-compiling Go implementation (`main.go` + `go.mod`) was removed; don't re-add a second implementation unless explicitly asked.
- **Two compose files, both valid:** the repo-root `docker-compose.yml` publishes HTTPS on 443 (from container 8443) and gRPC on 50051 directly — use for direct/generic runs. `deploy/docker-compose.nginx.yml` + `deploy/nginx.conf` add an **nginx sidecar** that multiplexes HTTP + gRPC on a single 443 (echo-server internal-only) — use behind a proxy that only forwards on 443 (e.g. Imperva's AWS vPOP). See `deploy/DEPLOY.md` §6.
- `GRPC_TLS=true` makes the gRPC server serve TLS (reusing the HTTPS cert) instead of plaintext h2c; default is plaintext.

## GoTestWAF patches (in this repo)

- Only `gotestwaf-graphql-get-double-encode.patch` (+ its `-PR.md`) remains — that bug is **still open upstream**. `gotestwaf-patched.Dockerfile` builds **v0.5.9** and applies just this patch.
- The former `skip-checks` and `grpc-availability-bugfix` patches were **merged upstream in v0.5.9** and removed from this repo. `--skipGraphQLCheck`/`--skipGRPCCheck` are now built in. Don't re-add them; if upstream drifts, re-check with `git grep` before assuming a patch is needed.

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
