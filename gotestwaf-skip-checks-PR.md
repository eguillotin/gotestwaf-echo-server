# PR: Add `--skipGraphQLCheck` and `--skipGRPCCheck` flags

> Base: `wallarm/gotestwaf@6381947` (master, 2025-07-31). Companion patch: `gotestwaf-skip-checks.patch`.

## Title

Add `--skipGraphQLCheck` / `--skipGRPCCheck` to bypass availability pre-checks when a WAF blocks the probe

## Summary

GoTestWAF runs an availability **pre-check** before scanning GraphQL and gRPC. When
the target sits behind a WAF, that pre-check can fail even though the endpoint is
perfectly reachable — so the entire GraphQL/gRPC suite is silently skipped and never
appears in the report.

Two real-world failure modes:

1. **GraphQL** — the pre-check sends `GET /graphql?query={__typename}`. WAFs commonly
   treat this introspection-like probe as an attack and block it (e.g. Imperva returns
   a challenge/redirect or a block page). The pre-check then reports
   `connection="not available"` and GraphQL tests don't run.
2. **gRPC** — the pre-check must reach the gRPC port; behind a WAF that only proxies
   80/443, or that resets the probe, availability comes back false.

Today the only workarounds are WAF-side exceptions (often too broad, and not always
possible) or dropping the protocol from the run. This PR adds two opt-in flags that
skip the pre-check and assume the protocol is available, so the scan proceeds to the
actual payloads — which the WAF still inspects, preserving a valid result.

## Changes

- **`cmd/gotestwaf/flags.go`** — declare `--skipGraphQLCheck` and `--skipGRPCCheck`
  (default `false`), consistent with the existing `--skipWAFBlockCheck` pattern;
  auto-bound via the existing `viper.BindPFlags`.
- **`internal/config/config.go`** — add `SkipGraphQLCheck` / `SkipGRPCCheck` fields.
- **`internal/scanner/scanner.go`** — early-return in `CheckGraphQLAvailability` /
  `CheckGRPCAvailability` when the flag is set: log `status=skipped`, mark the protocol
  available, and return.
- **`README.md`** — document both flags in the options list.

> Note: a separate, standalone bug fix (`CheckGraphQLAvailability` overwriting gRPC
> availability) is submitted independently — see `gotestwaf-grpc-availability-bugfix-PR.md`.
> This feature patch does **not** include it; the two apply cleanly in any order.

## Behavior

- Flags are **opt-in**; default behavior is unchanged.
- When set, the pre-check is skipped and `IsGraphQLAvailable` / `IsGrpcAvailable` are
  forced `true`, so payload tests run and the WAF's handling of them is measured
  normally.
- Log line changes from `status=started/done` to `status=skipped connection="assumed available"`.

## Example

```bash
gotestwaf --url=https://app-behind-waf.example.com \
  --graphqlURL=https://app-behind-waf.example.com/graphql \
  --skipGraphQLCheck \
  --blockStatusCodes=403 --blockConnReset --followCookies --renewSession \
  --nonBlockedAsPassed --ignoreUnresolved --reportFormat=pdf
```

## Testing

- `gofmt` clean; `go build ./...` passes.
- Manual: against an endpoint that blocks the pre-check probe, `--skipGraphQLCheck`
  lets the GraphQL suite run to completion where it was previously skipped.

## Notes / open questions

- Naming mirrors existing `--skipWAF*` flags; happy to rename (`--forceGraphQL`?) if
  maintainers prefer.
- Could optionally emit a one-line warning that results are only meaningful when the
  operator knows the endpoint is actually up. Let me know if you'd like that.
