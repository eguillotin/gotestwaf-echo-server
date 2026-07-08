# PR: Fix GraphQL pre-check overwriting gRPC availability

> Base: `wallarm/gotestwaf@6381947` (master, 2025-07-31). Companion patch: `gotestwaf-grpc-availability-bugfix.patch`.

## Title

Fix `CheckGraphQLAvailability` clobbering `IsGrpcAvailable`

## Summary

`Scanner.CheckGraphQLAvailability` (in `internal/scanner/scanner.go`) contains a
stray assignment that writes the **GraphQL** availability result into the **gRPC**
availability field:

```go
func (s *Scanner) CheckGraphQLAvailability(ctx context.Context) {
	...
	available, err := s.graphqlClient.CheckAvailability(ctx)   // GraphQL result
	...
	s.db.IsGrpcAvailable = available    // <-- BUG: sets gRPC availability
	...
	s.db.IsGraphQLAvailable = available // correct assignment
}
```

This looks like a copy/paste from `CheckGRPCAvailability`. The line overwrites
whatever `CheckGRPCAvailability` previously set on `s.db.IsGrpcAvailable` with the
GraphQL probe's result.

## Impact

Whenever both checks run, gRPC availability ends up reflecting the **GraphQL** probe
outcome instead of the gRPC one. Depending on the relative results this can:

- mark gRPC available when it is not (GraphQL up, gRPC down) → gRPC tests attempted
  against an unavailable endpoint, or
- mark gRPC unavailable when it is (GraphQL down, gRPC up) → gRPC test suite silently
  skipped.

Either way the gRPC section of the report can be wrong for reasons unrelated to gRPC.

## Fix

Remove the stray line. `CheckGRPCAvailability` already sets `IsGrpcAvailable`
correctly from its own probe; `CheckGraphQLAvailability` should only set
`IsGraphQLAvailable`.

```diff
-	s.db.IsGrpcAvailable = available
 	connection := "not available"
```

## Testing

- `gofmt` clean; `go build ./...` passes.
- One-line, behavior-only change; no flags or signatures affected.

## Note

Independent of the `--skipGraphQLCheck` / `--skipGRPCCheck` feature PR
(`gotestwaf-skip-checks-PR.md`). The two patches apply cleanly in any order.
