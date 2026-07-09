# PR: Fix GraphQL GET placeholder double-URL-encoding the payload

> Base: `wallarm/gotestwaf@6381947` (master). Companion patch: `gotestwaf-graphql-get-double-encode.patch`.

## Title

Fix double URL-encoding in the GraphQL GET placeholder

## Summary

When a test case targets GraphQL over GET (e.g. `testcases/owasp-api/graphql.yml`,
which uses `encoder: URL`), the payload is **URL-encoded twice**, so the request that
reaches the target is not what the test case intends.

The payload flows through two stages (`internal/payload/payload.go`):

1. **Encoder** — `encoder/url.go` runs `url.PathEscape(payload)` → 1st URL-encode.
2. **Placeholder** — `placeholder/graphql.go` (GET branch):
   ```go
   queryParams.Set("query", payload)      // payload is already encoded
   reqURL.RawQuery = queryParams.Encode() // url.Values.Encode → 2nd URL-encode
   ```

Example: `<script>alert(1)</script>` → after the URL encoder `%3Cscript%3E…` →
after `queryParams.Encode()` `query=%253Cscript%253E…` (note `%25` = re-encoded `%`).

## Why this is a bug, not intentional

- **Inconsistent with the sibling URL placeholders.** `URLPath` and `URLParam`
  concatenate the already-encoded payload directly (`requestURL += payload`,
  `urlpath.go:58` / `urlparam.go:72`) — no re-encode. Their test cases use the same
  `encoder: URL` and get single-encoding. Only the GraphQL GET placeholder re-encodes.
- **The test case lists a single encoder.** `graphql.yml` specifies just `encoder: URL`.
  GoTestWAF expresses intentional multi-encoding by **chaining encoders explicitly**
  (e.g. `nosql-injection.yml` → `Base64Flat, URL`). A hidden second encode inside the
  placeholder is not that.
- **The sibling `graphql-post.yml` uses `encoder: Plain`** because its POST placeholder
  writes the body verbatim — the author matched encoder to placeholder behavior. The GET
  case used `encoder: URL` expecting verbatim placement (URLPath-style), but the
  placeholder re-encodes.

## Fix

Make the GraphQL GET placeholder concatenate the (already-encoded) payload into the
query string verbatim, matching `URLPath`/`URLParam`:

```go
if reqURL.RawQuery != "" {
    reqURL.RawQuery += "&query=" + payload
} else {
    reqURL.RawQuery = "query=" + payload
}
```

(Alternative: change `graphql.yml` to `encoder: Plain`. Fixing the placeholder is
preferred — it makes `encoder: URL` behave consistently with every other URL placeholder.)

## Testing

- Adds `graphql_encoding_test.go` — `TestGraphQLGetDoesNotDoubleEncode`. It runs the
  real pipeline (URL encoder → GraphQL GET placeholder) and asserts one decode of the
  `query` parameter yields the original payload.
- **Fails on master** (query decodes to `%3Cscript%3E…`), **passes with the fix**.
- `gofmt` clean; `go build ./...` and the full `placeholder` package tests pass.

## Impact

WAFs receive the intended single-encoded payloads for GraphQL-over-GET test cases,
rather than double-encoded strings that may not match signatures (skewing bypass/block
results).
