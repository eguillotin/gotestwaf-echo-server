# syntax=docker/dockerfile:1
#
# Build a patched GoTestWAF with the GraphQL GET double-URL-encoding fix.
# Mirrors the upstream wallarm/gotestwaf image (chromium for JS checks, testcases,
# config.yaml, non-root user) but clones the source and applies our patch.
#
# As of v0.5.9 upstream already includes --skipGraphQLCheck / --skipGRPCCheck and
# the gRPC-availability fix (both merged), so only the double-encode patch remains.
#
# It needs one patch file from this repo's root as build context, so build
# from this repo's root:
#
#   docker build -f gotestwaf-patched.Dockerfile -t gotestwaf-patched .
#
# Run (reports land in ./reports):
#
#   docker run --rm --network host -v "$(pwd)/reports:/app/reports" gotestwaf-patched \
#     --url=https://app-behind-waf.example.com \
#     --graphqlURL=https://app-behind-waf.example.com/graphql --skipGraphQLCheck \
#     --blockStatusCodes=403 --blockConnReset --followCookies --renewSession \
#     --nonBlockedAsPassed --ignoreUnresolved --reportFormat=pdf --reportPath=/app/reports

# Build Stage ==================================================================
FROM golang:1.24-alpine AS build

RUN apk --no-cache add git

WORKDIR /app

# Upstream revision to build. v0.5.9 already includes the skip-checks flags and
# the gRPC-availability fix. Override with:
#   --build-arg GOTESTWAF_REF=<branch|tag|sha>
ARG GOTESTWAF_REF=v0.5.9
RUN git clone https://github.com/wallarm/gotestwaf.git . \
    && git checkout ${GOTESTWAF_REF}

# Apply the GraphQL GET double-URL-encoding fix (still open upstream).
# --3way lets it survive minor upstream drift.
COPY gotestwaf-graphql-get-double-encode.patch /tmp/graphql-get-double-encode.patch
RUN git apply --3way /tmp/graphql-get-double-encode.patch

RUN go mod download
RUN go build -o gotestwaf \
    -ldflags "-X github.com/wallarm/gotestwaf/internal/version.Version=$(git describe --tags --always)-skipchecks" \
    ./cmd/gotestwaf

# Main Stage ===================================================================
FROM alpine

RUN <<EOF
    set -e -o pipefail
    apk add --no-cache tini chromium font-inter fontconfig
    fc-cache -fv
    addgroup gtw
    adduser -D -G gtw gtw
    mkdir -p /app/reports
    chown -R gtw:gtw /app
EOF

WORKDIR /app

COPY --from=build /app/gotestwaf ./
COPY --from=build /app/testcases ./testcases
COPY --from=build /app/config.yaml ./

USER gtw

VOLUME [ "/app/reports" ]

ENTRYPOINT [ "/sbin/tini", "--", "/app/gotestwaf" ]
