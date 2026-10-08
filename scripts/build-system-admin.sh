#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out=${NSH_BUILD_DIR:-$here/build}
mkdir -p "$out"
out=$(CDPATH= cd -- "$out" && pwd)
cd "$here/node/agent"
export CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOWORK=off GOFLAGS=
"${GO:-go}" build -trimpath -buildvcs=false -ldflags=-s -o "$out/nassimhub-system-admin" ./cmd/nassimhub-system-admin
(cd "$out" && sha256sum nassimhub-system-admin > SYSTEM-ADMIN-SHA256SUMS)
