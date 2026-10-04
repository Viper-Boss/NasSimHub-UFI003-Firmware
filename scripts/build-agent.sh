#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$here/build"
cd "$here/node/agent"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o "$here/build/nassimhub-agent" ./cmd/nassimhub-agent
(cd "$here/build"; sha256sum nassimhub-agent > SHA256SUMS)
echo "Built static arm64 Agent; optional holder needs aarch64 C compiler (see node/deploy/audio)."
