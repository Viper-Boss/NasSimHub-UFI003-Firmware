#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python3 "$here/scripts/privacy-check.py"
python3 "$here/scripts/test_tools.py"
for script in "$here"/scripts/*.sh "$here"/kernel/audio/*.sh; do sh -n "$script"; done
cd "$here/node"
for m in agent proto xport; do
 (cd "$m"; go test ./...; go vet ./...)
done
