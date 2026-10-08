#!/bin/sh
# Reproducible build of the factory/OTA agent (static linux/arm64).
#
#   sh scripts/build-agent.sh [VERSION]        (or VERSION=... in the environment)
#
# Outputs, all inside the build directory (default: build/, git-ignored):
#   nassimhub-agent   the static arm64 agent
#   BUILDINFO.json    version, toolchain, target, content hash of node/, ML-DSA availability
#   SHA256SUMS        of the two files above
#   sbom/             SPDX 2.3 SBOM, third-party notices and licence texts (scripts/sbom.py)
#
# Why each input is pinned:
#   -trimpath            no build-host path reaches the binary, so the checkout
#                        location does not change the output.
#   -buildvcs=false      the result must not depend on whether .git is present
#                        or on uncommitted files elsewhere in the tree.
#   CGO_ENABLED=0        no host C toolchain or libc takes part.
#   GOWORK=off           the agent module's own go.mod (and its replace lines)
#                        decides the dependency set, not a workspace file.
#   GOFLAGS=             nothing inherited from the caller's environment.
#   no build timestamp   main.buildDate stays "unknown" unless BUILD_DATE is set
#                        explicitly; a clock value would differ on every build.
# scripts/test-reproducible-build.sh builds twice (different checkout path,
# cold build cache) and compares the result byte for byte.
#
# Environment:
#   VERSION          the version the agent reports with -version. Without one
#                    the agent is built as "dev", which runs but never installs
#                    or starts an update (see node/agent/cmd/nassimhub-agent/main.go).
#   BUILD_DATE       optional, recorded verbatim in the agent and BUILDINFO.json.
#   NSH_BUILD_DIR    output directory (default <repo>/build).
#   NSH_NODE_DIR     node source tree (default <repo>/node); the reproducibility
#                    test points this at a copy.
#   NSH_GO_FLAGS     extra flags for `go build`/`go list`. TEST USE ONLY, for an
#                    offline module cache that lacks a pinned module zip
#                    (-modfile=...). A release build leaves it empty and uses the
#                    committed go.mod; BUILDINFO.json records which was used.
#   GO               the go command (default: go).
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

version=${1:-${VERSION:-dev}}
# What proto.ParseVersion accepts (node/proto/compat.go): up to three numeric
# components, an optional leading "v", an optional -pre/+build suffix. Anything
# else cannot be compared by a device and is refused here rather than at the
# first update.
if [ "$version" != dev ] && ! printf '%s\n' "$version" | grep -Eq '^v?[0-9]+(\.[0-9]+){0,2}([-+][A-Za-z0-9._+-]*)?$'; then
	echo "build-agent.sh: VERSION '$version' is not a version a device can compare (e.g. 1.15.0 or 1.15.0-node.1)" >&2
	exit 2
fi
build_date=${BUILD_DATE:-unknown}
case "$build_date" in *[!A-Za-z0-9.:_+-]*) echo 'build-agent.sh: BUILD_DATE has unsupported characters' >&2; exit 2;; esac

out=${NSH_BUILD_DIR:-$here/build}
node=${NSH_NODE_DIR:-$here/node}
go=${GO:-go}
extra=${NSH_GO_FLAGS:-}
[ -d "$node/agent/cmd/nassimhub-agent" ] || { echo "build-agent.sh: no agent source under $node" >&2; exit 1; }
mkdir -p "$out"
out=$(CDPATH= cd -- "$out" && pwd)

export CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOWORK=off GOFLAGS=
go_version=$("$go" env GOVERSION)
echo "toolchain: $("$go" version)"
[ -z "$extra" ] || echo "NOTE: NSH_GO_FLAGS is set ($extra): this is not a release build; a release uses the committed go.mod."

cd "$node/agent"
ldflags="-X main.version=$version"
[ "$build_date" = unknown ] || ldflags="$ldflags -X main.buildDate=$build_date"
# shellcheck disable=SC2086 # $extra is a deliberately word-split flag list.
"$go" build $extra -trimpath -buildvcs=false -ldflags "$ldflags" -o "$out/nassimhub-agent" ./cmd/nassimhub-agent

# ML-DSA is available exactly when the toolchain compiles proto's go1.27 file
# (node/proto/pqmldsa_go127.go, `//go:build go1.27`); ask the toolchain which
# files it selects rather than parsing its version string.
# shellcheck disable=SC2086
proto_files=$("$go" list $extra -f '{{range .GoFiles}}{{.}} {{end}}' github.com/human-agent65535/nassimhub-node/proto)
case " $proto_files " in *' pqmldsa_go127.go '*) mldsa=true;; *) mldsa=false;; esac

python3 - "$out" "$node" "$version" "$go_version" "$mldsa" "$build_date" "$extra" <<'PY'
import hashlib, json, pathlib, sys
out, node, version, go_version, mldsa, build_date, extra = sys.argv[1:8]
out = pathlib.Path(out); node = pathlib.Path(node)

def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()

# Content hash of node/: the sorted "<sha256>  <relative path>" lines, hashed.
# It names the exact source the binary was built from without needing git, and
# does not depend on where the tree is checked out.
lines = []
for path in sorted(p for p in node.rglob('*') if p.is_file()):
    relative = path.relative_to(node).as_posix()
    if relative == 'go.work.sum':  # workspace by-product, git-ignored
        continue
    lines.append(f'{sha256(path)}  {relative}\n')
tree = hashlib.sha256(''.join(lines).encode()).hexdigest()

flags = ['-trimpath', '-buildvcs=false', '-ldflags=-X main.version=' + version]
if build_date != 'unknown':
    flags[-1] += ' -X main.buildDate=' + build_date
agent = out / 'nassimhub-agent'
info = {
    'schema': 1,
    'name': 'nassimhub-agent',
    'version': version,
    'build_date': build_date,
    'go_version': go_version,
    'goos': 'linux',
    'goarch': 'arm64',
    'cgo_enabled': False,
    'build_flags': flags,
    # "committed" is the only value a release may carry. An override names the
    # flag only, never a build-host path.
    'go_mod': 'override' if '-modfile' in extra else 'committed',
    'extra_go_flags': [flag.split('=', 1)[0] for flag in extra.split()],
    'node_tree_sha256': tree,
    'node_tree_files': len(lines),
    'ml_dsa_available': mldsa == 'true',
    'updates_capable': version != 'dev',
    'sha256': sha256(agent),
    'size': agent.stat().st_size,
}
(out / 'BUILDINFO.json').write_text(json.dumps(info, indent=2, sort_keys=True) + '\n')
PY
(cd "$out" && sha256sum nassimhub-agent BUILDINFO.json > SHA256SUMS)

# SBOM, third-party notices and licence texts for exactly this binary, made
# here because this is the step that has the toolchain and the module cache.
# The licence policy is enforced: a linked module whose licence is missing,
# unknown or not allowed fails the build (scripts/licence-policy.json).
# sbom/ is not part of SHA256SUMS: the SPDX document carries a creation time
# (set SOURCE_DATE_EPOCH to fix it).
rm -rf "$out/sbom"
mkdir -p "$out/sbom"
GO="$go" python3 "$here/scripts/sbom.py" generate --agent "$out/nassimhub-agent" --buildinfo "$out/BUILDINFO.json" --node "$node" \
	--out "$out/sbom/sbom.spdx.json" --notices "$out/sbom/THIRD-PARTY-NOTICES.md" --licence-dir "$out/sbom/third-party"
echo "built nassimhub-agent $version for linux/arm64 with $go_version (ML-DSA available: $mldsa)"
sed 's/^/  /' "$out/SHA256SUMS"
[ "$version" != dev ] || echo 'NOTE: built as "dev": this agent never installs or starts an update. Pass a VERSION for a factory or OTA build.'
echo "The optional voice holder needs an aarch64 C compiler (see node/deploy/audio); it is not built here."
