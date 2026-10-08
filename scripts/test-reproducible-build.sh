#!/bin/sh
# Builds the agent twice and requires the two results to be byte-identical.
#
# The second build is made as different from the first as an honest rebuild
# can be: the source is a copy at another absolute path, the Go build cache is
# empty, and the output directory is different. If a host path, a timestamp or
# cache state leaked into the binary, the hashes would differ.
#
# Offline; writes only under a temporary directory outside the repository
# (or under NSH_TEST_DIR when the caller wants to reuse the first build).
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=${NSH_TEST_VERSION:-9.9.1}

if [ -n "${NSH_TEST_DIR:-}" ]; then
	work=$NSH_TEST_DIR
	mkdir -p "$work"
else
	work=$(mktemp -d)
	trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
fi
rm -rf "$work/build-a" "$work/build-b" "$work/elsewhere" "$work/gocache"
mkdir -p "$work/elsewhere/checkout"
cp -R "$here/node" "$work/elsewhere/checkout/node"

echo '== build A: repository checkout, default build cache'
NSH_BUILD_DIR="$work/build-a" sh "$here/scripts/build-agent.sh" "$version"
echo '== build B: copied source at another path, empty build cache'
NSH_BUILD_DIR="$work/build-b" NSH_NODE_DIR="$work/elsewhere/checkout/node" GOCACHE="$work/gocache" \
	sh "$here/scripts/build-agent.sh" "$version"

a=$(sha256sum < "$work/build-a/nassimhub-agent" | cut -d' ' -f1)
b=$(sha256sum < "$work/build-b/nassimhub-agent" | cut -d' ' -f1)
echo "build A sha256: $a"
echo "build B sha256: $b"
[ "$a" = "$b" ] || { echo 'reproducible build FAILED: the two agents differ' >&2; exit 1; }
cmp "$work/build-a/nassimhub-agent" "$work/build-b/nassimhub-agent"
# BUILDINFO.json carries no clock, host name or path, so it must match too.
cmp "$work/build-a/BUILDINFO.json" "$work/build-b/BUILDINFO.json" || { echo 'reproducible build FAILED: BUILDINFO.json differs' >&2; exit 1; }
cmp "$work/build-a/SHA256SUMS" "$work/build-b/SHA256SUMS"
(cd "$work/build-a" && sha256sum -c SHA256SUMS >/dev/null)

# The version must be what the binary itself reports: a device validates a
# staged release by running it with -version. The string is looked for in the
# binary so the check also works on a host that cannot execute arm64.
grep -aq "$version" "$work/build-a/nassimhub-agent" || { echo "the agent does not contain version $version" >&2; exit 1; }
# No build-host path may survive -trimpath.
if grep -aq -e "$here/node" -e "$work/elsewhere" "$work/build-a/nassimhub-agent" "$work/build-b/nassimhub-agent"; then
	echo 'reproducible build FAILED: a build-host path is embedded in the agent' >&2; exit 1
fi
if command -v qemu-aarch64-static >/dev/null 2>&1; then
	reported=$(qemu-aarch64-static "$work/build-a/nassimhub-agent" -version)
	echo "emulated -version (qemu-user, not a device): $reported"
	case "$reported" in "nassimhub-agent $version "*) ;; *) echo 'the agent reports another version' >&2; exit 1;; esac
fi
chmod -R u+w "$work/gocache" 2>/dev/null || :
rm -rf "$work/gocache" "$work/elsewhere" "$work/build-b"
echo "reproducible build PASS: two independent builds are byte-identical ($a)"
