#!/bin/sh
# End-to-end test of scripts/package-ota.sh with THROW-AWAY keys.
#
# The keys are generated in a temporary directory outside the repository and
# deleted when the test ends. Offline and simulated: nothing here talks to a
# device, and a pass says the packaging and verification tooling agree with
# each other, not that a device accepted an update.
#
# What it shows:
#   1. without keys: unsigned manifest only, and the operator command is printed
#   2. a key directory inside the repository is refused
#   3. with keys: manifest.signed.json (dual-signed when this toolchain has
#      ML-DSA) that verifies against the PUBLIC key file, and SHA256SUMS
#   4. a tampered artifact fails verification
#   5. a tampered manifest fails verification
#   6. a manifest signed by a key the device does not trust fails verification
#   7. a classical-only signature fails where a post-quantum one is required
#   8. a private key file passed off as the public key file is refused
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=${NSH_TEST_VERSION:-9.9.1}
fail() { echo "test-package-ota FAILED: $*" >&2; exit 1; }

# A temporary directory that is not inside ANY version-controlled tree: the
# release tooling refuses to create or use private keys anywhere a commit could
# pick them up, and some hosts have a stray .git above their temp directory.
outside_repositories() {
	for base in "${NSH_TEST_TMPDIR:-}" "${TMPDIR:-/tmp}" /var/tmp /dev/shm; do
		[ -n "$base" ] && [ -d "$base" ] && [ -w "$base" ] || continue
		probe=$(CDPATH= cd -- "$base" && pwd -P)
		inside=no
		while :; do
			for marker in .git .hg .svn; do [ ! -e "$probe/$marker" ] || inside=yes; done
			[ "$probe" != / ] || break
			probe=$(dirname "$probe")
		done
		[ "$inside" = yes ] || { mktemp -d "$base/nsh-ota-test.XXXXXX"; return 0; }
	done
	return 1
}
work=$(outside_repositories) || fail 'no temporary directory outside a repository; set NSH_TEST_TMPDIR'
trap 'rm -rf "$work"' EXIT

# Reuse the agent the reproducibility test built, or build one.
build=${NSH_TEST_BUILD_DIR:-}
if [ -z "$build" ] || [ ! -f "$build/nassimhub-agent" ]; then
	build=$work/build
	NSH_BUILD_DIR="$build" sh "$here/scripts/build-agent.sh" "$version" >/dev/null
fi
tool=$work/nsh-release
# shellcheck disable=SC2086 # NSH_GO_FLAGS is a deliberately word-split flag list.
(cd "$here/node/agent" && unset GOOS GOARCH && CGO_ENABLED=0 GOWORK=off GOFLAGS= "${GO:-go}" build ${NSH_GO_FLAGS:-} -trimpath -buildvcs=false -o "$tool" ./cmd/nsh-release)
export NSH_RELEASE_TOOL="$tool" NSH_DIST_DIR="$work/dist" AGENT="$build/nassimhub-agent" SOURCE_DATE_EPOCH=1700000000
package() { sh "$here/scripts/package-ota.sh" "$@"; }

echo '== 1. no keys: unsigned manifest and the operator command'
package "$version" stable agent-test-1 > "$work/unsigned.log"
rel=$work/dist/ota/agent-test-1
[ -f "$rel/manifest.json" ] && [ -f "$rel/nassimhub-agent" ] || fail 'no unsigned manifest'
[ ! -e "$rel/manifest.signed.json" ] || fail 'a signed manifest appeared without keys'
grep -q 'NSH_RELEASE_KEY_DIR=' "$work/unsigned.log" && grep -q "package-ota.sh $version stable agent-test-1" "$work/unsigned.log" || fail 'the operator command was not printed'
(cd "$rel" && sha256sum -c SHA256SUMS >/dev/null) || fail 'SHA256SUMS of the unsigned release does not check'
cmp -s "$build/nassimhub-agent" "$rel/nassimhub-agent" || fail 'the artifact is not the built agent'

echo '== 2. a key directory inside the repository is refused'
if NSH_RELEASE_KEY_DIR="$here/build/release-keys" NSH_RELEASE_KEY_ID=test package "$version" stable agent-test-1 > "$work/inside.log" 2>&1; then
	fail 'a key directory inside the repository was accepted'
fi
grep -q 'inside a repository' "$work/inside.log" || fail 'wrong refusal for an in-repository key directory'
[ ! -e "$here/build/release-keys" ] || fail 'the refused key directory was created'
if "$tool" keygen -dir "$here/build/release-keys" -key-id test -pq none > "$work/keygen-inside.log" 2>&1; then
	rm -rf "$here/build/release-keys"
	fail 'nsh-release keygen created a key inside the repository'
fi

echo '== 3. throw-away keys outside the repository: sign and verify'
keys=$work/release-keys
pq=test-2026
if ! "$tool" keygen -dir "$keys" -key-id test-2026 -pq ml-dsa-87 > "$work/keygen.log" 2>&1; then
	# A host toolchain older than Go 1.27 cannot make an ML-DSA key. The
	# classical flow is still tested, and the report says which one ran.
	rm -rf "$keys"
	"$tool" keygen -dir "$keys" -key-id test-2026 -pq none > "$work/keygen.log"
	pq=
fi
"$tool" keyring -dir "$keys" -out "$work/ota-keys.json" >/dev/null
python3 "$here/scripts/privacy-check.py" --public-keyring "$work/ota-keys.json" >/dev/null
NSH_RELEASE_KEY_DIR="$keys" NSH_RELEASE_KEY_ID=test-2026 NSH_RELEASE_PQ_KEY_ID="$pq" NSH_OTA_KEYS="$work/ota-keys.json" \
	package "$version" stable agent-test-1 > "$work/signed.log"
[ -f "$rel/manifest.signed.json" ] || fail 'no signed manifest'
(cd "$rel" && sha256sum -c SHA256SUMS >/dev/null) || fail 'SHA256SUMS of the signed release does not check'
grep -q 'manifest.signed.json' "$rel/SHA256SUMS" || fail 'SHA256SUMS does not cover the signed manifest'
if [ -n "$pq" ]; then
	"$tool" verify -signed "$rel/manifest.signed.json" -keys "$work/ota-keys.json" -binary "$rel/nassimhub-agent" -require-pq | tee "$work/verify.log"
	grep -q 'ml-dsa-87' "$work/verify.log" || fail 'the release is not dual-signed'
	echo '   dual-signed (Ed25519 + ML-DSA-87) and verified with -require-pq'
else
	"$tool" verify -signed "$rel/manifest.signed.json" -keys "$work/ota-keys.json" -binary "$rel/nassimhub-agent"
	echo '   classical-only: this toolchain has no ML-DSA, the dual-signature path was NOT exercised'
fi
# Nothing private left the key directory.
if grep -rl '"seed"' "$rel" >/dev/null 2>&1; then fail 'private key material in the release directory'; fi
python3 "$here/scripts/privacy-check.py" --ota-release "$rel" >/dev/null || fail 'the release directory failed the privacy check'

echo '== 4. a tampered artifact fails verification'
cp -R "$rel" "$work/tampered-artifact"
printf 'x' >> "$work/tampered-artifact/nassimhub-agent"
if "$tool" verify -signed "$work/tampered-artifact/manifest.signed.json" -keys "$work/ota-keys.json" -binary "$work/tampered-artifact/nassimhub-agent" > "$work/t4.log" 2>&1; then
	fail 'a modified artifact verified'
fi
sed 's/^/   refused: /' "$work/t4.log"
# Same size, one byte changed: only the hash can notice.
cp "$rel/nassimhub-agent" "$work/tampered-artifact/nassimhub-agent"
python3 - "$work/tampered-artifact/nassimhub-agent" <<'PY'
import sys
with open(sys.argv[1], 'r+b') as handle:
    handle.seek(4096); byte = handle.read(1); handle.seek(4096); handle.write(bytes([byte[0] ^ 1]))
PY
if "$tool" verify -signed "$work/tampered-artifact/manifest.signed.json" -keys "$work/ota-keys.json" -binary "$work/tampered-artifact/nassimhub-agent" > "$work/t4b.log" 2>&1; then
	fail 'an artifact with one flipped byte verified'
fi
sed 's/^/   refused: /' "$work/t4b.log"

echo '== 5. a tampered manifest fails verification'
cp -R "$rel" "$work/tampered-manifest"
# The channel is changed inside the signed bytes; the signatures no longer cover what the file says.
sed 's/"channel":"stable"/"channel":"beta"/' "$rel/manifest.signed.json" > "$work/tampered-manifest/manifest.signed.json"
cmp -s "$rel/manifest.signed.json" "$work/tampered-manifest/manifest.signed.json" && fail 'the tamper step changed nothing'
if "$tool" verify -signed "$work/tampered-manifest/manifest.signed.json" -keys "$work/ota-keys.json" -binary "$rel/nassimhub-agent" > "$work/t5.log" 2>&1; then
	fail 'a modified manifest verified'
fi
sed 's/^/   refused: /' "$work/t5.log"

echo '== 6. a release signed by an untrusted key fails verification'
"$tool" keygen -dir "$work/other-keys" -key-id test-2026 -pq none >/dev/null
"$tool" keyring -dir "$work/other-keys" -out "$work/other-ota-keys.json" >/dev/null
if "$tool" verify -signed "$rel/manifest.signed.json" -keys "$work/other-ota-keys.json" -binary "$rel/nassimhub-agent" > "$work/t6.log" 2>&1; then
	fail 'a release verified against a keyring that does not hold its key'
fi
sed 's/^/   refused: /' "$work/t6.log"
# ... and package-ota.sh itself refuses to finish when the device key file would not accept the release.
if NSH_RELEASE_KEY_DIR="$keys" NSH_RELEASE_KEY_ID=test-2026 NSH_OTA_KEYS="$work/other-ota-keys.json" \
	package "$version" stable agent-test-1 > "$work/t6b.log" 2>&1; then
	fail 'package-ota.sh finished although the device key file rejects the release'
fi
[ ! -e "$rel/manifest.signed.json" ] || fail 'an unverifiable signed manifest was left in the release directory'

echo '== 7. classical-only where a post-quantum signature is required'
NSH_RELEASE_KEY_DIR="$keys" NSH_RELEASE_KEY_ID=test-2026 NSH_OTA_KEYS="$work/ota-keys.json" package "$version" stable agent-test-1 >/dev/null
if "$tool" verify -signed "$rel/manifest.signed.json" -keys "$work/ota-keys.json" -binary "$rel/nassimhub-agent" -require-pq > "$work/t7.log" 2>&1; then
	fail 'a classical-only release passed -require-pq'
fi
sed 's/^/   refused: /' "$work/t7.log"

echo '== 8. a private key file is not accepted as the public key file'
if NSH_RELEASE_KEY_DIR="$keys" NSH_RELEASE_KEY_ID=test-2026 NSH_OTA_KEYS="$keys/test-2026.ed25519.key" \
	package "$version" stable agent-test-1 > "$work/t8.log" 2>&1; then
	fail 'a private key file was accepted as NSH_OTA_KEYS'
fi
grep -q 'not a PUBLIC release keyring' "$work/t8.log" || fail 'wrong refusal for a private key file'
if grep -rl '"seed"' "$work/dist" >/dev/null 2>&1; then fail 'private key material reached the output directory'; fi

# A wrong version is caught before anything is written.
if package 9.9.2 stable agent-test-2 > "$work/t9.log" 2>&1; then fail 'a manifest version that the binary does not report was accepted'; fi
[ ! -e "$work/dist/ota/agent-test-2/manifest.json" ] || fail 'a manifest was written for a mismatched version'

echo "package-ota test PASS (offline, throw-away keys, removed with $work)"
