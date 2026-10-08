#!/bin/sh
# Package an agent OTA release: artifact + manifest, and - only when the release
# operator supplies keys that live OUTSIDE this repository - the signed manifest.
#
#   sh scripts/package-ota.sh VERSION CHANNEL RELEASE_ID
#
#   VERSION     the version the built agent reports with -version (it must be
#               the VERSION build/BUILDINFO.json records for that exact binary)
#   CHANNEL     stable | beta
#   RELEASE_ID  directory name on the device and in dist/ota/, e.g. agent-1.15.1
#
# Output: dist/ota/<RELEASE_ID>/
#   nassimhub-agent        the artifact, byte-identical to the built agent
#   BUILDINFO.json         how it was built
#   manifest.json          the UNSIGNED manifest (nsh-release manifest)
#   manifest.signed.json   only with keys: Ed25519, plus ML-DSA when a
#                          post-quantum key id is given (nsh-release sign)
#   ota-keys.json          only with keys: the PUBLIC keyring the result was
#                          verified against
#   SHA256SUMS             of everything above (integrity, not authenticity)
#
# Without keys the script stops after the unsigned manifest and prints the
# command for the release operator. Re-running it with keys signs the manifest
# that is already there; it does not regenerate it.
#
# Environment:
#   NSH_RELEASE_KEY_DIR    directory holding the PRIVATE release keys created by
#                          `nsh-release keygen`. Must be outside this repository
#                          (and outside any repository); it is only ever read.
#   NSH_RELEASE_KEY_ID     Ed25519 key id to sign with.
#   NSH_RELEASE_PQ_KEY_ID  optional ML-DSA key id: makes the release dual-signed
#                          (the signing host needs Go >= 1.27).
#   NSH_OTA_KEYS           optional PUBLIC key file to verify against - normally
#                          the ota-keys.json shipped in the factory image.
#                          Default: the public keyring derived from the key dir.
#   AGENT                  built agent (default build/nassimhub-agent, with its
#                          BUILDINFO.json beside it).
#   NSH_DIST_DIR           output root (default <repo>/dist).
#   NSH_RELEASE_TOOL       prebuilt nsh-release (default: built from node/ into
#                          build/tools/, for the host).
#   NSH_GO_FLAGS           extra go flags, test use only (see build-agent.sh).
#   SOURCE_DATE_EPOCH      optional, fixes released_at for a reproducible manifest.
#   NSH_RELEASE_NOTES, NSH_RELEASE_URL, NSH_MIN_CORE   optional manifest fields.
#
# The private key is never copied, printed or written by this script, and no
# file under the key directory is created or modified.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
die() { echo "package-ota.sh: $*" >&2; exit 1; }
[ "$#" = 3 ] || { echo 'usage: package-ota.sh VERSION CHANNEL RELEASE_ID   (see the header of this script)' >&2; exit 2; }
version=$1 channel=$2 release=$3
case "$channel" in stable|beta) ;; *) die "CHANNEL must be stable or beta, not '$channel'";; esac
# Same rule as proto.ValidateOTAReleaseID: the id becomes a directory name.
printf '%s\n' "$release" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' || die "RELEASE_ID '$release' is not usable"
case "$release" in current|previous) die "RELEASE_ID '$release' is reserved";; esac
[ "$version" != dev ] || die 'a "dev" agent never installs or starts an update; build with a VERSION'

# nearest_dir PATH: the physical path of PATH, or of its nearest existing
# ancestor when PATH does not exist yet.
nearest_dir() {
	case "$1" in /*) candidate=$1;; *) candidate=$PWD/$1;; esac
	while [ ! -d "$candidate" ]; do candidate=$(dirname "$candidate"); done
	(CDPATH= cd -- "$candidate" && pwd -P)
}
here_physical=$(nearest_dir "$here")

agent=${AGENT:-$here/build/nassimhub-agent}
[ -f "$agent" ] || die "no built agent at $agent; run scripts/build-agent.sh VERSION first"
agent=$(nearest_dir "$(dirname "$agent")")/$(basename "$agent")
buildinfo=$(dirname "$agent")/BUILDINFO.json
[ -f "$buildinfo" ] || die "no BUILDINFO.json beside $agent; package only agents built by scripts/build-agent.sh"
dist=${NSH_DIST_DIR:-$here/dist}
out=$dist/ota/$release

# inside_repository DIR: succeeds when DIR is this repository or inside any
# version-controlled tree. The same walk nsh-release keygen does, so the two
# tools cannot disagree about where a private key may live.
inside_repository() {
	current=$(nearest_dir "$1")
	case "$current/" in "$here_physical"/*) return 0;; esac
	while :; do
		for marker in .git .hg .svn; do [ ! -e "$current/$marker" ] || return 0; done
		[ "$current" != / ] || return 1
		current=$(dirname "$current")
	done
}

keydir=${NSH_RELEASE_KEY_DIR:-}
keyid=${NSH_RELEASE_KEY_ID:-}
pqid=${NSH_RELEASE_PQ_KEY_ID:-}
signing=no
if [ -n "$keydir" ] || [ -n "$keyid" ] || [ -n "$pqid" ]; then
	[ -n "$keydir" ] && [ -n "$keyid" ] || die 'signing needs both NSH_RELEASE_KEY_DIR and NSH_RELEASE_KEY_ID'
	# Checked before the directory is even looked at: a key directory inside a
	# repository is refused whether or not it holds a key yet.
	! inside_repository "$keydir" || die "NSH_RELEASE_KEY_DIR ($keydir) is inside a repository; release private keys must live where they cannot be committed"
	[ -d "$keydir" ] || die "NSH_RELEASE_KEY_DIR ($keydir) is not a directory"
	keydir=$(nearest_dir "$keydir")
	case "$(nearest_dir "$dist")/" in "$keydir"/*) die 'the output directory is inside the key directory';; esac
	[ -f "$keydir/$keyid.ed25519.key" ] || die "no Ed25519 release key '$keyid' in the key directory"
	[ -z "$pqid" ] || [ -f "$keydir/$pqid.mldsa.key" ] || die "no ML-DSA release key '$pqid' in the key directory"
	signing=yes
fi

# The publisher's tool, built for this host from the same node/ tree.
tool=${NSH_RELEASE_TOOL:-}
if [ -z "$tool" ]; then
	tool=$here/build/tools/nsh-release
	mkdir -p "$here/build/tools"
	# shellcheck disable=SC2086 # NSH_GO_FLAGS is a deliberately word-split flag list.
	(cd "$here/node/agent" && unset GOOS GOARCH && CGO_ENABLED=0 GOWORK=off GOFLAGS= \
		"${GO:-go}" build ${NSH_GO_FLAGS:-} -trimpath -buildvcs=false -o "$tool" ./cmd/nsh-release)
fi
[ -x "$tool" ] || die "nsh-release tool not found at $tool"

# The manifest promises a version; a device runs the staged binary with
# -version and refuses the update when the two differ. BUILDINFO.json is the
# record of what this exact binary was stamped with, so both are checked here,
# where a mismatch costs nothing.
python3 - "$agent" "$buildinfo" "$version" <<'PY' || exit 1
import hashlib, json, sys
agent, buildinfo, version = sys.argv[1:4]
info = json.load(open(buildinfo))
digest = hashlib.sha256(open(agent, 'rb').read()).hexdigest()
problems = []
if info.get('sha256') != digest: problems.append('BUILDINFO.json does not describe this agent binary (sha256 differs)')
if info.get('version') != version: problems.append(f"the agent was built as version {info.get('version')!r}, not {version!r}")
if (info.get('goos'), info.get('goarch')) != ('linux', 'arm64'): problems.append('the agent is not a linux/arm64 build')
if problems:
    sys.exit('package-ota.sh: ' + '; '.join(problems))
if info.get('go_mod') != 'committed':
    print('NOTE: this agent was built with a go.mod override (test build); do not publish it.')
PY

mkdir -p "$out"
if [ -f "$out/manifest.json" ]; then
	# Resume: sign what was reviewed. The artifact must still be the one the
	# existing manifest describes.
	cmp -s "$agent" "$out/nassimhub-agent" || die "$out already holds a different artifact; choose a new RELEASE_ID or remove that directory"
	echo "reusing the unsigned manifest already in $out"
else
	[ -z "$(ls -A "$out")" ] || die "$out exists and is not a release directory this script wrote"
	cp "$agent" "$out/nassimhub-agent"
	chmod 0755 "$out/nassimhub-agent"
	cp "$buildinfo" "$out/BUILDINFO.json"
	set -- manifest -binary "$out/nassimhub-agent" -version "$version" -release-id "$release" \
		-platform msm8916 -arch arm64 -channel "$channel" -out "$out/manifest.json"
	if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
		set -- "$@" -released-at "$(python3 -c 'import datetime,sys; print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$SOURCE_DATE_EPOCH")"
	fi
	[ -z "${NSH_RELEASE_NOTES:-}" ] || set -- "$@" -notes "$NSH_RELEASE_NOTES"
	[ -z "${NSH_RELEASE_URL:-}" ] || set -- "$@" -url "$NSH_RELEASE_URL"
	[ -z "${NSH_MIN_CORE:-}" ] || set -- "$@" -min-core "$NSH_MIN_CORE"
	"$tool" "$@"
fi

sums() {
	(cd "$out" && rm -f SHA256SUMS && for f in BUILDINFO.json manifest.json manifest.signed.json nassimhub-agent ota-keys.json; do
		[ ! -f "$f" ] || sha256sum "$f"
	done > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS)
}

if [ "$signing" = no ]; then
	rm -f "$out/manifest.signed.json" "$out/ota-keys.json"
	sums
	cat <<EOF
UNSIGNED release prepared in $out
A device installs nothing without a signature from a key in its /etc/nassimhub/ota-keys.json.
Release operator: sign it on the machine that holds the release keys (key directory OUTSIDE every repository):

  NSH_RELEASE_KEY_DIR=/path/outside/any/repository/release-keys \\
  NSH_RELEASE_KEY_ID=<ed25519-key-id> NSH_RELEASE_PQ_KEY_ID=<ml-dsa-key-id, optional> \\
  sh scripts/package-ota.sh $version $channel $release

which runs, in order:

  nsh-release sign -manifest $out/manifest.json -dir "\$NSH_RELEASE_KEY_DIR" -key-id "\$NSH_RELEASE_KEY_ID" [-pq-key-id "\$NSH_RELEASE_PQ_KEY_ID"] -out $out/manifest.signed.json
  nsh-release verify -signed $out/manifest.signed.json -keys <ota-keys.json> -binary $out/nassimhub-agent [-require-pq]
EOF
	exit 0
fi

# The device-side PUBLIC key file is checked before anything is signed: a
# private key file handed over by mistake must stop the run, not be copied.
rm -f "$out/manifest.signed.json" "$out/manifest.signed.json.unverified" "$out/ota-keys.json"
if [ -n "${NSH_OTA_KEYS:-}" ]; then
	[ -f "$NSH_OTA_KEYS" ] || die "NSH_OTA_KEYS ($NSH_OTA_KEYS) is not a file"
	python3 "$here/scripts/privacy-check.py" --public-keyring "$NSH_OTA_KEYS" || { sums; exit 1; }
fi

set -- sign -manifest "$out/manifest.json" -dir "$keydir" -key-id "$keyid" -out "$out/manifest.signed.json.unverified"
[ -z "$pqid" ] || set -- "$@" -pq-key-id "$pqid"
"$tool" "$@" || { rm -f "$out/manifest.signed.json.unverified"; sums; die 'signing failed'; }

# Verify the way a device will: against a PUBLIC key file, and against the
# artifact. With NSH_OTA_KEYS that is the file devices actually carry, which is
# the check that matters - a release signed with a key no shipped image trusts
# verifies against its own key directory and installs nowhere. The signed
# manifest only gets its final name after it has verified.
if [ -n "${NSH_OTA_KEYS:-}" ]; then
	cp "$NSH_OTA_KEYS" "$out/ota-keys.json"
else
	"$tool" keyring -dir "$keydir" -out "$out/ota-keys.json" >/dev/null
	python3 "$here/scripts/privacy-check.py" --public-keyring "$out/ota-keys.json" >/dev/null
fi
chmod 0644 "$out/ota-keys.json"
set -- verify -signed "$out/manifest.signed.json.unverified" -keys "$out/ota-keys.json" -binary "$out/nassimhub-agent"
[ -z "$pqid" ] || set -- "$@" -require-pq
if ! "$tool" "$@"; then
	rm -f "$out/manifest.signed.json.unverified" "$out/ota-keys.json"
	sums
	die 'the signed manifest does NOT verify against the public key file; nothing was signed for publication'
fi
mv "$out/manifest.signed.json.unverified" "$out/manifest.signed.json"
sums
# Last line of defence: nothing private may sit in a directory that is about to
# be published.
python3 "$here/scripts/privacy-check.py" --ota-release "$out"
echo "SIGNED release ready in $out (verified against $( [ -n "${NSH_OTA_KEYS:-}" ] && echo "$NSH_OTA_KEYS" || echo 'the key directory public keyring' ))"
echo "Publish manifest.signed.json and nassimhub-agent unmodified: re-formatting the signed manifest invalidates it."
