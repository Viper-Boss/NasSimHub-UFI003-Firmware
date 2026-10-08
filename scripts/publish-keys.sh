#!/bin/sh
# Write the public release-key statement, release-keys.json, from a release
# PUBLIC keyring (the output of `nsh-release keyring`), or check a key file
# against a published statement. Offline; reads no private key.
#
#   sh scripts/publish-keys.sh KEYRING OUT_DIR [--previous OLD/release-keys.json]
#        [--supersedes NEW_ID=OLD_ID]... [--note KEY_ID=TEXT]... [--retired KEY_ID=REASON]...
#        [--issued YYYY-MM-DD]
#   sh scripts/publish-keys.sh --check STATEMENT KEYRING [--sha256 HEX]
#
# Output: OUT_DIR/release-keys.json and OUT_DIR/release-keys.json.sha256.
#
# The statement is NOT signed: `nsh-release sign` signs agent update manifests
# and nothing else, and this script does not invent a signature format. Publish
# both files on a channel that is itself authenticated (a signed git tag, the
# release page) and repeat the SHA-256 in the announcement. See
# docs/KEY-MANAGEMENT.md for what the statement is for and what it is not (it
# revokes nothing).
#
# KEYRING is the public key file. A private key file (anything under the key
# directory) is refused, and OUT_DIR may not be the directory that holds
# private keys.
set -eu
# shellcheck disable=SC1007 # an empty CDPATH for this one cd
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PYTHONDONTWRITEBYTECODE=1
usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
[ "$#" -ge 2 ] || usage
if [ "$1" = --check ]; then
	[ "$#" -ge 3 ] || usage
	statement=$2
	keyring=$3
	shift 3
	exec python3 "$here/scripts/release_keys.py" check --statement "$statement" --keyring "$keyring" "$@"
fi
keyring=$1
out=$2
shift 2
[ -f "$keyring" ] || { echo "publish-keys.sh: $keyring is not a file" >&2; exit 1; }
# Never write next to private keys: what is in OUT_DIR gets published.
if [ -d "$out" ]; then
	for private in "$out"/*.ed25519.key "$out"/*.mldsa.key; do
		[ ! -e "$private" ] || { echo 'publish-keys.sh: OUT_DIR holds release PRIVATE keys; choose another directory' >&2; exit 1; }
	done
fi
python3 "$here/scripts/privacy-check.py" --public-keyring "$keyring"
exec python3 "$here/scripts/release_keys.py" statement --keyring "$keyring" --out "$out" "$@"
