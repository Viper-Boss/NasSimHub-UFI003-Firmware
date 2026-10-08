#!/bin/sh
# Test of scripts/publish-keys.sh with THROW-AWAY keys made by nsh-release in a
# temporary directory outside every repository and deleted at the end. Offline.
# It shows that the statement describes exactly the public keyring, that a
# rotation is expressed and checked, and that private key files never get in.
set -eu
export PYTHONDONTWRITEBYTECODE=1
# shellcheck disable=SC1007 # an empty CDPATH for this one cd
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail() { echo "test-publish-keys FAILED: $*" >&2; [ ! -f "${log:-/nonexistent}" ] || sed 's/^/    | /' "$log" >&2; exit 1; }
outside_repositories() {
	for base in "${NSH_TEST_TMPDIR:-}" "${TMPDIR:-/tmp}" /var/tmp /dev/shm; do
		[ -n "$base" ] && [ -d "$base" ] && [ -w "$base" ] || continue
		# shellcheck disable=SC1007
		probe=$(CDPATH= cd -- "$base" && pwd -P)
		inside=no
		while :; do
			for marker in .git .hg .svn; do [ ! -e "$probe/$marker" ] || inside=yes; done
			[ "$probe" != / ] || break
			probe=$(dirname "$probe")
		done
		[ "$inside" = yes ] || { mktemp -d "$base/nsh-keys-test.XXXXXX"; return 0; }
	done
	return 1
}
work=$(outside_repositories) || fail 'no temporary directory outside a repository; set NSH_TEST_TMPDIR'
trap 'rm -rf "$work"' EXIT
log=$work/log
tool=${NSH_RELEASE_TOOL:-}
if [ -z "$tool" ] || [ ! -x "$tool" ]; then
	tool=$work/nsh-release
	# shellcheck disable=SC2086 # NSH_GO_FLAGS is a deliberately word-split flag list.
	(cd "$here/node/agent" && unset GOOS GOARCH && CGO_ENABLED=0 GOWORK=off GOFLAGS= "${GO:-go}" build ${NSH_GO_FLAGS:-} -trimpath -buildvcs=false -o "$tool" ./cmd/nsh-release)
fi
publish() { sh "$here/scripts/publish-keys.sh" "$@" > "$log" 2>&1; }
field() { python3 -c 'import json,sys
value = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    value = value[int(key)] if isinstance(value, list) else value[key]
print(value)' "$1" "$2"; }
# Dual keys when this toolchain has ML-DSA, classical otherwise.
pq=ml-dsa-87
"$tool" keygen -dir "$work/keys-old" -key-id test-2026 -pq "$pq" > "$log" 2>&1 || { pq=none; rm -rf "$work/keys-old"; "$tool" keygen -dir "$work/keys-old" -key-id test-2026 -pq none > "$log" 2>&1 || fail 'keygen'; }
"$tool" keyring -dir "$work/keys-old" -out "$work/old.json" > "$log" 2>&1 || fail 'keyring'

echo "== 1. a statement for one key (post-quantum: $pq)"
SOURCE_DATE_EPOCH=1700000000 publish "$work/old.json" "$work/pub1" --note 'test-2026=throw-away test key' || fail 'publishing failed'
one=$work/pub1/release-keys.json
(cd "$work/pub1" && sha256sum -c release-keys.json.sha256 > /dev/null) || fail 'the .sha256 file does not match the statement'
[ "$(field "$one" signed)" = False ] || fail 'the statement claims to be signed'
grep -q 'NOT signed' "$one" || fail 'the statement does not say that it is unsigned'
[ "$(field "$one" keyring.sha256)" = "$(sha256sum < "$work/old.json" | cut -d' ' -f1)" ] || fail 'keyring.sha256 is not the hash of the key file'
[ "$(field "$one" issued)" = 2023-11-14 ] || fail 'SOURCE_DATE_EPOCH did not fix the date'
[ "$(field "$one" keys.0.key_id)" = test-2026 ] && [ "$(field "$one" keys.0.algorithm)" = ed25519 ] || fail 'the ed25519 key is not listed'
[ "$(field "$one" keys.0.validity_note)" = 'throw-away test key' ] || fail 'the note is missing'
python3 - "$one" "$work/old.json" <<'PY' || fail 'the statement does not carry exactly the public keys of the keyring'
import base64, hashlib, json, sys
statement, keyring = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
listed = {(key['key_id'], key['algorithm']): key for key in statement['keys']}
want = {(key_id, 'ed25519'): value for key_id, value in keyring['ed25519'].items()}
want.update({(key_id, identity['algorithm']): identity['public_key'] for key_id, identity in keyring.get('ml_dsa', {}).items()})
assert set(listed) == set(want), (sorted(listed), sorted(want))
for identity, key in listed.items():
    assert key['public_key'] == want[identity] and key['status'] == 'active'
    assert key['sha256'] == hashlib.sha256(base64.b64decode(key['public_key'])).hexdigest()
assert statement['retired'] == []
PY
SOURCE_DATE_EPOCH=1700000000 publish "$work/old.json" "$work/pub1b" --note 'test-2026=throw-away test key' || fail 'second run failed'
cmp -s "$one" "$work/pub1b/release-keys.json" || fail 'two runs gave different statements'
sh "$here/scripts/publish-keys.sh" --check "$one" "$work/old.json" --sha256 "$(cut -d' ' -f1 "$work/pub1/release-keys.json.sha256")" > "$log" 2>&1 || fail 'the key file does not check against its own statement'
grep -q 'byte for byte the published one' "$log" || fail 'the identical key file was not recognised'

echo '== 2. private key files and bad arguments are refused'
for private in "$work"/keys-old/*.key; do
	if publish "$private" "$work/pub-private"; then fail "a private key file was accepted as a keyring: $(basename "$private")"; fi
	if grep -q "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["seed"])' "$private")" "$log"; then fail 'the refusal printed private key material'; fi
done
[ ! -e "$work/pub-private/release-keys.json" ] || fail 'a statement was written from a private key file'
if publish "$work/old.json" "$work/keys-old"; then fail 'the statement was written into the private key directory'; fi
if publish "$work/old.json" "$work/pub-bad" --supersedes test-2026=never-existed; then fail 'superseding an unknown key was accepted'; fi
if publish "$work/old.json" "$work/pub-bad" --note 'other=x'; then fail 'a note for an unknown key was accepted'; fi
if publish "$work/old.json" "$work/pub-bad" --retired 'test-2026=x'; then fail 'a key still in the keyring was marked retired'; fi
if publish "$work/old.json" "$work/pub-bad" --issued tomorrow; then fail 'an unreadable date was accepted'; fi

echo '== 3. rotation: overlap (old + new), then the old key retired'
mkdir "$work/keys-both"
cp "$work"/keys-old/*.key "$work/keys-both/"
"$tool" keygen -dir "$work/keys-both" -key-id test-2027 -pq "$pq" > "$log" 2>&1 || fail 'keygen (new key)'
"$tool" keyring -dir "$work/keys-both" -out "$work/both.json" > "$log" 2>&1 || fail 'keyring (both)'
publish "$work/both.json" "$work/pub2" --previous "$one" --supersedes test-2027=test-2026 --issued 2026-02-01 || fail 'publishing the overlap failed'
two=$work/pub2/release-keys.json
python3 - "$two" <<'PY' || fail 'the overlap statement is wrong'
import json, sys
statement = json.load(open(sys.argv[1]))
by_id = {}
for key in statement['keys']:
    by_id.setdefault(key['key_id'], []).append(key)
assert set(by_id) == {'test-2026', 'test-2027'}, sorted(by_id)
assert all(key['supersedes'] == 'test-2026' for key in by_id['test-2027'])
assert all(key['supersedes'] is None for key in by_id['test-2026'])
assert statement['retired'] == [] and statement['issued'] == '2026-02-01'
PY
# An image from before the rotation still checks (the new key is merely absent); the overlap image checks.
sh "$here/scripts/publish-keys.sh" --check "$two" "$work/old.json" > "$log" 2>&1 || fail 'a pre-rotation key file fails against the overlap statement'
grep -q 'test-2027 (ed25519): published, not in this key file' "$log" || fail 'the missing new key was not noted'
sh "$here/scripts/publish-keys.sh" --check "$two" "$work/both.json" > "$log" 2>&1 || fail 'the overlap key file fails against its statement'
mkdir "$work/keys-new"
cp "$work"/keys-both/test-2027.*.key "$work/keys-new/"
"$tool" keyring -dir "$work/keys-new" -out "$work/new.json" > "$log" 2>&1 || fail 'keyring (new)'
publish "$work/new.json" "$work/pub3" --previous "$two" --supersedes test-2027=test-2026 --retired 'test-2026=rotated out (test)' --issued 2026-08-01 || fail 'publishing the final statement failed'
three=$work/pub3/release-keys.json
[ "$(field "$three" retired.0.key_id)" = test-2026 ] && [ "$(field "$three" retired.0.reason)" = 'rotated out (test)' ] || fail 'the old key is not listed as retired with its reason'
sh "$here/scripts/publish-keys.sh" --check "$three" "$work/new.json" > "$log" 2>&1 || fail 'the new key file fails against the final statement'
if sh "$here/scripts/publish-keys.sh" --check "$three" "$work/both.json" > "$log" 2>&1; then fail 'a key file that still trusts the retired key passed'; fi
grep -q 'RETIRED in the statement (rotated out (test)) but still trusted by this key file' "$log" || fail 'the retired key was not named'

echo '== 4. a foreign key, a re-used key id and a wrong statement hash fail'
"$tool" keygen -dir "$work/keys-foreign" -key-id test-2027 -pq none > "$log" 2>&1 || fail 'keygen (foreign)'
"$tool" keyring -dir "$work/keys-foreign" -out "$work/foreign.json" > "$log" 2>&1 || fail 'keyring (foreign)'
if sh "$here/scripts/publish-keys.sh" --check "$three" "$work/foreign.json" > "$log" 2>&1; then fail 'another key under a published key id passed'; fi
grep -q 'the public key differs from the published one' "$log" || fail 'the differing key was not named'
if publish "$work/foreign.json" "$work/pub-bad" --previous "$three"; then fail 'a changed key under an existing key id was published'; fi
grep -q 'a new key needs a new key id' "$log" || fail 'the re-used key id was not named'
if sh "$here/scripts/publish-keys.sh" --check "$three" "$work/new.json" --sha256 "$(printf '%064d' 0)" > "$log" 2>&1; then fail 'a statement with the wrong SHA-256 was accepted'; fi
sed 's/"public_key": "\(.\)/"public_key": "A\1/' "$three" > "$work/edited.json"
if sh "$here/scripts/publish-keys.sh" --check "$work/edited.json" "$work/new.json" > "$log" 2>&1; then fail 'an edited statement was accepted'; fi
# Nothing private anywhere in what would be published.
for published in "$work"/pub1 "$work"/pub2 "$work"/pub3; do
	if grep -rq '"seed"' "$published"; then fail "private key material in $published"; fi
done
echo 'test-publish-keys PASS (throw-away keys; the statement is unsigned by design and revokes nothing)'
