#!/bin/sh
# Offline syntax and behaviour checks of what the overlays grant the agent:
# the systemd units with their drop-ins, and the polkit rules.
#
#   sh scripts/test-setup-ap-overlay.sh
#
# 1. systemd-analyze verify on the agent unit as the image assembles it, without
#    and with firmware/setup-ap-overlay/. Any diagnostic that names a file and a
#    line (an unknown key, a value systemd cannot parse) fails the test.
# 2. Every polkit rule file is run in a JavaScript engine against a stand-in
#    `polkit` object, and its decisions are compared with the documented table
#    in scripts/imagepolicy.py: YES for the agent user and a listed action, no
#    decision for anything else.
#
# This checks that the files say what is intended. Whether NetworkManager and
# polkit on the stick then behave as expected, and whether the kernel honours
# SocketBindDeny, is NOT checked here: nothing in this test is a device result.
# A missing tool is reported as SKIPPED, never as a pass.
set -eu
export PYTHONDONTWRITEBYTECODE=1
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail() { echo "test-setup-ap-overlay FAILED: $*" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

assemble() { # assemble DIR [with-fragment]
	mkdir -p "$1/nassimhub-agent.service.d"
	cp "$here/node/deploy/nassimhub-agent.service" "$1/"
	cp "$here/node/deploy/nassimhub-agent-resources.conf" "$1/nassimhub-agent.service.d/resources.conf"
	cp "$here/firmware/overlay/etc/systemd/system/nassimhub-agent.service.d/persistent.conf" "$1/nassimhub-agent.service.d/"
	cp "$here/firmware/overlay/etc/systemd/system/"*.service "$here/firmware/overlay/etc/systemd/system/"*.mount "$1/"
	[ "$#" = 1 ] || cp "$here/firmware/setup-ap-overlay/etc/systemd/system/nassimhub-agent.service.d/setup-ap.conf" "$1/nassimhub-agent.service.d/"
}

echo '== 1. systemd unit syntax (systemd-analyze verify)'
if command -v systemd-analyze >/dev/null 2>&1; then
	for case in base setup-ap; do
		if [ "$case" = base ]; then assemble "$work/$case"; else assemble "$work/$case" with-fragment; fi
		# The exit status is not used: verify also fails because the agent
		# binary and the libexec scripts are not installed on a build host.
		systemd-analyze verify "$work/$case/nassimhub-agent.service" > "$work/$case.log" 2>&1 || :
		# A diagnostic about a unit file's content has the form "<path>:<line>: ...".
		if grep -E "^$work/$case/[^ ]+:[0-9]+:" "$work/$case.log"; then fail "systemd reports a problem in the $case unit files"; fi
		if grep -E -i 'unknown (key|section)|failed to parse|unable to parse|invalid' "$work/$case.log"; then fail "systemd reports a problem in the $case unit files"; fi
		echo "   $case: no diagnostic about unit file content ($(systemd-analyze --version | head -1))"
	done
	# The test must be able to fail: a broken copy of the drop-in is reported.
	assemble "$work/broken" with-fragment
	printf 'SocketBindDeny=tcp:not-a-port\n' >> "$work/broken/nassimhub-agent.service.d/setup-ap.conf"
	systemd-analyze verify "$work/broken/nassimhub-agent.service" > "$work/broken.log" 2>&1 || :
	grep -q -E "^$work/broken/[^ ]+:[0-9]+:" "$work/broken.log" || fail 'a deliberately broken drop-in was not reported; the check above proves nothing'
else
	echo '   SKIPPED: systemd-analyze is not installed (unit syntax NOT checked)'
fi

echo '== 2. polkit rules: decisions against the documented table'
engine=$(command -v node 2>/dev/null || command -v nodejs 2>/dev/null || :)
if [ -n "$engine" ]; then
	python3 "$here/scripts/imagepolicy.py" actions > "$work/actions.tsv"
	cat > "$work/polkit-harness.js" <<'JS'
// Runs each rule file the way polkitd does (rules registered with
// polkit.addRule, asked in order, first non-null result wins) and compares the
// outcome with the documented table.
'use strict';
const fs = require('fs'), path = require('path'), vm = require('vm');
const [table, ...directories] = process.argv.slice(2);
const documented = {};            // file name -> Set of action ids
for (const line of fs.readFileSync(table, 'utf8').split('\n').filter(Boolean)) {
  const [, file, action] = line.split('\t');
  (documented[path.basename(file)] = documented[path.basename(file)] || new Set()).add(action);
}
const everyAction = new Set([].concat(...Object.values(documented).map(set => [...set])));
// Actions nothing documents, which must never be granted: the open share, the
// device-wide switches, a prefix of a granted name and a longer form of one.
for (const extra of ['org.freedesktop.NetworkManager.wifi.share.open', 'org.freedesktop.NetworkManager.enable-disable-network',
  'org.freedesktop.NetworkManager.enable-disable-wifi', 'org.freedesktop.NetworkManager.settings.modify.own',
  'org.freedesktop.NetworkManager', 'org.freedesktop.NetworkManager.wifi.share.protected.extra',
  'org.freedesktop.ModemManager1.Voice', 'org.freedesktop.ModemManager1.Device.Control', 'org.freedesktop.login1.reboot',
  'org.freedesktop.systemd1.manage-units', '']) everyAction.add(extra);
let failures = 0, files = 0;
for (const directory of directories) {
  for (const name of fs.readdirSync(directory).filter(n => n.endsWith('.rules')).sort()) {
    files++;
    const rules = [];
    const polkit = { Result: { YES: 'yes', NO: 'no', AUTH_ADMIN: 'auth_admin', NOT_HANDLED: null },
      addRule: f => rules.push(f), addAdminRule: () => { throw new Error('admin rule'); }, log: () => {}, spawn: () => { throw new Error('spawn'); } };
    try {
      // polkitd's engine is ECMAScript 5: keep the rules to it.
      const source = fs.readFileSync(path.join(directory, name), 'utf8');
      if (/=>|\b(?:let|const|class)\b|`/.test(source.replace(/\/\/[^\n]*/g, ''))) throw new Error('uses syntax newer than ECMAScript 5');
      vm.runInNewContext(source, { polkit }, { filename: name });
    } catch (error) { console.log(`   FAIL ${name}: ${error.message}`); failures++; continue; }
    const expected = documented[name];
    if (!expected) { console.log(`   FAIL ${name}: not in the documented table`); failures++; continue; }
    const decide = (id, user) => { for (const rule of rules) { const r = rule({ id, lookup: () => undefined }, { user, groups: [], local: true, active: true, isInGroup: () => false }); if (r != null) return r; } return null; };
    for (const id of everyAction) {
      for (const user of ['nassimhub', 'root', 'nobody', 'nassimhub2', '']) {
        const want = user === 'nassimhub' && expected.has(id) ? 'yes' : null;
        const got = decide(id, user);
        if (got !== want) { console.log(`   FAIL ${name}: user "${user}", action "${id}": ${got}, expected ${want}`); failures++; }
      }
    }
    console.log(`   ${name}: YES for nassimhub and ${[...expected].join(', ')}; no decision for anything else tried`);
  }
}
if (!files) { console.log('   FAIL: no rule files found'); failures++; }
process.exit(failures ? 1 : 0);
JS
	"$engine" "$work/polkit-harness.js" "$work/actions.tsv" "$here/firmware/overlay/etc/polkit-1/rules.d" "$here/firmware/setup-ap-overlay/etc/polkit-1/rules.d" \
		|| fail 'a polkit rule does not decide as documented'
	# The harness must be able to fail: a rule widened to a prefix match is caught.
	mkdir -p "$work/wide"
	sed 's/action.id === "org.freedesktop.NetworkManager.wifi.share.protected"/action.id.indexOf("org.freedesktop.NetworkManager.wifi.share.") === 0/' \
		"$here/firmware/setup-ap-overlay/etc/polkit-1/rules.d/48-nassimhub-setup-ap.rules" > "$work/wide/48-nassimhub-setup-ap.rules"
	if "$engine" "$work/polkit-harness.js" "$work/actions.tsv" "$work/wide" > "$work/wide.log" 2>&1; then fail 'a rule widened to wifi.share.* was not caught; the check above proves nothing'; fi
	grep -q 'wifi.share.open' "$work/wide.log" || fail 'the widened rule failed for another reason than the open share'
else
	echo '   SKIPPED: no JavaScript engine (node) here; rule DECISIONS not checked. The static shape check in test_tools.py still applies.'
fi

echo 'setup-ap-overlay test PASS (file syntax and rule decisions only; offline; nothing verified on hardware)'
