#!/bin/sh
# Offline sandbox test of deploy/audio/install-voice.sh.
#
#   sh scripts/test-install-voice.sh
#
# No root, no device, no network. The installer runs against a directory tree
# (NSH_ROOT) with stand-ins on PATH for the commands that would act on a real
# system: systemctl (records every call and keeps a small unit state), id,
# uname and chown; and thin wrappers around install, mv, cp, mkdir, chmod, stat
# and sleep that count "steps" and can make exactly one of them fail or hang.
# sha256sum, cmp, sed and the rest are the real tools. The agent is a shell
# script that prints a chosen -version.
#
# What is asserted is the resulting file tree (type, mode, SHA-256 or link
# target of every path) and the recorded systemctl calls - not the installer's
# messages, except where a message IS the behaviour (which agent will serve).
#
# This says nothing about a UFI003: no sound card, no ModemManager, no real
# systemd. It proves the installer's file handling and its decisions.
#
# The same file is used from the Node repository (scripts/) and from the
# firmware repository (scripts/, against node/deploy/audio).
set -eu
# shellcheck disable=SC1007 # an empty CDPATH for this one cd
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
voice=${NSH_VOICE_DIR:-}
if [ -z "$voice" ]; then
	for candidate in "$here/../deploy/audio" "$here/../node/deploy/audio"; do
		[ ! -f "$candidate/install-voice.sh" ] || { voice=$candidate; break; }
	done
fi
if [ -z "$voice" ] || [ ! -f "$voice/install-voice.sh" ]; then echo 'test-install-voice: install-voice.sh not found' >&2; exit 1; fi
# shellcheck disable=SC1007
voice=$(CDPATH= cd -- "$voice" && pwd)
script=$voice/install-voice.sh
table=$here/install-voice-versions.tsv

LC_ALL=C
export LC_ALL
work=$(mktemp -d)
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
cases=0
fail() {
	echo "test-install-voice FAILED: $*" >&2
	[ ! -f "$work/out" ] || sed 's/^/    | /' "$work/out" >&2
	exit 1
}
begin() { cases=$((cases + 1)); echo "== $cases. $*"; }
real_stat=$(PATH=/usr/bin:/bin command -v stat)
mode_of() { "$real_stat" -c %a "$1"; }
inode_of() { "$real_stat" -c %i "$1"; }
sha() { sha256sum < "$1" | cut -d' ' -f1; }

# --- stand-ins ---------------------------------------------------------------

bin=$work/bin
mkdir "$bin"
cat > "$bin/id" <<'EOF'
#!/bin/sh
[ "$*" = -u ] && echo 0
EOF
cat > "$bin/uname" <<'EOF'
#!/bin/sh
[ "$*" = -m ] && echo aarch64
EOF
# One numbered "step" per call that changes something. SBX_FAIL_STEP makes
# that one call fail without doing anything; SBX_HANG_STEP makes it wait
# (announced through $SBX/hanging) so the harness can send a signal.
cat > "$bin/.step" <<'EOF'
n=$(cat "$SBX/step" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$SBX/step"
echo "$n $name $*" >> "$SBX/steps.log"
if [ "$n" = "${SBX_HANG_STEP:-}" ]; then : > "$SBX/hanging"; /bin/sleep 2; fi
if [ "$n" = "${SBX_FAIL_STEP:-}" ]; then echo "$name: injected failure at step $n" >&2; exit 1; fi
EOF
for tool in install mv cp mkdir chmod stat sleep; do
	real=$(PATH=/usr/bin:/bin command -v "$tool")
	cat > "$bin/$tool" <<EOF
#!/bin/sh
name=$tool
. "$bin/.step"
[ "$tool" != sleep ] || exit 0
exec $real "\$@"
EOF
done
# chown root:nassimhub needs root and a group that is not on the build host:
# recorded, not performed.
cat > "$bin/chown" <<EOF
#!/bin/sh
name=chown
. "$bin/.step"
echo "\$*" >> "\$SBX/chown.log"
EOF
# systemctl: unit state is a set of files, $SBX/unit/{active,enabled}.<unit>.
cat > "$bin/systemctl" <<EOF
#!/bin/sh
echo "\$*" >> "\$SBX/systemctl.log"
verb=\$1
shift
quiet=no
now=no
units=
for argument in "\$@"; do
	case \$argument in --quiet) quiet=yes;; --now) now=yes;; -p|MainPID|--value) ;; *) units="\$units \$argument";; esac
done
name=systemctl
case \$verb in
is-enabled) for unit in \$units; do [ -e "\$SBX/unit/enabled.\$unit" ] || exit 1; done; exit 0;;
show) for unit in \$units; do if [ -e "\$SBX/unit/active.\$unit" ]; then echo 4242; else echo 0; fi; done; exit 0;;
is-active)
	if [ "\$quiet" = no ]; then set -- "\$verb" \$units; . "$bin/.step"; fi
	for unit in \$units; do
		[ -e "\$SBX/unit/active.\$unit" ] || { [ "\$quiet" = yes ] || echo inactive; exit 3; }
	done
	[ "\$quiet" = yes ] || echo active
	exit 0
	;;
esac
set -- "\$verb" \$units
. "$bin/.step"
case \$verb in
daemon-reload) ;;
stop) for unit in \$units; do rm -f "\$SBX/unit/active.\$unit"; done;;
start|restart)
	for unit in \$units; do
		# agent-dies: the unit "starts" and is gone again, as an agent that
		# exits at once looks to systemd. One-shot, so the restore can start it.
		if [ "\$unit" = nassimhub-agent ] && [ -e "\$SBX/agent-dies" ]; then
			rm -f "\$SBX/unit/active.\$unit" "\$SBX/agent-dies"
		else
			: > "\$SBX/unit/active.\$unit"
		fi
	done
	;;
enable) for unit in \$units; do : > "\$SBX/unit/enabled.\$unit"; [ "\$now" = no ] || : > "\$SBX/unit/active.\$unit"; done;;
disable) for unit in \$units; do rm -f "\$SBX/unit/enabled.\$unit"; done;;
*) echo "systemctl stand-in: unexpected verb \$verb" >&2; exit 64;;
esac
EOF
chmod 0755 "$bin"/*

# fake_agent FILE VERSION: an "agent" that answers -version and -check-config.
fake_agent() {
	cat > "$1" <<EOF
#!/bin/sh
# synthetic agent stand-in, version $2
case "\$*" in
-version) echo "nassimhub-agent $2 (protocol 1.0, needs core 1.0+, built unknown)";;
*-check-config*) echo 'configuration is valid';;
*) exit 64;;
esac
EOF
	chmod 0755 "$1"
}
# Inputs shared by every case: a holder and candidate agents.
fix=$work/fix
mkdir "$fix"
holder=$fix/holder
printf 'synthetic holder stand-in\n' > "$holder"
for version in 1.15.0 1.15.1 1.16.0 1.18.0 dev voice-test 1.15.0.1; do fake_agent "$fix/agent-$version" "$version"; done
new=$fix/agent-1.16.0
new_sha=$(sha "$new")

# snapshot DIR: type, mode and link target of every path, then the SHA-256 of
# every regular file.
snapshot() {
	(cd "$1" && find . -printf '%y %m %p %l\n' | sort && find . -type f -exec sha256sum {} + | sort -k 2)
}

# --- the sandbox -------------------------------------------------------------

sandboxes=0
# new_sandbox [fresh|installed]: a device tree with factory agent 1.15.1.
# "installed" has an OLDER voice deployment in place (other file contents,
# timers enabled), so a restore has something to put back.
new_sandbox() {
	sandboxes=$((sandboxes + 1))
	SBX=$work/sbx$sandboxes
	ROOT=$SBX/root
	export SBX
	mkdir -p "$SBX/unit" "$ROOT/usr/bin" "$ROOT/usr/lib" "$ROOT/etc/nassimhub" "$ROOT/etc/polkit-1/rules.d" \
		"$ROOT/etc/systemd/system/nassimhub-agent.service.d" "$ROOT/proc/asound" "$ROOT/var/lib/nassimhub" "$ROOT/proc/4242"
	printf ' 0 [nassimhubufi003]: nassimhub-ufi003 - synthetic card\n' > "$ROOT/proc/asound/cards"
	printf 'state_dir = /var/lib/nassimhub\nupdates = true\nota_keys = /etc/nassimhub/ota-keys.json\n' > "$ROOT/etc/nassimhub/agent.conf"
	printf '{"version":1,"ed25519":{"synthetic":"not-a-key"}}\n' > "$ROOT/etc/nassimhub/ota-keys.json"
	: > "$ROOT/etc/nassimhub/local-volte.enabled"
	chmod 0600 "$ROOT/etc/nassimhub/local-volte.enabled"
	printf '[Service]\nMemoryMax=96M\n' > "$ROOT/etc/systemd/system/nassimhub-agent.service.d/resources.conf"
	fake_agent "$ROOT/usr/bin/nassimhub-agent" 1.15.1
	# Stand-ins for what must never be touched.
	printf 'synthetic identity stand-in\n' > "$ROOT/var/lib/nassimhub/device.json"
	printf 'synthetic pairing stand-in\n' > "$ROOT/var/lib/nassimhub/pairing.json"
	ln -s /usr/bin/nassimhub-agent "$ROOT/proc/4242/exe"
	: > "$SBX/unit/active.nassimhub-agent"
	: > "$SBX/systemctl.log"
	: > "$SBX/steps.log"
	: > "$SBX/chown.log"
	if [ "${1:-fresh}" = installed ]; then
		mkdir -p "$ROOT/usr/lib/nassimhub"
		for name in hold-cs-voice query-ims-status query-radio-status; do
			printf 'older %s\n' "$name" > "$ROOT/usr/lib/nassimhub/$name"
			chmod 0755 "$ROOT/usr/lib/nassimhub/$name"
		done
		for name in nassimhub-ims-status.service nassimhub-ims-status.timer nassimhub-radio-status.service nassimhub-radio-status.timer; do
			printf 'older %s\n' "$name" > "$ROOT/etc/systemd/system/$name"
		done
		printf 'older rule\n' > "$ROOT/etc/polkit-1/rules.d/51-nassimhub-modemmanager-voice.rules"
		printf 'older voice.conf\n' > "$ROOT/etc/systemd/system/nassimhub-agent.service.d/voice.conf"
		for timer in nassimhub-ims-status.timer nassimhub-radio-status.timer; do
			: > "$SBX/unit/enabled.$timer"
			: > "$SBX/unit/active.$timer"
		done
	fi
}
# stored_release ID VERSION: a selected release in the state directory, with a
# manifest in the compact form the agent stores.
stored_release() {
	mkdir -p "$ROOT/var/lib/nassimhub/agent-releases/$1"
	fake_agent "$ROOT/var/lib/nassimhub/agent-releases/$1/nassimhub-agent" "$2"
	printf '{"manifest":{"schema_version":1,"release_id":"%s","version":"%s","channel":"stable","min_core_version":"0.0.1","artifacts":[{"kind":"agent","name":"nassimhub-agent","arch":"arm64"}],"notes":"synthetic, \\"version\\":\\"0.0.0\\" in a note"},"key_id":"synthetic","signature":"synthetic"}' "$1" "$2" \
		> "$ROOT/var/lib/nassimhub/agent-releases/$1/manifest.json"
	ln -s "$1" "$ROOT/var/lib/nassimhub/agent-releases/current"
	printf '@factory\n' > "$ROOT/var/lib/nassimhub/agent-releases/rollback-target"
}
# update_state STATE: the update state file as ota.go writes it (indented).
update_state() {
	printf '{\n  "state": "%s",\n  "release_id": "agent-1.17.0",\n  "target_version": "1.17.0",\n  "attempts": 1,\n  "progress_percent": 100,\n  "updated_at": "2026-01-01T00:00:00Z",\n  "expected_restart": true\n}' "$1" \
		> "$ROOT/var/lib/nassimhub/ota-state.json"
}
# run ARGS...: the installer in the sandbox. Sets rc; output in $work/out.
run() {
	rc=0
	# shellcheck disable=SC2086 # AS is empty or a setpriv command line
	${AS:-} env PATH="$bin:/usr/bin:/bin" NSH_INSTALL_VOICE_SANDBOX=1 NSH_ROOT="$ROOT" NSH_VOICE_SETTLE_SECONDS="${SETTLE:-0}" \
		SBX_FAIL_STEP="${FAIL_STEP:-}" SBX_HANG_STEP="${HANG_STEP:-}" sh "$script" "$@" > "$work/out" 2>&1 || rc=$?
}
# before: remember the whole tree, the unit state and the state directory.
before() {
	snapshot "$ROOT" > "$SBX/before"
	ls "$SBX/unit" > "$SBX/units-before"
	snapshot "$ROOT/var/lib/nassimhub" > "$SBX/state-before"
}
# unchanged WHAT: the whole tree and the unit state are what `before` saw.
unchanged() {
	snapshot "$ROOT" > "$SBX/after"
	diff "$SBX/before" "$SBX/after" >&2 || fail "$1: the file tree is not what it was"
	ls "$SBX/unit" > "$SBX/units-after"
	diff "$SBX/units-before" "$SBX/units-after" >&2 || fail "$1: the agent or the timers are not in their previous state"
}
changes() { grep -Ev '^(is-active --quiet|is-enabled --quiet|show) ' "$SBX/systemctl.log" || :; }
# refused WHAT MESSAGE: non-zero, the reason was given, and nothing was even attempted.
refused() {
	[ "$rc" != 0 ] || fail "$1: the installer succeeded"
	grep -q -- "$2" "$work/out" || fail "$1: the refusal does not say '$2'"
	unchanged "$1"
	[ -z "$(changes)" ] || fail "$1: systemctl was asked to change something"
	[ ! -s "$SBX/steps.log" ] || fail "$1: a file operation was attempted"
}
# state_untouched WHAT: releases, identity, pairing and update state are byte for byte what they were.
state_untouched() {
	snapshot "$ROOT/var/lib/nassimhub" > "$SBX/state-after"
	diff "$SBX/state-before" "$SBX/state-after" >&2 || fail "$1: the state directory (releases, identity, pairing, update state) changed"
}
EXPECTED_CALLS='stop nassimhub-agent
daemon-reload
daemon-reload
enable --now nassimhub-ims-status.timer nassimhub-radio-status.timer
restart nassimhub-agent
is-active nassimhub-agent'
# installed_ok WHAT: the nine voice files are the shipped ones, with their modes.
installed_ok() {
	for pair in "755:usr/lib/nassimhub/hold-cs-voice:$holder" \
		"755:usr/lib/nassimhub/query-ims-status:$voice/query-ims-status" \
		"755:usr/lib/nassimhub/query-radio-status:$voice/query-radio-status" \
		"644:etc/systemd/system/nassimhub-ims-status.service:$voice/nassimhub-ims-status.service" \
		"644:etc/systemd/system/nassimhub-ims-status.timer:$voice/nassimhub-ims-status.timer" \
		"644:etc/systemd/system/nassimhub-radio-status.service:$voice/nassimhub-radio-status.service" \
		"644:etc/systemd/system/nassimhub-radio-status.timer:$voice/nassimhub-radio-status.timer" \
		"644:etc/polkit-1/rules.d/51-nassimhub-modemmanager-voice.rules:$voice/51-nassimhub-modemmanager-voice.rules" \
		"644:etc/systemd/system/nassimhub-agent.service.d/voice.conf:$voice/nassimhub-agent-voice.conf"; do
		mode=${pair%%:*}
		rest=${pair#*:}
		target=$ROOT/${rest%%:*}
		source=${rest#*:}
		cmp -s "$source" "$target" || fail "$1: ${rest%%:*} is not the shipped file"
		[ "$(mode_of "$target")" = "$mode" ] || fail "$1: ${rest%%:*} has mode $(mode_of "$target"), not $mode"
	done
	[ "$(mode_of "$ROOT/etc/nassimhub/local-volte.enabled")" = 640 ] || fail "$1: the marker is not 0640"
	grep -q '^root:nassimhub .*/etc/nassimhub/local-volte.enabled$' "$SBX/chown.log" || fail "$1: the marker was not given to root:nassimhub"
	[ -e "$SBX/unit/active.nassimhub-agent" ] || fail "$1: the agent is not running"
	for timer in nassimhub-ims-status.timer nassimhub-radio-status.timer; do
		if [ ! -e "$SBX/unit/enabled.$timer" ] || [ ! -e "$SBX/unit/active.$timer" ]; then fail "$1: $timer is not enabled and started"; fi
	done
	if find "$ROOT" -name '*.nsh-new.*' | grep -q .; then fail "$1: a temporary file was left behind"; fi
	if find "$ROOT/var/backups" -name .rollback | grep -q .; then fail "$1: the roll-back journal was left behind"; fi
	for kept in "$ROOT"/var/backups/nassimhub-voice-*; do
		if [ ! -f "$kept/agent" ] || [ ! -f "$kept/agent.conf" ] || [ ! -d "$kept/service.d" ]; then fail "$1: the backup lacks agent, agent.conf or service.d"; fi
	done
}

# --- the version reader against the shared table -----------------------------

begin 'version reader: every line of install-voice-versions.tsv'
[ -f "$table" ] || fail "$table is missing"
checked=0
tab=$(printf '\t')
while IFS= read -r line; do
	case $line in ''|'#'*) continue;; esac
	expected=${line%%"$tab"*}
	escaped=${line#*"$tab"}
	# shellcheck disable=SC2059 # the column IS a printf format: octal escapes only, % is escaped
	input=$(printf "x${escaped}x")
	input=${input#x}
	input=${input%x}
	got=$(sh "$script" --version-parse "$input")
	[ "$got" = "$expected" ] || fail "version line '$line': the installer says '$got'"
	checked=$((checked + 1))
done < "$table"
[ "$checked" -ge 50 ] || fail "only $checked version cases were read"
[ "$(sh "$script" --version-compare 1.15.1 1.15.1 1.15.1 1.16 v2 1.99.99 1.10 1.9 1.2 1.2.0-rc1 dev 1)" = "0
-1
1
1
0
reject" ] || fail 'version ordering'
echo "   $checked version strings read as expected"

# --- keeping the factory agent -----------------------------------------------

begin 'fresh system: only the holder and configuration are installed, the factory agent is kept'
new_sandbox fresh
agent_before=$(sha "$ROOT/usr/bin/nassimhub-agent")
inode_before=$(inode_of "$ROOT/usr/bin/nassimhub-agent")
before
run "$holder"
[ "$rc" = 0 ] || fail "the installer failed ($rc)"
installed_ok fresh
[ "$(sha "$ROOT/usr/bin/nassimhub-agent")" = "$agent_before" ] || fail 'the factory agent was changed'
[ "$(inode_of "$ROOT/usr/bin/nassimhub-agent")" = "$inode_before" ] || fail 'the factory agent was rewritten'
[ "$(changes)" = "$EXPECTED_CALLS" ] || { changes >&2; fail 'the systemctl calls are not the expected ones'; }
grep -q '^system agent kept: /usr/bin/nassimhub-agent 1.15.1$' "$work/out" || fail 'the kept agent was not reported'
grep -q '^expected to serve: the system agent /usr/bin/nassimhub-agent (1.15.1)$' "$work/out" || fail 'the serving agent was not reported'
grep -q "^observed: the service's main process is /usr/bin/nassimhub-agent$" "$work/out" || fail 'the observed executable was not reported'
state_untouched fresh
snapshot "$ROOT" | grep -v ' \./var/backups' > "$SBX/first"

begin 're-run: idempotent, same tree, factory agent still untouched'
: > "$SBX/systemctl.log"
run "$holder"
[ "$rc" = 0 ] || fail "the second run failed ($rc)"
snapshot "$ROOT" | grep -v ' \./var/backups' > "$SBX/second"
diff "$SBX/first" "$SBX/second" >&2 || fail 'the second run changed the tree'
[ "$(inode_of "$ROOT/usr/bin/nassimhub-agent")" = "$inode_before" ] || fail 'the second run rewrote the factory agent'
[ "$(changes)" = "$EXPECTED_CALLS" ] || fail 'the second run made other systemctl calls'
[ "$(find "$ROOT/var/backups" -mindepth 1 -maxdepth 1 | wc -l)" = 2 ] || fail 'the second run did not make its own backup'
installed_ok re-run
state_untouched re-run

begin 'fresh system without a service.d directory'
new_sandbox fresh
rm -rf "$ROOT/etc/systemd/system/nassimhub-agent.service.d"
run "$holder"
[ "$rc" = 0 ] || fail "the installer failed ($rc)"
installed_ok 'no service.d'

begin 'an older deployment is replaced file by file'
new_sandbox installed
before
run "$holder"
[ "$rc" = 0 ] || fail "the installer failed ($rc)"
installed_ok 'older deployment'
grep -q 'older voice.conf' "$ROOT"/var/backups/nassimhub-voice-*/service.d/voice.conf || fail 'the previous voice.conf is not in the backup'
state_untouched 'older deployment'

begin 'the settle check: the agent is looked at again after the wait'
new_sandbox fresh
SETTLE=1 run "$holder"
[ "$rc" = 0 ] || fail "the installer failed ($rc)"
[ "$(changes | grep -c '^is-active nassimhub-agent$')" = 2 ] || fail 'the agent was not looked at a second time'

begin 'an agent that does not stay up after the restart: everything is put back'
new_sandbox installed
before
: > "$SBX/agent-dies"
run "$holder"
[ "$rc" != 0 ] || fail 'the installer reported success although the agent is not active'
unchanged 'agent not active'
grep -q 'the previous state was restored' "$work/out" || fail 'the restore was not reported'
[ "$(changes | grep -c '^restart nassimhub-agent$')" = 2 ] || fail 'the agent was not restarted on the restored files'

begin 'the old calling convention (AGENT HOLDER) is refused, not obeyed'
new_sandbox fresh
before
run "$new" "$holder"
refused 'two file arguments' 'no longer does'
run --replace-agent "$new" "$holder"
refused 'no hash' 'only valid together'
run --expect-sha256 "$new_sha" "$holder"
refused 'hash without agent' 'only valid together'
run --supersede-release "$holder"
refused '--supersede-release alone' 'only meaningful with --replace-agent'
run
refused 'no argument' 'usage:'

begin 'preconditions: not the validated device'
new_sandbox fresh
rm "$ROOT/etc/nassimhub/local-volte.enabled"
before
run "$holder"
refused 'no marker' 'local-volte.enabled is missing'
new_sandbox fresh
printf ' 0 [other]: some-other-card\n' > "$ROOT/proc/asound/cards"
before
run "$holder"
refused 'no sound card' 'sound card is not present'
new_sandbox fresh
before
rc=0
env PATH="$bin:/usr/bin:/bin" NSH_ROOT="$ROOT" sh "$script" "$holder" > "$work/out" 2>&1 || rc=$?
refused 'NSH_ROOT without the sandbox switch' 'offline test harness only'

# --- every step failing ------------------------------------------------------

# each_step_fails KIND ARGS...: for every step of a successful run, a run in
# which exactly that step fails must end with everything as it was.
each_step_fails() {
	kind=$1
	shift
	new_sandbox "$kind"
	stored_release agent-1.17.0 1.17.0
	run "$@"
	[ "$rc" = 0 ] || fail "the reference run failed ($rc)"
	total=$(cat "$SBX/step")
	cp "$SBX/steps.log" "$work/reference-steps"
	step=1
	while [ "$step" -le "$total" ]; do
		new_sandbox "$kind"
		stored_release agent-1.17.0 1.17.0
		before
		FAIL_STEP=$step run "$@"
		what="step $step of $total ($(sed -n "${step}p" "$SBX/steps.log" | cut -d' ' -f2-4 | sed "s|$ROOT||g"))"
		[ "$rc" != 0 ] || fail "$what failed and the installer reported success"
		unchanged "$what"
		state_untouched "$what"
		grep -q 'the previous state was restored' "$work/out" || fail "$what: the restore was not reported"
		# The agent this run stopped must have been started again.
		if grep -qx 'stop nassimhub-agent' "$SBX/systemctl.log"; then
			sed -n '/^stop nassimhub-agent$/,$p' "$SBX/systemctl.log" | sed 1d | grep -qx 'restart nassimhub-agent' || fail "$what: the agent was stopped and not started again"
		fi
		step=$((step + 1))
	done
	echo "   $total steps, each failed once: tree, timers and agent restored every time"
}
begin 'each step failing, fresh system (the files did not exist before)'
each_step_fails fresh "$holder"
begin 'each step failing, older deployment in place, replacing the agent'
each_step_fails installed --replace-agent "$new" --expect-sha256 "$new_sha" "$holder"

begin 'a target that cannot be written: refused before the agent is stopped'
new_sandbox fresh
rmdir "$ROOT/etc/polkit-1/rules.d"
before
run "$holder"
[ "$rc" != 0 ] || fail 'the installer succeeded without a polkit rules directory'
unchanged 'no polkit directory'
[ -z "$(changes)" ] || fail 'the agent was stopped although nothing could be installed'
# Root is not stopped by a read-only directory, so as root the installer is run
# as an unprivileged user (setpriv) on a sandbox given to that user. The
# stand-in `id` still answers 0, so the installer takes the same path.
unprivileged=
if [ "$(PATH=/usr/bin:/bin id -u)" = 0 ]; then
	if command -v setpriv >/dev/null 2>&1 && setpriv --reuid=65534 --regid=65534 --clear-groups true 2>/dev/null; then
		unprivileged='setpriv --reuid=65534 --regid=65534 --clear-groups'
	else
		unprivileged=unavailable
	fi
fi
if [ "$unprivileged" != unavailable ]; then
	new_sandbox installed
	if [ -n "$unprivileged" ]; then
		chmod 0755 "$work"
		/bin/chown -R 65534:65534 "$SBX"
	fi
	chmod a-w "$ROOT/etc/systemd/system"
	before
	AS=$unprivileged
	run "$holder"
	AS=
	[ "$rc" != 0 ] || fail 'the installer succeeded on a read-only unit directory'
	unchanged 'read-only unit directory'
	[ -z "$(changes)" ] || fail 'the agent was stopped although the unit directory is read-only'
	chmod u+w "$ROOT/etc/systemd/system"
	echo '   read-only directory: refused, nothing changed, agent never stopped'
else
	echo '   NOT RUN: this is root and setpriv cannot drop privileges here, and a read-only directory does not stop root. Covered by the missing-directory case and the failing install steps above; run this test unprivileged for the real permission case.'
fi

begin 'interrupted by a signal while files are being renamed: everything is put back'
for signal in TERM HUP; do
	new_sandbox installed
	stored_release agent-1.17.0 1.17.0
	before
	# The step that hangs: the first rename after the agent was stopped.
	hang=$(grep -n ' mv ' "$work/reference-steps" | head -n 1 | cut -d: -f1)
	env PATH="$bin:/usr/bin:/bin" NSH_INSTALL_VOICE_SANDBOX=1 NSH_ROOT="$ROOT" NSH_VOICE_SETTLE_SECONDS=0 SBX_HANG_STEP="$hang" \
		sh "$script" --replace-agent "$new" --expect-sha256 "$new_sha" "$holder" > "$work/out" 2>&1 &
	pid=$!
	waited=0
	while [ ! -e "$SBX/hanging" ]; do
		waited=$((waited + 1))
		[ "$waited" -le 100 ] || { kill "$pid" 2>/dev/null || :; fail 'the installer never reached the rename'; }
		/bin/sleep 0.1
	done
	kill -s "$signal" "$pid"
	rc=0
	wait "$pid" || rc=$?
	case $signal in TERM) want=143;; HUP) want=129;; esac
	[ "$rc" = "$want" ] || fail "SIG$signal: exit status $rc, not $want"
	unchanged "SIG$signal"
	state_untouched "SIG$signal"
	grep -q 'the previous state was restored' "$work/out" || fail "SIG$signal: the restore was not reported"
	changes | grep -qx 'restart nassimhub-agent' || fail "SIG$signal: the stopped agent was not started again"
done

# --- replacing the factory agent ---------------------------------------------

begin 'replace-agent: verified hash, newer release version'
new_sandbox installed
before
old_sha=$(sha "$ROOT/usr/bin/nassimhub-agent")
run --replace-agent "$new" --expect-sha256 "$(printf '%s' "$new_sha" | tr a-f A-F)" "$holder"
[ "$rc" = 0 ] || fail "the installer failed ($rc)"
installed_ok replace
[ "$(sha "$ROOT/usr/bin/nassimhub-agent")" = "$new_sha" ] || fail 'the factory agent is not the requested binary'
[ "$(mode_of "$ROOT/usr/bin/nassimhub-agent")" = 755 ] || fail 'the factory agent is not 0755'
[ "$(sha "$(echo "$ROOT"/var/backups/nassimhub-voice-*/agent)")" = "$old_sha" ] || fail 'the previous factory agent is not in the backup'
grep -q "^system agent: 1.15.1 -> 1.16.0 (sha256 $new_sha)" "$work/out" || fail 'the replacement was not reported with versions and hash'
grep -q '^expected to serve: the system agent /usr/bin/nassimhub-agent (1.16.0)$' "$work/out" || fail 'the serving agent was not reported'
[ "$(changes)" = "$EXPECTED_CALLS" ] || fail 'replacing made other systemctl calls'
state_untouched replace

begin 'replace-agent: byte-identical to the installed agent is a no-op for the agent'
new_sandbox fresh
inode_before=$(inode_of "$ROOT/usr/bin/nassimhub-agent")
run --replace-agent "$fix/agent-1.15.1" --expect-sha256 "$(sha "$fix/agent-1.15.1")" "$holder"
[ "$rc" = 0 ] || fail "the installer failed ($rc)"
[ "$(inode_of "$ROOT/usr/bin/nassimhub-agent")" = "$inode_before" ] || fail 'an identical agent was rewritten'
grep -q 'byte-identical' "$work/out" || fail 'the identical agent was not reported as kept'

begin 'replace-agent refused: wrong hash, dev, unparsable, older, not an agent'
new_sandbox installed
before
run --replace-agent "$new" --expect-sha256 "$(sha "$holder")" "$holder"
refused 'wrong hash' 'not the expected'
run --replace-agent "$new" --expect-sha256 abc123 "$holder"
refused 'short hash' '64 hexadecimal digits'
run --replace-agent "$fix/agent-dev" --expect-sha256 "$(sha "$fix/agent-dev")" "$holder"
refused 'dev agent' 'a development build (version "dev")'
run --replace-agent "$fix/agent-voice-test" --expect-sha256 "$(sha "$fix/agent-voice-test")" "$holder"
refused 'unparsable version' 'version "voice-test", which is not a release version'
run --replace-agent "$fix/agent-1.15.0.1" --expect-sha256 "$(sha "$fix/agent-1.15.0.1")" "$holder"
refused 'four-component version' 'version "1.15.0.1", which is not a release version'
run --replace-agent "$fix/agent-1.15.0" --expect-sha256 "$(sha "$fix/agent-1.15.0")" "$holder"
refused 'older agent' 'older than the installed system agent (1.15.1)'
run --replace-agent "$holder" --expect-sha256 "$(sha "$holder")" "$holder"
refused 'not an agent' 'did not answer -version'
run --replace-agent "$fix/missing" --expect-sha256 "$new_sha" "$holder"
refused 'missing file' 'is not a file'

begin 'a dev factory agent already on the device: kept with a warning, replaceable by a release build'
new_sandbox fresh
fake_agent "$ROOT/usr/bin/nassimhub-agent" dev
run "$holder"
[ "$rc" = 0 ] || fail "the installer failed ($rc)"
grep -q 'WARNING: the installed system agent is a development build' "$work/out" || fail 'the dev factory agent was not called out'
new_sandbox fresh
fake_agent "$ROOT/usr/bin/nassimhub-agent" dev
run --replace-agent "$new" --expect-sha256 "$new_sha" "$holder"
[ "$rc" = 0 ] || fail "replacing a dev factory agent failed ($rc)"
[ "$(sha "$ROOT/usr/bin/nassimhub-agent")" = "$new_sha" ] || fail 'the dev factory agent was not replaced'

# --- the update mechanism's state --------------------------------------------

begin 'an update awaiting confirmation: refused in both modes, nothing restarted'
for state in PENDING_CONFIRM APPLYING ROLLING_BACK; do
	new_sandbox installed
	stored_release agent-1.17.0 1.17.0
	update_state "$state"
	before
	run "$holder"
	refused "keep, $state" "an agent update is in state $state"
	run --replace-agent "$fix/agent-1.18.0" --expect-sha256 "$(sha "$fix/agent-1.18.0")" --supersede-release "$holder"
	refused "replace, $state" "an agent update is in state $state"
	run --assume-no-pending-update "$holder"
	refused "$state with --assume-no-pending-update" "an agent update is in state $state"
done
new_sandbox fresh
printf '{"state":"PENDING_CONFIRM","release_id":"agent-1.17.0","staged_artifact":{"kind":"agent"}}' > "$ROOT/var/lib/nassimhub/ota-state.json"
before
run "$holder"
refused 'compact state file' 'an agent update is in state PENDING_CONFIRM'

begin 'a settled update state does not block; an unreadable one does until the operator says so'
for state in IDLE ROLLED_BACK FAILED READY; do
	new_sandbox fresh
	update_state "$state"
	before
	run "$holder"
	[ "$rc" = 0 ] || fail "state $state blocked the installer"
	state_untouched "state $state"
done
new_sandbox fresh
printf '{"sta' > "$ROOT/var/lib/nassimhub/ota-state.json"
before
run "$holder"
refused 'unreadable state' 'could not be read'
run --assume-no-pending-update "$holder"
[ "$rc" = 0 ] || fail '--assume-no-pending-update did not let an unreadable state file through'
state_untouched 'unreadable state, overridden'

begin 'a stored release newer than the replacement: the release is what will serve, and it is left alone'
new_sandbox installed
stored_release agent-1.17.0 1.17.0
rm "$ROOT/proc/4242/exe"
ln -s /var/lib/nassimhub/agent-releases/agent-1.17.0/nassimhub-agent "$ROOT/proc/4242/exe"
before
run --replace-agent "$new" --expect-sha256 "$new_sha" "$holder"
[ "$rc" = 0 ] || fail "the installer failed ($rc)"
[ "$(sha "$ROOT/usr/bin/nassimhub-agent")" = "$new_sha" ] || fail 'the factory agent was not replaced'
grep -q '^expected to serve: agent release agent-1.17.0 (1.17.0, as its stored manifest says) from /var/lib/nassimhub/agent-releases, NOT /usr/bin/nassimhub-agent$' "$work/out" \
	|| fail 'the installer did not say that the stored release will serve'
grep -q "^observed: the service's main process is /var/lib/nassimhub/agent-releases/agent-1.17.0/nassimhub-agent$" "$work/out" || fail 'the observed release binary was not reported'
state_untouched 'newer stored release'
[ "$(readlink "$ROOT/var/lib/nassimhub/agent-releases/current")" = agent-1.17.0 ] || fail 'the release selection changed'

begin 'keeping the agent with a stored release selected: said plainly'
new_sandbox fresh
stored_release agent-1.17.0 1.17.0
before
run "$holder"
[ "$rc" = 0 ] || fail "the installer failed ($rc)"
grep -q '^expected to serve: agent release agent-1.17.0 (1.17.0' "$work/out" || fail 'the selected release was not reported as serving'
state_untouched 'keep with release'

begin 'a replacement newer than the selected release: refused unless --supersede-release'
new_sandbox installed
stored_release agent-1.17.0 1.17.0
before
run --replace-agent "$fix/agent-1.18.0" --expect-sha256 "$(sha "$fix/agent-1.18.0")" "$holder"
refused 'newer than the release' 'Repeat with --supersede-release'
run --replace-agent "$fix/agent-1.18.0" --expect-sha256 "$(sha "$fix/agent-1.18.0")" --supersede-release "$holder"
[ "$rc" = 0 ] || fail "--supersede-release failed ($rc)"
grep -q 'because release agent-1.17.0 (1.17.0) is older than the system agent, which deselects it at start' "$work/out" || fail 'the effect on the release was not stated'
state_untouched 'superseded release'

begin 'updates = false, a dev factory agent or no key file: the stored release is not what serves'
new_sandbox fresh
stored_release agent-1.17.0 1.17.0
printf 'state_dir = "/var/lib/nassimhub"\nupdates = false\n' > "$ROOT/etc/nassimhub/agent.conf"
run "$holder"
[ "$rc" = 0 ] || fail "the installer failed ($rc)"
grep -q '^expected to serve: the system agent /usr/bin/nassimhub-agent (1.15.1)$' "$work/out" || fail 'updates = false: wrong serving agent'
grep -q 'because updates = false in agent.conf' "$work/out" || fail 'updates = false: reason not given'
new_sandbox fresh
stored_release agent-1.17.0 1.17.0
rm "$ROOT/etc/nassimhub/ota-keys.json"
run "$holder"
grep -q 'because there is no release key file' "$work/out" || fail 'no key file: reason not given'
new_sandbox fresh
stored_release agent-1.17.0 1.17.0
rm "$ROOT/var/lib/nassimhub/agent-releases/current"
ln -s ../../../etc/passwd "$ROOT/var/lib/nassimhub/agent-releases/current"
before
run "$holder"
[ "$rc" = 0 ] || fail "the installer failed ($rc)"
grep -q '^expected to serve: the system agent' "$work/out" || fail 'a link that is not a release id was treated as a selection'
state_untouched 'bogus link'

echo "test-install-voice PASS: $cases groups in $sandboxes sandboxes (offline stand-ins for systemctl and the agent; nothing here ran on a device)"
