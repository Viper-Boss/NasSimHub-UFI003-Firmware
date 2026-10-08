#!/bin/sh
set -eu
# Usage: sudo sh install-voice.sh [options] /path/to/holder-arm64
#
#   (no option)                 install ONLY the voice holder, units, polkit rule
#                               and timers. /usr/bin/nassimhub-agent - the factory
#                               agent of the system image - is not touched.
#   --replace-agent FILE        also replace the factory agent with FILE. Needs:
#   --expect-sha256 HEX         the SHA-256 FILE must have (64 hex digits).
#   --supersede-release         allow a replacement that is NEWER than the agent
#                               release currently selected in the state directory
#                               (the factory agent then deselects that release at
#                               its next start; see below).
#   --assume-no-pending-update  only for an update state file this script cannot
#                               read; a readable pending update is never overridden.
#
# Why the agent is no longer replaced by default. /usr/bin/nassimhub-agent is the
# one binary no update rewrites, the one every start begins in, and the version
# no installed release may be older than (agent/ota/boot.go, launch.go). Voice is
# the -voice-media argument of that same binary, not another build, so installing
# voice does not need a different agent. Replacing it moves the update floor and
# the roll-back target, which is why it must be asked for and is checked:
#   - FILE must hash to --expect-sha256, and the bytes installed are re-hashed;
#   - FILE must report, with -version, a version proto.ParseVersion accepts.
#     "dev" and anything else unparsable is refused: such an agent takes no part
#     in updates and cannot be an update floor (ota.NotAReleaseVersion);
#   - it must not be older than the installed factory agent (the floor never
#     moves down);
#   - it must not be newer than the selected stored release unless
#     --supersede-release is given (that release would stop being run).
# Neither mode runs while an update is being applied, awaits confirmation or is
# being rolled back: this script restarts the agent, and a second restart before
# confirmation is what the agent reads as a failed update.
#
# Nothing under the state directory is written, moved or deleted: releases
# (agent-releases/), the update state, identity and pairing files are only read.
# The release key file is only tested for existence.
#
# All or nothing. Every file is written beside its destination and renamed into
# place; if any step fails, or the script is interrupted by a signal, every
# file is put back exactly as it was (including "was not there"), the timers
# are returned to their previous state and the agent this script stopped is
# started again.
#
# Offline test hooks (no root, no device): scripts/test-install-voice.sh runs
# this script against a directory tree with NSH_INSTALL_VOICE_SANDBOX=1 and
# NSH_ROOT=<dir>; `--version-parse` / `--version-compare` print what the version
# reader below makes of its arguments, for the Go test that holds it to
# proto.ParseVersion (test/voiceinstall).

# Byte-wise pattern matching below, whatever the caller's locale.
LC_ALL=C
export LC_ALL

# --- versions, exactly as proto.ParseVersion reads them ----------------------
#
# proto/compat.go: strings.TrimSpace; one leading "v" removed; everything from
# the first "-" or "+" discarded; at most three "."-separated components, each
# a non-empty run of ASCII digits that fits a 64-bit int; missing components
# are 0. test/voiceinstall/version_equivalence_test.go feeds the same strings
# to both implementations and requires the same answer and the same ordering.

# The white space strings.TrimSpace removes: ASCII, then U+0085, U+00A0,
# U+1680, U+2000-U+200A, U+2028, U+2029, U+202F, U+205F, U+3000 as UTF-8.
nv_nl='
'
nv_tab=$(printf '\t')
nv_vt=$(printf '\013')
nv_ff=$(printf '\014')
nv_cr=$(printf '\015')
nv_85=$(printf '\302\205')
nv_a0=$(printf '\302\240')
nv_1680=$(printf '\341\232\200')
nv_2000=$(printf '\342\200\200')
nv_2001=$(printf '\342\200\201')
nv_2002=$(printf '\342\200\202')
nv_2003=$(printf '\342\200\203')
nv_2004=$(printf '\342\200\204')
nv_2005=$(printf '\342\200\205')
nv_2006=$(printf '\342\200\206')
nv_2007=$(printf '\342\200\207')
nv_2008=$(printf '\342\200\210')
nv_2009=$(printf '\342\200\211')
nv_200a=$(printf '\342\200\212')
nv_2028=$(printf '\342\200\250')
nv_2029=$(printf '\342\200\251')
nv_202f=$(printf '\342\200\257')
nv_205f=$(printf '\342\201\237')
nv_3000=$(printf '\343\200\200')

# nsh_num_cmp A B: A and B are digit strings without leading zeros. Sets nc to
# -1, 0 or 1. Digit by digit, so no shell integer width is involved.
nsh_num_cmp() {
	if [ "${#1}" -lt "${#2}" ]; then nc=-1; return 0; fi
	if [ "${#1}" -gt "${#2}" ]; then nc=1; return 0; fi
	nc_a=$1
	nc_b=$2
	while [ -n "$nc_a" ]; do
		nc_x=${nc_a%"${nc_a#?}"}
		nc_y=${nc_b%"${nc_b#?}"}
		if [ "$nc_x" -lt "$nc_y" ]; then nc=-1; return 0; fi
		if [ "$nc_x" -gt "$nc_y" ]; then nc=1; return 0; fi
		nc_a=${nc_a#?}
		nc_b=${nc_b#?}
	done
	nc=0
}

# nsh_version_numbers STRING: sets nv_major, nv_minor, nv_patch (digit strings
# without leading zeros) and returns 0, or returns 1 for a string
# proto.ParseVersion rejects.
nsh_version_numbers() {
	nv_s=$1
	while :; do
		nv_before=$nv_s
		for nv_w in ' ' "$nv_tab" "$nv_nl" "$nv_vt" "$nv_ff" "$nv_cr" "$nv_85" "$nv_a0" "$nv_1680" \
			"$nv_2000" "$nv_2001" "$nv_2002" "$nv_2003" "$nv_2004" "$nv_2005" "$nv_2006" "$nv_2007" \
			"$nv_2008" "$nv_2009" "$nv_200a" "$nv_2028" "$nv_2029" "$nv_202f" "$nv_205f" "$nv_3000"; do
			nv_s=${nv_s#"$nv_w"}
			nv_s=${nv_s%"$nv_w"}
		done
		[ "$nv_s" != "$nv_before" ] || break
	done
	nv_s=${nv_s#v}
	[ -n "$nv_s" ] || return 1
	nv_s=${nv_s%%[-+]*}
	[ -n "$nv_s" ] || return 1
	nv_major=0
	nv_minor=0
	nv_patch=0
	nv_count=0
	while :; do
		case $nv_s in
		*.*) nv_part=${nv_s%%.*}; nv_s=${nv_s#*.}; nv_more=1;;
		*) nv_part=$nv_s; nv_more=0;;
		esac
		nv_count=$((nv_count + 1))
		[ "$nv_count" -le 3 ] || return 1
		case $nv_part in ''|*[!0-9]*) return 1;; esac
		while :; do
			case $nv_part in 0?*) nv_part=${nv_part#0};; *) break;; esac
		done
		# strconv.Atoi on the 64-bit device: at most 9223372036854775807.
		[ "${#nv_part}" -le 19 ] || return 1
		if [ "${#nv_part}" -eq 19 ]; then
			nsh_num_cmp "$nv_part" 9223372036854775807
			[ "$nc" -le 0 ] || return 1
		fi
		case $nv_count in
		1) nv_major=$nv_part;;
		2) nv_minor=$nv_part;;
		3) nv_patch=$nv_part;;
		esac
		[ "$nv_more" = 1 ] || break
	done
	return 0
}

# nsh_version_compare A B: sets vc to -1, 0 or 1 (proto.Version.Compare) and
# returns 0, or returns 1 when either string is not a version.
nsh_version_compare() {
	nsh_version_numbers "$1" || return 1
	vc_major=$nv_major
	vc_minor=$nv_minor
	vc_patch=$nv_patch
	nsh_version_numbers "$2" || return 1
	nsh_num_cmp "$vc_major" "$nv_major"
	vc=$nc
	[ "$vc" = 0 ] || return 0
	nsh_num_cmp "$vc_minor" "$nv_minor"
	vc=$nc
	[ "$vc" = 0 ] || return 0
	nsh_num_cmp "$vc_patch" "$nv_patch"
	vc=$nc
	return 0
}

case ${1:-} in
--version-parse)
	# One line per argument: "ok MAJOR MINOR PATCH" or "reject".
	shift
	for argument in "$@"; do
		if nsh_version_numbers "$argument"; then echo "ok $nv_major $nv_minor $nv_patch"; else echo reject; fi
	done
	exit 0
	;;
--version-compare)
	# One line per PAIR of arguments: -1, 0, 1, or "reject".
	shift
	while [ "$#" -ge 2 ]; do
		if nsh_version_compare "$1" "$2"; then echo "$vc"; else echo reject; fi
		shift 2
	done
	exit 0
	;;
esac

# --- arguments ---------------------------------------------------------------

die() { echo "install-voice.sh: $*" >&2; exit 1; }
usage() {
	cat >&2 <<'USAGE'
usage: install-voice.sh [--replace-agent FILE --expect-sha256 HEX [--supersede-release]]
                        [--assume-no-pending-update] HOLDER
The factory agent /usr/bin/nassimhub-agent is kept unless --replace-agent is given.
USAGE
	exit 1
}

candidate=
expect=
supersede=no
assume_idle=no
holder=
positional=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--replace-agent) [ "$#" -ge 2 ] || usage; candidate=$2; shift 2;;
	--expect-sha256) [ "$#" -ge 2 ] || usage; expect=$2; shift 2;;
	--supersede-release) supersede=yes; shift;;
	--assume-no-pending-update) assume_idle=yes; shift;;
	-h|--help) usage;;
	--) shift; break;;
	-*) echo "install-voice.sh: unknown option $1" >&2; usage;;
	*) positional=$((positional + 1)); holder=$1; shift;;
	esac
done
for argument in "$@"; do positional=$((positional + 1)); holder=$argument; done
if [ "$positional" = 2 ]; then
	echo 'install-voice.sh: two file arguments were given. This script used to be called as' >&2
	echo '  install-voice.sh AGENT HOLDER   and silently replaced the factory agent. It no longer does:' >&2
	echo '  pass only HOLDER to keep the factory agent, or name the agent explicitly with' >&2
	echo '  --replace-agent AGENT --expect-sha256 HEX.' >&2
	exit 1
fi
[ "$positional" = 1 ] || usage
if [ -n "$candidate" ] || [ -n "$expect" ]; then
	if [ -z "$candidate" ] || [ -z "$expect" ]; then die '--replace-agent and --expect-sha256 are only valid together'; fi
	expect=$(printf '%s' "$expect" | tr 'A-F' 'a-f')
	case $expect in *[!0-9a-f]*) die '--expect-sha256 is not hexadecimal';; esac
	[ "${#expect}" = 64 ] || die '--expect-sha256 must be 64 hexadecimal digits'
fi
[ "$supersede" = no ] || [ -n "$candidate" ] || die '--supersede-release is only meaningful with --replace-agent'

# NSH_ROOT is the offline test harness's directory prefix and nothing else:
# systemctl is not redirected by it, so on a real system it must stay unset.
R=${NSH_ROOT:-}
case $R in
''|/) R=;;
/*)
	[ "${NSH_INSTALL_VOICE_SANDBOX:-}" = 1 ] || die 'NSH_ROOT is for the offline test harness only (NSH_INSTALL_VOICE_SANDBOX=1)'
	case $R in *[!A-Za-z0-9/._-]*) die 'NSH_ROOT has unsupported characters';; esac
	R=${R%/}
	;;
*) die 'NSH_ROOT must be an absolute path';;
esac

[ "$(id -u)" = 0 ] || { echo 'root required' >&2; exit 1; }
# shellcheck disable=SC1007 # an empty CDPATH for this one cd
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test "$(uname -m)" = aarch64 || die 'this is not an aarch64 system'
grep -q nassimhub-ufi003 "$R/proc/asound/cards" || die 'the nassimhub-ufi003 sound card is not present'
test -f "$R/etc/nassimhub/local-volte.enabled" || die '/etc/nassimhub/local-volte.enabled is missing: voice has not been accepted on this device'

installed=$R/usr/bin/nassimhub-agent
conf=$R/etc/nassimhub/agent.conf
units=$R/etc/systemd/system
dropins=$units/nassimhub-agent.service.d
libdir=$R/usr/lib/nassimhub
polkit=$R/etc/polkit-1/rules.d
marker=$R/etc/nassimhub/local-volte.enabled
timers='nassimhub-ims-status.timer nassimhub-radio-status.timer'

[ -f "$holder" ] || die "holder $holder is not a file"
[ -f "$installed" ] || die '/usr/bin/nassimhub-agent is missing: there is no factory agent to keep or to compare with'
[ -f "$conf" ] || die '/etc/nassimhub/agent.conf is missing'
for file in query-ims-status nassimhub-ims-status.service nassimhub-ims-status.timer 51-nassimhub-modemmanager-voice.rules \
	nassimhub-agent-voice.conf query-radio-status nassimhub-radio-status.service nassimhub-radio-status.timer; do
	[ -f "$here/$file" ] || die "$file is missing beside this script"
done

# --- what the update mechanism has on this device (read only) ---------------

# The last `key = value` of the agent's configuration, as config.go reads it
# (lower-case keys, optional double quotes).
conf_value() {
	sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$conf" | tail -n 1 | sed 's/[[:space:]]*$//; s/^"*//; s/"*$//'
}
state_dir=$(conf_value state_dir)
[ -n "$state_dir" ] || state_dir=/var/lib/nassimhub
updates=$(conf_value updates)
key_file=$(conf_value ota_keys)
[ -n "$key_file" ] || key_file=/etc/nassimhub/ota-keys.json
releases=$R$state_dir/agent-releases

# "nassimhub-agent 1.15.1 (protocol ...)" -> 1.15.1, as ota.ParseVersionLine
# reads it and with the environment ota.ExecProbe gives a staged binary.
# Prints nothing when the binary does not answer in that form.
agent_version() {
	if command -v timeout >/dev/null 2>&1; then
		av_text=$(timeout 15 env -i PATH=/usr/bin:/bin NSH_AGENT_CHAINED=@probe "$1" -version 2>/dev/null) || return 0
	else
		av_text=$(env -i PATH=/usr/bin:/bin NSH_AGENT_CHAINED=@probe "$1" -version 2>/dev/null) || return 0
	fi
	av_token=$(printf '%s\n' "$av_text" | sed -n '1s/^nassimhub-agent \([^ ]*\).*/\1/p')
	# Only the characters a version is ever built with; anything else is
	# reported as unreadable instead of being interpreted.
	case $av_token in *[!A-Za-z0-9.+_-]*) return 0;; esac
	printf '%s\n' "$av_token"
}
# Why an agent with this version takes no part in updates (ota.NotAReleaseVersion),
# or nothing when it is a release version.
not_a_release() {
	if nsh_version_numbers "$1"; then return 0; fi
	case $1 in
	''|dev) echo "a development build (version \"$1\")";;
	*) echo "version \"$1\", which is not a release version";;
	esac
}
sha256_of() { sha256sum < "$1" | cut -d' ' -f1; }

# The update state. APPLYING, PENDING_CONFIRM and ROLLING_BACK describe an agent
# that has been switched and not settled (ota.go: reset); restarting it now is
# the second restart the agent reads as a failed update.
state_file=$R$state_dir/ota-state.json
# One JSON member per line, however the file was indented.
# shellcheck disable=SC2020 # two characters, both become a newline
split_json() { tr ',{' '\n\n'; }
if [ -s "$state_file" ]; then
	ota_state=$(split_json < "$state_file" | sed -n 's/^[[:space:]]*"state"[[:space:]]*:[[:space:]]*"\([A-Z_]*\)".*/\1/p' | head -n 1)
	case $ota_state in
	APPLYING|PENDING_CONFIRM|ROLLING_BACK)
		die "an agent update is in state $ota_state. This script restarts the agent, which would undo that update. Confirm it on the NAS (or wait for it to roll back by itself), then run this again."
		;;
	'')
		[ "$assume_idle" = yes ] || die "the update state file $state_dir/ota-state.json could not be read. Check on the NAS that no agent update is in progress, then repeat with --assume-no-pending-update."
		echo 'note: the update state file could not be read; continuing because --assume-no-pending-update was given'
		;;
	esac
fi

# The selected stored release, if any: the link is read as installer.go reads
# it (a target that is not a release id is no selection at all), the version
# from the manifest stored beside the binary. The signature is NOT checked
# here - the factory agent does that at every start - so the version is only
# what the stored manifest claims.
release_id=
release_version=
if [ -L "$releases/current" ]; then
	release_id=$(readlink "$releases/current")
	case $release_id in ''|current|previous|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*) release_id=;; esac
	[ "${#release_id}" -le 64 ] || release_id=
fi
if [ -n "$release_id" ] && [ -f "$releases/$release_id/manifest.json" ]; then
	release_version=$(head -c 262144 "$releases/$release_id/manifest.json" | split_json |
		sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
fi

installed_version=$(agent_version "$installed")
installed_reason=$(not_a_release "$installed_version")

# --- the agent: keep, or replace when asked and checked ---------------------

replace=no
factory_version=$installed_version
if [ -z "$candidate" ]; then
	# Voice is an argument of the installed agent; make sure it accepts it.
	"$installed" -config "$conf" -voice-media -check-config
	echo "system agent kept: /usr/bin/nassimhub-agent ${installed_version:-(version unreadable)}"
	[ -z "$installed_reason" ] || echo "WARNING: the installed system agent is $installed_reason: it never installs or starts an update. This script did not change that."
else
	[ -f "$candidate" ] || die "--replace-agent $candidate is not a file"
	actual=$(sha256_of "$candidate")
	[ "$actual" = "$expect" ] || die "the SHA-256 of $candidate is $actual, not the expected $expect; nothing was changed"
	if cmp -s "$candidate" "$installed"; then
		"$installed" -config "$conf" -voice-media -check-config
		echo "system agent kept: $candidate is byte-identical to /usr/bin/nassimhub-agent (${installed_version:-version unreadable})"
	else
		new_version=$(agent_version "$candidate")
		[ -n "$new_version" ] || die "$candidate did not answer -version as nassimhub-agent; nothing was changed"
		new_reason=$(not_a_release "$new_version")
		[ -z "$new_reason" ] || die "refusing $candidate: it is $new_reason. Such an agent never installs or starts an update and cannot be the update floor. Build it with scripts/build-agent.sh VERSION."
		if [ -z "$installed_reason" ]; then
			nsh_version_compare "$new_version" "$installed_version"
			[ "$vc" -ge 0 ] || die "refusing $candidate ($new_version): older than the installed system agent ($installed_version). The update floor never moves down."
		else
			echo "note: the installed system agent is $installed_reason, so there is no version to compare the replacement with"
		fi
		if [ -n "$release_id" ] && [ "$supersede" = no ]; then
			if nsh_version_compare "$release_version" "$new_version"; then
				[ "$vc" -ge 0 ] || die "refusing $candidate ($new_version): the selected agent release $release_id is $release_version, which is older. The new system agent would stop running that release at its next start. Repeat with --supersede-release if that is intended."
			else
				die "refusing $candidate: agent release $release_id is selected and its version could not be read, so the effect on it is unknown. Repeat with --supersede-release if replacing the system agent is intended anyway."
			fi
		fi
		"$candidate" -config "$conf" -voice-media -check-config
		replace=yes
		factory_version=$new_version
		echo "system agent: ${installed_version:-(version unreadable)} -> $new_version (sha256 $expect); $new_version becomes the version no agent update may be older than, and what the device falls back to"
	fi
fi
factory_reason=$(not_a_release "$factory_version")

# Which agent serves after the restart, as boot.go decides it. Stated before
# anything is changed and repeated at the end.
serving="the system agent /usr/bin/nassimhub-agent (${factory_version:-version unreadable})"
serving_why='no agent release is selected in the state directory'
if [ -n "$release_id" ]; then
	case $updates in
	0|f|F|false|FALSE|False)
		serving_why="updates = false in agent.conf, so release $release_id stays stored and is not started"
		;;
	*)
		if [ -n "$factory_reason" ]; then
			serving_why="the system agent is $factory_reason, so release $release_id stays stored and is not started"
		elif [ ! -f "$R$key_file" ]; then
			serving_why="there is no release key file ($key_file), so release $release_id cannot be verified and the agent deselects it"
		elif nsh_version_compare "$release_version" "$factory_version" && [ "$vc" -lt 0 ]; then
			serving_why="release $release_id ($release_version) is older than the system agent, which deselects it at start"
		else
			serving="agent release $release_id (${release_version:-version unreadable}, as its stored manifest says) from $state_dir/agent-releases, NOT /usr/bin/nassimhub-agent"
			serving_why='it remains selected; the system agent verifies its signature and hash at start and, when they hold, runs it instead of itself'
		fi
		;;
	esac
fi
echo "after the restart, expected to serve: $serving"
echo "  because $serving_why"

# --- the transaction ---------------------------------------------------------

backup=$R/var/backups/nassimhub-voice-$(date +%Y%m%d-%H%M%S)
suffix=0
base=$backup
# Two runs within one second must not share (and nest into) one backup.
while [ -e "$backup" ]; do suffix=$((suffix + 1)); backup=$base-$suffix; done
journal=$backup/.rollback
txn_open=no
committed=no
stopped=no
enabled_step=no
restarted=no
agent_was_active=no
created_dirs=
made_backups=no
tmp_suffix=.nsh-new.$$

# restore: put every file, directory, mode, timer and the agent back.
restore() {
	echo 'install-voice.sh: FAILED - restoring the previous state' >&2
	incomplete=no
	if [ -f "$journal/files" ]; then
		while IFS="$nv_tab" read -r kind number target; do
			rm -f "$target$tmp_suffix"
			grep -qxF "$target" "$journal/touched" 2>/dev/null || continue
			case $kind in
			absent) rm -f "$target" || incomplete=yes;;
			saved)
				if cp -a "$journal/$number" "$target$tmp_suffix" && mv -f "$target$tmp_suffix" "$target"; then :; else
					rm -f "$target$tmp_suffix"
					incomplete=yes
				fi
				;;
			esac
		done < "$journal/files"
	fi
	if [ -f "$journal/marker" ]; then
		IFS=' ' read -r owner mode < "$journal/marker"
		chown "$owner" "$marker" || incomplete=yes
		chmod "$mode" "$marker" || incomplete=yes
	fi
	for directory in $created_dirs; do rmdir "$directory" 2>/dev/null || :; done
	if [ "$stopped" = yes ]; then
		systemctl daemon-reload || incomplete=yes
		if [ "$enabled_step" = yes ]; then
			for timer in $timers; do
				[ -f "$journal/enabled.$timer" ] || systemctl disable "$timer" || incomplete=yes
				[ -f "$journal/active.$timer" ] || systemctl stop "$timer" || incomplete=yes
			done
		fi
		if [ "$agent_was_active" = yes ]; then
			systemctl restart nassimhub-agent || incomplete=yes
		elif [ "$restarted" = yes ]; then
			systemctl stop nassimhub-agent || incomplete=yes
		fi
	fi
	if [ "$incomplete" = yes ]; then
		echo "install-voice.sh: THE RESTORE IS INCOMPLETE. The previous files are in $backup (agent, agent.conf, service.d, .rollback/); restore them by hand and restart nassimhub-agent." >&2
	else
		rm -rf "$backup"
		[ "$made_backups" = no ] || rmdir "$R/var/backups" 2>/dev/null || :
		echo 'install-voice.sh: the previous state was restored; nothing was changed' >&2
	fi
}
finish() {
	status=$?
	trap '' HUP INT TERM
	trap - EXIT
	set +e
	if [ "$txn_open" = yes ] && [ "$committed" = no ]; then
		[ "$status" != 0 ] || status=1
		restore
	fi
	exit "$status"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

txn_open=yes
if [ ! -d "$R/var/backups" ]; then
	mkdir -p "$R/var/backups"
	made_backups=yes
fi
mkdir "$backup"
cp -a "$installed" "$backup/agent"
cp -a "$conf" "$backup/agent.conf"
if [ -d "$dropins" ]; then cp -a "$dropins" "$backup/service.d"; else mkdir "$backup/service.d"; fi
echo "backup: $backup"
mkdir "$journal"
: > "$journal/files"
: > "$journal/touched"

for directory in "$libdir" "$dropins"; do
	if [ ! -d "$directory" ]; then
		mkdir "$directory"
		created_dirs="$directory $created_dirs"
	fi
done

# stage MODE SOURCE TARGET: write the new file beside its target and remember
# what the target was. Nothing a running system reads has changed yet.
staged=0
stage() {
	staged=$((staged + 1))
	if [ -e "$3" ] || [ -L "$3" ]; then
		cp -a "$3" "$journal/$staged"
		printf 'saved\t%s\t%s\n' "$staged" "$3" >> "$journal/files"
	else
		printf 'absent\t%s\t%s\n' "$staged" "$3" >> "$journal/files"
	fi
	install -m "$1" "$2" "$3$tmp_suffix"
}
# place TARGET: the rename that makes a staged file the installed one.
place() {
	printf '%s\n' "$1" >> "$journal/touched"
	mv -f "$1$tmp_suffix" "$1"
}

if [ "$replace" = yes ]; then
	stage 0755 "$candidate" "$installed"
	# What gets renamed into place is what was hashed: a file swapped after
	# the first check does not get in.
	[ "$(sha256_of "$installed$tmp_suffix")" = "$expect" ] || die "$candidate changed while it was being installed; nothing was changed"
fi
stage 0755 "$holder" "$libdir/hold-cs-voice"
stage 0755 "$here/query-ims-status" "$libdir/query-ims-status"
stage 0644 "$here/nassimhub-ims-status.service" "$units/nassimhub-ims-status.service"
stage 0644 "$here/nassimhub-ims-status.timer" "$units/nassimhub-ims-status.timer"
stage 0644 "$here/51-nassimhub-modemmanager-voice.rules" "$polkit/51-nassimhub-modemmanager-voice.rules"
stage 0644 "$here/nassimhub-agent-voice.conf" "$dropins/voice.conf"
stage 0755 "$here/query-radio-status" "$libdir/query-radio-status"
stage 0644 "$here/nassimhub-radio-status.service" "$units/nassimhub-radio-status.service"
stage 0644 "$here/nassimhub-radio-status.timer" "$units/nassimhub-radio-status.timer"

# What systemd has now, so that a failure can return to it.
if systemctl is-active --quiet nassimhub-agent; then agent_was_active=yes; fi
for timer in $timers; do
	if systemctl is-enabled --quiet "$timer"; then : > "$journal/enabled.$timer"; fi
	if systemctl is-active --quiet "$timer"; then : > "$journal/active.$timer"; fi
done

stopped=yes
systemctl stop nassimhub-agent
[ "$replace" = no ] || place "$installed"
place "$libdir/hold-cs-voice"
place "$libdir/query-ims-status"
place "$units/nassimhub-ims-status.service"
place "$units/nassimhub-ims-status.timer"
place "$polkit/51-nassimhub-modemmanager-voice.rules"
place "$dropins/voice.conf"
marker_was=$(stat -c '%u:%g %a' "$marker")
printf '%s\n' "$marker_was" > "$journal/marker"
chown root:nassimhub "$marker"
chmod 0640 "$marker"
systemctl daemon-reload
place "$libdir/query-radio-status"
place "$units/nassimhub-radio-status.service"
place "$units/nassimhub-radio-status.timer"
systemctl daemon-reload
enabled_step=yes
# shellcheck disable=SC2086 # the two timer names
systemctl enable --now $timers
restarted=yes
systemctl restart nassimhub-agent
systemctl is-active nassimhub-agent
# "active" straight after a restart is also what an agent shows that is about
# to exit: look once more after it has had time to start (or to fail).
settle=${NSH_VOICE_SETTLE_SECONDS:-3}
case $settle in ''|*[!0-9]*) settle=3;; esac
if [ "$settle" -gt 0 ]; then
	sleep "$settle"
	systemctl is-active nassimhub-agent
fi

committed=yes
rm -rf "$journal" || :

if [ "$replace" = yes ]; then
	echo 'installed: voice holder, units, polkit rule and timers, and the system agent'
else
	echo 'installed: voice holder, units, polkit rule and timers'
fi
echo "expected to serve: $serving"
echo "  because $serving_why"
# What is actually running, when the system can say: the executable of the
# service's main process is the release binary when a release was started.
pid=$(systemctl show -p MainPID --value nassimhub-agent 2>/dev/null || :)
case $pid in ''|0|*[!0-9]*) pid=;; esac
running=
[ -z "$pid" ] || running=$(readlink "$R/proc/$pid/exe" 2>/dev/null || :)
if [ -n "$running" ]; then
	echo "observed: the service's main process is $running"
else
	echo "observed: not available here; \`journalctl -u nassimhub-agent -b | grep 'starting installed release'\` shows whether a release was started"
fi
# Identity, pairing records, releases, release keys, NV and boot are never changed by this installer.
