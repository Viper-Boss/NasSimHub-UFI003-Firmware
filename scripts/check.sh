#!/bin/sh
# Source checks. Offline: no network, no device, no flashing; every key used is
# a throw-away created in a temporary directory outside the repository.
#
#   sh scripts/check.sh
#
# NSH_GO_FLAGS (optional, test use only) is passed to the go commands of the
# agent module, e.g. -modfile=... on a host whose offline module cache lacks a
# module zip that the committed go.mod pins. A release build never sets it.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
step() { printf '\n==== %s\n' "$*"; }

step 'source privacy check'
python3 "$here/scripts/privacy-check.py"
step 'tool unit tests (boot image, generic package rules, rootfs audit, image policy, SBOM/licence policy)'
python3 "$here/scripts/test_tools.py"
step 'rootfs build: lock, package set, finalize, kernel/vermagic, firmware rules, provenance (hand-written fixtures; no network, no bootstrap)'
python3 "$here/scripts/test_rootfs.py"
step 'device-owned firmware loader: real script in isolated roots (root required for ownership assertions)'
python3 "$here/scripts/test_device_firmware.py"
step 'radio resume: isolated files only; no real radio is started'
python3 "$here/scripts/test_radio_resume.py"
step 'overlay units and polkit rules: syntax, and decisions against the documented grants'
sh "$here/scripts/test-setup-ap-overlay.sh"
step 'SPDX licence coverage of scripts/, kernel/, node/'
python3 "$here/scripts/sbom.py" spdx-coverage
step 'shell syntax'
for script in "$here"/scripts/*.sh "$here"/kernel/audio/*.sh; do sh -n "$script"; done
echo "sh -n: $(ls "$here"/scripts/*.sh "$here"/kernel/audio/*.sh | wc -l) scripts parse"

step 'node: go test and go vet (agent, proto, xport)'
# Module by module with GOWORK=off: that is how the agent is built, and
# -modfile cannot be combined with workspace mode.
cd "$here/node"
for m in agent proto xport; do
 flags=
 [ "$m" != agent ] || flags=${NSH_GO_FLAGS:-}
 # shellcheck disable=SC2086 # $flags is a deliberately word-split flag list.
 (cd "$m"; GOWORK=off CGO_ENABLED=0 go test $flags ./...; GOWORK=off CGO_ENABLED=0 go vet $flags ./...)
done
cd "$here"

step 'voice installer: sandbox with command stand-ins (keeps the factory agent; explicit, verified replacement; full restore on failure)'
sh "$here/scripts/test-install-voice.sh"

# The packaging tests share one agent build. Its directory is temporary
# and removed at the end; nothing is written to build/ or dist/.
work=$(mktemp -d)
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
step 'reproducible agent build (two builds, byte for byte)'
NSH_TEST_DIR="$work" sh "$here/scripts/test-reproducible-build.sh"
step 'OTA packaging: manifest, sign, verify, tamper (throw-away keys)'
NSH_TEST_BUILD_DIR="$work/build-a" sh "$here/scripts/test-package-ota.sh"
step 'factory packaging: Lite/Dev, manifest, generic-package gate, setup access point switch (synthetic inputs)'
NSH_TEST_BUILD_DIR="$work/build-a" sh "$here/scripts/test-package-factory.sh"
step 'rootfs build + factory packaging provenance and repeatable image (SYNTHETIC bootstrap, kernel and modules: not a bootable system)'
NSH_TEST_BUILD_DIR="$work/build-a" sh "$here/scripts/test-build-rootfs.sh"
step 'release key statement: publish, rotation, check (throw-away keys)'
sh "$here/scripts/test-publish-keys.sh"

printf '\ncheck.sh: ALL CHECKS PASSED (offline; nothing here was verified on hardware)\n'
