#!/bin/sh
# build-dtb.sh BASE.dtb OUT.dtb [INCLUDE_DIR]
# INCLUDE_DIR defaults to the dt-bindings copies shipped next to this script.
# Decompiles the stick's own DTB, appends ufi003-audio.dtsi, recompiles.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
base=$1 out=$2 inc=${3:-$here/include}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
dtc -q -I dtb -O dts -o "$tmp/base.dts" "$base"
cpp -nostdinc -I "$inc" -undef -x assembler-with-cpp -P "$here/ufi003-audio.dtsi" -o "$tmp/audio.dtsi"
{ cat "$tmp/base.dts"; echo; cat "$tmp/audio.dtsi"; } > "$tmp/merged.dts"
dtc -q -I dts -O dtb -o "$out" "$tmp/merged.dts"
echo "built $out ($(stat -c %s "$out") bytes)"
