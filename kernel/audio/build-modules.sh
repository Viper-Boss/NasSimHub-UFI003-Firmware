#!/bin/sh
# Rebuild the module set from source.
#   build-modules.sh KERNEL_SRC_SOUND_SOC_QCOM HEADERS_DIR [CROSS_COMPILE]
# KERNEL_SRC_SOUND_SOC_QCOM: sound/soc/qcom of KyonLi/ufi003-kernel tag 6.12.49-1
# HEADERS_DIR: /usr/src/linux-headers-6.12.49-msm8916-g93a71ee9468d
# CROSS_COMPILE: aarch64-linux-gnu- when not building on the stick/arm64 chroot
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
src=$1 headers=$2 cross=${3:-}
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/sound/soc"
cp -r "$src" "$work/sound/soc/qcom"
(cd "$work" && patch -p1 < "$here/nassimhub-incall-audio.patch")
out="$here/modules.rebuilt"; rm -rf "$out"; mkdir -p "$out/build"
cp -r "$work/sound/soc/qcom/qdsp6" "$out/build/"
cp "$work/sound/soc/qcom/common.c" "$work/sound/soc/qcom/common.h" "$work/sound/soc/qcom/apq8016_sbc.c" "$out/build/"
cp "$here/src/Makefile.outoftree" "$out/build/Makefile"
make -C "$headers" ARCH=arm64 ${cross:+CROSS_COMPILE=$cross} M="$out/build" modules
find "$out/build" -name '*.ko' -exec cp {} "$out/" \;
ls "$out"/*.ko | wc -l
