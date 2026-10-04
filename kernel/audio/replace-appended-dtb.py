#!/usr/bin/env python3
"""Replace the DTB appended to the kernel of an Android boot image (header v0).

    replace-appended-dtb.py --boot boot.img --dtb new.dtb --out boot-audio.img
    replace-appended-dtb.py --boot boot.img --extract current.dtb

The UFI003 boot image carries Image.gz with the DTB appended at the very end of
the kernel section (aboot picks it up from there). Only that trailing DTB is
replaced; the gzip kernel, ramdisk, second stage, cmdline, addresses and page
size are kept byte for byte. The image ID is recomputed the way mkbootimg does.

Refuses anything it does not fully understand: another header version, a
kernel section that does not end in exactly one DTB, or an output that does not
parse back to the same pieces.
"""
import argparse
import hashlib
import struct
import sys

MAGIC = b"ANDROID!"
FDT_MAGIC = b"\xd0\x0d\xfe\xed"
HEADER = struct.Struct("<8s10I16s512s32s1024s")


def pad(n, page):
    return (page - n % page) % page


def parse(data):
    if data[:8] != MAGIC:
        raise SystemExit("not an Android boot image")
    fields = HEADER.unpack_from(data)
    (_, ksz, kaddr, rsz, raddr, ssz, saddr, tags, page, hver, osver,
     name, cmdline, ident, extra) = fields
    if hver != 0:
        raise SystemExit(f"header version {hver} is not supported (expected 0)")
    if page not in (2048, 4096):
        raise SystemExit(f"unexpected page size {page}")
    off = page
    kernel = data[off:off + ksz]
    off += ksz + pad(ksz, page)
    ramdisk = data[off:off + rsz]
    off += rsz + pad(rsz, page)
    second = data[off:off + ssz]
    off += ssz + pad(ssz, page)
    if len(kernel) != ksz or len(ramdisk) != rsz or len(second) != ssz:
        raise SystemExit("image is truncated")
    return dict(fields=list(fields), kernel=kernel, ramdisk=ramdisk,
                second=second, page=page, end=off)


def split_kernel(kernel):
    """Return (image_gz, dtb) where dtb is the single FDT ending the section."""
    if kernel[:2] != b"\x1f\x8b":
        raise SystemExit("kernel is not gzip-compressed Image.gz")
    starts = []
    i = kernel.find(FDT_MAGIC)
    while i >= 0:
        if i + 8 <= len(kernel):
            size = struct.unpack(">I", kernel[i + 4:i + 8])[0]
            if i + size == len(kernel):
                starts.append(i)
        i = kernel.find(FDT_MAGIC, i + 1)
    if len(starts) != 1:
        raise SystemExit(f"expected exactly one appended DTB, found {len(starts)}")
    return kernel[:starts[0]], kernel[starts[0]:]


def build(parsed, kernel):
    f = parsed["fields"]
    page = parsed["page"]
    f[1] = len(kernel)
    sha = hashlib.sha1()
    for blob in (kernel, parsed["ramdisk"], parsed["second"]):
        sha.update(blob)
        sha.update(struct.pack("<I", len(blob)))
    f[13] = sha.digest().ljust(32, b"\0")
    header = HEADER.pack(*f)
    out = bytearray(header + b"\0" * pad(len(header), page))
    for blob in (kernel, parsed["ramdisk"], parsed["second"]):
        out += blob + b"\0" * pad(len(blob), page)
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--boot", required=True)
    ap.add_argument("--dtb")
    ap.add_argument("--out")
    ap.add_argument("--extract")
    a = ap.parse_args()
    data = open(a.boot, "rb").read()
    parsed = parse(data)
    image_gz, old_dtb = split_kernel(parsed["kernel"])
    print(f"kernel: Image.gz {len(image_gz)} bytes + DTB {len(old_dtb)} bytes; "
          f"ramdisk {len(parsed['ramdisk'])} bytes; page {parsed['page']}")
    if a.extract:
        open(a.extract, "wb").write(old_dtb)
        print(f"wrote {a.extract}")
    if not a.dtb:
        return
    if not a.out:
        raise SystemExit("--out is required with --dtb")
    new_dtb = open(a.dtb, "rb").read()
    if new_dtb[:4] != FDT_MAGIC or struct.unpack(">I", new_dtb[4:8])[0] != len(new_dtb):
        raise SystemExit("--dtb is not a well-formed FDT")
    image = build(parsed, image_gz + new_dtb)
    check = parse(image)
    gz2, dtb2 = split_kernel(check["kernel"])
    same = (gz2 == image_gz and dtb2 == new_dtb and check["ramdisk"] == parsed["ramdisk"]
            and check["second"] == parsed["second"]
            and check["fields"][2:13] == parsed["fields"][2:13]
            and check["fields"][14:] == parsed["fields"][14:])
    if not same:
        raise SystemExit("self-check failed; output not written")
    open(a.out, "wb").write(image)
    print(f"wrote {a.out} ({len(image)} bytes): only the appended DTB and image ID changed")


if __name__ == "__main__":
    sys.exit(main())
