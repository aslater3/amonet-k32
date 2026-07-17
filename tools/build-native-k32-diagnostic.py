#!/usr/bin/env python3
"""Build a stock ARM32 boot image containing only the proven EVT DTB."""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


BOOT_MAGIC = b"ANDROID!"
MKIMG_MAGIC = bytes.fromhex("88168858")
ZIMAGE_MAGIC = bytes.fromhex("18286f01")
MKIMG_SIZE = 0x200
ZIMAGE_END = 0x578910
EVT_OFFSET = 0x585185
EVT_SIZE = 0xC875
# LK memcpy()s the appended DTB verbatim to tags_addr, so the blob's own
# totalsize is the only working space libfdt gets. Stock blobs are packed
# tight (slack 0), so creating /chosen/linux,initrd-* fails with NOSPACE.
# Inflate totalsize and zero-pad so the pass-2 copy has room to grow.
EVT_PADDED_SIZE = 0x10000
NEW_PAYLOAD_SIZE = ZIMAGE_END + EVT_PADDED_SIZE
EVT_SHA256 = "f44630ba28f503dd7503bc7cffa2ee96a319acf2f58f1456bb6f5ff23d57dee1"


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def android_id(kernel: bytes, ramdisk: bytes, second: bytes, dt: bytes) -> bytes:
    digest = hashlib.sha1()
    for blob in (kernel, ramdisk, second):
        digest.update(blob)
        digest.update(struct.pack("<I", len(blob)))
    # Legacy mkbootimg v0 only contributes the old DT field when it exists.
    if dt:
        digest.update(dt)
        digest.update(struct.pack("<I", len(dt)))
    return digest.digest().ljust(32, b"\0")


def build(source: Path, output: Path) -> None:
    image = source.read_bytes()
    if image[:8] != BOOT_MAGIC:
        raise SystemExit("ERROR: source is not an Android boot image")

    kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size, second_addr, \
        tags_addr, page_size, dt_size, unused = struct.unpack_from("<10I", image, 8)
    if page_size != 0x800:
        raise SystemExit(f"ERROR: unexpected page size: 0x{page_size:x}")

    kernel_offset = page_size
    old_ramdisk_offset = align(kernel_offset + kernel_size, page_size)
    old_second_offset = align(old_ramdisk_offset + ramdisk_size, page_size)
    old_dt_offset = align(old_second_offset + second_size, page_size)

    kernel = image[kernel_offset:kernel_offset + kernel_size]
    ramdisk = image[old_ramdisk_offset:old_ramdisk_offset + ramdisk_size]
    second = image[old_second_offset:old_second_offset + second_size]
    dt = image[old_dt_offset:old_dt_offset + dt_size]

    if kernel[:4] != MKIMG_MAGIC or len(kernel) < MKIMG_SIZE:
        raise SystemExit("ERROR: stock kernel MediaTek header missing")
    payload_size = struct.unpack_from("<I", kernel, 4)[0]
    payload = kernel[MKIMG_SIZE:MKIMG_SIZE + payload_size]
    if payload[0x24:0x28] != ZIMAGE_MAGIC:
        raise SystemExit("ERROR: ARM zImage magic missing")
    start, end = struct.unpack_from("<II", payload, 0x28)
    if (start, end) != (0, ZIMAGE_END):
        raise SystemExit(f"ERROR: unexpected zImage range: 0x{start:x}-0x{end:x}")

    evt = payload[EVT_OFFSET:EVT_OFFSET + EVT_SIZE]
    evt_hash = hashlib.sha256(evt).hexdigest()
    if len(evt) != EVT_SIZE or evt_hash != EVT_SHA256:
        raise SystemExit(f"ERROR: EVT DTB contract failed: size={len(evt)} sha256={evt_hash}")
    if evt[:4] != bytes.fromhex("d00dfeed"):
        raise SystemExit("ERROR: EVT FDT magic missing")
    if struct.unpack_from(">I", evt, 4)[0] != EVT_SIZE:
        raise SystemExit("ERROR: EVT FDT totalsize mismatch")

    evt_padded = bytearray(EVT_PADDED_SIZE)
    evt_padded[:EVT_SIZE] = evt
    struct.pack_into(">I", evt_padded, 4, EVT_PADDED_SIZE)

    new_payload = payload[:ZIMAGE_END] + bytes(evt_padded)
    if len(new_payload) != NEW_PAYLOAD_SIZE:
        raise SystemExit(f"ERROR: diagnostic payload size is 0x{len(new_payload):x}")
    if new_payload.find(bytes.fromhex("d00dfeed")) != ZIMAGE_END:
        raise SystemExit("ERROR: EVT is not the first appended FDT")
    if new_payload.find(bytes.fromhex("d00dfeed"), ZIMAGE_END + 4) != -1:
        raise SystemExit("ERROR: diagnostic payload contains more than one FDT")

    mkimg = bytearray(kernel[:MKIMG_SIZE])
    struct.pack_into("<I", mkimg, 4, len(new_payload))
    new_kernel = bytes(mkimg) + new_payload

    header = bytearray(image[:page_size])
    struct.pack_into("<I", header, 8, len(new_kernel))
    header[576:608] = android_id(new_kernel, ramdisk, second, dt)

    result = bytearray(header)
    result.extend(new_kernel)
    result.extend(b"\0" * (align(len(result), page_size) - len(result)))
    result.extend(ramdisk)
    result.extend(b"\0" * (align(len(result), page_size) - len(result)))
    result.extend(second)
    result.extend(b"\0" * (align(len(result), page_size) - len(result)))
    result.extend(dt)

    if len(result) > len(image):
        raise SystemExit("ERROR: diagnostic image grew beyond source partition image")
    result.extend(b"\0" * (len(image) - len(result)))
    output.write_bytes(result)

    print(f"native_k32_boot={output}")
    print(f"kernel_addr=0x{kernel_addr:08x} kernel_size=0x{len(new_kernel):x}")
    print(f"zimage_size=0x{ZIMAGE_END:x} evt_offset=0x{ZIMAGE_END:x} evt_size=0x{EVT_PADDED_SIZE:x} evt_raw_size=0x{EVT_SIZE:x}")
    print(f"evt_sha256={EVT_SHA256}")
    print(f"image_sha256={hashlib.sha256(result).hexdigest()}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    build(args.source, args.output)


if __name__ == "__main__":
    main()
