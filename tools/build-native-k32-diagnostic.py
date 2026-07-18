#!/usr/bin/env python3
"""Build a stock ARM32 boot image containing only the proven EVT DTB."""

from __future__ import annotations

import argparse
import hashlib
import struct
import subprocess
import tempfile
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

# The stock zImage starts with eight ARM NOPs (0x00-0x1f), then the entry
# branch at 0x20 and the magic/start/end header fields. Replace exactly the
# NOP sled with an 8-instruction UART probe that writes 'K': if 'K' appears
# on the serial log, the CPU fetched and executed code at 0x40008000, which
# distinguishes an interworking/first-fetch failure from a fault later in
# zImage startup. The probe clobbers only r3/r12 (unspecified at kernel
# entry) and preserves the ABI registers r0/r1/r2. It is assembled with the
# same toolchain as the LK payload -- never hand-encoded.
ARM_NOP = struct.pack("<I", 0xE1A00000)
ENTRY_BRANCH = 0xEA000003
ENTRY_PROBE_ASM = """\
    .syntax unified
    .arm
    .text
    .global _start
_start:
    movw    r3, #0x2014
    movt    r3, #0x1100      @ r3 = UART LSR (0x11002014)
1:  ldr     r12, [r3]
    tst     r12, #0x20
    beq     1b
    sub     r3, r3, #0x14    @ r3 = UART THR (0x11002000)
    mov     r12, #'K'
    str     r12, [r3]
"""

# Decompression-completion probe. The stock zImage finishes decompression in
# __enter_kernel with "mov r0, #0; mov pc, r4" at offsets 0x920/0x924, followed
# by a 6-NOP sled (0x928-0x93f). The mov pc, r4 word (e1a0f004) is unique in
# the whole zImage and reached only by fall-through from 0x920, so it can be
# redirected into the sled. The sled writes 'D' to the UART and continues with
# bx r4 into the decompressed kernel. No THRE poll: the UART has been idle for
# seconds by then, and a poll loop would not fit in six words. Clobbers only
# r3/r12; preserves the kernel ABI registers and r4 (entry target). The code
# is position-independent because the zImage executes from its self-relocated
# copy at this point.
DEJUMP_NOP = struct.pack("<I", 0xE320F000)
DEJUMP_OFF = 0x924
DEJUMP_MOV_PC_R4 = 0xE1A0F004
DEJUMP_BRANCH = 0xEAFFFFFF  # from 0x924: branches to the next word (the sled)
DEJUMP_SLED_OFF = 0x928
DEJUMP_SLED_SIZE = 6
DEJUMP_PROBE_ASM = """\
    .syntax unified
    .arm
    .text
    .global _start
_start:
    movw    r3, #0x2000
    movt    r3, #0x1100      @ r3 = UART THR (0x11002000)
    mov     r12, #'D'
    str     r12, [r3]
    bx      r4               @ continue into the decompressed kernel
"""


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def assemble_probe(asm: str, expected_size: int, name: str) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "probe.s"
        obj = Path(td) / "probe.o"
        raw = Path(td) / "probe.bin"
        src.write_text(asm)
        subprocess.run(
            ["arm-none-eabi-as", "-march=armv7-a", "-o", str(obj), str(src)],
            check=True)
        subprocess.run(
            ["arm-none-eabi-objcopy", "-O", "binary", "-j", ".text",
             str(obj), str(raw)],
            check=True)
        blob = raw.read_bytes()
    if len(blob) != expected_size:
        raise SystemExit(
            f"ERROR: {name} probe is 0x{len(blob):x} bytes, "
            f"expected 0x{expected_size:x}")
    return blob


def assemble_entry_probe() -> bytes:
    return assemble_probe(ENTRY_PROBE_ASM, 0x20, "entry")


def assemble_dejump_probe() -> bytes:
    # 5 of the 6 sled words; the last word must stay a NOP.
    return assemble_probe(DEJUMP_PROBE_ASM, (DEJUMP_SLED_SIZE - 1) * 4,
                          "decompression")


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

    # Entry probe: assert the stock NOP sled and entry header, then replace
    # exactly the sled (0x00-0x1f). The branch at 0x20 and every header
    # field from 0x24 onward must survive untouched.
    if payload[:0x20] != ARM_NOP * 8:
        raise SystemExit("ERROR: zImage entry NOP sled contract failed")
    if struct.unpack_from("<I", payload, 0x20)[0] != ENTRY_BRANCH:
        raise SystemExit("ERROR: zImage entry branch contract failed")
    probe = assemble_entry_probe()
    payload = probe + payload[0x20:]
    if payload[0x24:0x28] != ZIMAGE_MAGIC:
        raise SystemExit("ERROR: ARM zImage magic missing")
    start, end = struct.unpack_from("<II", payload, 0x28)
    if (start, end) != (0, ZIMAGE_END):
        raise SystemExit(f"ERROR: unexpected zImage range: 0x{start:x}-0x{end:x}")
    if struct.unpack_from("<I", payload, 0x20)[0] != ENTRY_BRANCH:
        raise SystemExit("ERROR: entry probe clobbered the zImage branch")

    # Decompression-completion probe: redirect the unique __enter_kernel
    # "mov pc, r4" into the following NOP sled and place the 'D' marker there.
    if struct.unpack_from("<I", payload, DEJUMP_OFF - 4)[0] != 0xE3A00000:
        raise SystemExit("ERROR: __enter_kernel mov r0,#0 contract failed")
    if struct.unpack_from("<I", payload, DEJUMP_OFF)[0] != DEJUMP_MOV_PC_R4:
        raise SystemExit("ERROR: __enter_kernel mov pc,r4 contract failed")
    if payload.count(struct.pack("<I", DEJUMP_MOV_PC_R4)) != 1:
        raise SystemExit("ERROR: mov pc,r4 is not unique in the zImage")
    sled_end = DEJUMP_SLED_OFF + DEJUMP_SLED_SIZE * 4
    if payload[DEJUMP_SLED_OFF:sled_end] != DEJUMP_NOP * DEJUMP_SLED_SIZE:
        raise SystemExit("ERROR: __enter_kernel NOP sled contract failed")
    dprobe = assemble_dejump_probe()
    payload = bytearray(payload)
    struct.pack_into("<I", payload, DEJUMP_OFF, DEJUMP_BRANCH)
    payload[DEJUMP_SLED_OFF:DEJUMP_SLED_OFF + len(dprobe)] = dprobe
    payload = bytes(payload)
    if payload[sled_end - 4:sled_end] != DEJUMP_NOP:
        raise SystemExit("ERROR: decompression probe overran the NOP sled")

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
    print("zimage_probe=" + " ".join(f"{w:08x}" for w in struct.unpack("<8I", probe)))
    print("zimage_dejump=" + " ".join(
        f"{w:08x}" for w in struct.unpack("<6I", payload[DEJUMP_OFF:DEJUMP_OFF + 0x18])))
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
