#!/usr/bin/env python3
"""Build a stock ARM32 boot image containing only the proven EVT DTB."""

from __future__ import annotations

import argparse
import binascii
import hashlib
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path
from typing import TypedDict


class HeadProbeMetadata(TypedDict):
    marker: str
    raw_head: bytes
    old_stream_size: int
    new_stream_size: int


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

# The compressed kernel embedded in the stock zImage.  The H probe changes
# only the first two decompressed words, recompresses into the original gzip
# envelope, and zero-pads any saved bytes so no zImage/DTB offsets move.
KERNEL_GZIP_OFFSET = 0x46D8
KERNEL_GZIP_SIZE = 0x5741FB
KERNEL_GZIP_END = KERNEL_GZIP_OFFSET + KERNEL_GZIP_SIZE
DECOMPRESSED_KERNEL_SIZE = 0xB86070
STOCK_DECOMPRESSED_SHA256 = "3eac3f3daf9daa04f1b67e78c3f2b1ead9a74d64aae435ef5f1988916d31cbd2"
STOCK_DECOMPRESSED_HEAD = bytes.fromhex(
    "ee4700eb00900fe11a9029e21f0019e3")
# str r12,[r3] emits H using state carried by the D trampoline.  The original
# BL __hyp_stub_install moves from 0x40008000 to 0x40008004, so its immediate
# changes by one word.  The displaced MRS r9,CPSR runs in the D trampoline.
HEAD_ENTRY_PROBE = bytes.fromhex("00c083e5ed4700eb")

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

# Decompression-completion/head-entry probe. Replace mov pc,r4 plus its six
# trailing NOPs with seven instructions. It writes D, prepares r3/r12 so the
# first decompressed instruction can write H, moves the displaced head.S
# MRS r9,CPSR here, and branches through r4. Thus KD means the decompressor
# completed but head.S did not execute; KDH proves the decompressed entry ran.
DEJUMP_NOP = struct.pack("<I", 0xE320F000)
DEJUMP_OFF = 0x924
DEJUMP_MOV_PC_R4 = 0xE1A0F004
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
    mov     r12, #'H'       @ consumed by patched head.S first instruction
    mrs     r9, cpsr        @ displaced head.S instruction at 0x40008004
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
    # Replaces mov pc,r4 plus all six following NOPs.
    return assemble_probe(DEJUMP_PROBE_ASM, (DEJUMP_SLED_SIZE + 1) * 4,
                          "decompression")


def decompress_kernel_image(zimage: bytes) -> bytes:
    """Return the first gzip member's decompressed ARM Image."""
    offset = zimage.find(b"\x1f\x8b\x08")
    if offset != KERNEL_GZIP_OFFSET:
        raise SystemExit(f"ERROR: kernel gzip offset is 0x{offset:x}")
    stream = zlib.decompressobj(16 + zlib.MAX_WBITS)
    raw = stream.decompress(zimage[offset:]) + stream.flush()
    if not stream.eof:
        raise SystemExit("ERROR: kernel gzip stream is truncated")
    return raw


def install_head_entry_probe(zimage: bytes) -> tuple[bytes, HeadProbeMetadata]:
    """Install H at decompressed head.S without changing zImage geometry."""
    offset = zimage.find(b"\x1f\x8b\x08")
    if offset != KERNEL_GZIP_OFFSET:
        raise SystemExit(f"ERROR: kernel gzip offset is 0x{offset:x}")
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    raw = bytearray(inflater.decompress(zimage[offset:]) + inflater.flush())
    consumed = len(zimage[offset:]) - len(inflater.unused_data)
    if not inflater.eof or consumed != KERNEL_GZIP_SIZE:
        raise SystemExit(f"ERROR: kernel gzip size is 0x{consumed:x}")
    if len(raw) != DECOMPRESSED_KERNEL_SIZE:
        raise SystemExit(f"ERROR: decompressed kernel size is 0x{len(raw):x}")
    if hashlib.sha256(raw).hexdigest() != STOCK_DECOMPRESSED_SHA256:
        raise SystemExit("ERROR: decompressed stock kernel hash mismatch")
    if bytes(raw[:len(STOCK_DECOMPRESSED_HEAD)]) != STOCK_DECOMPRESSED_HEAD:
        raise SystemExit("ERROR: decompressed head.S contract changed")

    raw[:len(HEAD_ENTRY_PROBE)] = HEAD_ENTRY_PROBE
    header = zimage[offset:offset + 10]
    if len(header) != 10 or header[:3] != b"\x1f\x8b\x08" or header[3] != 0:
        raise SystemExit("ERROR: unsupported stock gzip header")
    compressor = zlib.compressobj(8, zlib.DEFLATED, -15)
    deflate = compressor.compress(bytes(raw)) + compressor.flush()
    new_stream = header + deflate + struct.pack(
        "<II", binascii.crc32(raw) & 0xFFFFFFFF, len(raw) & 0xFFFFFFFF)
    if len(new_stream) > consumed:
        raise SystemExit("ERROR: H-probed kernel no longer fits stock gzip envelope")

    # head.S uses input_data_end - 4 as an out-of-band inflated-size word for
    # overlap/self-relocation decisions. A shorter gzip member may leave slack,
    # but the fixed envelope must still end in the original Image size. Zeroing
    # this word makes r9=0 and lets decompression overwrite its own stack.
    slack = consumed - len(new_stream)
    if slack < 4:
        raise SystemExit("ERROR: H-probed gzip has no room for terminal size word")
    envelope = (new_stream + b"\0" * (slack - 4) +
                struct.pack("<I", len(raw)))
    result = bytearray(zimage)
    result[offset:offset + consumed] = envelope
    metadata: HeadProbeMetadata = {
        "marker": "H",
        "raw_head": bytes(raw[:8]),
        "old_stream_size": consumed,
        "new_stream_size": len(new_stream),
    }
    return bytes(result), metadata


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

    # Patch the first decompressed head.S instructions inside the gzip member
    # while retaining the stock zImage size and every appended-DTB offset.
    zimage, head_meta = install_head_entry_probe(payload[:ZIMAGE_END])
    payload = zimage + payload[ZIMAGE_END:]

    # Decompression-completion probe: replace the unique __enter_kernel
    # "mov pc, r4" and all six following NOPs with the D-to-H trampoline.
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
    payload[DEJUMP_OFF:sled_end] = dprobe
    payload = bytes(payload)
    if len(dprobe) != (DEJUMP_SLED_SIZE + 1) * 4:
        raise SystemExit("ERROR: decompression/head trampoline size changed")

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
        f"{w:08x}" for w in struct.unpack("<7I", payload[DEJUMP_OFF:DEJUMP_OFF + 0x1C])))
    print(f"head_probe=H raw_head={head_meta['raw_head'].hex()} "
          f"gzip=0x{head_meta['new_stream_size']:x}/0x{head_meta['old_stream_size']:x}")
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
