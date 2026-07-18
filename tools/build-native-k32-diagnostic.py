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

# The compressed kernel embedded in the stock zImage.  The H/I probe replaces
# only the first word with a branch and consumes six verified alignment NOPs
# after __error_p's infinite loop. Every displaced head.S instruction is
# executed at the same semantic point before resuming untouched code.
KERNEL_GZIP_OFFSET = 0x46D8
KERNEL_GZIP_SIZE = 0x5741FB
KERNEL_GZIP_END = KERNEL_GZIP_OFFSET + KERNEL_GZIP_SIZE
DECOMPRESSED_KERNEL_SIZE = 0xB86070
STOCK_DECOMPRESSED_SHA256 = "3eac3f3daf9daa04f1b67e78c3f2b1ead9a74d64aae435ef5f1988916d31cbd2"
STOCK_DECOMPRESSED_HEAD = bytes.fromhex(
    "ee4700eb"  # 0x00 bl __hyp_stub_install
    "00900fe1"  # 0x04 mrs r9,cpsr
    "1a9029e2"  # 0x08 eor r9,r9,#HYP_MODE
    "1f0019e3"  # 0x0c tst r9,#MODE_MASK
    "1f90c9e3"  # 0x10 bic r9,r9,#MODE_MASK
    "d39089e3"  # 0x14 orr r9,r9,#(SVC|IRQ|FIQ)
)
DECOMPRESSED_BASE = 0x40008000
HEAD_TRAMPOLINE_OFF = 0x8C8
HEAD_TRAMPOLINE_ADDR = DECOMPRESSED_BASE + HEAD_TRAMPOLINE_OFF
HEAD_TRAMPOLINE_SIZE = 0x18
HEAD_HYP_STUB_ADDR = 0x40019FC0
HEAD_RESUME_ADDR = 0x40008008
HEAD_CAVE_STOCK = struct.pack("<I", 0xE320F000) * 6
# Independently pinned encoding; install_head_entry_probe also assembles it
# from HEAD_ENTRY_BRANCH_ASM and rejects any toolchain disagreement.
HEAD_ENTRY_BRANCH = bytes.fromhex("300200ea")
HEAD_ENTRY_BRANCH_ASM = f"""\
    .syntax unified
    .arm
    .text
    .global _start
    .equ HEAD_PROBE, 0x{HEAD_TRAMPOLINE_ADDR:08x}
_start:
    b       HEAD_PROBE
"""
HEAD_TRAMPOLINE_ASM = f"""\
    .syntax unified
    .arm
    .text
    .global _start
    .equ HYP_STUB, 0x{HEAD_HYP_STUB_ADDR:08x}
    .equ HEAD_RESUME, 0x{HEAD_RESUME_ADDR:08x}
_start:
    str     r12, [r3]       @ H: decompressed head trampoline entered
    bl      HYP_STUB
    mov     r12, #'I'
    str     r12, [r3]       @ I: __hyp_stub_install returned
    mrs     r9, cpsr        @ original head.S instruction at offset 0x04
    b       HEAD_RESUME     @ resume at original eor r9,r9,#HYP_MODE
"""

# Expanded one-shot head.S boundary probe. The 0xFAC-byte zero run at
# 0x40775054 is padding between a stock literal-pool block and the
# initcall_debug format string, has no direct B/BL sources, and has no
# little-endian pointers into it. Use nine fixed 0x40-byte marker slots; the
# rest of the zero run remains untouched.
HEAD_WRAPPER_CAVE_OFF = 0x76D054
HEAD_WRAPPER_CAVE_ADDR = DECOMPRESSED_BASE + HEAD_WRAPPER_CAVE_OFF
HEAD_WRAPPER_SLOT_SIZE = 0x40
HEAD_WRAPPER_CAVE_SIZE = 9 * HEAD_WRAPPER_SLOT_SIZE
HEAD_WRAPPER_STOCK = b"\0" * HEAD_WRAPPER_CAVE_SIZE
HEAD_WRAPPER_MARKERS = "SPLVUTFCE"
HEAD_MARKER_SEQUENCE = "HI" + HEAD_WRAPPER_MARKERS

# kind:
#   sp:   the stock msr at 0x30 has already completed; execute mrc and S/P
#         markers in one cave, then resume at 0x38
#   call: BL to wrapper, save inherited r11/LR, BL original, marker, restore
#         r11/return through the saved LR
#   ce:   the CPU init returned to the stock branch; emit C/E and branch on
#         to __enable_mmu
_HEAD_WRAPPER_DEFS = (
    {"site": 0x0034, "offset": 0x000, "marker": "SP", "kind": "sp",
     "target": 0x40008038, "stock": "109f10ee"},
    {"site": 0x0038, "offset": 0x040, "marker": "L", "kind": "call",
     "target": 0x40008878, "stock": "0e0200eb"},
    {"site": 0x0054, "offset": 0x080, "marker": "V", "kind": "call",
     "target": 0x4000821C, "stock": "700000eb"},
    {"site": 0x0058, "offset": 0x0C0, "marker": "U", "kind": "call",
     "target": 0x4000813C, "stock": "370000eb"},
    {"site": 0x005C, "offset": 0x100, "marker": "F", "kind": "call",
     "target": 0x400081C8, "stock": "590000eb"},
    {"site": 0x0060, "offset": 0x140, "marker": "T", "kind": "call",
     "target": 0x40008084, "stock": "070000eb"},
    {"site": 0x0074, "offset": 0x180, "marker": "CE", "kind": "ce",
     "target": 0x400087C4, "stock": "d20100ea"},
)
HEAD_WRAPPER_PATCH_SITES = tuple(
    (definition["site"], definition["offset"]) for definition in _HEAD_WRAPPER_DEFS
)
_HEAD_WRAPPER_BY_SITE = {
    definition["site"]: definition for definition in _HEAD_WRAPPER_DEFS
}
_HEAD_WRAPPER_CALL_SITES = {
    definition["site"] for definition in _HEAD_WRAPPER_DEFS
    if definition["kind"] == "call"
}
# Every call wrapper must preserve the caller's r11 and return address across
# the stock call.  These are independent word pins: assembler output remains
# authoritative, but a drift in the push/pop contract fails closed.
HEAD_WRAPPER_CALL_START = bytes.fromhex("00482de9")  # push {r11, lr}
HEAD_WRAPPER_CALL_END = bytes.fromhex("0088bde8")    # pop {r11, pc}
# Independent encoding pins. The assembler remains authoritative for
# generation; these constants make a toolchain or source drift fail closed.
HEAD_WRAPPER_PATCH_EXPECTED = {
    0x0034: bytes.fromhex("06b41dea"),
    0x0038: bytes.fromhex("15b41deb"),
    0x0054: bytes.fromhex("1eb41deb"),
    0x0058: bytes.fromhex("2db41deb"),
    0x005C: bytes.fromhex("3cb41deb"),
    0x0060: bytes.fromhex("4bb41deb"),
    0x0074: bytes.fromhex("56b41dea"),
}
HEAD_WRAPPER_SLOT_EXPECTED = {
    0x000: bytes.fromhex(
        "003002e3003141e353c0a0e300c083e5109f10ee"
        "003002e3003141e350c0a0e300c083e5ee4be2ea"),
    0x040: bytes.fromhex(
        "00482de9f64de2eb003002e3003141e34cc0a0e300c083e5"
        "0088bde8"),
    0x080: bytes.fromhex(
        "00482de94f4ce2eb003002e3003141e356c0a0e300c083e5"
        "0088bde8"),
    0x0C0: bytes.fromhex(
        "00482de9074ce2eb003002e3003141e355c0a0e300c083e5"
        "0088bde8"),
    0x100: bytes.fromhex(
        "00482de91a4ce2eb003002e3003141e346c0a0e300c083e5"
        "0088bde8"),
    0x140: bytes.fromhex(
        "00482de9b94be2eb003002e3003141e354c0a0e300c083e5"
        "0088bde8"),
    0x180: bytes.fromhex(
        "003002e3003141e343c0a0e300c083e5"
        "003002e3003141e345c0a0e300c083e5724de2ea"),
}


def expected_head_wrappers() -> bytes:
    expected = bytearray(HEAD_WRAPPER_CAVE_SIZE)
    for offset, blob in HEAD_WRAPPER_SLOT_EXPECTED.items():
        expected[offset:offset + len(blob)] = blob
    return bytes(expected)


def _head_wrapper_asm() -> str:
    lines = [
        "    .syntax unified",
        "    .arm",
        "    .text",
        "    .global _start",
        "    .macro EMIT marker",
        "    movw    r3, #0x2000",
        "    movt    r3, #0x1100",
        "    mov     r12, #\\marker",
        "    str     r12, [r3]",
        "    .endm",
    ]
    for definition in _HEAD_WRAPPER_DEFS:
        lines.append(f"    .org 0x{definition['offset']:03x}")
        if definition["offset"] == 0:
            lines.append("_start:")
        lines.append(f"wrapper_{definition['marker']}:")
        if definition["kind"] == "sp":
            lines.extend([
                "    EMIT    'S'",
                "    mrc     p15, 0, r9, c0, c0",
                "    EMIT    'P'",
                f"    b       0x{definition['target']:08x}",
            ])
        elif definition["kind"] == "call":
            lines.extend([
                "    push    {r11, lr}",
                f"    bl      0x{definition['target']:08x}",
                f"    EMIT    '{definition['marker']}'",
                "    pop     {r11, pc}",
            ])
        elif definition["kind"] == "ce":
            lines.extend([
                "    EMIT    'C'",
                "    EMIT    'E'",
                f"    b       0x{definition['target']:08x}",
            ])
        else:
            raise AssertionError(f"unknown wrapper kind: {definition['kind']}")
    lines.append(f"    .org 0x{HEAD_WRAPPER_CAVE_SIZE:x}")
    return "\n".join(lines) + "\n"

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
# decompressed trampoline can write H, leaves one sled word as a NOP, and
# branches through r4. The MRS remains after the hyp-stub call in the head
# trampoline, preserving stock ordering.
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
    mov     r12, #'H'       @ consumed by decompressed head trampoline
    nop                      @ MRS runs after the hyp stub, as in stock head.S
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


def assemble_linked_probe(asm: str, address: int, expected_size: int,
                          name: str) -> bytes:
    """Assemble ARM code whose PC-relative branches require a runtime VMA."""
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "probe.s"
        obj = Path(td) / "probe.o"
        elf = Path(td) / "probe.elf"
        raw = Path(td) / "probe.bin"
        src.write_text(asm)
        subprocess.run(
            ["arm-none-eabi-as", "-march=armv7-a", "-o", str(obj), str(src)],
            check=True)
        subprocess.run(
            ["arm-none-eabi-ld", f"-Ttext=0x{address:08x}", "-o", str(elf),
             str(obj)],
            check=True)
        subprocess.run(
            ["arm-none-eabi-objcopy", "-O", "binary", "-j", ".text",
             str(elf), str(raw)],
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


def assemble_head_entry_branch() -> bytes:
    return assemble_linked_probe(HEAD_ENTRY_BRANCH_ASM, DECOMPRESSED_BASE, 4,
                                 "head entry branch")


def assemble_head_trampoline() -> bytes:
    return assemble_linked_probe(HEAD_TRAMPOLINE_ASM, HEAD_TRAMPOLINE_ADDR,
                                 HEAD_TRAMPOLINE_SIZE, "head H/I trampoline")


def assemble_head_wrappers() -> bytes:
    blob = assemble_linked_probe(_head_wrapper_asm(), HEAD_WRAPPER_CAVE_ADDR,
                                 HEAD_WRAPPER_CAVE_SIZE, "expanded head wrappers")
    if blob != expected_head_wrappers():
        raise SystemExit("ERROR: expanded head wrapper encoding changed")
    for definition in _HEAD_WRAPPER_DEFS:
        if definition["kind"] != "call":
            continue
        offset = definition["offset"]
        if blob[offset:offset + 4] != HEAD_WRAPPER_CALL_START:
            raise SystemExit(
                f"ERROR: call wrapper at 0x{offset:x} lacks push {{r11, lr}}")
        if blob[offset + 0x18:offset + 0x1C] != HEAD_WRAPPER_CALL_END:
            raise SystemExit(
                f"ERROR: call wrapper at 0x{offset:x} lacks pop {{r11, pc}}")
    return blob


def head_wrapper_patch_word(site: int, wrapper_offset: int) -> bytes:
    """Return the independently calculated ARM B/BL word for a patch site."""
    definition = _HEAD_WRAPPER_BY_SITE.get(site)
    if definition is None or definition["offset"] != wrapper_offset:
        raise SystemExit(f"ERROR: unknown head wrapper patch site 0x{site:x}")
    source = DECOMPRESSED_BASE + site
    target = HEAD_WRAPPER_CAVE_ADDR + wrapper_offset
    displacement = target - (source + 8)
    if displacement % 4 or not -(1 << 25) <= displacement < (1 << 25):
        raise SystemExit(
            f"ERROR: head wrapper target out of range: 0x{source:08x} -> 0x{target:08x}")
    word = 0xEA000000 | ((displacement >> 2) & 0xFFFFFF)
    if site in _HEAD_WRAPPER_CALL_SITES:
        word |= 0x01000000
    result = struct.pack("<I", word)
    expected = HEAD_WRAPPER_PATCH_EXPECTED[site]
    if result != expected:
        raise SystemExit(f"ERROR: head wrapper patch encoding changed at 0x{site:x}")
    return result


def assemble_head_wrapper_patch(site: int, wrapper_offset: int) -> bytes:
    """Assemble the same patch-site B/BL with the cross-assembler."""
    definition = _HEAD_WRAPPER_BY_SITE.get(site)
    if definition is None or definition["offset"] != wrapper_offset:
        raise SystemExit(f"ERROR: unknown head wrapper patch site 0x{site:x}")
    mnemonic = "bl" if site in _HEAD_WRAPPER_CALL_SITES else "b"
    target = HEAD_WRAPPER_CAVE_ADDR + wrapper_offset
    asm = f"""\
    .syntax unified
    .arm
    .text
    .global _start
_start:
    {mnemonic}     0x{target:08x}
"""
    blob = assemble_linked_probe(asm, DECOMPRESSED_BASE + site, 4,
                                 f"head wrapper patch 0x{site:x}")
    if blob != HEAD_WRAPPER_PATCH_EXPECTED[site]:
        raise SystemExit(f"ERROR: assembled head wrapper patch changed at 0x{site:x}")
    return blob


def _head_cave_targets() -> range:
    return range(HEAD_WRAPPER_CAVE_ADDR,
                 HEAD_WRAPPER_CAVE_ADDR + HEAD_WRAPPER_CAVE_SIZE, 4)


def head_wrapper_cave_branch_sources(raw: bytes) -> list[int]:
    """Return aligned stock ARM B/BL sites that target the wrapper cave."""
    sources: list[int] = []
    lo = HEAD_WRAPPER_CAVE_ADDR
    hi = HEAD_WRAPPER_CAVE_ADDR + HEAD_WRAPPER_CAVE_SIZE
    for offset in range(0, len(raw) - 3, 4):
        word = struct.unpack_from("<I", raw, offset)[0]
        if ((word >> 28) & 0xF) == 0xF or ((word >> 25) & 0x7) != 0x5:
            continue
        displacement = word & 0xFFFFFF
        if displacement & 0x800000:
            displacement -= 1 << 24
        destination = (DECOMPRESSED_BASE + offset + 8 + (displacement << 2)) & 0xFFFFFFFF
        if lo <= destination < hi:
            sources.append(DECOMPRESSED_BASE + offset)
    return sources


def head_wrapper_cave_literal_pointers(raw: bytes) -> list[int]:
    """Return offsets whose little-endian word points into the wrapper cave."""
    pointers: list[int] = []
    lo = HEAD_WRAPPER_CAVE_ADDR
    hi = HEAD_WRAPPER_CAVE_ADDR + HEAD_WRAPPER_CAVE_SIZE
    for offset in range(0, len(raw) - 3, 4):
        value = struct.unpack_from("<I", raw, offset)[0]
        if lo <= value < hi:
            pointers.append(DECOMPRESSED_BASE + offset)
    return pointers


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
    """Install semantics-preserving early-head markers without changing geometry."""
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
    cave_end = HEAD_TRAMPOLINE_OFF + HEAD_TRAMPOLINE_SIZE
    if bytes(raw[HEAD_TRAMPOLINE_OFF:cave_end]) != HEAD_CAVE_STOCK:
        raise SystemExit("ERROR: decompressed head.S NOP-cave contract changed")
    wrapper_end = HEAD_WRAPPER_CAVE_OFF + HEAD_WRAPPER_CAVE_SIZE
    if bytes(raw[HEAD_WRAPPER_CAVE_OFF:wrapper_end]) != HEAD_WRAPPER_STOCK:
        raise SystemExit("ERROR: decompressed expanded-wrapper cave is not stock zero padding")
    if head_wrapper_cave_branch_sources(bytes(raw)):
        raise SystemExit("ERROR: stock decompressed Image directly branches into wrapper cave")
    if head_wrapper_cave_literal_pointers(bytes(raw)):
        raise SystemExit("ERROR: stock decompressed Image contains a pointer into wrapper cave")
    for site, _ in HEAD_WRAPPER_PATCH_SITES:
        definition = _HEAD_WRAPPER_BY_SITE[site]
        expected = bytes.fromhex(definition["stock"])
        if bytes(raw[site:site + 4]) != expected:
            raise SystemExit(f"ERROR: head.S wrapper stock word changed at 0x{site:x}")

    head_branch = assemble_head_entry_branch()
    head_trampoline = assemble_head_trampoline()
    head_wrappers = assemble_head_wrappers()
    if head_branch != HEAD_ENTRY_BRANCH:
        raise SystemExit("ERROR: head entry branch assembly changed")
    raw[:len(head_branch)] = head_branch
    raw[HEAD_TRAMPOLINE_OFF:cave_end] = head_trampoline
    raw[HEAD_WRAPPER_CAVE_OFF:wrapper_end] = head_wrappers
    for site, wrapper_offset in HEAD_WRAPPER_PATCH_SITES:
        patch_word = head_wrapper_patch_word(site, wrapper_offset)
        assembled = assemble_head_wrapper_patch(site, wrapper_offset)
        if patch_word != assembled:
            raise SystemExit(f"ERROR: head wrapper patch encoding changed at 0x{site:x}")
        raw[site:site + 4] = patch_word
    header = zimage[offset:offset + 10]
    if len(header) != 10 or header[:3] != b"\x1f\x8b\x08" or header[3] != 0:
        raise SystemExit("ERROR: unsupported stock gzip header")
    compressor = zlib.compressobj(8, zlib.DEFLATED, -15)
    deflate = compressor.compress(bytes(raw)) + compressor.flush()
    new_stream = header + deflate + struct.pack(
        "<II", binascii.crc32(raw) & 0xFFFFFFFF, len(raw) & 0xFFFFFFFF)
    if len(new_stream) > consumed:
        raise SystemExit("ERROR: expanded-head-probed kernel no longer fits stock gzip envelope")

    # head.S uses input_data_end - 4 as an out-of-band inflated-size word for
    # overlap/self-relocation decisions. A shorter gzip member may leave slack,
    # but the fixed envelope must still end in the original Image size. Zeroing
    # this word makes r9=0 and lets decompression overwrite its own stack.
    slack = consumed - len(new_stream)
    if slack < 4:
        raise SystemExit("ERROR: expanded-head gzip has no room for terminal size word")
    envelope = (new_stream + b"\0" * (slack - 4) +
                struct.pack("<I", len(raw)))
    result = bytearray(zimage)
    result[offset:offset + consumed] = envelope
    metadata: HeadProbeMetadata = {
        "marker": HEAD_MARKER_SEQUENCE,
        "raw_head": bytes(raw[:len(head_branch)]),
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
    print(f"head_probe={head_meta['marker']} raw_head={head_meta['raw_head'].hex()} "
          f"cave=0x{HEAD_TRAMPOLINE_ADDR:08x} "
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
