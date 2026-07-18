#!/usr/bin/env python3
"""Verify the exact v184 native-K32/EVT diagnostic artifact contract."""

from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LK_BASE = 0x4BD00000
LK_HEADER_SIZE = 0x200
PAYLOAD_BLOCK = 223215
RAW_PAYLOAD_OFFSET = 576
RAW_PAYLOAD_SIZE = 0x18E4
ZIMAGE_END = 0x578910
EVT_SIZE = 0xC875
EVT_PADDED_SIZE = 0x10000  # totalsize inflated + zero-padded: libfdt needs slack for fixups
EVT_SHA256 = "f44630ba28f503dd7503bc7cffa2ee96a319acf2f58f1456bb6f5ff23d57dee1"
KERNEL_GZIP_OFFSET = 0x46D8
KERNEL_GZIP_SIZE = 0x5741FB
KERNEL_GZIP_PROBED_SIZE = 0x573D28
DECOMPRESSED_KERNEL_SIZE = 0xB86070
HEAD_ENTRY_BRANCH = bytes.fromhex("300200ea")
HEAD_TRAMPOLINE_OFF = 0x8C8
HEAD_TRAMPOLINE_SIZE = 0x18
HEAD_TRAMPOLINE = bytes.fromhex(
    "00c083e5" "bb4500eb" "49c0a0e3" "00c083e5"
    "00900fe1" "c9fdffea")
HEAD_WRAPPER_CAVE_OFF = 0x76D054
HEAD_WRAPPER_CAVE_ADDR = 0x40008000 + HEAD_WRAPPER_CAVE_OFF
HEAD_WRAPPER_SLOT_SIZE = 0x40
HEAD_WRAPPER_CAVE_SIZE = 9 * HEAD_WRAPPER_SLOT_SIZE
HEAD_WRAPPER_CALL_START = bytes.fromhex("00482de9")  # push {r11, lr}
HEAD_WRAPPER_CALL_END = bytes.fromhex("0088bde8")    # pop {r11, pc}
HEAD_WRAPPER_PATCHES = {
    0x0034: ("109f10ee", "06b41dea"),
    0x0038: ("0e0200eb", "15b41deb"),
    0x0054: ("700000eb", "1eb41deb"),
    0x0058: ("370000eb", "2db41deb"),
    0x005C: ("590000eb", "3cb41deb"),
    0x0060: ("070000eb", "4bb41deb"),
    0x0074: ("d20100ea", "56b41dea"),
    0xAA72E0: ("40308fe2", "cb17f3ea"),
    0xAA78B0: ("f0432de9", "6716f3ea"),
}
HEAD_WRAPPER_CAVE = bytearray(HEAD_WRAPPER_CAVE_SIZE)
for _offset, _slot in {
    0x000: (
        "003002e3003141e353c0a0e300c083e5109f10ee"
        "003002e3003141e350c0a0e300c083e5ee4be2ea"),
    0x040: (
        "00482de9f64de2eb003002e3003141e34cc0a0e300c083e5"
        "0088bde8"),
    0x080: (
        "00482de94f4ce2eb003002e3003141e356c0a0e300c083e5"
        "0088bde8"),
    0x0C0: (
        "00482de9074ce2eb003002e3003141e355c0a0e300c083e5"
        "0088bde8"),
    0x100: (
        "00482de91a4ce2eb003002e3003141e346c0a0e300c083e5"
        "0088bde8"),
    0x140: (
        "00482de9b94be2eb003002e3003141e354c0a0e300c083e5"
        "403003e3033084e012cc01e300c141e300c083e5"
        "0088bde8"),
    0x180: (
        "003002e3003141e343c0a0e300c083e5"
        "003002e3003141e345c0a0e300c083e5724de2ea"),
    0x1C0: (
        "00c002e300c14ce34d30a0e300308ce5"
        "00c00fe3dfc04ce30430cce54b3303e3"
        "323045e300308ce54ff07ff53acf07ee"
        "4ff07ff528330fe3aa304ce323e80cea"),
    0x200: (
        "00c002e300c14ce35700a0e300008ce5"
        "00c00fe3dfc04ce30500cce54ff07ff5"
        "3acf07ee4ff07ff5f0432de98be90cea"),
}.items():
    _blob = bytes.fromhex(_slot)
    HEAD_WRAPPER_CAVE[_offset:_offset + len(_blob)] = _blob
HEAD_WRAPPER_CAVE = bytes(HEAD_WRAPPER_CAVE)
STOCK_HEAD_AFTER_BRANCH = bytes.fromhex(
    "00900fe1" "1a9029e2" "1f0019e3" "1f90c9e3" "d39089e3")
STOCK_HEAD_CAVE = struct.pack("<I", 0xE320F000) * 6
STOCK_DECOMPRESSED_SHA256 = "3eac3f3daf9daa04f1b67e78c3f2b1ead9a74d64aae435ef5f1988916d31cbd2"
UART_PGD_INDEX = 0xC10
UART_PGD_OFFSET = 0x3040
UART_DEVICE_SECTION = 0x11011C12
POST_MMU_CAVE_VA = 0xC0775054
POST_MMU_M_SITE_VA = 0xC0AAF2E0
POST_MMU_W_SITE_VA = 0xC0AAF8B0
POST_MMU_RETAINED_PHYS = 0x40DFF000
POST_MMU_RETAINED_VA = 0xC0DFF000
POST_MMU_RETAINED_LOAD = bytes.fromhex("00c00fe3dfc04ce3")
POST_MMU_M_MARKER_AND_MAGIC = bytes.fromhex(
    "0430cce54b3303e3323045e300308ce5")
POST_MMU_W_MARKER = bytes.fromhex("0500cce5")
# Independent displaced-instruction pins: M reconstructs the original
# add r3,pc,#64 result (C0AAF328), while W relocates the exact start_kernel
# push {r4-r9,sl,fp,lr} word before resuming at site+4.
POST_MMU_M_DISPLACED = bytes.fromhex("28330fe3aa304ce3")
POST_MMU_W_DISPLACED = bytes.fromhex("f0432de9")
POST_MMU_M_EXPECTED = bytes.fromhex(
    "00c002e300c14ce34d30a0e300308ce5"
    "00c00fe3dfc04ce30430cce54b3303e3"
    "323045e300308ce54ff07ff53acf07ee"
    "4ff07ff528330fe3aa304ce323e80cea")
POST_MMU_W_EXPECTED = bytes.fromhex(
    "00c002e300c14ce35700a0e300008ce5"
    "00c00fe3dfc04ce30500cce54ff07ff5"
    "3acf07ee4ff07ff5f0432de98be90cea"
    "00000000000000000000000000000000")
# T-wrapper sequence after its UART marker: r4 is the page-table base,
# 0x3040 is pgd[0xC10], and 0x11011C12 is the pinned Device section.
POST_MMU_PGD_POKE = bytes.fromhex(
    "403003e3033084e012cc01e300c141e300c083e5")
POST_MMU_PGD_POKE_OFFSET = 0x140 + 0x18
POST_MMU_M_BRANCH_OFFSET = 0x1C0 + 0x3C
POST_MMU_W_BRANCH_OFFSET = 0x200 + 0x2C

EXPECTED = {
    "lk.bin": "5cb92494340417b1e5d18c3eaa34844dbcfec2cc8086451f087867cd06b15472",
    "boot-k32-native-evt.img": "13922dcfdb045ba3b67f8709c395254ac7a3582e2819b545adf0f604dae31424",
    "boot-k32-native-diag.hdr": "dbbff7eeb8830c0d6cde454a97dc31be73d1cba32e6be9b21fe3c7be2b659066",
    "boot-k32-native-diag.payload": "5e9908c33221c5d39f52e2ffb4fd8c733d55a4b40501074ff12a01ec35a8b9cd",
    "boot-k32-native-diag-wrapper.full.img": "64f14102856bf905073fff756058b2bc175be0888dcb5c060ffb619e004eb72f",
    "boot-k32-native-diag-wrapper.sparse.img": "7a1b548551537b918fb39cddd3b2a00ef380f819a40178bd2982d9c75b291c26",
}
RAW_PAYLOAD_SHA256 = "ed520aa2c9848e6d57f9adfc62d868892b322810e1ac71d478115fc9fdd01869"

# Assembled by tools/build-native-k32-diagnostic.py (arm-none-eabi-as
# -march=armv7-a). Replaces the stock 8-NOP sled at the zImage entry; writes
# 'K' to the UART, clobbers only r3/r12, then falls into the stock branch.
#   movw r3,#0x2014 / movt r3,#0x1100 / ldr r12,[r3] / tst r12,#0x20
#   beq -8 / sub r3,r3,#0x14 / mov r12,#'K' / str r12,[r3]
ENTRY_PROBE = bytes.fromhex(
    "143002e3" "003141e3" "00c093e5" "20001ce3"
    "fcffff0a" "143043e2" "4bc0a0e3" "00c083e5")
ENTRY_BRANCH = struct.pack("<I", 0xEA000003)
DEJUMP_OFF = 0x924
DEJUMP_SLED_OFF = 0x928
DEJUMP_SLED_SIZE = 6
DEJUMP_PROBE = bytes.fromhex(
    "003002e3" "003141e3" "44c0a0e3" "00c083e5"
    "48c0a0e3" "00f020e3" "14ff2fe1")

FDT_CALLS = {
    0x4BD33206: (0xF007, 0xFFC3),
    0x4BD33288: (0xF007, 0xFF82),
    0x4BD332AA: (0xF007, 0xFF71),
    0x4BD332CA: (0xF007, 0xFF61),
    0x4BD332F8: (0xF007, 0xFF4A),
    0x4BD33322: (0xF007, 0xFF35),
    0x4BD3335C: (0xF007, 0xFF18),
    0x4BD3338A: (0xF007, 0xFF01),
    0x4BD333B8: (0xF007, 0xFEEA),
    0x4BD333F0: (0xF007, 0xFECE),
    0x4BD3341E: (0xF007, 0xFEB7),
    0x4BD335DE: (0xF007, 0xFDD7),
    0x4BD335FE: (0xF007, 0xFDC7),
    0x4BD3394C: (0xF007, 0xFC20),
    # Internal fdt_setprop call reached through fdt_setprop_u32.
    0x4BD32F68: (0xF008, 0xF912),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"ERROR: {message}")


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def arm_branch_sources(blob: bytes, base: int, target: int) -> list[int]:
    """Return aligned ARM B/BL sites that directly target an address."""
    sources: list[int] = []
    for offset in range(0, len(blob) - 3, 4):
        word = struct.unpack_from("<I", blob, offset)[0]
        if ((word >> 28) & 0xF) == 0xF or ((word >> 25) & 0x7) != 0x5:
            continue
        displacement = word & 0xFFFFFF
        if displacement & 0x800000:
            displacement -= 1 << 24
        destination = (base + offset + 8 + (displacement << 2)) & 0xFFFFFFFF
        if destination == target:
            sources.append(base + offset)
    return sources


def arm_branch_sources_into(blob: bytes, base: int, low: int, high: int) -> list[int]:
    """Return aligned ARM B/BL sites targeting an address interval."""
    sources: list[int] = []
    for offset in range(0, len(blob) - 3, 4):
        word = struct.unpack_from("<I", blob, offset)[0]
        if ((word >> 28) & 0xF) == 0xF or ((word >> 25) & 0x7) != 0x5:
            continue
        displacement = word & 0xFFFFFF
        if displacement & 0x800000:
            displacement -= 1 << 24
        destination = (base + offset + 8 + (displacement << 2)) & 0xFFFFFFFF
        if low <= destination < high:
            sources.append(base + offset)
    return sources


def arm_branch_destination(blob: bytes, base: int, source: int) -> int:
    """Decode one aligned ARM B/BL destination from a blob VMA."""
    offset = source - base
    word = struct.unpack_from("<I", blob, offset)[0]
    require(((word >> 25) & 0x7) == 0x5, f"not an ARM B/BL at 0x{source:x}")
    displacement = word & 0xFFFFFF
    if displacement & 0x800000:
        displacement -= 1 << 24
    return (source + 8 + (displacement << 2)) & 0xFFFFFFFF

def little_endian_pointers_into(blob: bytes, low: int, high: int) -> list[int]:
    """Return aligned words whose little-endian value points into an interval."""
    pointers: list[int] = []
    for offset in range(0, len(blob) - 3, 4):
        value = struct.unpack_from("<I", blob, offset)[0]
        if low <= value < high:
            pointers.append(offset)
    return pointers


def lk_slice(lk: bytes, runtime_address: int, size: int) -> bytes:
    offset = LK_HEADER_SIZE + runtime_address - LK_BASE
    return lk[offset:offset + size]


def verify_sparse(sparse: bytes, full: bytes) -> None:
    fields = struct.unpack_from("<I4H4I", sparse)
    magic, major, minor, file_hdr, chunk_hdr, block_size, total_blocks, total_chunks, _ = fields
    require(magic == 0xED26FF3A and (major, minor) == (1, 0), "sparse header invalid")
    require((file_hdr, chunk_hdr) == (28, 12), "sparse header geometry mismatch")
    require(block_size == 4096 and total_blocks == 28160, "sparse logical geometry mismatch")

    in_pos = file_hdr
    out_pos = 0
    for _ in range(total_chunks):
        chunk_type, _, chunk_blocks, total_size = struct.unpack_from("<HHII", sparse, in_pos)
        in_pos += chunk_hdr
        logical_size = chunk_blocks * block_size
        require(total_size >= chunk_hdr, "sparse chunk size underflow")
        data_size = total_size - chunk_hdr

        if chunk_type == 0xCAC1:
            require(data_size == logical_size, "RAW sparse chunk size mismatch")
            require(full[out_pos:out_pos + logical_size] == sparse[in_pos:in_pos + data_size],
                    "RAW sparse chunk differs from full wrapper")
        elif chunk_type in (0xCAC2, 0xCAC3):
            if chunk_type == 0xCAC2:
                require(data_size == 4, "FILL sparse chunk has invalid payload")
                pattern = sparse[in_pos:in_pos + 4]
            else:
                require(data_size == 0, "DONT_CARE sparse chunk has payload")
                pattern = b"\0\0\0\0"
            for pos in range(out_pos, out_pos + logical_size, 1024 * 1024):
                size = min(1024 * 1024, out_pos + logical_size - pos)
                require(full[pos:pos + size] == pattern * (size // 4),
                        "sparse fill/don't-care chunk differs from full wrapper")
        elif chunk_type == 0xCAC4:
            require(data_size == 4 and logical_size == 0, "CRC sparse chunk invalid")
        else:
            raise SystemExit(f"ERROR: unknown sparse chunk type 0x{chunk_type:04x}")

        in_pos += data_size
        out_pos += logical_size

    require(in_pos == len(sparse), "trailing or truncated sparse data")
    require(out_pos == len(full), "sparse logical size differs from full wrapper")


def verify_boot_image(image: bytes) -> None:
    require(image[:8] == b"ANDROID!", "native K32 boot magic missing")
    kernel_size, kernel_addr, ramdisk_size, _, second_size, _, _, page_size, dt_size, _ = \
        struct.unpack_from("<10I", image, 8)
    require(kernel_addr == 0x40008000 and page_size == 0x800, "native K32 boot geometry changed")
    require(kernel_size == 0x588B10, "native K32 kernel size mismatch")

    kernel = image[page_size:page_size + kernel_size]
    require(kernel[:4] == bytes.fromhex("88168858"), "kernel MediaTek header missing")
    payload_size = struct.unpack_from("<I", kernel, 4)[0]
    require(payload_size == 0x588910, "MediaTek payload size mismatch")
    payload = kernel[0x200:0x200 + payload_size]
    require(payload[:0x20] == ENTRY_PROBE, "zImage entry probe mismatch")
    require(payload[0x20:0x24] == ENTRY_BRANCH, "zImage entry branch clobbered")
    require(payload[0x24:0x28] == bytes.fromhex("18286f01"), "ARM zImage magic missing")
    require(struct.unpack_from("<II", payload, 0x28) == (0, ZIMAGE_END), "ARM zImage range changed")
    require(payload[DEJUMP_OFF - 4:DEJUMP_OFF] == bytes.fromhex("0000a0e3"),
            "decompression pre-return instruction changed")
    sled_end = DEJUMP_SLED_OFF + DEJUMP_SLED_SIZE * 4
    require(payload[DEJUMP_OFF:sled_end] == DEJUMP_PROBE,
            "decompression D-to-H trampoline mismatch")

    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    raw = inflater.decompress(payload[KERNEL_GZIP_OFFSET:ZIMAGE_END]) + inflater.flush()
    consumed = (ZIMAGE_END - KERNEL_GZIP_OFFSET) - len(inflater.unused_data)
    require(inflater.eof and consumed == KERNEL_GZIP_PROBED_SIZE,
            "H-probed kernel gzip envelope mismatch")
    require(len(raw) == DECOMPRESSED_KERNEL_SIZE,
            "H-probed decompressed kernel size mismatch")
    require(raw[:4] == HEAD_ENTRY_BRANCH,
            "decompressed head.S H/I entry branch mismatch")
    require(raw[4:4 + len(STOCK_HEAD_AFTER_BRANCH)] == STOCK_HEAD_AFTER_BRANCH,
            "decompressed head.S stock sequence after branch changed")
    cave_end = HEAD_TRAMPOLINE_OFF + HEAD_TRAMPOLINE_SIZE
    require(raw[HEAD_TRAMPOLINE_OFF:cave_end] == HEAD_TRAMPOLINE,
            "decompressed head.S H/I trampoline mismatch")
    wrapper_end = HEAD_WRAPPER_CAVE_OFF + HEAD_WRAPPER_CAVE_SIZE
    require(raw[HEAD_WRAPPER_CAVE_OFF:wrapper_end] == HEAD_WRAPPER_CAVE,
            "expanded head.S wrapper encoding mismatch")
    require(raw[HEAD_WRAPPER_CAVE_OFF + POST_MMU_PGD_POKE_OFFSET:
                HEAD_WRAPPER_CAVE_OFF + POST_MMU_PGD_POKE_OFFSET +
                len(POST_MMU_PGD_POKE)] == POST_MMU_PGD_POKE,
            "T-wrapper UART PGD poke sequence mismatch")
    require(POST_MMU_CAVE_VA == HEAD_WRAPPER_CAVE_ADDR + 0x80000000,
            "post-MMU wrapper VMA is not the physical cave alias")
    require(POST_MMU_RETAINED_VA == POST_MMU_RETAINED_PHYS + 0x80000000,
            "post-MMU retained VA/physical alias changed")
    require(UART_DEVICE_SECTION == 0x11011C12,
            "UART PGD descriptor changed")
    require(POST_MMU_M_SITE_VA == 0xC0AAF2E0 and
            POST_MMU_W_SITE_VA == 0xC0AAF8B0,
            "post-MMU patch-site VMA contract changed")
    m_slot = raw[HEAD_WRAPPER_CAVE_OFF + 0x1C0:
                 HEAD_WRAPPER_CAVE_OFF + 0x200]
    w_slot = raw[HEAD_WRAPPER_CAVE_OFF + 0x200:
                 HEAD_WRAPPER_CAVE_OFF + 0x240]
    require(m_slot[0x10:0x18] == POST_MMU_RETAINED_LOAD and
            w_slot[0x10:0x18] == POST_MMU_RETAINED_LOAD,
            "post-MMU retained address load changed")
    require(m_slot[0x18:0x28] == POST_MMU_M_MARKER_AND_MAGIC,
            "post-MMU M retained magic/marker layout changed")
    require(m_slot[0x34:0x3C] == POST_MMU_M_DISPLACED,
            "post-MMU M displaced add semantics changed")
    require(w_slot[0x18:0x1C] == POST_MMU_W_MARKER,
            "post-MMU W retained marker offset changed")
    require(w_slot[0x28:0x2C] == POST_MMU_W_DISPLACED,
            "post-MMU W displaced push semantics changed")
    require(m_slot == POST_MMU_M_EXPECTED,
            "post-MMU M wrapper slot encoding mismatch")
    require(w_slot == POST_MMU_W_EXPECTED,
            "post-MMU W wrapper slot encoding mismatch")
    require(arm_branch_destination(
        raw, 0x40008000,
        HEAD_WRAPPER_CAVE_ADDR + POST_MMU_M_BRANCH_OFFSET) ==
        0x40008000 + 0xAA72E0 + 4,
        "post-MMU M wrapper does not resume at __mmap_switched+4")
    require(arm_branch_destination(
        raw, 0x40008000,
        HEAD_WRAPPER_CAVE_ADDR + POST_MMU_W_BRANCH_OFFSET) ==
        0x40008000 + 0xAA78B0 + 4,
        "post-MMU W wrapper does not resume at start_kernel+4")
    for offset in (0x040, 0x080, 0x0C0, 0x100, 0x140):
        require(raw[HEAD_WRAPPER_CAVE_OFF + offset:
                    HEAD_WRAPPER_CAVE_OFF + offset + 4] == HEAD_WRAPPER_CALL_START,
                f"call wrapper 0x{offset:x} does not start with push {{r11, lr}}")
        end_offset = 0x2C if offset == 0x140 else 0x18
        require(raw[HEAD_WRAPPER_CAVE_OFF + offset + end_offset:
                    HEAD_WRAPPER_CAVE_OFF + offset + end_offset + 4] == HEAD_WRAPPER_CALL_END,
                f"call wrapper 0x{offset:x} does not end with pop {{r11, pc}}")
    stock = (ROOT / "inputs/boot-v184-stock32-parity-stock.img").read_bytes()
    stock_kernel_size = struct.unpack_from("<I", stock, 8)[0]
    stock_zimage = stock[0x800 + 0x200:0x800 + stock_kernel_size]
    stock_inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    stock_raw = stock_inflater.decompress(
        stock_zimage[KERNEL_GZIP_OFFSET:]) + stock_inflater.flush()
    require(digest(stock_raw) == STOCK_DECOMPRESSED_SHA256,
            "stock decompressed kernel contract changed")
    require(stock_raw[HEAD_TRAMPOLINE_OFF:cave_end] == STOCK_HEAD_CAVE,
            "stock decompressed head.S NOP cave changed")
    for site, (stock_word, patched_word) in HEAD_WRAPPER_PATCHES.items():
        require(stock_raw[site:site + 4] == bytes.fromhex(stock_word),
                f"stock head.S word changed at 0x{site:x}")
        require(raw[site:site + 4] == bytes.fromhex(patched_word),
                f"expanded head.S patch mismatch at 0x{site:x}")
    for site, wrapper_offset in ((0xAA72E0, 0x1C0), (0xAA78B0, 0x200)):
        require(arm_branch_destination(raw, 0x40008000,
                                       0x40008000 + site) ==
                HEAD_WRAPPER_CAVE_ADDR + wrapper_offset,
                f"post-MMU site 0x{site:x} does not branch to its wrapper")
    require(not arm_branch_sources(stock_raw, 0x40008000, 0x400088C8),
            "stock decompressed Image directly branches into H/I NOP cave")
    require(stock_raw[HEAD_WRAPPER_CAVE_OFF:wrapper_end] ==
            b"\0" * HEAD_WRAPPER_CAVE_SIZE,
            "stock expanded-wrapper cave is not zero padding")
    require(not arm_branch_sources_into(
        stock_raw, 0x40008000, HEAD_WRAPPER_CAVE_ADDR,
        HEAD_WRAPPER_CAVE_ADDR + HEAD_WRAPPER_CAVE_SIZE),
            "stock decompressed Image directly branches into expanded-wrapper cave")
    require(not little_endian_pointers_into(
        stock_raw, HEAD_WRAPPER_CAVE_ADDR,
        HEAD_WRAPPER_CAVE_ADDR + HEAD_WRAPPER_CAVE_SIZE),
            "stock decompressed Image contains a pointer into expanded-wrapper cave")
    allowed = [
        (0, 4),
        (HEAD_TRAMPOLINE_OFF, cave_end),
        (HEAD_WRAPPER_CAVE_OFF, wrapper_end),
    ]
    allowed.extend((site, site + 4) for site in HEAD_WRAPPER_PATCHES)
    masked_raw = bytearray(raw)
    masked_stock = bytearray(stock_raw)
    for start, end in allowed:
        masked_raw[start:end] = b"\0" * (end - start)
        masked_stock[start:end] = b"\0" * (end - start)
    require(bytes(masked_raw) == bytes(masked_stock),
            "expanded head.S kernel differs from stock outside probe regions")
    gzip_pad_start = KERNEL_GZIP_OFFSET + consumed
    gzip_envelope_end = KERNEL_GZIP_OFFSET + KERNEL_GZIP_SIZE
    gzip_size_word = gzip_envelope_end - 4
    require(payload[gzip_pad_start:gzip_size_word] ==
            b"\0" * (gzip_size_word - gzip_pad_start),
            "H-probed gzip envelope slack is not zero-filled")
    require(struct.unpack_from("<I", payload, gzip_size_word)[0] ==
            DECOMPRESSED_KERNEL_SIZE,
            "head.S input_data_end-4 inflated-size contract changed")
    evt = payload[ZIMAGE_END:]
    require(len(evt) == EVT_PADDED_SIZE, "padded EVT DTB size mismatch")
    raw_evt = bytearray(evt[:EVT_SIZE])
    struct.pack_into(">I", raw_evt, 4, EVT_SIZE)  # undo totalsize inflation before hashing
    require(digest(bytes(raw_evt)) == EVT_SHA256, "raw EVT DTB content mismatch")
    require(evt[EVT_SIZE:] == b"\0" * (EVT_PADDED_SIZE - EVT_SIZE),
            "EVT padding is not zero-filled")
    require(evt[:4] == bytes.fromhex("d00dfeed"), "EVT FDT magic missing")
    require(struct.unpack_from(">I", evt, 4)[0] == EVT_PADDED_SIZE,
            "EVT FDT totalsize not inflated to 0x10000")
    require(payload.find(bytes.fromhex("d00dfeed")) == ZIMAGE_END, "EVT is not first appended FDT")
    require(payload.find(bytes.fromhex("d00dfeed"), ZIMAGE_END + 4) == -1,
            "more than one appended FDT remains")

    ramdisk_offset = align(page_size + kernel_size, page_size)
    second_offset = align(ramdisk_offset + ramdisk_size, page_size)
    dt_offset = align(second_offset + second_size, page_size)
    require(dt_offset + dt_size <= len(image), "boot image components are truncated")
    boot_id = hashlib.sha1()
    for blob in (
        kernel,
        image[ramdisk_offset:ramdisk_offset + ramdisk_size],
        image[second_offset:second_offset + second_size],
    ):
        boot_id.update(blob)
        boot_id.update(struct.pack("<I", len(blob)))
    if dt_size:
        dt = image[dt_offset:dt_offset + dt_size]
        boot_id.update(dt)
        boot_id.update(struct.pack("<I", len(dt)))
    require(image[576:608] == boot_id.digest().ljust(32, b"\0"),
            "legacy Android boot ID mismatch")


def main() -> None:
    lk = (ROOT / "bin/lk.bin").read_bytes()
    boot = (ROOT / "bin/boot-k32-native-evt.img").read_bytes()
    hdr = (ROOT / "bin/boot-k32-native-diag.hdr").read_bytes()
    payload = (ROOT / "bin/boot-k32-native-diag.payload").read_bytes()
    full = (ROOT / "bin/boot-k32-native-diag-wrapper.full.img").read_bytes()
    sparse = (ROOT / "bin/boot-k32-native-diag-wrapper.sparse.img").read_bytes()
    source_patch = (ROOT / "patches/native-k32-diagnostic.patch").read_text()
    added_source = "\n".join(
        line[1:] for line in source_patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )

    require(lk[:4] == bytes.fromhex("88168858"), "LK MediaTek header magic mismatch")
    require(lk_slice(lk, 0x4BD33704, 6) == bytes.fromhex("002800f06082"),
            "stock LK CMP/BEQ.W ARM32 selector changed")
    require(lk_slice(lk, 0x4BD33BCA, 6) == bytes.fromhex("0c993246d847"),
            "stock LK ARM32 r1/r2/BLX sequence changed")
    require(lk_slice(lk, 0x4BD33888, 4) == bytes.fromhex("0df2ac4d"),
            "stock M3 error epilogue changed")
    require(lk_slice(lk, 0x4BD33DC0, 4) == bytes.fromhex("fff792f9"),
            "stock M4 boot_linux_fdt call changed")
    for address, expected in FDT_CALLS.items():
        require(struct.unpack("<HH", lk_slice(lk, address, 4)) == expected,
                f"stock fdt_setprop call changed at 0x{address:08x}")

    require(len(hdr) == 96 and hdr[:8] == b"ANDROID!", "wrapper header invalid")
    require(len(payload) == 9792, "wrapper payload section size mismatch")
    raw_payload = payload[RAW_PAYLOAD_OFFSET:RAW_PAYLOAD_OFFSET + RAW_PAYLOAD_SIZE]
    require(digest(raw_payload) == RAW_PAYLOAD_SHA256, "embedded compiled payload hash mismatch")
    for marker in (
        b"Radar/Puffin native K32 diagnostic (Biscuit-derived Amonet)",
        b"ABI handoff: native K32 loader + stock ARM32 jump",
        b"FDT setprop name=%s ret=%x len=%x fdt=%x node=%x",
        b"FDT magic=%x total=%x",
        b"FDT initrd-start val=%x",
        b"FDT initrd-end val=%x",
        b"M3 boot_linux_fdt common error epilogue reached",
        b"M4 boot_linux_fdt args a0=%x a1=%x a2=%x a3=%x a4=%x a5=%x",
        b"M4 boot_linux_fdt returned to boot_linux ret=%x",
        b"K32J r0=%x machid=%x r2=%x fp=%x sp=%x",
        b"K32J cpu cpsr=%08x mode=%x sctlr=%08x vbar=%08x",
        b"K32J zimg %x %x %x %x magic24=%x",
        b"K32J fdt magic=%x total=%x",
        b"K32J initrd %x-%x head %x %x %x %x",
        b"block_off=%08x%08x",
        b"ATFCR flag=%08x addr=%08x size=%08x",
        b"ATFCR bounds rejected",
        b"ATFCR dump begin",
        b"ATFCR dump end",
        b"K32P magic ok markers=",
    ):
        require(marker in raw_payload, f"compiled payload marker missing: {marker!r}")
    require(b"K64 FDT prep" not in raw_payload, "obsolete cached=1 marker remains")
    require(struct.pack("<I", 0x4BD641F4) not in raw_payload,
            "selector should be addressed through exact 0x4BD64000 base")
    require(struct.pack("<I", 0x4BD64000) in raw_payload, "cached selector base missing")
    require(struct.pack("<I", 0x4BD33700) in raw_payload, "stock selector validation base missing")
    require("*patch32 = 0;" in added_source, "source patch does not clear cached selector")
    require("if (!fastboot) {" in added_source,
            "K32 image loading is not guarded against fastboot fallback")
    require("#define ATF_CRASH_MAX 0x20000U" in added_source,
            "ATF crash-record bound does not accept the observed 0x20000-byte buffer")
    require("addr > ATF_CTL_LIMIT - size" in added_source,
            "ATF crash-record end bound is missing")
    require("#define RETAINED_POST_MMU_BASE 0x40DFF000U" in added_source,
            "post-MMU retained block base is missing")
    require("#define RETAINED_POST_MMU_SIZE 0x1000U" in added_source,
            "post-MMU retained block size is missing")
    require("p[0] == 'K' && p[1] == '3' && p[2] == '2' && p[3] == 'P'" in added_source,
            "post-MMU retained magic check is missing")
    require("low_uart_put(p[4]);" in added_source and
            "low_uart_put(p[5]);" in added_source,
            "post-MMU retained marker offsets are missing")
    require("memset((void *)RETAINED_POST_MMU_BASE, 0, RETAINED_POST_MMU_SIZE);" in added_source,
            "post-MMU retained block is not invalidated")
    require("dump_retained_post_mmu_markers();" in added_source,
            "post-MMU retained dump is not placed in main")
    require("dev->read(dev, g_misc * 0x200, bootloader_msg, 0x20, USER_PART);" in added_source,
            "misc bootloader message does not read UART_PLEASE half")
    selector_writes = [
        line for line in added_source.splitlines()
        if line.strip().startswith("*selector =")
    ]
    require(not selector_writes and "0xBA60" not in added_source,
            "source patch still modifies final selector/branch")

    require(len(full) == 110 * 1024 * 1024, "full wrapper is not 110 MiB")
    require(full[:len(hdr)] == hdr, "wrapper header embedding mismatch")
    payload_offset = PAYLOAD_BLOCK * 0x200
    require(full[payload_offset:payload_offset + len(payload)] == payload,
            "wrapper payload embedding mismatch")
    verify_sparse(sparse, full)
    verify_boot_image(boot)

    for name, expected in EXPECTED.items():
        actual = digest((ROOT / "bin" / name).read_bytes())
        require(actual == expected, f"{name} hash mismatch: {actual}")

    print("exact_lk_contract=PASS cached_selector=0x4BD641F4 stock_final=0x4BD33704")
    print("native_k32_handoff_contract=PASS r0=0 r1=machid r2=fdt target=0x4BD33BCA")
    print("evt_only_boot_contract=PASS zimage=0x578910 evt_raw=0xC875 evt_padded=0x10000 kernel=0x588B10")
    print("fdt_diagnostic_contract=PASS setprop_calls=15 M3=0x4BD33888 M4=0x4BD33DC0")
    print("k32_jump_contract=PASS stub=0x4BD33BCA stock=990c:4632 log=regs+cpu+zimg+fdt+initrd")
    print("zimage_probe_contract=PASS entry=0x40008000 marker=K clobbers=r3,r12")
    print("zimage_dejump_contract=PASS return=0x924 markers=D,H target=r4")
    print("kernel_head_probe_contract=PASS entry_branch=0x40008000 "
          "trampoline=0x400088C8 markers=H,I resume=0x40008008 "
          "wrappers=0x40775054 markers=S,P,L,V,U,F,T,C,E "
          "sites=0x40008034,0x40008038,0x40008054,0x40008058,0x4000805C,0x40008060,0x40008074 "
          "gzip_fixed=0x5741FB terminal_size=0x00B86070")
    print("atf_crash_contract=PASS range=0x5F800000-0x5FA00000 max=0x20000")
    print("wrapper_sparse_contract=PASS block=223215 logical=110MiB")


if __name__ == "__main__":
    main()
