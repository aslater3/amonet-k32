#!/usr/bin/env python3
"""Verify the exact v184 native-K32/EVT diagnostic artifact contract."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LK_BASE = 0x4BD00000
LK_HEADER_SIZE = 0x200
PAYLOAD_BLOCK = 223215
RAW_PAYLOAD_OFFSET = 576
RAW_PAYLOAD_SIZE = 0x14B0
ZIMAGE_END = 0x578910
EVT_SIZE = 0xC875
EVT_SHA256 = "f44630ba28f503dd7503bc7cffa2ee96a319acf2f58f1456bb6f5ff23d57dee1"

EXPECTED = {
    "lk.bin": "5cb92494340417b1e5d18c3eaa34844dbcfec2cc8086451f087867cd06b15472",
    "boot-k32-native-evt.img": "87c2b9dc27625775549fd687268dd810d42ac660d6d6f0b398dfc52c5a962535",
    "boot-k32-native-diag.hdr": "dbbff7eeb8830c0d6cde454a97dc31be73d1cba32e6be9b21fe3c7be2b659066",
    "boot-k32-native-diag.payload": "8e6b0d3399054872442aa5ed348e18d89be65766257f86d68e669a0060b7d27c",
    "boot-k32-native-diag-wrapper.full.img": "e2400614b75e7a28941b19b76b7a1a46b6fe9ee8e1eb7dfe933d4aab4799c27a",
    "boot-k32-native-diag-wrapper.sparse.img": "6fc1f50802632ba27653c7c54f8a195c4d245993baf8a987a29c3f58277a0f82",
}
RAW_PAYLOAD_SHA256 = "9ed10c3c6534be4d9281a0fe681f449444e6d310ba732941cd268e29a26d07de"

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
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"ERROR: {message}")


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


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
    require(kernel_size == 0x585385, "native K32 kernel size mismatch")

    kernel = image[page_size:page_size + kernel_size]
    require(kernel[:4] == bytes.fromhex("88168858"), "kernel MediaTek header missing")
    payload_size = struct.unpack_from("<I", kernel, 4)[0]
    require(payload_size == 0x585185, "MediaTek payload size mismatch")
    payload = kernel[0x200:0x200 + payload_size]
    require(payload[0x24:0x28] == bytes.fromhex("18286f01"), "ARM zImage magic missing")
    require(struct.unpack_from("<II", payload, 0x28) == (0, ZIMAGE_END), "ARM zImage range changed")
    evt = payload[ZIMAGE_END:]
    require(len(evt) == EVT_SIZE and digest(evt) == EVT_SHA256, "sole EVT DTB hash/size mismatch")
    require(evt[:4] == bytes.fromhex("d00dfeed"), "EVT FDT magic missing")
    require(struct.unpack_from(">I", evt, 4)[0] == EVT_SIZE, "EVT FDT totalsize mismatch")
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
        b"Biscuit native K32 EVT diagnostic",
        b"ABI handoff: native K32 loader + stock ARM32 jump",
        b"FDT setprop name=%s ret=%d len=%d",
        b"M3 boot_linux_fdt common error epilogue reached",
        b"M4 boot_linux_fdt returned to boot_linux ret=%d",
    ):
        require(marker in raw_payload, f"compiled payload marker missing: {marker!r}")
    require(b"K64 FDT prep" not in raw_payload, "obsolete cached=1 marker remains")
    require(struct.pack("<I", 0x4BD641F4) not in raw_payload,
            "selector should be addressed through exact 0x4BD64000 base")
    require(struct.pack("<I", 0x4BD64000) in raw_payload, "cached selector base missing")
    require(struct.pack("<I", 0x4BD33700) in raw_payload, "stock selector validation base missing")
    require("*patch32 = 0;" in added_source, "source patch does not clear cached selector")
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
    print("evt_only_boot_contract=PASS zimage=0x578910 evt=0xC875 kernel=0x585385")
    print("fdt_diagnostic_contract=PASS setprop_calls=14 M3=0x4BD33888 M4=0x4BD33DC0")
    print("wrapper_sparse_contract=PASS block=223215 logical=110MiB")


if __name__ == "__main__":
    main()
