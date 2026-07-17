#!/usr/bin/env python3
"""Verify the v184 post-payload ARM32 LK handoff contract."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LK_BASE = 0x4BD00000
LK_HEADER_SIZE = 0x200
PAYLOAD_BLOCK = 223215
RAW_PAYLOAD_OFFSET = 576
RAW_PAYLOAD_SIZE = 4464

EXPECTED = {
    "boot-k32.hdr": "dbbff7eeb8830c0d6cde454a97dc31be73d1cba32e6be9b21fe3c7be2b659066",
    "boot-k32.payload": "b916cf5f6f7f947deeb114b4e490b543a62c82be6205f0f2a76b68bcd913e450",
    "boot-k32-wrapper.full.img": "08266756e38138fcf71471e32be111d192dcb70e595572eb725363f38e9e0cfe",
    "boot-k32-wrapper.sparse.img": "b9a9dc0549b117a600ae497ce3f569171bb08fd94a35e225c04e784927403184",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"ERROR: {message}")


def lk_slice(lk: bytes, runtime_address: int, size: int) -> bytes:
    offset = LK_HEADER_SIZE + runtime_address - LK_BASE
    return lk[offset:offset + size]


def main() -> None:
    lk = (ROOT / "bin/lk.bin").read_bytes()
    hdr = (ROOT / "bin/boot-k32.hdr").read_bytes()
    payload = (ROOT / "bin/boot-k32.payload").read_bytes()
    full = (ROOT / "bin/boot-k32-wrapper.full.img").read_bytes()
    sparse = (ROOT / "bin/boot-k32-wrapper.sparse.img").read_bytes()

    require(lk[:4] == bytes.fromhex("88168858"), "LK MediaTek header magic mismatch")
    require(
        lk_slice(lk, 0x4BD33704, 6) == bytes.fromhex("002800f06082"),
        "stock LK selector is not CMP r0,#0; BEQ.W ARM32",
    )
    require(
        lk_slice(lk, 0x4BD33BCA, 6) == bytes.fromhex("0c993246d847"),
        "stock LK ARM32 target/calling sequence changed",
    )

    marker = b"ABI handoff: K64 FDT prep + ARM32 jump r0=0 target=0x4BD33BCA"
    require(marker in payload, "corrected post-payload UART marker missing")
    require(b"Biscuit post-payload ARM32 handoff" in payload, "K32 payload banner missing")
    raw_payload = payload[RAW_PAYLOAD_OFFSET:RAW_PAYLOAD_OFFSET + RAW_PAYLOAD_SIZE]
    require(len(raw_payload) == RAW_PAYLOAD_SIZE, "embedded raw payload is truncated")
    # Compiled patch: MOV.W r7,#0x2000; selector base; STRH r7,[r0,#4].
    # GCC coalesces 0x4BD33704/06/08 into base 0x4BD33700 plus offsets.
    require(
        raw_payload[0x516:0x51A] == bytes.fromhex("4ff40057"),
        "compiled payload does not materialize MOVS r0,#0 opcode 0x2000",
    )
    require(
        raw_payload[0x870:0x874] == struct.pack("<I", 0x4BD33700),
        "compiled payload does not use corrected LK selector base",
    )
    require(
        raw_payload[0x7F0:0x7F2] == bytes.fromhex("8780"),
        "compiled payload does not store 0x2000 at selector base + 4",
    )
    require(struct.pack("<I", 0x4BD33900) not in payload, "old +0x200 LK selector base remains")
    require(b"forced K32 jump" not in payload, "obsolete unconditional-branch payload remains")
    require(len(hdr) == 96 and hdr[:8] == b"ANDROID!", "wrapper header invalid")
    require(len(payload) == 9792, "wrapper payload section is not 9792 bytes")
    require(len(full) == 110 * 1024 * 1024, "full wrapper is not 110 MiB")
    require(full[:len(hdr)] == hdr, "header is not embedded in full wrapper")
    payload_offset = PAYLOAD_BLOCK * 0x200
    require(
        full[payload_offset:payload_offset + len(payload)] == payload,
        "payload is not embedded at block 223215",
    )

    require(sparse[:4] == bytes.fromhex("3aff26ed"), "sparse magic mismatch")
    file_hdr, chunk_hdr, block_size, total_blocks = struct.unpack_from("<HHII", sparse, 8)
    require((file_hdr, chunk_hdr) == (28, 12), "sparse header geometry mismatch")
    require(block_size == 4096 and total_blocks == 28160, "sparse logical geometry mismatch")

    for name, expected in EXPECTED.items():
        actual = digest((ROOT / "bin" / name).read_bytes())
        require(actual == expected, f"{name} hash mismatch: {actual}")

    print("lk_header_offset_contract=PASS disk_header=0x200 runtime_selector=0x4BD33704")
    print("lk_arm32_abi_contract=PASS target=0x4BD33BCA r0=0 r1=machid r2=fdt")
    print("post_payload_patch_contract=PASS CMP_r0_0->MOVS_r0_0 BEQ.W=retained")
    print("wrapper_embedding_contract=PASS block=223215 logical=110MiB")


if __name__ == "__main__":
    main()
