#!/usr/bin/env python3
"""Build the reviewed, unsigned MT8163 K32N2 preloader candidate.

The change is deliberately limited to the two mirrored Thumb instructions
that copy the stock kernel_boot_opt into the BL31-facing boot argument:
``ldr r2, [r2]`` becomes ``movs r2, #2``.  This candidate is not signed and is
never selected by the normal signed-preloader scripts.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

SOURCE_SHA256 = "49193a8c06f3ac4c70691cb8bcaa3e2ddcefbd36d54b8d425a014aa2318846ff"
PATCH_SITES = (0x11AD0, 0x51AD0)
OLD = bytes.fromhex("1268")
NEW = bytes.fromhex("0222")
STORE = bytes.fromhex("c3f85423")
MIRROR_START = 0x11AC0
MIRROR_END = 0x11AE0


def sha(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} INPUT_PRELOADER OUTPUT_PRELOADER")

    source, output = map(Path, sys.argv[1:])
    data = bytearray(source.read_bytes())
    if sha(data) != SOURCE_SHA256:
        raise RuntimeError(f"source hash mismatch: {sha(data)}")
    if len(data) != 0x100000:
        raise RuntimeError(f"unexpected preloader size: {len(data):#x}")
    if data[MIRROR_START:MIRROR_END] != data[0x51AC0:0x51AE0]:
        raise RuntimeError("preloader copies are not mirrored")

    for site in PATCH_SITES:
        if data[site:site + 2] != OLD:
            raise RuntimeError(f"unexpected opcode at {site:#x}: {data[site:site + 2].hex()}")
        if data[site + 4:site + 8] != STORE:
            raise RuntimeError(f"unexpected store at {site + 4:#x}")
        data[site:site + 2] = NEW

    if data[MIRROR_START:MIRROR_END] != data[0x51AC0:0x51AE0]:
        raise RuntimeError("patched preloader copies are not mirrored")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    print(f"source_sha256={SOURCE_SHA256}")
    print(f"output_sha256={sha(data)}")
    print("patches=0x11ad0,0x51ad0:ldr-r2-[r2]->movs-r2-2")
    print("signature_status=UNSIGNED_CANDIDATE")
    print("deployment=EXPLICIT_ONLY")


if __name__ == "__main__":
    main()
