#!/usr/bin/env python3
"""Contracts for the decompressed ARM head-entry UART probe."""

import importlib.util
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "build_native_k32_diagnostic", ROOT / "tools/build-native-k32-diagnostic.py")
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class HeadEntryProbeTest(unittest.TestCase):
    def test_patches_head_and_keeps_stock_gzip_envelope(self):
        image = (ROOT / "inputs/boot-v184-stock32-parity-stock.img").read_bytes()
        kernel_size = struct.unpack_from("<I", image, 8)[0]
        kernel = image[0x800:0x800 + kernel_size]
        stock_zimage = kernel[0x200:0x200 + BUILDER.ZIMAGE_END]

        patched, metadata = BUILDER.install_head_entry_probe(stock_zimage)

        self.assertEqual(len(patched), len(stock_zimage))
        self.assertEqual(metadata["marker"], "H")
        self.assertEqual(metadata["raw_head"], BUILDER.HEAD_ENTRY_PROBE)
        self.assertLessEqual(metadata["new_stream_size"], metadata["old_stream_size"])
        self.assertEqual(patched[BUILDER.KERNEL_GZIP_END - 4:BUILDER.KERNEL_GZIP_END],
                         struct.pack("<I", BUILDER.DECOMPRESSED_KERNEL_SIZE))
        self.assertEqual(patched[BUILDER.ZIMAGE_END - 0x3D:],
                         stock_zimage[BUILDER.ZIMAGE_END - 0x3D:])

        raw = BUILDER.decompress_kernel_image(patched)
        self.assertEqual(raw[:8], BUILDER.HEAD_ENTRY_PROBE)
        self.assertEqual(raw[8:16], BUILDER.STOCK_DECOMPRESSED_HEAD[8:16])
        stock_raw = BUILDER.decompress_kernel_image(stock_zimage)
        self.assertEqual(raw[8:], stock_raw[8:])

    def test_d_to_h_trampoline_preserves_arm_boot_abi_contract(self):
        probe = BUILDER.assemble_dejump_probe()
        self.assertEqual(probe, bytes.fromhex(
            "003002e3"  # movw r3,#0x2000
            "003141e3"  # movt r3,#0x1100
            "44c0a0e3"  # mov r12,#'D'
            "00c083e5"  # str r12,[r3]
            "48c0a0e3"  # mov r12,#'H'
            "00900fe1"  # mrs r9,cpsr (displaced from head.S)
            "14ff2fe1"  # bx r4
        ))
        # No instruction in this exact trampoline writes r0/r1/r2/r4; r4 is
        # consumed only as the decompressed-kernel branch target. Moving MRS
        # before __hyp_stub_install is safe because that inspected stock stub
        # preserves r9 and does not change CPSR control/mode bits.


if __name__ == "__main__":
    unittest.main()
