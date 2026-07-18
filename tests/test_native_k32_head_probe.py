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
        self.assertEqual(metadata["marker"], "HI")
        self.assertEqual(metadata["raw_head"], BUILDER.HEAD_ENTRY_BRANCH)
        self.assertLessEqual(metadata["new_stream_size"], metadata["old_stream_size"])
        self.assertEqual(patched[BUILDER.KERNEL_GZIP_END - 4:BUILDER.KERNEL_GZIP_END],
                         struct.pack("<I", BUILDER.DECOMPRESSED_KERNEL_SIZE))
        self.assertEqual(patched[BUILDER.ZIMAGE_END - 0x3D:],
                         stock_zimage[BUILDER.ZIMAGE_END - 0x3D:])

        raw = BUILDER.decompress_kernel_image(patched)
        stock_raw = BUILDER.decompress_kernel_image(stock_zimage)
        self.assertEqual(raw[:4], BUILDER.HEAD_ENTRY_BRANCH)
        self.assertEqual(raw[4:BUILDER.HEAD_TRAMPOLINE_OFF],
                         stock_raw[4:BUILDER.HEAD_TRAMPOLINE_OFF])
        self.assertEqual(
            raw[BUILDER.HEAD_TRAMPOLINE_OFF:
                BUILDER.HEAD_TRAMPOLINE_OFF + BUILDER.HEAD_TRAMPOLINE_SIZE],
            BUILDER.assemble_head_trampoline(),
        )
        self.assertEqual(raw[BUILDER.HEAD_TRAMPOLINE_OFF +
                             BUILDER.HEAD_TRAMPOLINE_SIZE:],
                         stock_raw[BUILDER.HEAD_TRAMPOLINE_OFF +
                                   BUILDER.HEAD_TRAMPOLINE_SIZE:])

    def test_post_hyp_trampoline_has_exact_control_flow(self):
        self.assertEqual(BUILDER.HEAD_ENTRY_BRANCH, bytes.fromhex(
            "300200ea"  # 0x40008000 b 0x400088c8
        ))
        self.assertEqual(BUILDER.assemble_head_trampoline(), bytes.fromhex(
            "00c083e5"  # 0x400088c8 str r12,[r3] -> H
            "bb4500eb"  # 0x400088cc bl 0x40019fc0 (__hyp_stub_install)
            "49c0a0e3"  # 0x400088d0 mov r12,#'I'
            "00c083e5"  # 0x400088d4 str r12,[r3] -> I
            "00900fe1"  # 0x400088d8 mrs r9,cpsr (stock offset 0x04)
            "c9fdffea"  # 0x400088dc b 0x40008008 (stock eor)
        ))
        # The trampoline lives in six stock NOPs after __error_p's infinite
        # loop. It emits H, calls the exact stock stub, emits I only after the
        # return, restores MRS at its original semantic point, then resumes at
        # the untouched safe_svcmode_maskall EOR.

    def test_d_to_h_trampoline_preserves_arm_boot_abi_contract(self):
        probe = BUILDER.assemble_dejump_probe()
        self.assertEqual(probe, bytes.fromhex(
            "003002e3"  # movw r3,#0x2000
            "003141e3"  # movt r3,#0x1100
            "44c0a0e3"  # mov r12,#'D'
            "00c083e5"  # str r12,[r3]
            "48c0a0e3"  # mov r12,#'H'
            "00f020e3"  # nop; MRS now runs after the hyp stub in the head cave
            "14ff2fe1"  # bx r4
        ))
        # No instruction in this exact trampoline writes r0/r1/r2/r4; r4 is
        # consumed only as the decompressed-kernel branch target.


if __name__ == "__main__":
    unittest.main()
