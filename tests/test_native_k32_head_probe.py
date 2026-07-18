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
        self.assertEqual(metadata["marker"], BUILDER.HEAD_MARKER_SEQUENCE)
        self.assertEqual(metadata["raw_head"], BUILDER.HEAD_ENTRY_BRANCH)
        self.assertLessEqual(metadata["new_stream_size"], metadata["old_stream_size"])
        self.assertEqual(patched[BUILDER.KERNEL_GZIP_END - 4:BUILDER.KERNEL_GZIP_END],
                         struct.pack("<I", BUILDER.DECOMPRESSED_KERNEL_SIZE))
        self.assertEqual(patched[BUILDER.ZIMAGE_END - 0x3D:],
                         stock_zimage[BUILDER.ZIMAGE_END - 0x3D:])

        raw = BUILDER.decompress_kernel_image(patched)
        stock_raw = BUILDER.decompress_kernel_image(stock_zimage)
        self.assertEqual(raw[:4], BUILDER.HEAD_ENTRY_BRANCH)
        cave_end = (BUILDER.HEAD_WRAPPER_CAVE_OFF +
                    BUILDER.HEAD_WRAPPER_CAVE_SIZE)
        self.assertEqual(
            raw[BUILDER.HEAD_WRAPPER_CAVE_OFF:cave_end],
            BUILDER.assemble_head_wrappers(),
        )
        allowed = [(0, 4),
                   (BUILDER.HEAD_TRAMPOLINE_OFF,
                    BUILDER.HEAD_TRAMPOLINE_OFF + BUILDER.HEAD_TRAMPOLINE_SIZE),
                   (BUILDER.HEAD_WRAPPER_CAVE_OFF, cave_end)]
        allowed.extend((site, site + 4)
                       for site, _ in BUILDER.HEAD_WRAPPER_PATCH_SITES)
        masked_raw = bytearray(raw)
        masked_stock = bytearray(stock_raw)
        for start, end in allowed:
            masked_raw[start:end] = b"\0" * (end - start)
            masked_stock[start:end] = b"\0" * (end - start)
        self.assertEqual(bytes(masked_raw), bytes(masked_stock))

    def test_expanded_wrapper_patch_sites_have_exact_control_flow(self):
        self.assertEqual(BUILDER.HEAD_MARKER_SEQUENCE, "HISPLVUTFCE")
        self.assertEqual(BUILDER.HEAD_WRAPPER_MARKERS, "SPLVUTFCE")
        self.assertEqual(len(BUILDER.HEAD_WRAPPER_PATCH_SITES), 7)
        self.assertEqual(
            [site for site, _ in BUILDER.HEAD_WRAPPER_PATCH_SITES],
            [
                0x0034,  # S/P: post-SVC join, CPU ID read
                0x0038,  # L: __lookup_processor_type returned
                0x0054,  # V: __vet_atags returned
                0x0058,  # U: __fixup_smp returned
                0x005C,  # F: __fixup_pv_table returned
                0x0060,  # T: __create_page_tables returned
                0x0074,  # C/E: CPU init returned, __enable_mmu branch
            ],
        )
        for site, wrapper in BUILDER.HEAD_WRAPPER_PATCH_SITES:
            with self.subTest(site=site, wrapper=wrapper):
                self.assertEqual(
                    BUILDER.assemble_head_wrapper_patch(site, wrapper),
                    BUILDER.head_wrapper_patch_word(site, wrapper),
                )

    def test_wrapper_assembly_uses_flags_safe_uart_stubs_with_r11_save(self):
        asm = BUILDER._head_wrapper_asm()
        self.assertNotIn("mov     r11, lr", asm)
        self.assertNotIn("bx      r11", asm)
        self.assertIn("bl      0x40008878", asm)
        self.assertIn("bl      0x4000821c", asm.lower())
        self.assertIn("bl      0x4000813c", asm.lower())
        self.assertIn("bl      0x400081c8", asm.lower())
        self.assertIn("bl      0x40008084", asm.lower())
        self.assertIn("push    {r11, lr}", asm)
        self.assertIn("pop     {r11, pc}", asm)
        self.assertIn("movw    r3, #0x2000", asm)
        self.assertIn("movt    r3, #0x1100", asm)

    def test_splvuf_tce_sites_are_not_past_enable_mmu(self):
        self.assertLessEqual(
            max(site for site, _ in BUILDER.HEAD_WRAPPER_PATCH_SITES), 0x0074)
        self.assertEqual(BUILDER.HEAD_WRAPPER_CAVE_SIZE,
                         9 * BUILDER.HEAD_WRAPPER_SLOT_SIZE)

    def test_large_wrapper_cave_is_unreachable_and_unreferenced_in_stock(self):
        image = (ROOT / "inputs/boot-v184-stock32-parity-stock.img").read_bytes()
        kernel_size = struct.unpack_from("<I", image, 8)[0]
        kernel = image[0x800:0x800 + kernel_size]
        stock_zimage = kernel[0x200:0x200 + BUILDER.ZIMAGE_END]
        stock_raw = BUILDER.decompress_kernel_image(stock_zimage)
        start = BUILDER.HEAD_WRAPPER_CAVE_OFF
        end = start + BUILDER.HEAD_WRAPPER_CAVE_SIZE
        self.assertEqual(stock_raw[start:end], b"\0" * (end - start))
        self.assertEqual(BUILDER.head_wrapper_cave_branch_sources(stock_raw), [])
        self.assertEqual(BUILDER.head_wrapper_cave_literal_pointers(stock_raw), [])
        # The preceding literal-pool block is skipped by an unconditional stock
        # branch, and the first non-zero data after the cave is the stock
        # initcall_debug format string. This pins the cave as padding, not as
        # reachable code or addressed data.
        self.assertEqual(stock_raw[0x76D030:0x76D034],
                         bytes.fromhex("a2a7e2ea"))
        self.assertTrue(stock_raw[0x76E000:0x76E010].startswith(b"initcall_debug"))

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
