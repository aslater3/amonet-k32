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
        self.assertEqual(len(BUILDER._HEAD_WRAPPER_DEFS), 7)
        self.assertEqual(
            [definition["site"] for definition in BUILDER._HEAD_WRAPPER_DEFS],
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

    def test_splvuf_tce_sites_and_post_mmu_sites_are_separate(self):
        self.assertLessEqual(
            max(definition["site"] for definition in BUILDER._HEAD_WRAPPER_DEFS), 0x0074)
        self.assertEqual(BUILDER.POST_MMU_PATCH_SITES,
                         ((0xAA72E0, 0x1C0), (0xAA78B0, 0x200)))
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

    def test_post_mmu_sites_and_device_pgd_descriptor_are_pinned(self):
        self.assertEqual(BUILDER.POST_MMU_PATCH_SITES,
                         ((0xAA72E0, 0x1C0), (0xAA78B0, 0x200)))
        self.assertEqual(BUILDER.POST_MMU_STOCK_WORDS,
                         {0xAA72E0: bytes.fromhex("40308fe2"),
                          0xAA78B0: bytes.fromhex("f0432de9")})
        self.assertEqual(BUILDER.UART_PGD_INDEX, 0xC10)
        self.assertEqual(BUILDER.UART_PGD_OFFSET, 0x3040)
        self.assertEqual(BUILDER.UART_DEVICE_SECTION, 0x11011C12)
        self.assertEqual(BUILDER.UART_DEVICE_SECTION & 0xFFFF, 0x1C12)

    def test_post_mmu_wrappers_have_dual_channels_and_displaced_semantics(self):
        asm = BUILDER._post_mmu_wrapper_asm()
        self.assertIn("movw    r12, #0x2000", asm)
        self.assertIn("movt    r12, #0xc100", asm.lower())
        self.assertIn("movw    r12, #0xf000", asm.lower())
        self.assertIn("movt    r12, #0xc0df", asm.lower())
        self.assertNotIn("sub     r12, r12, #0x21000", asm.lower())
        self.assertIn("strb    r3, [r12, #4]", asm.lower())
        self.assertIn("strb    r0, [r12, #5]", asm.lower())
        m_wrapper = asm.split("wrapper_M:", 1)[1].split(".org 0x200", 1)[0]
        self.assertNotIn("r0", m_wrapper.lower(),
                         "M wrapper must preserve live SCTLR value in r0")
        self.assertIn("mcr     p15, 0, r12, c7, c10, 1", asm.lower())
        self.assertIn("movw    r3, #0xf328", asm.lower())
        self.assertIn("movt    r3, #0xc0aa", asm.lower())
        self.assertIn(".equ M_SITE, 0xc0aaf2e0", asm)
        self.assertIn("b       M_SITE + 4", asm)
        self.assertIn(".word   0xe92d43f0", asm.lower())
        self.assertIn(".equ W_SITE, 0xc0aaf8b0", asm)
        self.assertIn("b       W_SITE + 4", asm)

        blob = BUILDER.assemble_head_wrappers()
        self.assertEqual(blob[0x1C0:0x200], BUILDER.POST_MMU_M_EXPECTED)
        self.assertEqual(blob[0x200:0x240], BUILDER.POST_MMU_W_EXPECTED)

    def test_head_patch_words_include_post_mmu_redirects(self):
        self.assertEqual(len(BUILDER.HEAD_WRAPPER_PATCH_SITES), 9)
        for site, wrapper in BUILDER.POST_MMU_PATCH_SITES:
            with self.subTest(site=site, wrapper=wrapper):
                self.assertEqual(
                    BUILDER.assemble_head_wrapper_patch(site, wrapper),
                    BUILDER.head_wrapper_patch_word(site, wrapper),
                )

    def test_payload_has_retained_marker_dump_and_invalidate_contract(self):
        source = (ROOT / "lk-payload/main.c").read_text()
        self.assertIn("0x40DFF000U", source)
        self.assertIn("K32P", source)
        self.assertIn('"K32P magic ok markers="', source)
        self.assertIn("low_uart_put(p[4]);", source)
        self.assertIn("low_uart_put(p[5]);", source)
        self.assertIn("dump_retained_post_mmu_markers();", source)
        self.assertIn("memset((void *)RETAINED_POST_MMU_BASE, 0, RETAINED_POST_MMU_SIZE);", source)


if __name__ == "__main__":
    unittest.main()
