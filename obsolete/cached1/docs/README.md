# Amonet K32 / 32N2 variant

> **OBSOLETE—DO NOT DEPLOY:** this page and the unqualified
> `boot-k32-wrapper.*`, `boot-k32.hdr`, and `boot-k32.payload` artifacts describe
> the superseded `cached_is_64=1` hybrid. The exact v184 LK reads that selector
> before kernel-image processing as well as before final entry, so it sends a
> stock ARM32 zImage through the incompatible K64 loader/decompressor path.
> Use [the native-K32 repository README](../../../README.md) and the
> `boot-k32-native-*` artifacts instead.

This directory documents the separate Amonet payload built for the v184
stock ARM32 image. The existing `bin/boot.hdr` and `bin/boot.payload` remain
unchanged.

The K32 payload applies a post-payload handoff fix before returning to stock
LK:

1. It leaves preloader/ATF and LK's DT preparation on the already-working K64
   path by setting LK's cached selector to `1`.
2. At LK's final selector, it changes `CMP r0,#0` to `MOVS r0,#0` at runtime
   address `0x4BD33704` and retains the stock `BEQ.W` to `0x4BD33BCA`.

The one-halfword change is `0x2800` to `0x2000`, or little-endian bytes
`00 28` to `00 20`. `MOVS` supplies the ARM32 Linux ABI's required `r0=0` and
sets Z, causing the existing conditional branch to enter LK's native ARM32
epilogue with `r1=machid` and `r2=tags/FDT`.

The previous candidate changed `F000 8260` to the unconditional branch
`F000 BA60`. Although its target was correct, it left the K64 selector's
nonzero value in `r0` and therefore violated the ARM32 kernel entry ABI.

The still-earlier experimental address `0x4BD33908` was also incorrect: it
treated an on-disk offset as a runtime address. The preloader skips the LK
image's 0x200-byte MediaTek header. The corrected runtime selector starts at
`0x4BD33704`.

This variant deliberately keeps the signed stock preloader unchanged. ATF
has already consumed `kernel_boot_opt=4` before Amonet runs; secure world and
LK remain AArch64-capable while the final normal-world kernel entry uses LK's
native ARM32 calling convention.

Artifacts:

- `bin/boot-k32.hdr` — 96-byte wrapper header
- `bin/boot-k32.payload` — injected payload section
- `bin/boot-k32-wrapper.full.img` — 110 MiB logical fastboot image
- `bin/boot-k32-wrapper.sparse.img` — sparse fastboot image

The wrapper is intended to be flashed through the existing Amonet fastboot
redirection. It does not modify the signed preloader. The runtime LK selector
patch is reapplied every boot while this wrapper remains installed.

Expected UART marker:

```text
ABI handoff: K64 FDT prep + ARM32 jump r0=0 target=0x4BD33BCA bootopt=4 cached=1 opcode=2000 f000 8260
```

The artifacts were built from the local v184 Amonet source tree with the
minimal change recorded in `main.c.patch`. No device flashing was performed.
