# v184 native K32 + sole-EVT diagnostic

This is the corrected next candidate for bringing up the v184 ARM32 kernel.
It keeps LK's native 32-bit loader and entry path intact:

```text
cached_is_64 = 0
boot_arg[0x53] unchanged (observed value 4)
0x4BD33704 CMP r0,#0 unchanged
0x4BD33706 BEQ.W unchanged
0x4BD33708 branch halfword unchanged
```

The stock branch therefore supplies the ARM32 Linux entry state without a
hybrid K64 path: `r0=0`, `r1=machid`, `r2=FDT`, then `BLX` to the zImage.

## Boot-image isolation

`bin/boot-k32-native-evt.img` contains the original ARM zImage through its
header-declared end at `0x578910`, followed by only the EVT DTB:

```text
zImage:       original payload[0:0x578910]
EVT source:   original payload[0x585185:0x5919FA]
EVT size:     0xC875
new payload:  0x585185
new kernel:   0x585385 (includes the 0x200 MediaTek header)
```

EVT SHA-256:
`f44630ba28f503dd7503bc7cffa2ee96a319acf2f58f1456bb6f5ff23d57dee1`.
The stock ramdisk and Android boot parameters are preserved.

## Runtime diagnostics

The wrapper validates the exact stock instructions before installing hooks.
It wraps all 14 direct `fdt_setprop` calls in the exact v184
`boot_linux_fdt()` and prints:

```text
FDT setprop name=<property> ret=<signed return> len=<length>
```

This provides the useful M1/M2 information at property granularity without
guessing stripped helper boundaries. Two exact control-flow checkpoints are
also installed:

```text
M3 boot_linux_fdt common error epilogue reached
M4 boot_linux_fdt returned to boot_linux ret=<value>
```

If Linux entry succeeds, M3/M4 do not execute. If both appear, the watchdog is
explained by `boot_linux_fdt()` returning and `boot_linux()` entering its stock
infinite loop. The last `FDT setprop` line identifies the preceding property
operation and its return value.

Expected pre-resume marker:

```text
ABI handoff: native K32 loader + stock ARM32 jump bootopt=4 cached=0 opcode=2800 f000 8260
```

The existing full-LK cache clean remains immediately before LK restart.

This directory is its own Git repository and contains the patched Amonet
source (`lk-payload/`), BROM injector source (`brom-payload/` and `modules/`),
exact firmware inputs, generated artifacts, deployment scripts and the
superseded experiments under `obsolete/`.

## Artifacts

- `bin/boot-k32-native-evt.img` — 16 MiB ARM32 boot image, sole EVT DTB.
- `bin/boot-k32-native-diag.hdr` — Amonet BROM wrapper header.
- `bin/boot-k32-native-diag.payload` — injected payload section.
- `bin/boot-k32-native-diag-wrapper.full.img` — 110 MiB logical wrapper.
- `bin/boot-k32-native-diag-wrapper.sparse.img` — sparse fastboot wrapper.
- `patches/native-k32-diagnostic.patch` — exact source change.
- `tools/build-native-k32-diagnostic.py` — reproducible boot-image builder.
- `tools/verify-native-k32-diagnostic.py` — exact LK, boot, wrapper and
  sparse round-trip verifier.

Run the non-device preflight with:

```sh
./fastboot-k32-native-diag-step.sh --preflight-only
```

Rebuild and verify every current artifact with:

```sh
./tools/rebuild-native-k32.sh
```

Rebuild the sole-EVT boot image from the preserved stock input with:

```sh
python3 tools/build-native-k32-diagnostic.py \
  inputs/boot-v184-stock32-parity-stock.img \
  bin/boot-k32-native-evt.img
```

The old cached=1 + unconditional-branch and cached=1 + MOVS wrappers are
obsolete and must not be deployed. Their hashes only proved internal artifact
consistency, not a valid v184 LK execution path.
