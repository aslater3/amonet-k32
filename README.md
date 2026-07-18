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
EVT raw size: 0xC875 (totalsize inflated to 0x10000, zero-padded)
new payload:  0x588910
new kernel:   0x588B10 (includes the 0x200 MediaTek header)
```

EVT SHA-256:
`f44630ba28f503dd7503bc7cffa2ee96a319acf2f58f1456bb6f5ff23d57dee1`.
The stock ramdisk and Android boot parameters are preserved.

## Runtime diagnostics

The wrapper validates the exact stock instructions before installing hooks.
It wraps all 15 `fdt_setprop` call sites used by the exact v184
`boot_linux_fdt()` — the 14 direct calls plus the internal call inside the
`fdt_setprop_u32` helper at `0x4BD32F40` (which writes `linux,initrd-start`
and `linux,initrd-end`) — and prints:

```text
FDT setprop name=<property> ret=<ret,hex> len=<hex> fdt=<fdt pointer> node=<node offset>
FDT magic=<first u32 at fdt> total=<fdt_totalsize, host order>
```

The two initrd u32 writes are additionally captured and echoed with their
values:

```text
FDT initrd-start val=<hex>
FDT initrd-end val=<hex>
```

(The payload mini-printf has no `%d`; signed returns print as two's-complement
hex, e.g. FDT_ERR_BADOFFSET -4 shows as `fffffffc`.)

This provides the useful M1/M2 information at property granularity without
guessing stripped helper boundaries. Two exact control-flow checkpoints are
also installed:

```text
M3 boot_linux_fdt common error epilogue reached
M4 boot_linux_fdt args a0=<kernel> a1=<fdt> a2=<hex> a3=<machid> a4=<hex> a5=<hex>
M4 boot_linux_fdt returned to boot_linux ret=<hex>
```

If Linux entry succeeds, M3 and the M4 return line do not execute. If both M3
and the M4 return appear, the watchdog is explained by `boot_linux_fdt()`
returning and `boot_linux()` entering its stock infinite loop. The last
`FDT setprop` line identifies the preceding property operation and its return
value. The M4 args line records all six `boot_linux_fdt()` arguments,
including the machid later reloaded as `r1` by the ARM32 jump stub.

Expected pre-resume marker:

```text
ABI handoff: native K32 loader + stock ARM32 jump bootopt=4 cached=0 opcode=2800 f000 8260
```

The existing full-LK cache clean remains immediately before LK restart.

A final hook sits on the ARM32 kernel-jump stub at `0x4BD33BCA` (stock
`ldr r1,[sp,#48]; mov r2,r6; blx fp`). Immediately before the handoff it
emits a raw UART `J` marker, then logs the exact kernel-consumed state:

```text
K32J r0=<hex> machid=<hex> r2=<fdt> fp=<kernel entry> sp=<hex>
K32J cpu cpsr=<hex> mode=<0x13=SVC 0x1a=HYP> sctlr=<bit0=MMU bit2=D$ bit12=I$> vbar=<hex>
K32J zimg <first 4 words at fp> magic24=<word at fp+0x24, expect 16f2818>
K32J fdt magic=<edfe0dd0> total=<packed totalsize, <=0x10000; 0xdd92 observed>
K32J initrd <start>-<end> head <first 4 bytes at initrd-start>
```

The initrd head bytes answer whether the ramdisk is physically present where
`/chosen/linux,initrd-start` points (gzip ramdisks start `1f 8b`). After
logging, the trampoline restores the full register frame and performs the
stock `blx fp` handoff unchanged.

The final FDT `total=` is **not** `0x10000`: `0x10000` is only the writable
capacity supplied so libfdt can create `/chosen/linux,initrd-*`. Before the
handoff LK calls `fdt_pack()`, which compacts the tree and rewrites
`totalsize` to the actual packed length (`0xdd92` for this build). Any valid
packed size no greater than `0x10000` with magic `edfe0dd0` is expected.

In addition, the EVT boot image's zImage entry NOP sled (offsets `0x00-0x1f`)
is replaced by an 8-instruction ARM UART probe (assembled with
`arm-none-eabi-as -march=armv7-a` at build time, never hand-encoded). It
polls UART LSR `0x11002014` and writes `K` to THR `0x11002000`, clobbering
only `r3`/`r12` (unspecified at kernel entry) and preserving the ABI
registers `r0`/`r1`/`r2`, then falls through to the untouched stock branch
at `+0x20`. Interpretation:

- `J...K32J...` but no `K` → the `blx` interworking, execution state, or the
  first fetch at `0x40008000` failed (use the `K32J cpu` line to diagnose).
- `K` appears but no kernel output follows → the CPU entered the zImage and
  the failure is inside zImage startup, relocation, or decompression.

This directory is its own Git repository and contains the patched Amonet
source (`lk-payload/`), BROM injector source (`brom-payload/` and `modules/`),
exact firmware inputs, generated artifacts, deployment scripts and the
superseded experiments under `obsolete/`.

## Root cause found (2026-07-17) and fix

The first run with property-level hooks showed:

```text
FDT setprop name=reg ret=0 len=10 fdt=48000000 node=b324
M3 boot_linux_fdt common error epilogue reached
M4 boot_linux_fdt returned to boot_linux ret=0
```

The in-place `/memory@00000000` `reg` rewrite succeeds, then execution
diverges to the error epilogue before the next hooked call. Static
disassembly of the window showed the failing operation: `fdt_setprop_u32`
of `linux,initrd-start`/`linux,initrd-end` on `/chosen`. Those properties do
not exist in the appended DTB, so libfdt must create them — but LK copies
the appended DTB to `tags_addr` with a verbatim `memcpy` of exactly
`fdt_totalsize` bytes, and the blob is packed tight (zero internal slack),
so the creation fails with `FDT_ERR_NOSPACE` and `boot_linux_fdt()` returns
without ever reaching the ARM32 kernel-jump stub at `0x4BD33BCA`.

Fix: the builder inflates the appended EVT blob's `fdt_totalsize` to
`0x10000` and zero-pads the stored blob to match, giving libfdt room for all
runtime fixups. The raw DTB content (first `0xC875` bytes, SHA pinned) is
unchanged; `hw_code` stays at offset `0x24`.

The payload reads the full 0x20-byte misc bootloader message so the optional
`UART_PLEASE` marker at offset `0x10` is reachable. When fastboot is requested
by the action key, boot mode, or a one-shot marker, the payload prepares
fastboot and deliberately skips the K32 image read hook, inner boot-header
validation, selector change, and FDT/jump diagnostics. Thus a damaged/missing
GPT or `boot_a_x` cannot turn the recovery path into a K32 diagnostic halt.

## Artifacts

- `bin/boot-k32-native-evt.img` — 16 MiB ARM32 boot image, sole EVT DTB with
  `fdt_totalsize` inflated to `0x10000` (zero-padded) for libfdt fixup slack.
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
