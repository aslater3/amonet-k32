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

The builder also replaces the stock decompressor return at zImage offset
`0x924` (the unique `mov pc,r4`) plus its following six-word ARM NOP sled with
a seven-instruction position-independent trampoline. It writes `D`, carries the
UART THR address and an `H` byte into the decompressed image, and executes
`bx r4`. The spare trampoline word is an ARM NOP; the stock `mrs r9,cpsr` now
runs after the virtualization stub exactly where `head.S` originally required it.

Inside the gzip member, the first decompressed word becomes a branch to six
verified alignment NOPs at `0x400088c8–0x400088df`. These NOPs follow
`__error_p`'s infinite loop, and the verifier confirms that the stock Image has
no direct ARM branch into the region. The six-word H/I trampoline:

1. writes `H` using the UART state carried from the D trampoline;
2. calls the exact stock `__hyp_stub_install` at `0x40019fc0`;
3. loads and writes `I` only after that call returns;
4. executes the displaced stock `mrs r9,cpsr`; and
5. branches to untouched `head.S+8` (`eor r9,r9,#HYP_MODE`).

Thus the stock `safe_svcmode_maskall` ordering and all untouched kernel bytes
remain unchanged; the separate expanded cave and nine early-head redirect words
carry the additional markers described below. The kernel is recompressed into
the exact original `0x5741fb`-byte envelope. Saved space is zero-filled except
for the mandatory
final little-endian `0x00b86070` inflated-size word consumed by `head.S` at
`input_data_end - 4`; retaining that word is required for safe decompressor
self-relocation. The zImage end and EVT offset do not move. Interpretation:

- `K` but no `D` → failure before the decompressor's final return, including
  cache/MMU setup, decompressor relocation, or gzip decompression.
- `KD` but no `H` → decompression completed, but `bx r4`, the first fetch, or
  the branch into the decompressed H/I trampoline failed.
- `KDH` without `I` → decompressed code ran, but the branch/call into
  `__hyp_stub_install`, the stub itself, or its return failed.
- `KDHI` → the virtualization stub returned; the next marker is the expanded
  early-head sequence below.

### Expanded early-head markers

The decompressed Image contains one verified zero-padding cave at
`0x40775054` (offset `0x76D054`, nine `0x40`-byte slots). The stock image has
no aligned ARM `B`/`BL` target in the cave, no aligned little-endian pointer
into it, and the preceding stock branch skips the literal/data block before
the cave; the first non-zero bytes after it are the `initcall_debug` string.
Only the seven listed head words and this cave are changed. Each UART stub
reloads THR `0x11002000` with `movw`/`movt` and uses only flags-safe
`mov`/`str` operations after the displaced stock call. Each call wrapper starts
with `push {r11, lr}` (`0xE92D4800`) and ends with `pop {r11, pc}`
(`0xE8BD8800`), so the original caller `LR` and `r11` survive the stock call.

The push/pop wrappers deliberately depend on inherited LK stack state: at the
five call sites kernel `sp` has not yet been initialized (stock loads kernel
`sp` at `0x40008064`). LK hands off with `sp = 0x41FFFA80`; this is 8-byte
aligned, points into plain writable DRAM, and is the dead LK stack at this
point. A wrapper call writes exactly eight bytes at `0x41FFFA78` (saved `r11`
and saved `LR`) and the matching pop restores `sp` before returning. The five
stock functions are disassembled from the deployed stock Image and contain no
`sp` access or reference to those eight bytes; the dependency is therefore
limited to the short pre-kernel-stack window before `0x40008064`. ARM `push`,
`pop`, `bl`, `movw`, `movt`, `mov`, and `str` without the `S` suffix do not
modify CPSR flags, and `pop {r11, pc}` loads the saved caller `LR` into `pc`,
returning to each patched call site +4.

| Marker | Site | Mechanism and interpretation |
|---|---|---|
| `S` | `0x40008034` | Stock `safe_svcmode_maskall` has completed (both SVC and HYP-ERET joins); cave emits `S`. |
| `P` | `0x40008034` | Cave executes displaced `mrc p15,0,r9,c0,c0`, then emits `P`; CPU ID read completed. |
| `L` | `0x40008038` | `BL` wrapper calls `__lookup_processor_type`, emits `L` after return, and pops the saved `LR` into `pc`. |
| `V` | `0x40008054` | `BL` wrapper calls `__vet_atags`, emits `V` after return. |
| `U` | `0x40008058` | `BL` wrapper calls `__fixup_smp`, emits `U` after return. |
| `F` | `0x4000805C` | `BL` wrapper calls `__fixup_pv_table`, emits `F` after return. |
| `T` | `0x40008060` | `BL` wrapper calls `__create_page_tables`, emits `T` after return. |
| `C` | `0x40008074` | CPU-specific init returned through `ret lr`; the C/E cave emits `C`. |
| `E` | `0x40008074` → `0x400087C4` | Same cave emits `E`, then performs the untouched `B __enable_mmu`. |

### Post-MMU dual-channel markers

The `T` wrapper also writes `pgd[0xC10]` at `[r4,#0x3040]` with the pinned
Device-section descriptor `0x11011C12`. This maps UART physical `0x11000000`
to VA `0xC1000000`, including THR VA `0xC1002000`. `paging_init` may later
replace this entry; that is an expected limitation of the narrow early mapping.

After the MMU transition, two wrappers run at their real virtual VMAs and emit
both a raw UART marker and a retained low-memory marker:

| Marker | Runtime site | Raw UART channel | Retained channel |
|---|---|---|---|
| `M` | `__mmap_switched`, VA `0xC0AAF2E0` (Image offset `0xAA72E0`) | `M` through VA `0xC1002000` | `M` at `0xC0DFF000+4` |
| `W` | `start_kernel`, VA `0xC0AAF8B0` (Image offset `0xAA78B0`) | `W` through VA `0xC1002000` | `W` at `0xC0DFF000+5` |

The retained record is `K32P` at `0x40DFF000` physical / `0xC0DFF000`
virtual, with marker bytes at `+4` and `+5`. Each wrapper performs
`DSB; DCCMVAC; DSB` after its retained write. At the beginning of the next
LK payload, a valid record prints `K32P magic ok markers=<M><W>` and the full
`0x1000` block is then zeroed, including malformed records. This is a
single-boot dump-and-invalidate channel, not a persistent event log.

Interpret the post-MMU evidence together with the existing UART stream:

| Observed evidence | Interpretation / next boundary |
|---|---|
| `TCE` but no `M` | Failure in `__enable_mmu` entry/transition or `turn_mmu_on`; inspect the MMU handoff and first post-MMU fetch. |
| `M` but no `W` | `__mmap_switched` ran; failure is before or inside the early `start_kernel` path. |
| `MW` but no kernel text | `start_kernel` was reached, but the failure is before earlycon/normal kernel text; inspect very-early init and console setup. |
| `MW` plus early serial console | Kernel is alive past the diagnostic sites; try the custom initramfs/next userspace-stage probe. |

Caveats: the retained block is ordinary low memory and may become
allocator-owned if the kernel gets far enough; allocation or later writes can
therefore clobber it, producing an acceptable false negative. The UART PGD
poke is intentionally temporary and may be overwritten by normal `paging_init`
setup. M/W prove execution of the wrappers and their immediate cache-clean
sequence, not successful completion of `start_kernel`, a healthy scheduler,
or a booted userspace. Raw UART and retained markers can be observed on
different boots; correlate the retained `K32P` record with the immediately
preceding reset and remember that LK consumes it once.

The expected one-boot stream after the existing probes is `KDHI SPLVUTFCE`
(UART output has no separators: `KDHISPLVUTFCE`). Interpretation is ordered:

| Last marker | Boundary reached | Next failure plane |
|---|---|---|
| `I` | `__hyp_stub_install` returned | `safe_svcmode_maskall` / SVC-HYP join |
| `S` | SVC mode write and join complete | CPU ID read |
| `P` | CPU ID read complete | processor-type lookup |
| `L` | `__lookup_processor_type` returned | ATAG vetting |
| `V` | `__vet_atags` returned | SMP fixup |
| `U` | `__fixup_smp` returned | PV-table fixup |
| `F` | `__fixup_pv_table` returned | page-table creation |
| `T` | `__create_page_tables` returned | CPU-specific init |
| `C` | CPU-specific init returned | `__enable_mmu` entry |
| `E` | `__enable_mmu` branch reached | MMU transition and later code |

All probe code is assembled and linked at its real runtime VMA. The verifier
decompresses the final artifact, checks the entry branch, exact H/I trampoline,
exact S/P/L/V/U/F/T/C/E cave encodings and patch words, proves all bytes outside
the entry word, seven patched head words, and the two probe caves remain stock,
and verifies the fixed-size gzip envelope and complete seven-word D trampoline.

Before GPT parsing, the payload also inspects the retained MediaTek ATF crash
control block at `0x5F800000`: indices 14, 15, and 16 provide the crash-buffer
address, size, and flag. It prints `ATFCR flag=... addr=... size=...`, rejects
anything outside `0x5F800000–0x5FA00000` or larger than `0x20000`, and replaces
non-printable bytes with `.` while dumping the bounded record. The `0x20000`
limit matches the retained crash-buffer capacity observed on Radar/Puffin: the
record at `0x5F9DC000` ends exactly at the ATF AEE boundary `0x5F9FC000`. This is
read-only and runs before normal LK/device setup:

```text
ATFCR flag=<hex> addr=<hex> size=<hex>
ATFCR dump begin
<bounded printable crash record>
ATFCR dump end
```

If the metadata is stale or invalid, the payload prints `ATFCR bounds rejected`
and continues normally.

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
