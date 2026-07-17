#!/usr/bin/env bash
# Deploy the reviewed v184 stock ARM32 candidate after bootrom-step.sh.
#
# The wrapper deliberately maps fastboot boot_a/boot_b writes to the shadow
# boot_a_x/boot_b_x partitions.  Do not replace those commands with direct
# boot_a_x/boot_b writes: the wrapper must remain the active LK entry path.
set -euo pipefail

WORKDIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
cd "$WORKDIR"

preflight_only=0
case "${1:-}" in
  --preflight-only)
    preflight_only=1
    shift
    ;;
  "")
    ;;
  *)
    printf 'ERROR: unknown argument: %s\n' "$1" >&2
    exit 1
    ;;
esac

FASTBOOT_BIN="${FASTBOOT_BIN:-fastboot}"
FASTBOOT_SERIAL="${FASTBOOT_SERIAL:-G2A0RF0485020316}"
K32_WRAPPER_IMAGE="${K32_WRAPPER_IMAGE:-/home/andy/workspace/echo-evidence/v184-stock32-parity/boot-v184-diag-cached1-forcek32.fastboot.sparse.img}"
K32_WRAPPER_SHA256="${K32_WRAPPER_SHA256:-a38b131606de4c3e58b464a4b4a5008e691f3b0289dd2fabb47b6753bf7be67a}"
K32_BOOT_IMAGE="${K32_BOOT_IMAGE:-/home/andy/workspace/echo-evidence/v184-stock32-parity/boot-v184-stock32-parity-stock.img}"
K32_BOOT_SHA256="${K32_BOOT_SHA256:-c0f52a3b079d214495cd3dd22f92fd85695d1b868c58b491a2edb933bc4f6d1a}"
K32_EXPDB_CLEAR="${K32_EXPDB_CLEAR:-/home/andy/workspace/echo-evidence/v184-stock32-parity/expdb-clear-512.bin}"
K32_EXPDB_CLEAR_SHA256="${K32_EXPDB_CLEAR_SHA256:-076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560}"

command -v "$FASTBOOT_BIN" >/dev/null || {
  printf 'ERROR: fastboot not found: %s\n' "$FASTBOOT_BIN" >&2
  exit 1
}

for f in "$K32_WRAPPER_IMAGE" "$K32_BOOT_IMAGE" "$K32_EXPDB_CLEAR"; do
  [[ -f "$f" ]] || { printf 'ERROR: missing %s\n' "$f" >&2; exit 1; }
done

sha256_of() { sha256sum "$1" | awk '{print $1}'; }
require_hash() {
  local path="$1" expected="$2" label="$3" actual
  actual="$(sha256_of "$path")"
  [[ "$actual" == "$expected" ]] || {
    printf 'ERROR: %s hash mismatch\nexpected=%s\nactual=%s\npath=%s\n' \
      "$label" "$expected" "$actual" "$path" >&2
    exit 1
  }
  printf '%-16s %s\n' "$label" "$actual"
}

require_hash "$K32_WRAPPER_IMAGE" "$K32_WRAPPER_SHA256" wrapper_sparse
require_hash "$K32_BOOT_IMAGE" "$K32_BOOT_SHA256" stock32_boot
require_hash "$K32_EXPDB_CLEAR" "$K32_EXPDB_CLEAR_SHA256" expdb_clear

python3 - "$K32_WRAPPER_IMAGE" "$K32_BOOT_IMAGE" "$K32_EXPDB_CLEAR" <<'PY'
from pathlib import Path
import struct
import sys

wrapper, boot, expdb = map(Path, sys.argv[1:])
ws = wrapper.read_bytes()
if ws[:4] != bytes.fromhex("3aff26ed"):
    raise SystemExit("ERROR: wrapper is not an Android sparse image")
file_hdr, chunk_hdr, block_size, total_blocks, total_chunks = struct.unpack_from("<HHIII", ws, 8)
if (file_hdr, chunk_hdr, block_size, total_blocks) != (28, 12, 4096, 28160):
    raise SystemExit(
        f"ERROR: unexpected wrapper sparse geometry: hdr={file_hdr}/{chunk_hdr} "
        f"block={block_size} blocks={total_blocks}"
    )
if total_blocks * block_size != 110 * 1024 * 1024:
    raise SystemExit("ERROR: wrapper logical size is not 110 MiB")

b = boot.read_bytes()
if len(b) != 16 * 1024 * 1024 or b[:8] != b"ANDROID!":
    raise SystemExit("ERROR: stock ARM32 image is not a 16 MiB legacy Android boot image")
kernel_addr, ramdisk_addr, tags_addr, page_size = (
    struct.unpack_from("<I", b, 0x0C)[0],
    struct.unpack_from("<I", b, 0x14)[0],
    struct.unpack_from("<I", b, 0x20)[0],
    struct.unpack_from("<I", b, 0x24)[0],
)
cmdline = b[0x40:0x240].split(b"\0", 1)[0]
if (kernel_addr, ramdisk_addr, tags_addr, page_size) != (
    0x40008000, 0x44000000, 0x48000000, 2048
):
    raise SystemExit(
        f"ERROR: unexpected ARM32 header: kernel={kernel_addr:#x} "
        f"ramdisk={ramdisk_addr:#x} tags={tags_addr:#x} page={page_size}"
    )
if b"bootopt=64S3,32N2,32N2" not in cmdline:
    raise SystemExit(f"ERROR: stock ARM32 bootopt missing: {cmdline!r}")
if len(expdb.read_bytes()) != 512:
    raise SystemExit("ERROR: expdb clear image must be exactly 512 bytes")
print("wrapper_sparse_contract=PASS logical=110MiB")
print("stock32_boot_contract=PASS kernel=0x40008000 ramdisk=0x44000000 tags=0x48000000 bootopt=32N2")
print("expdb_clear_contract=PASS size=512")
PY

if (( preflight_only )); then
  printf 'v184 stock ARM32 artifact preflight PASS (no device access)\n'
  exit 0
fi

mapfile -t detected < <("$FASTBOOT_BIN" devices | awk '$2 == "fastboot" {print $1}')
if [[ "$FASTBOOT_SERIAL" == auto ]]; then
  [[ "${#detected[@]}" -eq 1 ]] || {
    printf 'ERROR: expected exactly one fastboot device, found %s\n' "${#detected[@]}" >&2
    exit 1
  }
  FASTBOOT_SERIAL="${detected[0]}"
elif ! printf '%s\n' "${detected[@]}" | grep -Fxq "$FASTBOOT_SERIAL"; then
  printf 'ERROR: expected fastboot serial %s is not present\n' "$FASTBOOT_SERIAL" >&2
  printf 'detected: %s\n' "${detected[*]:-none}" >&2
  exit 1
fi

FASTBOOT=("$FASTBOOT_BIN" -s "$FASTBOOT_SERIAL")
product_output="$("${FASTBOOT[@]}" getvar product 2>&1 || true)"
printf '%s\n' "$product_output"
printf '%s\n' "$product_output" | grep -Eiq 'product:[[:space:]]*BISCUIT' || {
  printf 'ERROR: fastboot product is not BISCUIT\n' >&2
  exit 1
}

printf 'v184 stock ARM32 fastboot preflight PASS\n'
printf 'target serial: %s\n' "$FASTBOOT_SERIAL"
printf '1. wrapper -> boot_a_amonet and boot_b_amonet (primary LK entry)\n'
printf '2. stock ARM32 -> boot_a and boot_b (wrapper redirects to boot_a_x/boot_b_x)\n'
printf '3. clear expdb marker\n'
printf '4. reboot\n'

"${FASTBOOT[@]}" flash boot_a_amonet "$K32_WRAPPER_IMAGE"
"${FASTBOOT[@]}" flash boot_b_amonet "$K32_WRAPPER_IMAGE"
"${FASTBOOT[@]}" flash boot_a "$K32_BOOT_IMAGE"
"${FASTBOOT[@]}" flash boot_b "$K32_BOOT_IMAGE"
"${FASTBOOT[@]}" flash expdb "$K32_EXPDB_CLEAR"
"${FASTBOOT[@]}" reboot
printf 'v184_stock32_flash_reboot=PASS\n'
