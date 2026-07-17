#!/usr/bin/env bash
# Deploy the exact v184 native-K32 wrapper and sole-EVT ARM32 boot image.
set -euo pipefail

WORKDIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
cd "$WORKDIR"

preflight_only=0
case "${1:-}" in
  --preflight-only) preflight_only=1; shift ;;
  "") ;;
  *) printf 'ERROR: unknown argument: %s\n' "$1" >&2; exit 1 ;;
esac

FASTBOOT_BIN="${FASTBOOT_BIN:-fastboot}"
FASTBOOT_SERIAL="${FASTBOOT_SERIAL:-G2A0RF0485020316}"
K32_WRAPPER_IMAGE="${K32_WRAPPER_IMAGE:-$WORKDIR/bin/boot-k32-native-diag-wrapper.sparse.img}"
K32_WRAPPER_SHA256="${K32_WRAPPER_SHA256:-acef9a7095c6dfc06e487b0a6afcacb54593e03c351ac2720da28eeba19eba44}"
K32_BOOT_IMAGE="${K32_BOOT_IMAGE:-$WORKDIR/bin/boot-k32-native-evt.img}"
K32_BOOT_SHA256="${K32_BOOT_SHA256:-1fe75af0428a6fbd9566505bb084af23e7e00c16c11ed0c6e19a95349c2e22c1}"
K32_EXPDB_CLEAR="${K32_EXPDB_CLEAR:-$WORKDIR/inputs/expdb-clear-512.bin}"
K32_EXPDB_CLEAR_SHA256="${K32_EXPDB_CLEAR_SHA256:-076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560}"

command -v "$FASTBOOT_BIN" >/dev/null || {
  printf 'ERROR: fastboot not found: %s\n' "$FASTBOOT_BIN" >&2
  exit 1
}

require_hash() {
  local path="$1" expected="$2" label="$3" actual
  [[ -f "$path" ]] || { printf 'ERROR: missing %s\n' "$path" >&2; exit 1; }
  actual="$(sha256sum "$path" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || {
    printf 'ERROR: %s hash mismatch\nexpected=%s\nactual=%s\npath=%s\n' \
      "$label" "$expected" "$actual" "$path" >&2
    exit 1
  }
  printf '%-18s %s\n' "$label" "$actual"
}

require_hash "$K32_WRAPPER_IMAGE" "$K32_WRAPPER_SHA256" wrapper_sparse
require_hash "$K32_BOOT_IMAGE" "$K32_BOOT_SHA256" native_evt_boot
require_hash "$K32_EXPDB_CLEAR" "$K32_EXPDB_CLEAR_SHA256" expdb_clear
python3 tools/verify-native-k32-diagnostic.py

if (( preflight_only )); then
  printf 'v184 native K32 + sole EVT diagnostic preflight PASS (no device access)\n'
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

printf 'target serial: %s\n' "$FASTBOOT_SERIAL"
printf '1. native diagnostic wrapper -> boot_a_amonet and boot_b_amonet\n'
printf '2. sole-EVT ARM32 boot -> boot_a and boot_b (redirected to shadow slots)\n'
printf '3. clear expdb marker and reboot\n'

"${FASTBOOT[@]}" flash boot_a_amonet "$K32_WRAPPER_IMAGE"
"${FASTBOOT[@]}" flash boot_b_amonet "$K32_WRAPPER_IMAGE"
"${FASTBOOT[@]}" flash boot_a "$K32_BOOT_IMAGE"
"${FASTBOOT[@]}" flash boot_b "$K32_BOOT_IMAGE"
"${FASTBOOT[@]}" flash expdb "$K32_EXPDB_CLEAR"
"${FASTBOOT[@]}" reboot
printf 'v184_native_k32_evt_flash_reboot=PASS\n'
