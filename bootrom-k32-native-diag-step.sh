#!/usr/bin/env bash
# Install the corrected native-K32 diagnostic Amonet wrapper through BROM.
set -euo pipefail

WORKDIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
cd "$WORKDIR"

preflight_only=0
if [[ "${1:-}" == --preflight-only ]]; then
  preflight_only=1
  shift
fi

declare -A expected=(
  [brom-payload/build/payload.bin]=16ff2539761a85fe6eea0dcb461b3904bfd0f01c431b49010ebeb5fc2407e5e5
  [bin/preloader.img]=49193a8c06f3ac4c70691cb8bcaa3e2ddcefbd36d54b8d425a014aa2318846ff
  [bin/tz.img]=fe1de9f18aa0f82a308f0c08da3be1f7c7ac2fd65832e26a3a6bdeb0e6e10136
  [bin/lk.bin]=5cb92494340417b1e5d18c3eaa34844dbcfec2cc8086451f087867cd06b15472
  [modules/main.py]=f6afc444a8ef7cc28ec6d9803b57d52c4ff66a1946afea36853295a83ce73cf9
  [bin/boot-k32-native-diag.hdr]=dbbff7eeb8830c0d6cde454a97dc31be73d1cba32e6be9b21fe3c7be2b659066
  [bin/boot-k32-native-diag.payload]=1696899c450ff2f518367901c620dde4519af5345712842fa1c2d2bd394f7f1f
)

for path in "${!expected[@]}"; do
  [[ -f "$path" ]] || { printf 'ERROR: missing %s\n' "$path" >&2; exit 1; }
  actual="$(sha256sum "$path" | awk '{print $1}')"
  [[ "$actual" == "${expected[$path]}" ]] || {
    printf 'ERROR: hash mismatch: %s\nexpected=%s\nactual=%s\n' \
      "$path" "${expected[$path]}" "$actual" >&2
    exit 1
  }
  printf '%-40s %s\n' "$path" "$actual"
done

python3 tools/verify-native-k32-diagnostic.py
printf 'native K32 EVT Amonet BROM preflight PASS\n'
printf 'signed stock preloader/TZ/LK remain unchanged\n'

if (( preflight_only )); then
  printf 'preflight only; no device access\n'
  exit 0
fi

(cd modules && \
  AMONET_PRELOADER=../bin/preloader.img \
  AMONET_BOOT_HDR=../bin/boot-k32-native-diag.hdr \
  AMONET_BOOT_PAYLOAD=../bin/boot-k32-native-diag.payload \
  python3 main.py "$@")

printf 'BROM wrapper install complete; run fastboot-k32-native-diag-step.sh next\n'
