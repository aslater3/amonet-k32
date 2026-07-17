#!/usr/bin/env bash
# Install the K32-specific Amonet wrapper through BROM and stop in fastboot.
# The subsequent stock ARM32 deployment is handled by
# fastboot-k32-amonet-step.sh.
set -euo pipefail

WORKDIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
cd "$WORKDIR"

preflight_only=0
if [[ "${1:-}" == "--preflight-only" ]]; then
  preflight_only=1
  shift
fi

for f in brom-payload/build/payload.bin modules/main.py bin/preloader.img \
         bin/lk.bin bin/tz.img bin/boot-k32.hdr bin/boot-k32.payload; do
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
  printf '%-18s %s\n' "$label" "$actual"
}

require_hash brom-payload/build/payload.bin \
  16ff2539761a85fe6eea0dcb461b3904bfd0f01c431b49010ebeb5fc2407e5e5 brom_payload
require_hash bin/preloader.img \
  49193a8c06f3ac4c70691cb8bcaa3e2ddcefbd36d54b8d425a014aa2318846ff signed_stock_preloader
require_hash bin/tz.img \
  fe1de9f18aa0f82a308f0c08da3be1f7c7ac2fd65832e26a3a6bdeb0e6e10136 tz
require_hash bin/lk.bin \
  5cb92494340417b1e5d18c3eaa34844dbcfec2cc8086451f087867cd06b15472 lk
require_hash modules/main.py \
  f6afc444a8ef7cc28ec6d9803b57d52c4ff66a1946afea36853295a83ce73cf9 injector
require_hash bin/boot-k32.hdr \
  dbbff7eeb8830c0d6cde454a97dc31be73d1cba32e6be9b21fe3c7be2b659066 k32_header
require_hash bin/boot-k32.payload \
  b916cf5f6f7f947deeb114b4e490b543a62c82be6205f0f2a76b68bcd913e450 k32_payload

python3 amonet-k32/verify-post-payload.py

python3 - <<'PY'
from pathlib import Path
import struct

hdr = Path('bin/boot-k32.hdr').read_bytes()
payload = Path('bin/boot-k32.payload').read_bytes()
if len(hdr) != 96 or hdr[:8] != b'ANDROID!':
    raise SystemExit('ERROR: invalid K32 Amonet header')
if len(payload) != 9792:
    raise SystemExit('ERROR: unexpected K32 Amonet payload size')
if struct.unpack_from('<I', hdr, 0x24)[0] != 0x40:
    raise SystemExit('ERROR: unexpected wrapper page size')
print('k32_amonet_contract=PASS payload=9792 bootopt_wrapper=32N2')
PY

printf 'K32 Amonet BROM preflight PASS\n'
printf 'BROM will install the unchanged signed stock preloader, signed TZ/LK, and post-payload K32 wrapper.\n'
printf 'preloader signature status: SIGNED_STOCK_UNCHANGED\n'
printf 'The device should enter fastboot after the injector completes.\n'

if (( preflight_only )); then
  printf 'K32 Amonet preflight only; no device access\n'
  exit 0
fi

(cd modules && \
  AMONET_PRELOADER=../bin/preloader.img \
  AMONET_BOOT_HDR=../bin/boot-k32.hdr \
  AMONET_BOOT_PAYLOAD=../bin/boot-k32.payload \
  python3 main.py "$@")

printf 'K32 Amonet BROM install complete; run fastboot-k32-amonet-step.sh next.\n'
