#!/usr/bin/env bash
# Rebuild the sole-EVT boot image and native-K32 Amonet wrapper deterministically.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$ROOT"

command -v arm-none-eabi-gcc >/dev/null
command -v arm-none-eabi-objcopy >/dev/null
command -v img2simg >/dev/null

python3 tools/build-native-k32-diagnostic.py \
  inputs/boot-v184-stock32-parity-stock.img \
  bin/boot-k32-native-evt.img

make -C lk-payload clean
make -C lk-payload

python3 lk-payload/create_boot_img.py \
  bin/lk.bin lk-payload/build/payload.bin \
  bin/boot-k32-native-diag.hdr \
  bin/boot-k32-native-diag.payload

python3 lk-payload/create_boot_img.py \
  bin/lk.bin lk-payload/build/payload.bin \
  bin/boot-k32-native-diag-wrapper.full.img

truncate -s 115343360 bin/boot-k32-native-diag-wrapper.full.img
img2simg \
  bin/boot-k32-native-diag-wrapper.full.img \
  bin/boot-k32-native-diag-wrapper.sparse.img

python3 tools/verify-native-k32-diagnostic.py
