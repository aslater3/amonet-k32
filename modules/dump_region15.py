#!/usr/bin/env python3
"""
dump_region15.py -- NON-DESTRUCTIVE BROM-stage read of EMI MPU region 15.

Reads the three region-15 EMI MPU registers via the amonet brom-payload
(0x4000 read-reg command) so we can see what the TEE locked the CONSYS
EMI window to. This touches NO flash: it only does handshake -> load payload
-> read registers -> reboot.

EMI base (mt8163.dtsi:484) = 0x10203000
  EMI_MPUH2      = base + 0x0298  -> 0x10203298  (region 15 start/end, 16-bit, >>16)
  EMI_MPUL2      = base + 0x02B8  -> 0x102032B8  (region 15 permissions)
  EMI_MPUL2_2ND  = base + 0x02BC  -> 0x102032BC  (region 15 2nd permissions)
  EMI_MPUS/EMI_MPUT (optional lock/status readout)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import Device
from handshake import handshake
from load_payload import load_payload

EMI_BASE = 0x10203000

REGS = {
    "EMI_MPUH2     (r15 addr start/end)": EMI_BASE + 0x0298,
    "EMI_MPUL2     (r15 perm)":           EMI_BASE + 0x02B8,
    "EMI_MPUL2_2ND (r15 perm2nd)":        EMI_BASE + 0x02BC,
    "EMI_MPUS      (violation status)":   EMI_BASE + 0x01F0,
    "EMI_MPUT      (violation addr)":     EMI_BASE + 0x01F8,
    "EMI_WP_CTRL   (lock ctrl)":          EMI_BASE + 0x05E8,
}


def perm_decode(val):
    """Decode the 3-bit per-domain permission fields (d0..d7)."""
    perms = ["No protect", "SEC_RW", "SEC_RW/NSEC_R", "SEC_RW/NSEC_W",
             "SEC_R/NSEC_R", "FORBIDDEN", "SEC_R/NSEC_RW"]
    out = []
    for d in range(8):
        p = (val >> (d * 3)) & 0x7
        out.append("d%d=%s" % (d, perms[p] if p < len(perms) else "?"))
    return " ".join(out)


def main():
    # payload path: prefer the patched one in ../brom-payload/build
    here = os.path.dirname(os.path.abspath(__file__))
    payload = os.path.join(here, "..", "brom-payload", "build", "payload.bin")
    if not os.path.exists(payload):
        payload = "/home/andy/amonet2/echo-testing-main/brom-payload/build/payload.bin"

    dev = Device()
    dev.find_device()           # wait for BOOTROM
    handshake(dev)              # BROM handshake
    load_payload(dev, payload)  # load patched brom-payload (has 0x4000 cmd)

    print("\n=== EMI MPU region 15 readback (BROM stage) ===")
    results = {}
    for name, addr in REGS.items():
        try:
            val = dev.read_reg(addr)
            results[name] = val
            print("0x%08X  %-32s = 0x%08X" % (addr, name, val))
        except Exception as e:
            print("0x%08X  %-32s = READ FAIL (%s)" % (addr, name, e))

    # decode region 15 specifically
    h2 = results.get("EMI_MPUH2     (r15 addr start/end)")
    if h2 is not None:
        start = (h2 >> 16) << 16
        end = (h2 & 0xFFFF) << 16
        print("\nRegion 15 physical window: 0x%08X - 0x%08X  (size 0x%X)" %
              (start, end + 0xFFFF, (end - start) + 0x10000))
    p = results.get("EMI_MPUL2     (r15 perm)")
    if p is not None:
        print("Region 15 permissions (low 16): " + perm_decode(p & 0xFFFF))
        print("Region 15 permissions (hi 16) : " + perm_decode((p >> 16) & 0xFFFF))

    print("\nRebooting device (non-destructive).")
    dev.reboot()


if __name__ == "__main__":
    main()
