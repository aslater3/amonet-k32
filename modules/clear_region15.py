#!/usr/bin/env python3
"""
clear_region15.py - Clear EMI MPU Region 15 at BROM stage before TEE loads.

This script loads a custom BROM payload that clears the EMI MPU Region 15
registers BEFORE the TEE/ATF can lock them. This is critical for unlocking
the CONSYS (WiFi/BT) memory region on the Amazon Echo 2nd Gen (radar_puffin).

Target: Amazon Echo 2nd Gen (radar_puffin), MediaTek MT8163

The payload:
1. Initializes BROM functions (UART, USB, watchdog)
2. Reads current Region 15 register values
3. Writes 0 to EMI_MPUH2, EMI_MPUL2, EMI_MPUL2_2ND to clear the region
4. Triggers watchdog reboot

After reboot, Region 15 should be unlocked and accessible.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import Device
from handshake import handshake
from load_payload import load_payload
from logger import log


def main():
    # Find the payload - prefer the one in build/, fallback to hardcoded path
    here = os.path.dirname(os.path.abspath(__file__))
    payload = os.path.join(here, "..", "brom-payload", "build", "clear_region15.bin")
    if not os.path.exists(payload):
        payload = "/home/andy/amonet2/echo-testing-main/brom-payload/build/clear_region15.bin"
    
    if not os.path.exists(payload):
        print("ERROR: Payload not found at:")
        print(f"  {os.path.join(here, '..', 'brom-payload', 'build', 'clear_region15.bin')}")
        print(f"  /home/andy/amonet2/echo-testing-main/brom-payload/build/clear_region15.bin")
        print("\nPlease build it first:")
        print("  cd /home/andy/amonet2/echo-testing-main/brom-payload && make")
        sys.exit(1)

    print("=" * 70)
    print("EMI MPU Region 15 Clear Tool")
    print("Target: Amazon Echo 2nd Gen (radar_puffin) / MT8163")
    print("=" * 70)
    print()
    
    print("This will:")
    print("  1. Load a custom BROM payload")
    print("  2. Clear EMI MPU Region 15 (address + permissions)")
    print("  3. Reboot the device")
    print()
    print("After reboot, Region 15 should be unlocked.")
    print()
    
    response = input("Continue? [y/N]: ")
    if response.lower() not in ['y', 'yes']:
        print("Aborted.")
        sys.exit(0)
    
    print()
    print("Please connect the device and short CLK/CMD to trigger BROM mode.")
    print("Waiting for device...")
    print()
    
    dev = Device()
    dev.find_device()           # Wait for BOOTROM
    handshake(dev)              # BROM handshake
    load_payload(dev, payload)  # Load the Region 15 clearing payload
    
    print()
    print("=" * 70)
    print("Payload loaded and running!")
    print("The payload will:")
    print("  - Read current Region 15 values")
    print("  - Clear all Region 15 registers to 0")
    print("  - Verify the clear")
    print("  - Trigger watchdog reboot")
    print()
    print("Check the separate UART console (/dev/ttyUSB0) at 921600 baud for details.")
    print()
    print("Device should reboot automatically.")
    print("=" * 70)


if __name__ == "__main__":
    main()
