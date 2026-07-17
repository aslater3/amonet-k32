# EMI MPU Region 15 Clear Payload - README

## Overview

This BROM payload clears EMI MPU Region 15 on the Amazon Echo 2nd Gen (radar_puffin, MediaTek MT8163) **before** the TEE/ATF can lock it. This is critical for unlocking the CONSYS (WiFi/BT) memory region.

## What is Region 15?

Region 15 is an EMI MPU (External Memory Interface Memory Protection Unit) region that protects a specific memory range. On the Echo 2nd Gen, this region typically protects the CONSYS memory used by WiFi/Bluetooth hardware.

The TEE (Trusted Execution Environment) / ATF (ARM Trusted Firmware) locks this region during boot, making it inaccessible to the normal world. By clearing it at BROM stage (before TEE loads), we can unlock this memory region.

## Registers

- **EMI_MPUH2** (0x10203298): Region 15 address range (start/end)
- **EMI_MPUL2** (0x102032B8): Region 15 permissions (low 16 bits)
- **EMI_MPUL2_2ND** (0x102032BC): Region 15 permissions (high 16 bits)

## Files

### Source Code
- `clear_region15.c` - Main payload source (C)
- `start.S` - Assembly entry point (ARM → Thumb mode switch)
- `clear_region15.ld` - Linker script

### Build
- `Makefile` - Build configuration
- `build/clear_region15.bin` - Compiled payload binary (1.3K)

### Driver
- `../modules/clear_region15.py` - Python script to load and run the payload

## Building

```bash
cd /home/andy/amonet2/echo-testing-main/brom-payload
make
```

This produces `build/clear_region15.bin` (1.3K).

## Usage

1. **Connect device in BROM mode** (short CLK/CMD pins)
2. **Run the driver script**:
   ```bash
   cd /home/andy/amonet2/echo-testing-main/modules
   python3 clear_region15.py
   ```

3. **Monitor UART output** (115200 baud) to see:
   - Current Region 15 register values
   - Clear operation
   - Verification
   - Watchdog reboot trigger

## What the Payload Does

1. **Initializes BROM functions** (UART, USB download, watchdog)
2. **Reads current Region 15 values** (for verification)
3. **Clears all three registers to 0**:
   - `*EMI_MPUH2 = 0` (clear address range)
   - `*EMI_MPUL2 = 0` (clear permissions)
   - `*EMI_MPUL2_2ND = 0` (clear 2nd permissions)
4. **Verifies the write** (reads back values)
5. **Triggers watchdog reboot**

## Expected Output

```
Clear Region 15 payload (c) 2024
Reading Region 15 registers...
EMI_MPUH2     = 0xXXXXYYYY
EMI_MPUL2     = 0xZZZZZZZZ
EMI_MPUL2_2ND = 0xWWWWWWWW
Clearing Region 15...
Region 15 cleared!
Verification:
EMI_MPUH2     = 0x00000000
EMI_MPUL2     = 0x00000000
EMI_MPUL2_2ND = 0x00000000
Triggering watchdog reboot...
Waiting for reset...
```

## Verification

After reboot, you can run `dump_region15.py` again to confirm Region 15 is now cleared:

```bash
cd /home/andy/amonet2/echo-testing-main/modules
python3 dump_region15.py
```

Expected result: All Region 15 registers should read as `0x00000000`.

## Technical Details

- **Architecture**: ARM Cortex-A9 (Thumb mode)
- **Toolchain**: arm-none-eabi-gcc
- **Base address**: Loaded at 0x201000 (SRAM)
- **Size**: ~1.3K
- **Dependencies**: Uses amonet BROM exploit for code execution

## Comparison with dump_region15.py

| Feature | dump_region15.py | clear_region15.py |
|---------|------------------|-------------------|
| Reads Region 15 | ✓ | ✓ |
| Writes Region 15 | ✗ | ✓ |
| Modifies flash | ✗ | ✗ |
| Reboots device | ✓ | ✓ |
| Purpose | Diagnostic | Unlock Region 15 |

## Integration with amonet

This payload uses the same infrastructure as the amonet exploit:
- BROM handshake protocol
- Payload loading at 0x201000
- USB communication functions
- Watchdog reboot mechanism

The payload is based on `generic_stage1.c` from mtkclient, adapted to perform Region 15 clearing instead of eMMC operations.

## Troubleshooting

### Payload doesn't load
- Ensure device is in BROM mode (CLK/CMD short)
- Check USB connection
- Verify payload binary exists at expected path

### Region 15 not cleared after reboot
- Check UART output for verification values
- Ensure TEE hasn't already locked registers before payload runs
- Try running immediately after power-on (before TEE loads)

### UART output missing
- Verify UART baud rate (115200)
- Check UART connection
- Payload may still work even without UART (blind operation)

## License

Based on mtkclient (B.Kerler, k4y0z 2021). Use at your own risk.

## References

- MediaTek MT8163 datasheet
- EMI MPU documentation
- amonet exploit chain
- mtkclient source code
