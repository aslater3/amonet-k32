import os
import struct
import sys

from common import Device
from handshake import handshake
from load_payload import load_payload
from logger import log
from gpt import parse_gpt_compat, generate_gpt, modify_step1, modify_step2, parse_gpt as gpt_parse_gpt

BOOT_WRAPPER_HDR = os.environ.get("AMONET_BOOT_HDR", "../bin/boot.hdr")
BOOT_WRAPPER_PAYLOAD = os.environ.get("AMONET_BOOT_PAYLOAD", "../bin/boot.payload")
PRELOADER_IMAGE = os.environ.get("AMONET_PRELOADER", "../bin/preloader.img")

def switch_boot0(dev):
    dev.emmc_switch(1)
    block = dev.emmc_read(0)
    if block[0:9] != b"EMMC_BOOT" and block[0:9] != b'\x00' * 9:
        dev.reboot()
        raise RuntimeError("what's wrong with your BOOT0?")

def flash_data(dev, data, start_block, max_size=0):
    while len(data) % 0x200 != 0:
        data += b"\x00"

    if max_size and len(data) > max_size:
        raise RuntimeError("data too big to flash")

    blocks = len(data) // 0x200
    for x in range(blocks):
        print("[{} / {}]".format(x + 1, blocks), end='\r')
        dev.emmc_write(start_block + x, data[x * 0x200:(x + 1) * 0x200])
    print("")

def flash_binary(dev, path, start_block, max_size=0):
    with open(path, "rb") as fin:
        data = fin.read()
    if max_size and len(data) > max_size:
        raise RuntimeError(f"{path} does not fit at block {start_block}: {len(data)} > {max_size}")
    while len(data) % 0x200 != 0:
        data += b"\x00"

    flash_data(dev, data, start_block, max_size=max_size)

def dump_binary(dev, path, start_block, max_size=0):
    with open(path, "w+b") as fout:
        blocks = max_size // 0x200
        for x in range(blocks):
            print("[{} / {}]".format(x + 1, blocks), end='\r')
            fout.write(dev.emmc_read(start_block + x))
    print("")

def force_fastboot(dev, gpt):
    switch_user(dev)
    block = bytearray(dev.emmc_read(gpt["expdb"][0]))
    marker = b"FASTBOOT_PLEASE\x00"
    block[0:len(marker)] = marker
    dev.emmc_write(gpt["expdb"][0], bytes(block))
    verify = dev.emmc_read(gpt["expdb"][0])
    if verify[0:len(marker)] != marker:
        raise RuntimeError("failed to verify FASTBOOT_PLEASE in expdb")
    log("FASTBOOT_PLEASE verified in expdb")

def reset_bcb(dev, gpt):
    switch_user(dev)
    block = bytearray(dev.emmc_read(gpt["misc"][0] + 1))
    bcb_start = 0x160
    # Write full BCB slot metadata (13 bytes):
    # slot_suffix=0, magic='BCb', version=1,
    # slot0: prio=15, tries=7, success=0, reserved=0
    # slot1: prio=14, tries=7, success=0, reserved=0
    block[bcb_start:bcb_start+13] = b'\x00\x42\x43\x62\x01\x0f\x07\x00\x00\x0e\x07\x00\x00'
    dev.emmc_write(gpt["misc"][0] + 1, bytes(block))

def reset_bootcount(dev):
    """Reset IDME bootcount in boot1 to 0 so LK doesn't refuse to boot.

    The bootcount counter lives in boot1 at offset 0x6c4 and is stored
    as a null-terminated ASCII string (max 4 bytes: "0\0" to "999\0").
    When bootcount >= MAX (likely 256), LK refuses to load the kernel
    and falls back to fastboot (rainbow LEDs).
    """
    log("Reset bootcount")
    switch_boot0(dev)                    # boot1 is eMMC boot partition 1
    block = bytearray(dev.emmc_read(3))  # sector containing offset 0x6c4
    block[0xc4:0xc8] = b"0\x00\x00\x00" # overwrite "261" with "0"
    dev.emmc_write(3, bytes(block))
    log("bootcount reset to 0")

#NOTE: This doesn't actually wipe userdata, it just erases the first 10 blocks.
#      A new filesystem should be created at next boot.
def wipe_userdata(dev, gpt):
    switch_user(dev)
    block = b"\x00" * 0x200
    for x in range(0, 10):
        dev.emmc_write(gpt["userdata"][0] + x, block)

def switch_user(dev):
    dev.emmc_switch(0)
    block = dev.emmc_read(0)
    if block[510:512] != b"\x55\xAA":
        dev.reboot()
        raise RuntimeError("what's wrong with your GPT?")

def parse_gpt(dev):
    data = dev.emmc_read(0x400 // 0x200) + dev.emmc_read(0x600 // 0x200) + dev.emmc_read(0x800 // 0x200) + dev.emmc_read(0xA00 // 0x200) + dev.emmc_read(0xC00 // 0x200)
    num = len(data) // 0x80
    return parse_gpt_compat(dev.emmc_read(0x200 // 0x200) + data)
#    parts = dict()
#    for x in range(num):
#        part = data[x * 0x80:(x + 1) * 0x80]
#        part_name = part[0x38:].decode("utf-16le").rstrip("\x00")
#        part_start = struct.unpack("<Q", part[0x20:0x28])[0]
#        part_end = struct.unpack("<Q", part[0x28:0x30])[0]
#        parts[part_name] = (part_start, part_end - part_start + 1)
#    return parts

def main():
    dev = Device()
    dev.find_device()

    # 0.1) Handshake
    handshake(dev)

    # 0.2) Load brom payload
    load_payload(dev, "../brom-payload/build/payload.bin")

    # Clear preloader so, we get into bootrom without shorting, should the script stall (we flash preloader as last step)
    # 1) Downgrade preloader
    log("Clear preloader header")
    switch_boot0(dev)
    flash_data(dev, b"EMMC_BOOT" + b"\x00" * ((0x200 * 8) - 9), 0)

    if len(sys.argv) == 2 and sys.argv[1] == "fixgpt":
        dev.emmc_switch(0)
        log("Flashing GPT")
        flash_binary(dev, "../bin/gpt-biscuit.bin", 0, 34 * 0x200)

    # 2) Sanity check GPT
    log("Check GPT")
    switch_user(dev)

    # 2.1) Parse gpt
    gpt, gpt_header, part_list = parse_gpt(dev)
    if "lk_a" not in gpt or "tee1" not in gpt or "boot_a" not in gpt or "recovery" not in gpt:
        raise RuntimeError("bad gpt")

    if "boot_a_x" not in gpt or "boot_b_x" not in gpt:
        log("Modify GPT")

        if "boot_a_tmp" not in gpt and "boot_b_tmp" not in gpt:
            part_list_mod1 = modify_step1(part_list)
        else:
            part_list_mod1 = part_list

        part_list_mod2 = modify_step2(part_list_mod1)
        primary, backup = generate_gpt(gpt_header, part_list_mod2)

        log("Validate GPT")
        gpt_header, part_list = gpt_parse_gpt(bytes(primary))

        log("Flash new primary GPT")
        flash_data(dev, primary, 0)

        log("Flash new backup GPT")
        flash_data(dev, backup, gpt_header['last_lba'] + 1)

        gpt, gpt_header, part_list = parse_gpt(dev)
        if "boot_a_x" not in gpt or "boot_b_x" not in gpt:
            raise RuntimeError("bad gpt")

        log("Wipe userdata")
        wipe_userdata(dev, gpt)

    # 3) Sanity check boot0
    log("Check boot0")
    switch_boot0(dev)

    # 4) Sanity check rpmb
    log("Check rpmb")
    rpmb = dev.rpmb_read()
    if rpmb[0:4] != b"AMZN":
        log("rpmb looks broken; if this is expected (i.e. you're retrying the exploit) press enter, otherwise terminate with Ctrl+C")
        input()

    # 5) Zero out rpmb to enable downgrade
    log("Downgrade rpmb")
    dev.rpmb_write(b"\x00" * 0x100)
    log("Recheck rpmb")
    rpmb = dev.rpmb_read()
    if rpmb != b"\x00" * 0x100:
        dev.reboot()
        raise RuntimeError("downgrade failure, giving up")
    log("rpmb downgrade ok")

    # 6) Downgrade tz
    log("Flash tz")
    switch_user(dev)
    flash_binary(dev, "../bin/tz.img", gpt["tee1"][0], gpt["tee1"][1] * 0x200)

    # 7) Downgrade lk
    log("Flash lk")
    switch_user(dev)
    flash_binary(dev, "../bin/lk.bin", gpt["lk_a"][0], gpt["lk_a"][1] * 0x200)
    flash_binary(dev, "../bin/lk.bin", gpt["lk_b"][0], gpt["lk_b"][1] * 0x200)

    # 8) Flash the wrapper into the primary boot partitions. The LK payload
    # is entered from boot_a/boot_b; boot_a_x/boot_b_x are read redirection
    # targets and are only 16 MiB, too small for this 0x367ef-block layout.
    log("Inject payload into boot_a/boot_b")
    payload_block = 223215
    switch_user(dev)
    flash_binary(dev, BOOT_WRAPPER_HDR, gpt["boot_a"][0], gpt["boot_a"][1] * 0x200)
    flash_binary(dev, BOOT_WRAPPER_PAYLOAD, gpt["boot_a"][0] + payload_block, (gpt["boot_a"][1] * 0x200) - (payload_block * 0x200))

    switch_user(dev)
    flash_binary(dev, BOOT_WRAPPER_HDR, gpt["boot_b"][0], gpt["boot_b"][1] * 0x200)
    flash_binary(dev, BOOT_WRAPPER_PAYLOAD, gpt["boot_b"][0] + payload_block, (gpt["boot_b"][1] * 0x200) - (payload_block * 0x200))

    # 8.5) Boot image flash is now done from fastboot — skip redundant BROM flash

    log("Force fastboot")
    force_fastboot(dev, gpt)

    # Reset BCB
    log("Reset BCB")
    reset_bcb(dev, gpt)

    # 9) Downgrade preloader
    log("Flash preloader")
    switch_boot0(dev)
    flash_binary(dev, PRELOADER_IMAGE, 0)

    # Reset bootcount so LK doesn't refuse to boot after many cycles
    reset_bootcount(dev)

    # 10) Reboot (to fastboot)
    log("Reboot to unlocked fastboot")
    dev.reboot()


if __name__ == "__main__":
    main()
