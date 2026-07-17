#include "libc.h"
#include "common.h"

void low_uart_put(int ch) {
    volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x11002014;
    volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x11002000;

    while ( !((*uart_reg0) & 0x20) )
    {}

    *uart_reg1 = ch;
}

void _putchar(char character)
{
    if (character == '\n')
        low_uart_put('\r');
    low_uart_put(character);
}

int (*original_read)(struct device_t *dev, uint64_t block_off, void *dst, size_t sz, int part) = (void*)0x4BD2AE2D;
int (*app)() = (void*)0x4BD341D5;
extern void restart_lk(void *entry) __attribute__((noreturn));

uint64_t g_boot_a, g_boot_a_x, g_boot_b, g_boot_b_x, g_lk_a, g_lk_b, g_expdb, g_misc, g_recovery;
uint8_t boot_recovery = 0;

typedef int (*fdt_setprop_fn)(void *, int, const char *, const void *, int);
typedef int (*boot_linux_fdt_fn)(uint32_t, uint32_t, uint32_t,
                                 uint32_t, uint32_t, uint32_t);

static int diag_fdt_setprop(void *fdt, int node, const char *name,
                            const void *value, int len)
{
    int ret = ((fdt_setprop_fn)0x4BD3B191)(fdt, node, name, value, len);
    /* mini-printf has no %d: signed values go out as %x (two's complement). */
    printf("FDT setprop name=%s ret=%x len=%x fdt=%x node=%x\n",
           name ? name : "(null)", ret, len, (uint32_t)fdt, (uint32_t)node);
    /* Separate line: a faulting read of a bad fdt must not eat the line above. */
    printf("FDT magic=%x total=%x\n",
           fdt ? *(volatile uint32_t *)fdt : 0,
           fdt ? __builtin_bswap32(*((volatile uint32_t *)fdt + 1)) : 0);
    return ret;
}

__attribute__((used, noinline)) void diag_m3_log(void)
{
    printf("M3 boot_linux_fdt common error epilogue reached\n");
}

__attribute__((naked)) static void diag_m3_trampoline(void)
{
    __asm__ volatile(
        "bl diag_m3_log\n"
        "movs r0, #0\n"
        "add.w sp, sp, #0x4ac\n"
        "ldr r3, =0x4BD3388D\n"
        "bx r3\n"
    );
}

static int diag_boot_linux_fdt(uint32_t a0, uint32_t a1, uint32_t a2,
                               uint32_t a3, uint32_t a4, uint32_t a5)
{
    int ret = ((boot_linux_fdt_fn)0x4BD330E9)(a0, a1, a2, a3, a4, a5);
    printf("M4 boot_linux_fdt returned to boot_linux ret=%x\n", ret);
    return ret;
}

static void patch_thumb_bl(uint32_t address, uint32_t target)
{
    int32_t delta = (int32_t)((target & ~1U) - (address + 4));
    uint32_t udelta = (uint32_t)delta;
    uint32_t s = (udelta >> 24) & 1;
    uint32_t i1 = (udelta >> 23) & 1;
    uint32_t i2 = (udelta >> 22) & 1;
    uint32_t j1 = (~(i1 ^ s)) & 1;
    uint32_t j2 = (~(i2 ^ s)) & 1;
    volatile uint16_t *p = (void *)address;

    if ((delta & 1) || delta < -0x1000000 || delta > 0x0fffffe) {
        printf("diag BL out of range: %08x -> %08x\n", address, target);
        while (1) {}
    }

    p[0] = 0xF000 | (s << 10) | ((udelta >> 12) & 0x3ff);
    p[1] = 0xD000 | (j1 << 13) | (j2 << 11) | ((udelta >> 1) & 0x7ff);
}

static void install_fdt_diagnostics(void)
{
    static const uint32_t fdt_setprop_calls[] = {
        0x4BD33206, 0x4BD33288, 0x4BD332AA, 0x4BD332CA,
        0x4BD332F8, 0x4BD33322, 0x4BD3335C, 0x4BD3338A,
        0x4BD333B8, 0x4BD333F0, 0x4BD3341E, 0x4BD335DE,
        0x4BD335FE, 0x4BD3394C,
        /* 15th site: the fdt_setprop_u32 helper's internal call
         * (covers linux,initrd-start/end and every other u32 fixup). */
        0x4BD32F68,
    };
    static const uint16_t fdt_setprop_stock[][2] = {
        { 0xF007, 0xFFC3 }, { 0xF007, 0xFF82 },
        { 0xF007, 0xFF71 }, { 0xF007, 0xFF61 },
        { 0xF007, 0xFF4A }, { 0xF007, 0xFF35 },
        { 0xF007, 0xFF18 }, { 0xF007, 0xFF01 },
        { 0xF007, 0xFEEA }, { 0xF007, 0xFECE },
        { 0xF007, 0xFEB7 }, { 0xF007, 0xFDD7 },
        { 0xF007, 0xFDC7 }, { 0xF007, 0xFC20 },
        { 0xF008, 0xF912 },
    };

    for (unsigned i = 0; i < sizeof(fdt_setprop_calls) / sizeof(fdt_setprop_calls[0]); i++) {
        volatile uint16_t *call = (void *)fdt_setprop_calls[i];
        if (call[0] != fdt_setprop_stock[i][0] ||
            call[1] != fdt_setprop_stock[i][1]) {
            printf("FDT hook mismatch at %08x: %04x %04x\n",
                   fdt_setprop_calls[i], call[0], call[1]);
            while (1) {}
        }
        patch_thumb_bl(fdt_setprop_calls[i], (uint32_t)diag_fdt_setprop);
    }

    /* Replace only the common error epilogue's stack-restore instruction. */
    volatile uint16_t *m3 = (void *)0x4BD33888;
    if (m3[0] != 0xF20D || m3[1] != 0x4DAC) {
        printf("M3 hook mismatch: %04x %04x\n", m3[0], m3[1]);
        while (1) {}
    }
    patch_thumb_bl(0x4BD33888, (uint32_t)diag_m3_trampoline);

    /* boot_linux()'s call to boot_linux_fdt(); success never returns. */
    volatile uint16_t *m4 = (void *)0x4BD33DC0;
    if (m4[0] != 0xF7FF || m4[1] != 0xF992) {
        printf("M4 hook mismatch: %04x %04x\n", m4[0], m4[1]);
        while (1) {}
    }
    patch_thumb_bl(0x4BD33DC0, (uint32_t)diag_boot_linux_fdt);
}

void set_led_ring(uint8_t colors[12][3]) {
    static uint8_t frame[36];
    for (int i = 0; i < 12; i++) {
        frame[i*3] = colors[i][0];
        frame[i*3+1] = colors[i][1]; 
        frame[i*3+2] = colors[i][2];
    }
    led_update(1, frame);
    led_write(0x25, 0); 
}

void* led_animation_thread(void* arg) {
    while (1) {
        for (int step = 0; step < 36; step++) {
            uint8_t frame[12][3];
            for (int i = 0; i < 12; i++) {
                int pos = step + i;
                while (pos >= 12) pos -= 12;
                if (pos < 2) { frame[i][0] = 0xFF; frame[i][1] = 0x00; frame[i][2] = 0x00; }
                else if (pos < 4) { frame[i][0] = 0xFF; frame[i][1] = 0x7F; frame[i][2] = 0x00; }
                else if (pos < 6) { frame[i][0] = 0x00; frame[i][1] = 0xFF; frame[i][2] = 0x00; }
                else if (pos < 8) { frame[i][0] = 0x00; frame[i][1] = 0xFF; frame[i][2] = 0xFF; }
                else if (pos < 10) { frame[i][0] = 0x00; frame[i][1] = 0x00; frame[i][2] = 0xFF; }
                else { frame[i][0] = 0xFF; frame[i][1] = 0x00; frame[i][2] = 0xFF; }
            }
            set_led_ring(frame);
            thread_sleep(50);
        }
    }
    return NULL;
}

void create_led_thread() {
  thread_t* led_thread = thread_create("rainbow", led_animation_thread, NULL, 10, 4096);
  if (led_thread) {
    thread_resume(led_thread);
  }
}

int read_func(struct device_t *dev, uint64_t block_off, void *dst, size_t sz, int part) {
    printf("read_func hook\n");
    printf("block_off 0x%08X 0x%08X\n", block_off, *(&(block_off)+4));
    printf("dev 0x%08X dst 0x%08X sz 0x%08X part 0x%08X\n", dev, dst, sz, part);

    int ret = 0;

    if (block_off == g_boot_a * 0x200) {
      if (boot_recovery) {
        block_off = g_recovery * 0x200;
      }
      else {
        block_off = g_boot_a_x * 0x200;
      }
    } else if (block_off == (g_boot_a * 0x200) + 0x800) {
      if (boot_recovery) {
         block_off = (g_recovery * 0x200) + 0x800;
      }
      else {
        block_off = (g_boot_a_x * 0x200) + 0x800;
      }
    } else if (block_off == g_boot_b * 0x200) {
      if (boot_recovery) {
        block_off = g_recovery * 0x200;
      }
      else {
        block_off = g_boot_b_x * 0x200;
      }
    } else if (block_off == (g_boot_b * 0x200) + 0x800) {
      if (boot_recovery) {
        block_off = (g_recovery * 0x200) + 0x800;
      }
      else {
        block_off = (g_boot_b_x * 0x200) + 0x800;
      }
    }
    return original_read(dev, block_off, dst, sz, part);
}

static void parse_gpt() {
    // Keep the 4 KiB GPT scratch area off the LK application thread stack.
    // PAYLOAD_DST is reserved payload scratch RAM and dev->read overwrites it.
    uint8_t *raw = (uint8_t *)PAYLOAD_DST;
    struct device_t *dev = get_device();
    dev->read(dev, 0x400, raw, 0x1000, USER_PART);
    for (int i = 0; i < 0x1000 / 0x80; ++i) {
        uint8_t *ptr = &raw[i * 0x80];
        uint8_t *name = ptr + 0x38;
        uint32_t start;
        memcpy(&start, ptr + 0x20, 4);
        if (memcmp(name, "b\x00o\x00o\x00t\x00_\x00\x61\x00\x00\x00", 14) == 0) {
            printf("found boot_a at 0x%08X\n", start);
            g_boot_a = start;
        } else if (memcmp(name, "b\x00o\x00o\x00t\x00_\x00\x61\x00_\x00x\x00\x00\x00", 18) == 0) {
            printf("found boot_a_x at 0x%08X\n", start);
            g_boot_a_x = start;
        } else if (memcmp(name, "b\x00o\x00o\x00t\x00_\x00\x62\x00\x00\x00", 14) == 0) {
            printf("found boot_b at 0x%08X\n", start);
            g_boot_b = start;
        } else if (memcmp(name, "b\x00o\x00o\x00t\x00_\x00\x62\x00_\x00x\x00\x00\x00", 18) == 0) {
            printf("found boot_b_x at 0x%08X\n", start);
            g_boot_b_x = start;
        } else if (memcmp(name, "l\x00k\x00_\x00\x61\x00\x00\x00", 10) == 0) {
            printf("found lk_a at 0x%08X\n", start);
            g_lk_a = start;
        } else if (memcmp(name, "l\x00k\x00_\x00\x62\x00\x00\x00", 10) == 0) {
            printf("found lk_b at 0x%08X\n", start);
            g_lk_b = start;
        } else if (memcmp(name, "e\x00" "x\x00" "p\x00" "d\x00" "b\x00\x00\x00", 12) == 0) {
            printf("found expdb at 0x%08X\n", start);
            g_expdb = start;
        } else if (memcmp(name, "m\x00" "i\x00" "s\x00" "c\x00\x00\x00", 10) == 0) {
            printf("found misc at 0x%08X\n", start);
            g_misc = start;
        } else if (memcmp(name, "r\x00\x65\x00\x63\x00o\x00v\x00\x65\x00r\x00y\x00\x00\x00", 18) == 0) {
            printf("found recovery at 0x%08X\n", start);
            g_recovery = start;
        }
    }
}

void (*fastboot_info)(const char *reason) = (void *)(0x4bd34814 | 1);
void (*fastboot_fail)(const char *reason) = (void *)(0x4bd3485c | 1);
void (*fastboot_okay)(const char *reason) = (void *)(0x4bd34a20 | 1);

void (*fastboot_register)(const char *prefix,
                          void (*handle)(const char *arg, void *data, unsigned sz),
                          unsigned char security_enabled) = (void *)(0x4bd345e4 | 1);

void (*cmd_flash)(const char *arg, void *data, unsigned sz) = (void *)(0x4bd36d68 | 1);

void cmd_flash_wrapper(const char *arg, void *data, unsigned sz) {
    const char *name = arg + 1;

    if (strncmp(name, "boot_a_amonet", 13) == 0) {
        printf("boot_a_amonet -> boot_a\n");
        cmd_flash("boot_a", data, sz);
        return;
    }

    if (strncmp(name, "boot_b_amonet", 13) == 0) {
        printf("boot_b_amonet -> boot_b\n");
        cmd_flash("boot_b", data, sz);
        return;
    }
    
    if (strncmp(name, "boot_a", 6) == 0) {
        printf("boot_a -> boot_a_x\n");
        cmd_flash("boot_a_x", data, sz);
        return;
    }

    if (strncmp(name, "boot_b", 6) == 0) {
        printf("boot_b -> boot_b_x\n");
        cmd_flash("boot_b_x", data, sz);
        return;
    }

    cmd_flash(name, data, sz);
}

void prepare_fastboot() {
    uint16_t *patch;

    // Disable built-in flash command
    patch = (void*)0x4BD34B68;
    *patch++ = 0x46C0; // nop
    *patch = 0x46C0;   // nop
    fastboot_register("flash", cmd_flash_wrapper, 1);

    // Rainbow LED
    patch = (void*)0x4BD349C8;
    *patch++ = 0x46C0; // nop
    *patch = 0x46C0;   // nop
    create_led_thread();
}

int main() {
    int ret = 0, fastboot = 0;
    uint16_t *patch;
    uint32_t *patch32;

    printf("This is LK-payload by xyz. Copyright 2019\n");
    printf("Biscuit native K32 EVT diagnostic by k4y0z and R0rt1z2. Copyright 2020-2026\n");

    parse_gpt();

    if (!g_boot_a_x || !g_boot_b_x || !g_lk_a) {
        printf("failed to find boot, recovery or lk\n");
        printf("falling back to fastboot mode\n");
        fastboot = 1;
    }

    unsigned char overwritten[] = {
        0x6C, 0xBC, 0x05, 0x00, 0x60, 0xBC, 0x05, 0x00, 0x2D, 0xE9, 0xF8, 0x43, 0x5D, 0x48, 0x5E, 0x4D,
        0x78, 0x44, 0x5E, 0x4F, 0x39, 0xF0, 0x0E, 0xF8, 0x7D, 0x44, 0x29, 0x68, 0x7F, 0x44, 0x69, 0xBB,
        0x5B, 0x4C, 0x4F, 0xF4, 0x70, 0x52, 0x7C, 0x44, 0x20, 0x46, 0x3A, 0xF0, 0x0C, 0xE8, 0x20, 0x46,
        0x30, 0xF0, 0x00, 0xFE, 0x00, 0x28, 0x40, 0xF0, 0x9D, 0x80, 0x20, 0x46, 0x2C, 0x60, 0xFF, 0xF7,
    };

    memcpy((void*)0x4BD003C0, overwritten, sizeof(overwritten));

    struct device_t *dev = get_device();

    // If action button is pressed, go to fastboot
    if (mtk_detect_key(KEY_UBER)) {
        printf("Action key pressed, going to fastboot\n");
        fastboot = 1;
    }

    // If mute button is pressed, go to recovery
    if (detect_power_key()) {
        printf("Mute key pressed, booting recovery\n");
        *g_boot_mode = 2;
    }

    // factory and factory advanced boot
    if(*o_boot_mode == 4 ) {
      fastboot = 1;
    }

    // use advanced factory mode to boot recovery
    else if(*o_boot_mode == 6) {
      *g_boot_mode = 2;
    }

    // Use seperate recovery partition
    else if(*g_boot_mode == 2){
        if(g_recovery) {
          boot_recovery = 1;
          // kernel checks this to decide whether to enable USB or not
          *g_boot_mode = 0;
        }
    }



    if (g_expdb) {
      uint8_t expdb_msg[0x20] = { 0 };
      dev->read(dev, g_expdb * 0x200, expdb_msg, 0x10, USER_PART);
      printf("Read expdb_msg: %s\n", expdb_msg);
      if (strncmp(expdb_msg, "FASTBOOT_PLEASE", 15) == 0) {
        fastboot = 1;
      }
    }

    if (g_misc) {
      uint8_t bootloader_msg[0x20] = { 0 };
      dev->read(dev, g_misc * 0x200, bootloader_msg, 0x10, USER_PART);
      printf("Read bootloader_msg: %s\n", bootloader_msg);

      if (strncmp(bootloader_msg, "boot-amonet", 11) == 0) {
        fastboot = 1;
        memset(bootloader_msg, 0, 0x10);
        dev->write(dev, bootloader_msg, g_misc * 0x200, 0x10, USER_PART);
      }

      else if (strncmp(bootloader_msg, "FASTBOOT_PLEASE", 15) == 0) {
        // Consume the one-shot fastboot request before entering fastboot.
        // Leaving this marker set makes every later reboot return to fastboot.
        fastboot = 1;
        memset(bootloader_msg, 0, 0x10);
        dev->write(dev, bootloader_msg, g_misc * 0x200, 0x10, USER_PART);
        printf("Consumed FASTBOOT_PLEASE\n");
      }

      else if (strncmp(bootloader_msg, "boot-recovery", 13) == 0) {
        *g_boot_mode = 2;
        memset(bootloader_msg, 0, 0x10);
        dev->write(dev, bootloader_msg, g_misc * 0x200, 0x10, USER_PART);
      }

      if (strncmp(bootloader_msg + 0x10, "UART_PLEASE", 11) == 0) {
        char* disable_uart = (char*)0x4BD4B0F8;
        strcpy(disable_uart, "printk.disable_uart=0");
        disable_uart = (char*)0x4BD4A56C;
        strcpy(disable_uart, " printk.disable_uart=0");
      }
    }

    // Force fastboot mode
    if (fastboot) {
        printf("well since you're asking so nicely...\n");
        *g_boot_mode = 99;
        prepare_fastboot();
    }

    // The device is unlocked
    patch = (void*)0x4BD1D2FC;
    *patch++ = 0x2001; // movs r0, #1
    *patch = 0x4770;   // bx lr

    // Amazon specific unlock patch
    patch = (void*)0x4BD1D51C;
    *patch++ = 0x2000; // movs r0, #0
    *patch = 0x4770;   // bx lr

    // Hook bootimg read function
    original_read = (void*)dev->read;
    patch32 = (void*)0x4BD57670;
    *patch32 = (uint32_t)read_func;

    patch32 = (void*)&dev->read;
    *patch32 = (uint32_t)read_func;

    // Keep LK's native ARM32 image-processing and final handoff path.  The
    // preloader/ATF have already consumed the live boot option, which remains
    // untouched; only LK's cached image selector is corrected here.
    uint8_t *hdr = (uint8_t *)PAYLOAD_DST;
    original_read(dev, (g_boot_a_x) * 0x200, hdr, 0x800, USER_PART);
    if (memcmp(hdr, "ANDROID!", 8) == 0) {
        uint32_t **boot_arg_ptr = (void *)0x4BD664E0;
        uint32_t *boot_arg = *boot_arg_ptr;

        if (!boot_arg) {
            printf("ABI handoff failed: boot_arg is NULL\n");
            while (1) {}
        }

        patch32 = (void*)0x4BD641F4;
        *patch32 = 0;

        volatile uint16_t *selector = (void*)0x4BD33704;
        if (selector[0] != 0x2800 || selector[1] != 0xF000 || selector[2] != 0x8260) {
            printf("ABI handoff failed: selector/branch=%04x %04x %04x\n",
                   selector[0], selector[1], selector[2]);
            while (1) {}
        }

        install_fdt_diagnostics();

        printf("ABI handoff: native K32 loader + stock ARM32 jump bootopt=%u cached=%u opcode=%04x %04x %04x\n",
               boot_arg[0x53], *patch32, selector[0], selector[1], selector[2]);
    } else {
        printf("ABI handoff failed: inner boot header missing\n");
        while (1) {}
    }

    // Accomodate the max download size
    patch32 = (void*)0x4BD34CE0;
    *patch32 = 0x0380F503; // ADD.W	R3, R3, #0x400000

    printf("Clean lk\n");
    cache_clean((void *)LK_BASE, LK_SIZE);

    // Drain UART TX before re-entering LK so the ABI diag/Clean messages
    // are not lost when the UART controller resets during the transition. 
    mdelay(100);

    restart_lk((void *)app);
    thread_exit(0);
}
