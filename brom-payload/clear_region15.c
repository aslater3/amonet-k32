/*
 * clear_region15.c - Minimal BROM payload to clear EMI MPU Region 15
 * 
 * Target: Amazon Echo 2nd Gen (radar_puffin), MediaTek MT8163
 * 
 * This payload runs at BROM stage BEFORE TEE/ATF loads and clears the
 * EMI MPU Region 15 registers that protect the CONSYS (WiFi/BT) memory.
 * 
 * Region 15 registers:
 *   EMI_MPUH2     (0x10203298) - Region address range (start/end)
 *   EMI_MPUL2     (0x102032B8) - Region permissions (low 16 bits)
 *   EMI_MPUL2_2ND (0x102032BC) - Region permissions (high 16 bits)
 * 
 * By clearing these to 0, we remove the MPU protection before TEE can lock it.
 * 
 * Based on generic_stage1.c structure from mtkclient (B.Kerler, k4y0z 2021)
 */

#include <stdint.h>

/* Hardware base addresses */
#define WDT_BASE        0x10007000
#define UART_BASE       0x11002000
#define EMI_BASE        0x10203000

/* EMI MPU Region 15 register offsets */
#define EMI_MPUH2       (EMI_BASE + 0x0298)  /* Region 15 addr start/end */
#define EMI_MPUL2       (EMI_BASE + 0x02B8)  /* Region 15 permissions */
#define EMI_MPUL2_2ND   (EMI_BASE + 0x02BC)  /* Region 15 2nd permissions */

/* Volatile pointers to hardware registers */
static volatile uint32_t *wdt           = (volatile uint32_t *)WDT_BASE;
static volatile uint32_t *uart_base     = (volatile uint32_t *)UART_BASE;
static volatile uint32_t *uart_reg0     = (volatile uint32_t *)0x0;
static volatile uint32_t *uart_reg1     = (volatile uint32_t *)0x0;

/* USB download functions (found dynamically in BROM) */
void (*send_usb_response)(int, int, int) = (void*)0x0;
int (*usbdl_put_data)() = (void*)0x0;
int (*usbdl_get_data)() = (void*)0x0;
uint32_t (*usbdl_put_word)() = (void*)0x0;

/* Low-level UART output */
void low_uart_put(int ch) {
    while (!((*uart_reg0) & 0x20))
        {}
    *uart_reg1 = ch;
}

void _putchar(char character) {
    if (character == '\n')
        low_uart_put('\r');
    low_uart_put(character);
}

/* Send 32-bit word over USB (big-endian) */
void send_dword(uint32_t value) {
    uint32_t ack = __builtin_bswap32(value);
    usbdl_put_data(&ack, 4);
}

/* Receive 32-bit word over USB (big-endian) */
uint32_t recv_dword() {
    uint32_t value;
    usbdl_get_data(&value, 4);
    return __builtin_bswap32(value);
}

/* Print string to UART */
int print(char* s) {
    char c = s[0];
    int i = 0;
    while(c) {
        _putchar(c);
        c = s[++i];
    }
    return i;
}

/* Hex digit lookup table */
static const char hex[] = "0123456789ABCDEF";

/* Print 32-bit value as hex */
void pdword(uint32_t value) {
    int i;
    _putchar(0x30);  /* '0' */
    _putchar(0x78);  /* 'x' */
    for (i = 3; i >= 0; i--) {
        _putchar(hex[(((value >> (i*8)) & 0xFF) >> 4) & 0xf]);
        _putchar(hex[((value >> (i*8)) & 0xFF) & 0xf]);
    }
}

/* Search for instruction pattern in BROM */
uint32_t searchfunc(uint32_t startoffset, uint32_t endoffset, 
                    const uint16_t *pattern, uint8_t patternsize) {
    uint8_t matched = 0;
    for (uint32_t offset = startoffset; offset < endoffset; offset += 2) {
        for (uint32_t i = 0; i < patternsize; i++) {
            if (((uint16_t *)offset)[i] != pattern[i]) {
                matched = 0;
                break;
            }
            if (++matched == patternsize) return offset;
        }
    }
    return 0;
}

/* Decode LDR literal instruction to get address */
uint32_t * ldr_lit(const uint32_t curpc, uint16_t instr, uint8_t *Rt) {
    uint8_t imm8 = instr & 0xFF;
    *Rt = (instr >> 8) & 7;
    uint32_t pc = (((uint32_t)curpc) / 4 * 4);
    return (uint32_t *)(pc + (imm8 * 4) + 4);
}

/*
 * main - Payload entry point
 * 
 * Called by amonet exploit after loading payload at 0x201000 in SRAM.
 * Initializes BROM functions, clears Region 15, and reboots.
 */
__attribute__((section(".text.main")))
int main() {
    uint32_t offs1 = 0;
    uint32_t bromstart;
    uint32_t bromend;
    uint32_t startpos;

    /* Find BROM base address */
    volatile uint32_t brom_base = 0;
    if (((uint32_t *)(brom_base))[0] == 0xe51ff004)
        brom_base = ((uint32_t *)(brom_base))[1];

    /* Find and initialize UART for debug output */
    static const uint16_t uartb[3] = {0x5F31, 0x4E45, 0x0F93};
    offs1 = searchfunc(brom_base + 0x100, brom_base + 0x14000, uartb, 3);
    if (offs1) {
        uart_base = (volatile uint32_t *)(((uint32_t *)(offs1 + 0x8))[0] & 0xFFFFFFFF);
        uart_reg0 = (volatile uint32_t *)((volatile uint32_t)uart_base + 0x14);
        uart_reg1 = (volatile uint32_t *)uart_base;
    }

    bromstart = brom_base + 0x100;
    bromend = brom_base + 0x14000;

    /* Find and disable watchdog to prevent timeout */
    static const uint16_t wdts[3] = {0xF641, 0x1071, 0x6088};
    uint8_t Rt = 0;
    offs1 = searchfunc(bromstart, bromend, wdts, 3);
    if (offs1) {
        wdt = (volatile uint32_t *)(ldr_lit((uint32_t)offs1 - 2, 
                     ((uint16_t*)(offs1 - 2))[0], &Rt)[0]);
        wdt[0] = 0x22000064;  /* Disable watchdog timeout */
    }

    /* Find send_usb_response function */
    static const uint16_t sur1a[2] = {0xB530, 0x2300};
    static const uint16_t sur1b[3] = {0x2808, 0xD00F, 0x2807};
    static const uint16_t sur2[3] = {0x2400, 0xF04F, 0x5389};
    static const uint16_t sur3[3] = {0x2400, 0x2803, 0xD006};
    
    offs1 = searchfunc(bromstart, bromend, sur1a, 2);
    if (offs1) {
        startpos = searchfunc(offs1 + 6, offs1 + 12, sur1b, 3);
        if (startpos != offs1 + 6) {
            offs1 = 0;
        }
    }
    if (!offs1) {
        offs1 = searchfunc(bromstart, bromend, sur2, 3);
        if (offs1) {
            offs1 -= 2;
        } else {
            offs1 = searchfunc(bromstart, bromend, sur3, 3);
            if (offs1) {
                offs1 -= 4;
            }
        }
    }
    if (offs1) {
        send_usb_response = (void *)(offs1 | 1);
    }

    /* Find USB download functions */
    static const uint16_t sdda[2] = {0x0AA0, 0x0550};
    offs1 = (uint32_t)(searchfunc(bromstart, bromend, sdda, 2));
    if (offs1) {
        offs1 = (uint32_t)(searchfunc(offs1 + 0x4, bromend, sdda, 2));
        if (offs1) {
            usbdl_put_word = (void*)(*((uint32_t *)((offs1 - 0x1C))));
            usbdl_get_data = (void*)(*((uint32_t *)((offs1 - 0x10))) | 1);
            usbdl_put_data = (void*)(*((uint32_t *)((offs1 - 0xC))) | 1);
            int (*(*usbdl_ptr))() = (void *)(ldr_lit((uint32_t)usbdl_put_word + 7, 
                                         ((uint16_t*)(usbdl_put_word + 7))[0], 0));
            /* Fix ptr_send pointer */
            *(volatile uint32_t *)(usbdl_ptr[0] + 8) = (uint32_t)usbdl_ptr[2];
        }
    }

    print("Clear Region 15 payload (c) 2024\n");
    
    /* Send USB acknowledgment */
    send_usb_response(1, 0, 1);
    send_dword(0xA1A2A3A4);

    print("Reading Region 15 registers...\n");
    
    /* Read current values for verification */
    volatile uint32_t *emi_mpuh2_ptr = (volatile uint32_t *)EMI_MPUH2;
    volatile uint32_t *emi_mpul2_ptr = (volatile uint32_t *)EMI_MPUL2;
    volatile uint32_t *emi_mpul2_2nd_ptr = (volatile uint32_t *)EMI_MPUL2_2ND;
    
    uint32_t h2_val = *emi_mpuh2_ptr;
    uint32_t l2_val = *emi_mpul2_ptr;
    uint32_t l2_2nd_val = *emi_mpul2_2nd_ptr;
    
    print("EMI_MPUH2     = ");
    pdword(h2_val);
    print("\n");
    
    print("EMI_MPUL2     = ");
    pdword(l2_val);
    print("\n");
    
    print("EMI_MPUL2_2ND = ");
    pdword(l2_2nd_val);
    print("\n");

    print("Clearing Region 15...\n");
    
    /* CLEAR REGION 15 - This is the critical part */
    *emi_mpuh2_ptr = 0;      /* Clear address range */
    *emi_mpul2_ptr = 0;      /* Clear permissions (low) */
    *emi_mpul2_2nd_ptr = 0;  /* Clear permissions (high) */
    
    print("Region 15 cleared!\n");
    
    /* Verify the write */
    h2_val = *emi_mpuh2_ptr;
    l2_val = *emi_mpul2_ptr;
    l2_2nd_val = *emi_mpul2_2nd_ptr;
    
    print("Verification:\n");
    print("EMI_MPUH2     = ");
    pdword(h2_val);
    print("\n");
    
    print("EMI_MPUL2     = ");
    pdword(l2_val);
    print("\n");
    
    print("EMI_MPUL2_2ND = ");
    pdword(l2_2nd_val);
    print("\n");
    
    print("Triggering watchdog reboot...\n");
    
    /* 
     * Trigger watchdog reboot
     * Standard MTK watchdog reset sequence:
     * 1. Write magic value to enable watchdog (WDT_MODE)
     * 2. Configure watchdog timer (WDT_LENGTH)  
     * 3. Trigger immediate software reset (WDT_RST)
     */
    wdt[8/4]    = 0x1971;      /* WDT_MODE: enable with magic key */
    wdt[0/4]    = 0x22000014;  /* WDT_LENGTH: timeout configuration */
    wdt[0x14/4] = 0x1209;      /* WDT_RST: trigger software reset */

    /* Wait for reset (should never reach here) */
    print("Waiting for reset...\n");
    while (1) {
        /* Infinite loop until watchdog triggers */
    }
    
    return 0;
}
