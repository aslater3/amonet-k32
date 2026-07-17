/*
 * enable_consys_clk.ko - Enable CONSYS-related infra clocks on MT8163
 *
 * The WMT driver has CONSYS_AHB_CLK_MAGEMENT=0, so all clock management
 * code is compiled out. The consys DTB node also has no clocks property.
 * This means infra_pmic_conn (the CONSYS PMIC/AHB clock) is never enabled.
 *
 * Without this clock, BTIF WRITE_DATA and CLOCK_DIV registers don't hold
 * values (they're in the CONSYS clock domain), so STP can't send data to
 * the CONSYS chip and WiFi init fails.
 *
 * This module directly enables the specific clock bits via the infracfg
 * set registers, avoiding the need for a DTB+kernel rebuild.
 *
 * infracfg base = 0x10001000
 *   infra0 SET = 0x10001080  (write 1 to enable bit)
 *   infra0 CLR = 0x10001084  (write 1 to disable bit)
 *   infra0 STA = 0x10001090  (read status)
 *
 * Clocks enabled:
 *   bit 3  = infra_pmic_conn  (CONSYS PMIC clock - THE MISSING ONE)
 *   bit 31 = infra_btif       (BTIF bus clock - ensure it's on)
 *
 * We also try the CCF approach: clk_get_sys("infra_pmic_conn", NULL)
 * followed by clk_prepare_enable, which is cleaner if it works.
 * If it fails (ENOENT because the clock isn't in a DTB consumer node),
 * we fall back to direct MMIO.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/clk.h>
#include <linux/delay.h>

#define INFRA_BASE         0x10001000
#define INFRA0_SET_OFFSET  0x0080
#define INFRA0_CLR_OFFSET  0x0084
#define INFRA0_STA_OFFSET  0x0090

#define BIT_PMIC_CONN  (1 << 3)
#define BIT_BTIF       (1 << 31)
#define CONSYS_CLK_MASK (BIT_PMIC_CONN | BIT_BTIF)

/* CONSYS MCU config registers for verification */
#define CONSYS_MCU_BASE   0x18070000
#define CONSYS_CHIP_ID    0x0008
#define CONSYS_CLOCK_DIV  0x1800

/* BTIF registers */
#define BTIF_BASE          0x1100C000
#define BTIF_WRITE_DATA   0x0000
#define BTIF_READ_DATA    0x0004
#define BTIF_INT_FLAG     0x0008
#define BTIF_CLOCK_DIV    0x0018
#define BTIF_BUS_MONITOR  0x0014

static void __iomem *infracfg;
static void __iomem *consys_mcu;
static void __iomem *btif;

static int __init enable_consys_clk_init(void)
{
    u32 val, chip_id, btif_write, btif_clkdiv, btif_monitor, btif_read, btif_intflag;
    struct clk *clk_pmic_conn;
    struct clk *clk_btif;
    int ccf_ok = 0;

    printk(KERN_INFO "enable_consys_clk: Enabling CONSYS infra clocks on MT8163\n");

    /* --- Try CCF first (cleaner) --- */
    clk_pmic_conn = clk_get_sys("infra_pmic_conn", NULL);
    if (IS_ERR(clk_pmic_conn)) {
        printk(KERN_WARNING "enable_consys_clk: clk_get_sys(infra_pmic_conn) failed=%ld, will use MMIO\n",
               PTR_ERR(clk_pmic_conn));
    } else {
        int ret = clk_prepare_enable(clk_pmic_conn);
        if (ret) {
            printk(KERN_WARNING "enable_consys_clk: clk_prepare_enable(infra_pmic_conn) failed=%d\n", ret);
        } else {
            printk(KERN_INFO "enable_consys_clk: CCF enabled infra_pmic_conn OK\n");
            ccf_ok |= 1;
        }
    }

    clk_btif = clk_get_sys("infra_btif", NULL);
    if (IS_ERR(clk_btif)) {
        printk(KERN_WARNING "enable_consys_clk: clk_get_sys(infra_btif) failed=%ld\n",
               PTR_ERR(clk_btif));
    } else {
        int ret = clk_prepare_enable(clk_btif);
        if (ret) {
            printk(KERN_WARNING "enable_consys_clk: clk_prepare_enable(infra_btif) failed=%d\n", ret);
        } else {
            printk(KERN_INFO "enable_consys_clk: CCF enabled infra_btif OK\n");
            ccf_ok |= 2;
        }
    }

    /* --- Direct MMIO for the bits CCF couldn't get --- */
    if ((ccf_ok & 1) == 0 || (ccf_ok & 2) == 0) {
        infracfg = ioremap(INFRA_BASE, 0x1000);
        if (!infracfg) {
            printk(KERN_ERR "enable_consys_clk: cannot ioremap infracfg!\n");
            return -ENOMEM;
        }

        /* Read current status */
        val = readl(infracfg + INFRA0_STA_OFFSET);
        printk(KERN_INFO "enable_consys_clk: infra0 STA before = 0x%08x\n", val);
        printk(KERN_INFO "enable_consys_clk:   pmic_conn(bit3)=%d btif(bit31)=%d\n",
               (val & BIT_PMIC_CONN) ? 1 : 0,
               (val & BIT_BTIF) ? 1 : 0);

        /* Enable missing bits via SET register (only those not already on) */
        u32 to_enable = 0;
        if ((ccf_ok & 1) == 0 && !(val & BIT_PMIC_CONN))
            to_enable |= BIT_PMIC_CONN;
        if ((ccf_ok & 2) == 0 && !(val & BIT_BTIF))
            to_enable |= BIT_BTIF;

        if (to_enable) {
            printk(KERN_INFO "enable_consys_clk: MMIO enabling bits 0x%08x\n", to_enable);
            writel(to_enable, infracfg + INFRA0_SET_OFFSET);
            /* Set/clear registers need a moment to take effect */
            udelay(100);
        }

        val = readl(infracfg + INFRA0_STA_OFFSET);
        printk(KERN_INFO "enable_consys_clk: infra0 STA after = 0x%08x\n", val);
        printk(KERN_INFO "enable_consys_clk:   pmic_conn(bit3)=%d btif(bit31)=%d\n",
               (val & BIT_PMIC_CONN) ? 1 : 0,
               (val & BIT_BTIF) ? 1 : 0);
    }

    /* --- Verify CONSYS chip responds --- */
    consys_mcu = ioremap(CONSYS_MCU_BASE, 0x2000);
    if (consys_mcu) {
        chip_id = readl(consys_mcu + CONSYS_CHIP_ID);
        printk(KERN_INFO "enable_consys_clk: CONSYS_CHIP_ID = 0x%08x (expect 0x8163)\n", chip_id);
    } else {
        printk(KERN_ERR "enable_consys_clk: cannot ioremap consys_mcu!\n");
    }

    /* --- Verify BTIF registers now hold values --- */
    btif = ioremap(BTIF_BASE, 0x100);
    if (btif) {
        btif_monitor = readl(btif + BTIF_BUS_MONITOR);
        btif_read    = readl(btif + BTIF_READ_DATA);
        btif_intflag = readl(btif + BTIF_INT_FLAG);
        btif_clkdiv  = readl(btif + BTIF_CLOCK_DIV);
        btif_write   = readl(btif + BTIF_WRITE_DATA);
        printk(KERN_INFO "enable_consys_clk: BTIF regs after clock enable:\n");
        printk(KERN_INFO "enable_consys_clk:   BUS_MONITOR=0x%08x READ_DATA=0x%08x INT_FLAG=0x%08x\n",
               btif_monitor, btif_read, btif_intflag);
        printk(KERN_INFO "enable_consys_clk:   CLOCK_DIV=0x%08x  WRITE_DATA=0x%08x\n",
               btif_clkdiv, btif_write);

        /* Test: can we WRITE CLOCK_DIV and have it stick? */
        writel(0x3, btif + BTIF_CLOCK_DIV);
        btif_clkdiv = readl(btif + BTIF_CLOCK_DIV);
        printk(KERN_INFO "enable_consys_clk:   after write 0x3 → CLOCK_DIV=0x%08x %s\n",
               btif_clkdiv,
               (btif_clkdiv == 0x3) ? "STICKS! ✓" : "DOESN'T STICK ✗");

        /* Test: can we WRITE WRITE_DATA and have it stick? */
        writel(0xAA55F00F, btif + BTIF_WRITE_DATA);
        btif_write = readl(btif + BTIF_WRITE_DATA);
        printk(KERN_INFO "enable_consys_clk:   after write 0xAA55F00F → WRITE_DATA=0x%08x %s\n",
               btif_write,
               (btif_write == 0xAA55F00F) ? "STICKS! ✓" : "DOESN'T STICK ✗");
    } else {
        printk(KERN_ERR "enable_consys_clk: cannot ioremap btif!\n");
    }

    printk(KERN_INFO "enable_consys_clk: Done. If CLOCK_DIV/WRITE_DATA stick, CONSYS clock is running.\n");

    /* Don't stay loaded - the registers are already set */
    return -EAGAIN;
}

static void __exit enable_consys_clk_exit(void)
{
    if (infracfg)
        iounmap(infracfg);
    if (consys_mcu)
        iounmap(consys_mcu);
    if (btif)
        iounmap(btif);
}

module_init(enable_consys_clk_init);
module_exit(enable_consys_clk_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Enable CONSYS infra clocks on MT8163 Amazon Echo");
