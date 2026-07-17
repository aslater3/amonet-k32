/*
 * consys_pwr_on.ko - Properly power on CONSYS domain on MT8163
 *
 * The genpd runtime PM says "active" but the actual SPM register shows:
 *   PWR_ON=1, PWR_ON_2ND=0, ISO=1 (half-powered, isolated)
 *
 * This module runs the full SPM power-on sequence as defined in
 * mtk-scpsys-mt8163.c scpsys_power_on():
 *
 * SPM base = 0x10006000
 *   SPM_CONN_PWR_CON  = 0x0280
 *   SPM_PWR_STATUS    = 0x060C
 *   SPM_PWR_STATUS_2ND = 0x0610
 *
 * Bit definitions:
 *   PWR_RST_B   = BIT(0) = 0x01
 *   PWR_ISO     = BIT(1) = 0x02
 *   PWR_ON      = BIT(2) = 0x04
 *   PWR_ON_2ND  = BIT(3) = 0x08
 *   PWR_CLK_DIS = BIT(4) = 0x10
 *
 * PWR_STATUS_CONN = BIT(1) = 0x02
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/delay.h>

#define SPM_BASE        0x10006000
#define SPM_CONN_PWR_CON    0x0280
#define SPM_PWR_STATUS       0x060C
#define SPM_PWR_STATUS_2ND   0x0610
#define PWR_STATUS_CONN      BIT(1)

#define PWR_RST_B_BIT    (1 << 0)
#define PWR_ISO_BIT      (1 << 1)
#define PWR_ON_BIT       (1 << 2)
#define PWR_ON_2ND_BIT   (1 << 3)
#define PWR_CLK_DIS_BIT  (1 << 4)

#define CONSYS_MCU_BASE  0x18070000
#define BTIF_BASE        0x1100C000
#define INFRA_BASE       0x10001000

static int __init consys_pwr_on_init(void)
{
    void __iomem *spm;
    void __iomem *consys;
    void __iomem *btif;
    void __iomem *infracfg;
    void __iomem *ctl_addr;
    u32 val, status, status2;
    int i;

    printk(KERN_INFO "consys_pwr_on: Starting CONSYS SPM power-on sequence\n");

    spm = ioremap(SPM_BASE, 0x1000);
    if (!spm) {
        printk(KERN_ERR "consys_pwr_on: cannot ioremap SPM\n");
        return -ENOMEM;
    }
    ctl_addr = spm + SPM_CONN_PWR_CON;

    /* Read initial state */
    val = readl(ctl_addr);
    printk(KERN_INFO "consys_pwr_on: CONN_PWR_CON initial = 0x%08x\n", val);
    printk(KERN_INFO "consys_pwr_on:   PWR_RST_B=%d ISO=%d PWR_ON=%d PWR_ON_2ND=%d CLK_DIS=%d\n",
           val & PWR_RST_B_BIT, (val>>1)&1, (val>>2)&1, (val>>3)&1, (val>>4)&1);

    status = readl(spm + SPM_PWR_STATUS);
    status2 = readl(spm + SPM_PWR_STATUS_2ND);
    printk(KERN_INFO "consys_pwr_on: PWR_STATUS=0x%08x PWR_STATUS_2ND=0x%08x\n", status, status2);
    printk(KERN_INFO "consys_pwr_on:   CONN status=%d 2nd=%d\n",
           (status & PWR_STATUS_CONN) ? 1:0, (status2 & PWR_STATUS_CONN) ? 1:0);

    /* Step 1: Set PWR_ON */
    val = readl(ctl_addr);
    val |= PWR_ON_BIT;
    writel(val, ctl_addr);
    printk(KERN_INFO "consys_pwr_on: Set PWR_ON -> 0x%08x\n", readl(ctl_addr));

    /* Step 2: Set PWR_ON_2ND */
    val |= PWR_ON_2ND_BIT;
    writel(val, ctl_addr);
    printk(KERN_INFO "consys_pwr_on: Set PWR_ON_2ND -> 0x%08x\n", readl(ctl_addr));

    /* Step 3: Wait for PWR_ACK (both status bits set) */
    for (i = 0; i < 100; i++) {
        status = readl(spm + SPM_PWR_STATUS);
        status2 = readl(spm + SPM_PWR_STATUS_2ND);
        if ((status & PWR_STATUS_CONN) && (status2 & PWR_STATUS_CONN))
            break;
        udelay(10);
    }
    printk(KERN_INFO "consys_pwr_on: After %d*10us waits: PWR_STATUS=0x%08x 2ND=0x%08x\n",
           i, status, status2);
    printk(KERN_INFO "consys_pwr_on:   CONN status=%d 2nd=%d\n",
           (status & PWR_STATUS_CONN) ? 1:0, (status2 & PWR_STATUS_CONN) ? 1:0);

    if (!((status & PWR_STATUS_CONN) && (status2 & PWR_STATUS_CONN))) {
        printk(KERN_ERR "consys_pwr_on: PWR_ACK timeout! Power domain did not come up.\n");
        printk(KERN_ERR "consys_pwr_on: The TEE may be blocking CONSYS power on.\n");
    }

    /* Step 4: Clear PWR_CLK_DIS */
    val = readl(ctl_addr);
    val &= ~PWR_CLK_DIS_BIT;
    writel(val, ctl_addr);
    printk(KERN_INFO "consys_pwr_on: Cleared CLK_DIS -> 0x%08x\n", readl(ctl_addr));

    /* Step 5: Clear PWR_ISO (release isolation) */
    val = readl(ctl_addr);
    val &= ~PWR_ISO_BIT;
    writel(val, ctl_addr);
    printk(KERN_INFO "consys_pwr_on: Cleared ISO -> 0x%08x\n", readl(ctl_addr));

    /* Step 6: Set PWR_RST_B (deassert reset) */
    val = readl(ctl_addr);
    val |= PWR_RST_B_BIT;
    writel(val, ctl_addr);
    printk(KERN_INFO "consys_pwr_on: Set PWR_RST_B -> 0x%08x\n", readl(ctl_addr));

    /* Step 7: Clear SRAM power-down bit (bit 8 for CONN) */
    val = readl(ctl_addr);
    val &= ~(1 << 8); /* sram_pdn_bits = GENMASK(8,8) */
    writel(val, ctl_addr);
    printk(KERN_INFO "consys_pwr_on: Cleared SRAM_PDN -> 0x%08x\n", readl(ctl_addr));

    /* Wait a bit for everything to stabilize */
    msleep(10);

    /* Final state */
    val = readl(ctl_addr);
    printk(KERN_INFO "consys_pwr_on: CONN_PWR_CON final = 0x%08x\n", val);
    status = readl(spm + SPM_PWR_STATUS);
    status2 = readl(spm + SPM_PWR_STATUS_2ND);
    printk(KERN_INFO "consys_pwr_on: PWR_STATUS=0x%08x 2ND=0x%08x\n", status, status2);

    /* Now check if CONSYS chip responds */
    consys = ioremap(CONSYS_MCU_BASE, 0x2000);
    if (consys) {
        u32 chip_id = readl(consys + 0x0008);
        printk(KERN_INFO "consys_pwr_on: CONSYS_CHIP_ID = 0x%08x (expect 0x8163 or similar)\n", chip_id);
        iounmap(consys);
    }

    /* Check BTIF registers now */
    btif = ioremap(BTIF_BASE, 0x100);
    if (btif) {
        val = readl(btif + 0x18);
        printk(KERN_INFO "consys_pwr_on: BTIF_CLOCK_DIV = 0x%08x (before write)\n", val);

        /* Test write */
        writel(0x3, btif + 0x18);
        val = readl(btif + 0x18);
        printk(KERN_INFO "consys_pwr_on: after write 0x3 -> BTIF_CLOCK_DIV = 0x%08x %s\n",
               val, (val == 0x3) ? "STICKS! CONSYS IS ALIVE!" : "still doesn't stick");

        iounmap(btif);
    }

    /* Also verify infra clock state */
    infracfg = ioremap(INFRA_BASE, 0x1000);
    if (infracfg) {
        val = readl(infracfg + 0x0090);
        printk(KERN_INFO "consys_pwr_on: infra0 STA = 0x%08x\n", val);
        iounmap(infracfg);
    }

    iounmap(spm);
    printk(KERN_INFO "consys_pwr_on: Done.\n");
    return -EAGAIN;
}

static void __exit consys_pwr_on_exit(void) {}
module_init(consys_pwr_on_init);
module_exit(consys_pwr_on_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Power on CONSYS SPM domain on MT8163 Amazon Echo");
