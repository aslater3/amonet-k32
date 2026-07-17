#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/regulator/consumer.h>

#define SPM_BASE              0x10006000
#define SPM_PWRON_CONFG_EN    0x0000
#define SPM_PWRON_CONFG_VAL   0x0b160001
#define SPM_TOP1_PWR_CTRL     0x0280
#define SPM_PWR_CONN_ACK      0x060C
#define SPM_PWR_CONN_ACK_S    0x0610

#define CONSYS_SPM_PWR_ON_BIT    (1 << 2)
#define CONSYS_SPM_PWR_ON_S_BIT  (1 << 3)
#define CONSYS_CLK_CTRL_BIT      (1 << 4)
#define CONSYS_SPM_PWR_ISO_S_BIT (1 << 1)
#define CONSYS_SPM_PWR_RST_BIT   (1 << 0)
#define CONSYS_PWR_ON_ACK_BIT    (1 << 1)
#define CONSYS_PWR_CONN_ACK_S_BIT (1 << 1)

#define AP_RGU_BUS_BASE       0xF0007000
#define AP_RGU_PHYS_BASE      0x10007000
#define CONSYS_CPU_SW_RST_OFF 0x0018
#define CONSYS_CPU_SW_RST_BIT (1 << 12)
#define CONSYS_CPU_SW_RST_KEY (0x88 << 24)

#define CONSYS_MCU_BASE       0x18070000
#define CONSYS_CHIP_ID_OFF    0x0008
#define CONSYS_MCU_CFG_ACR    0x0110
#define CONSYS_ACR_MBIST_BIT  (1 << 18)

#define BTIF_BASE            0x1100C000
#define BTIF_WRITE_DATA      0x0000
#define BTIF_READ_DATA       0x0004
#define BTIF_INT_FLAG        0x0008
#define BTIF_BUS_MONITOR     0x0014
#define BTIF_CLOCK_DIV       0x0018

static int __init consys_full_pwr_init(void)
{
    void __iomem *spm;
    void __iomem *ap_rgu_bus;
    void __iomem *ap_rgu_phys;
    void __iomem *consys_mcu;
    void __iomem *btif;
    u32 val;
    int i;

    printk(KERN_INFO "consys2: Full CONSYS power-on (v2 - dual RGU)\n");

    {
        struct regulator *r;
        r = regulator_get(NULL, "vcn18");
        if (!IS_ERR(r)) regulator_enable(r);
        r = regulator_get(NULL, "vcn28");
        if (!IS_ERR(r)) regulator_enable(r);
        r = regulator_get(NULL, "vcn33_bt");
        if (IS_ERR(r)) r = regulator_get(NULL, "vcn33-bt");
        if (!IS_ERR(r)) regulator_enable(r);
        r = regulator_get(NULL, "vcn33_wifi");
        if (IS_ERR(r)) r = regulator_get(NULL, "vcn33-wifi");
        if (!IS_ERR(r)) regulator_enable(r);
        printk(KERN_INFO "consys2: regulators done\n");
    }
    udelay(150);

    spm = ioremap(SPM_BASE, 0x1000);
    ap_rgu_bus = ioremap(AP_RGU_BUS_BASE, 0x100);
    ap_rgu_phys = ioremap(AP_RGU_PHYS_BASE, 0x100);
    consys_mcu = ioremap(CONSYS_MCU_BASE, 0x2000);
    btif = ioremap(BTIF_BASE, 0x100);

    /* Try both RGU addresses */
    if (ap_rgu_bus) {
        val = readl(ap_rgu_bus + CONSYS_CPU_SW_RST_OFF);
        printk(KERN_INFO "consys2: RGU_BUS SW_RST = 0x%08x\n", val);
        val |= CONSYS_CPU_SW_RST_BIT | CONSYS_CPU_SW_RST_KEY;
        writel(val, ap_rgu_bus + CONSYS_CPU_SW_RST_OFF);
        printk(KERN_INFO "consys2: RGU_BUS after assert write = 0x%08x\n", readl(ap_rgu_bus + CONSYS_CPU_SW_RST_OFF));
    }
    if (ap_rgu_phys) {
        val = readl(ap_rgu_phys + CONSYS_CPU_SW_RST_OFF);
        printk(KERN_INFO "consys2: RGU_PHYS SW_RST = 0x%08x\n", val);
        val |= CONSYS_CPU_SW_RST_BIT | CONSYS_CPU_SW_RST_KEY;
        writel(val, ap_rgu_phys + CONSYS_CPU_SW_RST_OFF);
        printk(KERN_INFO "consys2: RGU_PHYS after assert write = 0x%08x\n", readl(ap_rgu_phys + CONSYS_CPU_SW_RST_OFF));
    }

    /* SPM power-on sequence */
    writel(SPM_PWRON_CONFG_VAL, spm + SPM_PWRON_CONFG_EN);
    
    val = readl(spm + SPM_TOP1_PWR_CTRL);
    val |= CONSYS_SPM_PWR_ON_BIT;
    writel(val, spm + SPM_TOP1_PWR_CTRL);
    
    for (i = 0; i < 1000; i++) {
        if (readl(spm + SPM_PWR_CONN_ACK) & CONSYS_PWR_ON_ACK_BIT) break;
        udelay(10);
    }
    printk(KERN_INFO "consys2: PWR_ACK waited %d*10us\n", i);
    
    val = readl(spm + SPM_TOP1_PWR_CTRL);
    val |= CONSYS_SPM_PWR_ON_S_BIT;
    writel(val, spm + SPM_TOP1_PWR_CTRL);
    
    val &= ~CONSYS_CLK_CTRL_BIT;
    writel(val, spm + SPM_TOP1_PWR_CTRL);
    
    udelay(1);
    
    for (i = 0; i < 1000; i++) {
        if (readl(spm + SPM_PWR_CONN_ACK_S) & CONSYS_PWR_CONN_ACK_S_BIT) break;
        udelay(10);
    }
    printk(KERN_INFO "consys2: PWR_ACK_S waited %d*10us\n", i);
    
    val = readl(spm + SPM_TOP1_PWR_CTRL);
    val &= ~CONSYS_SPM_PWR_ISO_S_BIT;
    writel(val, spm + SPM_TOP1_PWR_CTRL);
    
    val |= CONSYS_SPM_PWR_RST_BIT;
    writel(val, spm + SPM_TOP1_PWR_CTRL);
    printk(KERN_INFO "consys2: CONN_TOP1 final = 0x%08x\n", readl(spm + SPM_TOP1_PWR_CTRL));

    udelay(10);

    /* CONSYS chip ID */
    val = readl(consys_mcu + CONSYS_CHIP_ID_OFF);
    printk(KERN_INFO "consys2: CONSYS_CHIP_ID = 0x%08x\n", val);

    /* ACR MBIST */
    val = readl(consys_mcu + CONSYS_MCU_CFG_ACR);
    val |= CONSYS_ACR_MBIST_BIT;
    writel(val, consys_mcu + CONSYS_MCU_CFG_ACR);
    printk(KERN_INFO "consys2: ACR = 0x%08x\n", readl(consys_mcu + CONSYS_MCU_CFG_ACR));

    /* Deassert SW reset via both addresses */
    if (ap_rgu_bus) {
        val = readl(ap_rgu_bus + CONSYS_CPU_SW_RST_OFF);
        val = (val & ~CONSYS_CPU_SW_RST_BIT) | CONSYS_CPU_SW_RST_KEY;
        writel(val, ap_rgu_bus + CONSYS_CPU_SW_RST_OFF);
        printk(KERN_INFO "consys2: RGU_BUS after deassert = 0x%08x\n", readl(ap_rgu_bus + CONSYS_CPU_SW_RST_OFF));
    }
    if (ap_rgu_phys) {
        val = readl(ap_rgu_phys + CONSYS_CPU_SW_RST_OFF);
        val = (val & ~CONSYS_CPU_SW_RST_BIT) | CONSYS_CPU_SW_RST_KEY;
        writel(val, ap_rgu_phys + CONSYS_CPU_SW_RST_OFF);
        printk(KERN_INFO "consys2: RGU_PHYS after deassert = 0x%08x\n", readl(ap_rgu_phys + CONSYS_CPU_SW_RST_OFF));
    }

    msleep(20);

    /* Final chip ID */
    val = readl(consys_mcu + CONSYS_CHIP_ID_OFF);
    printk(KERN_INFO "consys2: CONSYS_CHIP_ID FINAL = 0x%08x\n", val);

    /* Dump multiple CONSYS registers */
    for (i = 0; i < 0x20; i += 4) {
        val = readl(consys_mcu + i);
        if (val) printk(KERN_INFO "consys2: CONSYS[0x%04x] = 0x%08x\n", i, val);
    }

    /* BTIF registers */
    if (btif) {
        printk(KERN_INFO "consys2: BTIF dump:\n");
        for (i = 0; i < 0x20; i += 4) {
            val = readl(btif + i);
            printk(KERN_INFO "consys2:   BTIF[0x%02x] = 0x%08x\n", i, val);
        }
        
        writel(0x3, btif + BTIF_CLOCK_DIV);
        val = readl(btif + BTIF_CLOCK_DIV);
        printk(KERN_INFO "consys2: BTIF_CLOCK_DIV after write 0x3 = 0x%08x %s\n",
               val, (val == 0x3) ? "STICKS!" : "no stick");
        
        writel(0xDEADBEEF, btif + BTIF_WRITE_DATA);
        val = readl(btif + BTIF_WRITE_DATA);
        printk(KERN_INFO "consys2: BTIF_WRITE_DATA after write = 0x%08x %s\n",
               val, (val == 0xDEADBEEF) ? "STICKS!" : "no stick");
    }

    if (btif) iounmap(btif);
    if (consys_mcu) iounmap(consys_mcu);
    if (ap_rgu_phys) iounmap(ap_rgu_phys);
    if (ap_rgu_bus) iounmap(ap_rgu_bus);
    if (spm) iounmap(spm);
    return -EAGAIN;
}

static void __exit consys_full_pwr_exit(void) {}
module_init(consys_full_pwr_init);
module_exit(consys_full_pwr_exit);
MODULE_LICENSE("GPL");
