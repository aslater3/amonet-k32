/*
 * unlock_mpu.ko — Unlock EMI MPU Region 15 for CONSYS DMA access
 *
 * Build: make -C <kernel_source> M=$(pwd) ARCH=arm64 \
 *          CROSS_COMPILE=<toolchain>/aarch64-linux-android- modules
 *
 * Load: insmod /tmp/unlock_mpu.ko
 *
 * Verified working on MT8163 / radar_puffin (Amazon Echo 2nd Gen)
 * with custom 3.18.19 kernel. Returns 0 = SUCCESS.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

/* CONSYS reserve memory: 0x5f600000, size 0x200000 (2MB) */
#define CONSYS_START 0x5f600000
#define CONSYS_END   0x5f7fffff

/* Exported by the kernel's emi_mpu driver */
extern int emi_mpu_set_region_protection(unsigned int start, unsigned int end,
                                         int region, int access_type);

static int __init unlock_mpu_init(void)
{
    int ret;

    printk(KERN_INFO "unlock_mpu: Unlocking EMI MPU Region 15 for CONSYS\n");
    printk(KERN_INFO "unlock_mpu: Region 0x%x - 0x%x, access_type=0 (NO_PROTECTION)\n",
           CONSYS_START, CONSYS_END);

    /* access_type 0 = NO_PROTECTION for all domains */
    ret = emi_mpu_set_region_protection(CONSYS_START, CONSYS_END, 15, 0);

    printk(KERN_INFO "unlock_mpu: emi_mpu_set_region_protection returned %d\n", ret);

    if (ret == 0)
        printk(KERN_INFO "unlock_mpu: SUCCESS - Region 15 unlocked\n");
    else
        printk(KERN_ERR "unlock_mpu: FAILED - ret=%d\n", ret);

    /* Return non-zero so module doesn't stay loaded (one-shot) */
    return -EAGAIN;
}

static void __exit unlock_mpu_exit(void)
{
    /* Never reached — module init returns -EAGAIN */
}

module_init(unlock_mpu_init);
module_exit(unlock_mpu_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("pmOS");
MODULE_DESCRIPTION("Unlock EMI MPU Region 15 for CONSYS DMA");
