/* Simple ARM64 program to trigger WMT module init via ioctl */
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/ioctl.h>

#define WMT_IOC_MAGIC 'w'
#define COMBO_IOCTL_GET_CHIP_ID    _IOR(WMT_IOC_MAGIC, 0, int)
#define COMBO_IOCTL_SET_CHIP_ID    _IOW(WMT_IOC_MAGIC, 1, int)
#define COMBO_IOCTL_DO_MODULE_INIT _IOR(WMT_IOC_MAGIC, 4, int)
#define COMBO_IOCTL_EXT_CHIP_PWR_ON _IOR(WMT_IOC_MAGIC, 6, int)

int main() {
    int fd, ret, chip_id = 0;
    
    /* First: get chip ID via wmtdetect */
    fd = open("/dev/wmtdetect", O_RDWR);
    if (fd < 0) {
        perror("open /dev/wmtdetect");
        return 1;
    }
    printf("Opened /dev/wmtdetect (fd=%d)\n", fd);
    
    /* Get chip ID */
    ret = ioctl(fd, COMBO_IOCTL_GET_CHIP_ID, &chip_id);
    printf("GET_CHIP_ID ret=%d chip_id=0x%08x\n", ret, chip_id);
    
    /* Do module init */
    ret = ioctl(fd, COMBO_IOCTL_DO_MODULE_INIT, &chip_id);
    printf("DO_MODULE_INIT ret=%d\n", ret);
    
    close(fd);
    
    /* Now try /dev/wmtWifi for the STP path */
    fd = open("/dev/wmtWifi", O_RDWR);
    if (fd < 0) {
        perror("open /dev/wmtWifi");
        return 1;
    }
    printf("Opened /dev/wmtWifi (fd=%d)\n", fd);
    
    /* Try to power on the chip via STP */
    ret = ioctl(fd, COMBO_IOCTL_EXT_CHIP_PWR_ON, &chip_id);
    printf("EXT_CHIP_PWR_ON ret=%d\n", ret);
    
    close(fd);
    return 0;
}
