/* FirmwareGuard Kernel Module
 * Phase 2: MMIO Write Protection and DMA Restriction Layer
 *
 * SECURITY NOTE: This is a minimal placeholder implementation.
 * Production use requires extensive security review and testing.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/version.h>
#include "fwguard_km.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(FWGUARD_KM_AUTHOR);
MODULE_DESCRIPTION(FWGUARD_KM_DESC);
MODULE_VERSION(FWGUARD_KM_VERSION);

/* Device numbers */
static dev_t fwguard_dev;
static struct class *fwguard_class;
static struct cdev fwguard_cdev;

/* Protection state */
static struct fwguard_status status = {
    .num_protected_regions = 0,
    .num_dma_restrictions = 0,
    .flags = 0
};

/* Protected MMIO regions (simple array for demonstration) */
#define MAX_PROTECTED_REGIONS 16
static struct fwguard_mmio_region protected_regions[MAX_PROTECTED_REGIONS];

/* Device operations */
static int fwguard_open(struct inode *inode, struct file *file)
{
    pr_info("fwguard: device opened\n");
    return 0;
}

static int fwguard_release(struct inode *inode, struct file *file)
{
    pr_info("fwguard: device closed\n");
    return 0;
}

static long fwguard_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct fwguard_status __user *user_status;
    struct fwguard_mmio_region region;
    int ret = 0;

    /* Check for required capabilities */
    if (!capable(CAP_SYS_RAWIO)) {
        pr_warn("fwguard: operation requires CAP_SYS_RAWIO capability\n");
        return -EPERM;
    }

    switch (cmd) {
    case FWGUARD_IOC_PROTECT_MMIO:
        if (copy_from_user(&region, (void __user *)arg, sizeof(region))) {
            return -EFAULT;
        }

        /* Input validation */
        if (region.size == 0 || region.size > (1UL << 30)) {
            pr_err("fwguard: invalid MMIO region size: %lu\n", region.size);
            return -EINVAL;
        }

        /* Validate base address is in valid MMIO range (x86/x64 typical range) */
        if (region.base_addr == 0) {
            pr_err("fwguard: invalid MMIO base address: 0x%lx\n", region.base_addr);
            return -EINVAL;
        }

        /* Check for integer overflow in region calculation */
        if (region.base_addr + region.size < region.base_addr) {
            pr_err("fwguard: MMIO region overflow detected\n");
            return -EINVAL;
        }

        /* Validate the region doesn't overlap with kernel memory */
        if (region.base_addr < 0xC0000000UL) {
            pr_err("fwguard: MMIO address too low (overlaps RAM): 0x%lx\n",
                   region.base_addr);
            return -EINVAL;
        }

        if (status.num_protected_regions >= MAX_PROTECTED_REGIONS) {
            pr_err("fwguard: maximum protected regions reached\n");
            return -ENOMEM;
        }

        /*
         * TODO: Implement actual MMIO protection mechanism
         *
         * Current implementation only tracks protected regions but doesn't
         * enforce protection. Production implementation requires:
         *
         * 1. Page Table Manipulation:
         *    - Use set_memory_ro() or similar to mark MMIO pages read-only
         *    - Or use set_memory_nx() to make them non-executable
         *    - Handle page alignment (MMIO regions must be page-aligned)
         *
         * 2. Memory Type Range Registers (MTRRs):
         *    - Configure MTRRs to control caching behavior
         *    - Prevent unauthorized MMIO access via cache manipulation
         *
         * 3. IOMMU Integration:
         *    - Use Intel VT-d or AMD-Vi to restrict DMA access
         *    - Require IOMMU_API support in kernel config
         *
         * 4. Exception Handler:
         *    - Register page fault handler to intercept unauthorized access
         *    - Log attempted violations for audit
         *
         * 5. Synchronization:
         *    - Use proper locking (spinlocks for interrupt context)
         *    - Handle SMP race conditions
         *
         * Example skeleton code:
         *   unsigned long pfn = region.base_addr >> PAGE_SHIFT;
         *   unsigned long num_pages = (region.size + PAGE_SIZE - 1) >> PAGE_SHIFT;
         *   set_memory_ro(region.base_addr, num_pages);
         *
         * WARNING: Incorrect implementation can cause kernel panics or
         * system instability. Extensive testing required on multiple platforms.
         */

        /* Add to protected regions (tracking only - no enforcement yet) */
        protected_regions[status.num_protected_regions] = region;
        status.num_protected_regions++;

        pr_info("fwguard: tracked MMIO region 0x%lx-0x%lx (protection not enforced - see TODO)\n",
                region.base_addr, region.base_addr + region.size);
        break;

    case FWGUARD_IOC_UNPROTECT_MMIO:
        /* Remove protection (simplified - production needs proper handling) */
        if (status.num_protected_regions > 0) {
            status.num_protected_regions--;
            pr_info("fwguard: removed MMIO protection\n");
        }
        break;

    case FWGUARD_IOC_RESTRICT_DMA:
        /* DMA restriction placeholder */
        pr_info("fwguard: DMA restriction requested (not implemented)\n");
        status.num_dma_restrictions++;
        break;

    case FWGUARD_IOC_GET_STATUS:
        user_status = (struct fwguard_status __user *)arg;
        if (copy_to_user(user_status, &status, sizeof(status))) {
            return -EFAULT;
        }
        break;

    default:
        pr_warn("fwguard: unknown ioctl command: 0x%x\n", cmd);
        return -ENOTTY;
    }

    return ret;
}

static const struct file_operations fwguard_fops = {
    .owner = THIS_MODULE,
    .open = fwguard_open,
    .release = fwguard_release,
    .unlocked_ioctl = fwguard_ioctl,
};

static int __init fwguard_init(void)
{
    int ret;
    struct file *test_fp;

    pr_info("fwguard: initializing kernel module v%s\n", FWGUARD_KM_VERSION);

    /* PHASE 3: Symbol conflict detection
     * Check if /dev/fwguard already exists from another module
     * This prevents conflicts with other security modules
     */
    test_fp = filp_open("/dev/fwguard", O_RDONLY, 0);
    if (!IS_ERR(test_fp)) {
        filp_close(test_fp, NULL);
        pr_err("fwguard: CONFLICT - /dev/fwguard already exists\n");
        pr_err("fwguard: Another fwguard instance or conflicting module is loaded\n");
        pr_err("fwguard: Run 'lsmod | grep fwguard' to check for duplicates\n");
        return -EEXIST;
    }

    /* Allocate device number */
    ret = alloc_chrdev_region(&fwguard_dev, 0, 1, "fwguard");
    if (ret < 0) {
        pr_err("fwguard: failed to allocate device number (error: %d)\n", ret);
        pr_err("fwguard: This may indicate a symbol conflict with another module\n");
        return ret;
    }

    /* Create device class */
    /* Kernel API changed in 6.4+ - class_create() now takes only name */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
    fwguard_class = class_create("fwguard");
#else
    fwguard_class = class_create(THIS_MODULE, "fwguard");
#endif
    if (IS_ERR(fwguard_class)) {
        pr_err("fwguard: failed to create device class\n");
        unregister_chrdev_region(fwguard_dev, 1);
        return PTR_ERR(fwguard_class);
    }

    /* Initialize character device */
    cdev_init(&fwguard_cdev, &fwguard_fops);
    fwguard_cdev.owner = THIS_MODULE;

    ret = cdev_add(&fwguard_cdev, fwguard_dev, 1);
    if (ret < 0) {
        pr_err("fwguard: failed to add character device\n");
        class_destroy(fwguard_class);
        unregister_chrdev_region(fwguard_dev, 1);
        return ret;
    }

    /* Create device node */
    device_create(fwguard_class, NULL, fwguard_dev, NULL, "fwguard");

    pr_info("fwguard: kernel module loaded successfully\n");
    pr_info("fwguard: device node created at /dev/fwguard\n");

    return 0;
}

static void __exit fwguard_exit(void)
{
    pr_info("fwguard: unloading kernel module\n");

    device_destroy(fwguard_class, fwguard_dev);
    cdev_del(&fwguard_cdev);
    class_destroy(fwguard_class);
    unregister_chrdev_region(fwguard_dev, 1);

    pr_info("fwguard: kernel module unloaded\n");
}

module_init(fwguard_init);
module_exit(fwguard_exit);
