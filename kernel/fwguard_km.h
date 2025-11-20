/* FirmwareGuard Kernel Module
 * Provides MMIO write protection and DMA window restriction
 *
 * WARNING: This is a Phase 2 placeholder. Full implementation requires
 * extensive kernel development and testing.
 */

#ifndef _FWGUARD_KM_H
#define _FWGUARD_KM_H

/* Module information */
#define FWGUARD_KM_VERSION "0.2.0"
#define FWGUARD_KM_AUTHOR  "FirmwareGuard Project"
#define FWGUARD_KM_DESC    "Firmware telemetry protection layer"

/* IOCTL commands for userspace communication */
#define FWGUARD_IOC_MAGIC  'F'
#define FWGUARD_IOC_PROTECT_MMIO    _IOW(FWGUARD_IOC_MAGIC, 1, unsigned long)
#define FWGUARD_IOC_UNPROTECT_MMIO  _IOW(FWGUARD_IOC_MAGIC, 2, unsigned long)
#define FWGUARD_IOC_RESTRICT_DMA    _IOW(FWGUARD_IOC_MAGIC, 3, unsigned long)
#define FWGUARD_IOC_GET_STATUS      _IOR(FWGUARD_IOC_MAGIC, 4, unsigned long)

/* Protection status */
struct fwguard_status {
    int num_protected_regions;
    int num_dma_restrictions;
    unsigned long flags;
};

/* MMIO protection region */
struct fwguard_mmio_region {
    unsigned long base_addr;
    unsigned long size;
    unsigned int protection_level;
};

#endif /* _FWGUARD_KM_H */
