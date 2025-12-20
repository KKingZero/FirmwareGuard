/* FirmwareGuard Kernel Module
 * Provides MMIO write protection and DMA window restriction
 *
 * WARNING: This is a Phase 2 placeholder. Full implementation requires
 * extensive kernel development and testing.
 */

#ifndef _FWGUARD_KM_H
#define _FWGUARD_KM_H

/* Module information */
#define FWGUARD_KM_VERSION "0.3.0"
#define FWGUARD_KM_AUTHOR  "FirmwareGuard Project"
#define FWGUARD_KM_DESC    "Firmware telemetry protection layer"

/* IOCTL commands for userspace communication */
#define FWGUARD_IOC_MAGIC  'F'
#define FWGUARD_IOC_PROTECT_MMIO    _IOW(FWGUARD_IOC_MAGIC, 1, unsigned long)
#define FWGUARD_IOC_UNPROTECT_MMIO  _IOW(FWGUARD_IOC_MAGIC, 2, unsigned long)
#define FWGUARD_IOC_RESTRICT_DMA    _IOW(FWGUARD_IOC_MAGIC, 3, unsigned long)
#define FWGUARD_IOC_GET_STATUS      _IOR(FWGUARD_IOC_MAGIC, 4, unsigned long)

/* SPI Flash Protection Monitoring IOCTL commands */
#define FWGUARD_IOC_SPI_GET_STATUS     _IOR(FWGUARD_IOC_MAGIC, 10, struct spi_protection_status)
#define FWGUARD_IOC_SPI_START_MONITOR  _IOW(FWGUARD_IOC_MAGIC, 11, unsigned int)
#define FWGUARD_IOC_SPI_STOP_MONITOR   _IO(FWGUARD_IOC_MAGIC, 12)
#define FWGUARD_IOC_SPI_GET_EVENTS     _IOWR(FWGUARD_IOC_MAGIC, 13, struct spi_event_ioctl)

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

/* SPI Flash Protection Monitoring structures */

/* SPI Event Types - Bitmask flags */
#define SPI_EVENT_WRITE_ENABLE      0x01  /* BIOS Write Enable detected */
#define SPI_EVENT_LOCK_DISABLED     0x02  /* BIOS Lock disabled */
#define SPI_EVENT_WRITE_ATTEMPT     0x04  /* Flash write operation attempted */
#define SPI_EVENT_ERASE_ATTEMPT     0x08  /* Flash erase operation attempted */
#define SPI_EVENT_PROTECTION_OFF    0x10  /* SMM write protection disabled */
#define SPI_EVENT_BIOS_REGION       0x20  /* Operation targets BIOS region */

/* SPI security event record */
struct spi_event {
    __u64 timestamp;          /* Kernel jiffies when event occurred */
    __u32 event_type;         /* Bitmask of SPI_EVENT_* flags */
    __u32 bios_cntl;          /* BIOS_CNTL register value */
    __u32 hsfsts_ctl;         /* HSFSTS_CTL register value */
    __u32 flash_addr;         /* Flash address being accessed */
    __u32 flash_cycle;        /* Flash cycle type (0=read, 2=write, 3=erase) */
};

/* SPI protection status */
struct spi_protection_status {
    __u8 monitoring_active;       /* Is monitoring enabled? (bool) */
    __u8 bios_cntl;               /* Current BIOS_CNTL value */
    __u8 bios_cntl_baseline;      /* Baseline BIOS_CNTL value */
    __u8 _padding1;               /* Padding for alignment */
    __u32 poll_interval_ms;       /* Polling interval in milliseconds */
    __u32 hsfsts_ctl;             /* Current HSFSTS_CTL value */
    __u32 pending_events;         /* Number of buffered events */
};

/* IOCTL structure for event retrieval */
struct spi_event_ioctl {
    struct spi_event *events;     /* Pointer to userspace event array */
    __u32 max_events;             /* Maximum events to retrieve */
    __u32 num_events;             /* Actual events retrieved (output) */
};

/* Function declarations for SPI monitoring (kernel internal use) */
#ifdef __KERNEL__
int spi_monitor_init(void);
void spi_monitor_cleanup(void);
int spi_start_monitoring(unsigned int poll_interval_ms);
void spi_stop_monitoring(void);
int spi_get_events(struct spi_event __user *events, unsigned int max_events,
                   unsigned int *num_events);
int spi_get_status(struct spi_protection_status *status);
#endif /* __KERNEL__ */

#endif /* _FWGUARD_KM_H */
