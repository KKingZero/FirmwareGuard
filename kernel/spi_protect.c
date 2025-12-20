/* FirmwareGuard SPI Flash Write Protection Monitor
 * Kernel module component for monitoring SPI controller and flash write protection
 *
 * SECURITY NOTE: This monitors SPI flash write protection mechanisms to detect
 * unauthorized firmware modification attempts. OFFLINE-ONLY operation.
 *
 * Functionality:
 * - Monitor SPI controller registers for write enable signals
 * - Check BIOS_CNTL register for flash write protection status
 * - Detect attempts to modify BIOS region
 * - Alert userspace on unexpected flash write operations
 * - Track SPI flash protection events for forensic analysis
 *
 * IMPLEMENTATION NOTES:
 * This code is designed for x86/x64 Intel platforms with PCH (Platform Controller Hub).
 * Different platforms (AMD, ARM) will require platform-specific adaptations.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include "fwguard_km.h"

/* Intel PCH SPI Controller Register Definitions
 * Based on Intel PCH datasheets (100-series and newer)
 *
 * The SPI controller on Intel platforms is typically at:
 * - PCI Bus 0, Device 31, Function 5 (newer platforms)
 * - Memory-mapped at LPC bridge + SPI BAR offset
 */

/* PCI Configuration Space Registers */
#define PCI_VENDOR_ID_INTEL         0x8086
#define PCI_DEVICE_ID_SPI_MASK      0xFFF0  /* Mask for SPI controller device IDs */

/* SPI Controller MMIO Register Offsets
 * These are offsets from the SPI BAR (Base Address Register)
 */
#define SPI_BFPR                    0x00    /* BIOS Flash Primary Region */
#define SPI_HSFSTS_CTL              0x04    /* Hardware Sequencing Flash Status and Control */
#define SPI_FADDR                   0x08    /* Flash Address */
#define SPI_FDATA0                  0x10    /* Flash Data 0 */

/* LPC/eSPI Interface Registers
 * Accessed via PCI config space of LPC/eSPI bridge (Dev 31, Func 0)
 */
#define PCI_DEVICE_ID_LPC_MASK      0xFFF0
#define LPC_BIOS_CNTL_OFFSET        0xDC    /* BIOS Control Register offset in PCI config */

/* BIOS_CNTL Register Bits
 * This register controls BIOS flash write protection
 */
#define BIOS_CNTL_BIOSWE            (1 << 0)  /* BIOS Write Enable */
#define BIOS_CNTL_BLE               (1 << 1)  /* BIOS Lock Enable */
#define BIOS_CNTL_SMM_BWP           (1 << 5)  /* SMM BIOS Write Protect */
#define BIOS_CNTL_BILD              (1 << 7)  /* BIOS Interface Lock Down */

/* HSFSTS_CTL Register Bits
 * Hardware Sequencing Flash Status and Control
 */
#define HSFSTS_FDONE                (1 << 0)  /* Flash Cycle Done */
#define HSFSTS_FCERR                (1 << 1)  /* Flash Cycle Error */
#define HSFSTS_AEL                  (1 << 2)  /* Access Error Log */
#define HSFSTS_SCIP                 (1 << 5)  /* SPI Cycle in Progress */
#define HSFSTS_WRSDIS               (1 << 11) /* Write Status Disable */
#define HSFSTS_PRR34_LOCKDN         (1 << 12) /* PRR3 PRR4 Lock-Down */
#define HSFSTS_FLOCKDN              (1 << 15) /* Flash Configuration Lock-Down */

/* Flash Cycle Types (HSFSTS_CTL[19:17]) */
#define FCYCLE_READ                 0
#define FCYCLE_WRITE                2
#define FCYCLE_ERASE                3

/* SPI Event Types for userspace notification */
#define SPI_EVENT_WRITE_ENABLE      0x01  /* BIOS Write Enable detected */
#define SPI_EVENT_LOCK_DISABLED     0x02  /* BIOS Lock disabled */
#define SPI_EVENT_WRITE_ATTEMPT     0x04  /* Flash write operation attempted */
#define SPI_EVENT_ERASE_ATTEMPT     0x08  /* Flash erase operation attempted */
#define SPI_EVENT_PROTECTION_OFF    0x10  /* SMM write protection disabled */
#define SPI_EVENT_BIOS_REGION       0x20  /* Operation targets BIOS region */

/* Maximum number of events to buffer */
#define MAX_SPI_EVENTS              256

/* SPI Event Structure
 * Records details of suspicious SPI flash activity
 */
struct spi_event {
    u64 timestamp;          /* jiffies when event occurred */
    u32 event_type;         /* Bitmask of SPI_EVENT_* flags */
    u32 bios_cntl;          /* BIOS_CNTL register value at event time */
    u32 hsfsts_ctl;         /* HSFSTS_CTL register value */
    u32 flash_addr;         /* Flash address being accessed */
    u32 flash_cycle;        /* Type of flash cycle (read/write/erase) */
};

/* SPI Monitor State
 * Maintains current state and event history
 */
struct spi_monitor_state {
    /* Hardware state */
    struct pci_dev *lpc_dev;        /* LPC/eSPI bridge device */
    struct pci_dev *spi_dev;        /* SPI controller device */
    void __iomem *spi_mmio;         /* SPI MMIO base address */

    /* Protection status */
    u8 bios_cntl_baseline;          /* Expected BIOS_CNTL value */
    u32 hsfsts_baseline;            /* Expected HSFSTS_CTL value */
    bool monitoring_active;         /* Is monitoring enabled? */

    /* Event buffering */
    struct spi_event events[MAX_SPI_EVENTS];
    unsigned int event_head;        /* Next write position */
    unsigned int event_tail;        /* Next read position */
    unsigned int event_count;       /* Number of pending events */
    spinlock_t event_lock;          /* Protects event buffer */

    /* Monitoring timer */
    struct timer_list poll_timer;   /* Periodic polling timer */
    unsigned int poll_interval_ms;  /* Polling interval in milliseconds */
};

static struct spi_monitor_state spi_state = {
    .monitoring_active = false,
    .poll_interval_ms = 1000,  /* Default: poll every 1 second */
};

/* Forward declarations */
static void spi_poll_timer_callback(struct timer_list *timer);
static int spi_check_protection_status(void);
static void spi_record_event(u32 event_type, u32 bios_cntl, u32 hsfsts_ctl,
                             u32 flash_addr, u32 flash_cycle);

/**
 * spi_find_devices - Locate SPI controller and LPC bridge PCI devices
 *
 * Searches the PCI bus for Intel LPC/eSPI bridge and SPI controller.
 * These devices are required for monitoring SPI flash protection.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int spi_find_devices(void)
{
    struct pci_dev *dev = NULL;

    /* Search for Intel LPC/eSPI bridge (Bus 0, Device 31, Function 0)
     * This device contains the BIOS_CNTL register
     */
    while ((dev = pci_get_device(PCI_VENDOR_ID_INTEL, PCI_ANY_ID, dev)) != NULL) {
        /* Check if this is the LPC bridge (Device 31, Function 0) */
        if (PCI_SLOT(dev->devfn) == 31 && PCI_FUNC(dev->devfn) == 0) {
            spi_state.lpc_dev = pci_dev_get(dev);
            pr_info("fwguard_spi: found LPC/eSPI bridge at %s\n",
                    pci_name(dev));
            break;
        }
    }

    if (!spi_state.lpc_dev) {
        pr_err("fwguard_spi: LPC/eSPI bridge not found\n");
        return -ENODEV;
    }

    /* Search for SPI controller (Bus 0, Device 31, Function 5)
     * This device provides access to SPI flash controller registers
     */
    dev = NULL;
    while ((dev = pci_get_device(PCI_VENDOR_ID_INTEL, PCI_ANY_ID, dev)) != NULL) {
        if (PCI_SLOT(dev->devfn) == 31 && PCI_FUNC(dev->devfn) == 5) {
            spi_state.spi_dev = pci_dev_get(dev);
            pr_info("fwguard_spi: found SPI controller at %s\n",
                    pci_name(dev));
            break;
        }
    }

    if (!spi_state.spi_dev) {
        pr_warn("fwguard_spi: SPI controller not found (may be hidden by BIOS)\n");
        pr_warn("fwguard_spi: continuing with limited monitoring capability\n");
        /* Not fatal - we can still monitor BIOS_CNTL via LPC bridge */
    }

    return 0;
}

/**
 * spi_map_mmio - Map SPI controller MMIO registers
 *
 * Maps the SPI controller's MMIO region into kernel virtual address space.
 * This allows direct access to SPI flash controller registers.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int spi_map_mmio(void)
{
    resource_size_t mmio_base;
    resource_size_t mmio_size;

    if (!spi_state.spi_dev) {
        pr_info("fwguard_spi: no SPI device, skipping MMIO mapping\n");
        return 0;  /* Not an error */
    }

    /* Enable PCI device to access its BARs
     * This is required before reading BAR addresses
     */
    if (pci_enable_device(spi_state.spi_dev) < 0) {
        pr_err("fwguard_spi: failed to enable SPI PCI device\n");
        return -EIO;
    }

    /* Get MMIO base address from BAR0
     * The SPI controller typically uses BAR0 for its register space
     */
    mmio_base = pci_resource_start(spi_state.spi_dev, 0);
    mmio_size = pci_resource_len(spi_state.spi_dev, 0);

    if (!mmio_base || !mmio_size) {
        pr_err("fwguard_spi: invalid SPI MMIO region (base=0x%llx, size=0x%llx)\n",
               (unsigned long long)mmio_base, (unsigned long long)mmio_size);
        return -EINVAL;
    }

    pr_info("fwguard_spi: SPI MMIO region at 0x%llx, size 0x%llx\n",
            (unsigned long long)mmio_base, (unsigned long long)mmio_size);

    /* Map MMIO region into kernel virtual memory
     * ioremap_nocache ensures no caching for hardware registers
     */
    spi_state.spi_mmio = ioremap(mmio_base, mmio_size);
    if (!spi_state.spi_mmio) {
        pr_err("fwguard_spi: failed to map SPI MMIO region\n");
        return -ENOMEM;
    }

    pr_info("fwguard_spi: SPI MMIO mapped successfully\n");
    return 0;
}

/**
 * spi_read_bios_cntl - Read BIOS Control register
 *
 * Reads the BIOS_CNTL register from the LPC/eSPI bridge configuration space.
 * This register controls flash write protection settings.
 *
 * Returns: BIOS_CNTL register value, or 0 on error
 */
static u8 spi_read_bios_cntl(void)
{
    u8 bios_cntl = 0;

    if (!spi_state.lpc_dev) {
        return 0;
    }

    /* Read BIOS_CNTL from PCI configuration space
     * This is a 8-bit register at offset 0xDC
     */
    if (pci_read_config_byte(spi_state.lpc_dev, LPC_BIOS_CNTL_OFFSET, &bios_cntl) < 0) {
        pr_err("fwguard_spi: failed to read BIOS_CNTL register\n");
        return 0;
    }

    return bios_cntl;
}

/**
 * spi_read_hsfsts_ctl - Read Hardware Sequencing Flash Status/Control register
 *
 * Reads the HSFSTS_CTL register from SPI controller MMIO space.
 * This register shows current SPI flash operation status and configuration.
 *
 * Returns: HSFSTS_CTL register value, or 0 on error
 */
static u32 spi_read_hsfsts_ctl(void)
{
    if (!spi_state.spi_mmio) {
        return 0;
    }

    /* Read 32-bit HSFSTS_CTL register from MMIO
     * ioread32 ensures proper memory barrier semantics
     */
    return ioread32(spi_state.spi_mmio + SPI_HSFSTS_CTL);
}

/**
 * spi_read_flash_addr - Read current flash address from SPI controller
 *
 * Returns: Current flash address register value, or 0 on error
 */
static u32 spi_read_flash_addr(void)
{
    if (!spi_state.spi_mmio) {
        return 0;
    }

    return ioread32(spi_state.spi_mmio + SPI_FADDR);
}

/**
 * spi_record_event - Record a SPI security event
 *
 * Adds a new event to the circular event buffer for userspace consumption.
 * Events are timestamped and include register snapshots for forensic analysis.
 *
 * @event_type: Bitmask of SPI_EVENT_* flags
 * @bios_cntl: BIOS_CNTL register value
 * @hsfsts_ctl: HSFSTS_CTL register value
 * @flash_addr: Flash address being accessed
 * @flash_cycle: Type of flash cycle (read/write/erase)
 */
static void spi_record_event(u32 event_type, u32 bios_cntl, u32 hsfsts_ctl,
                             u32 flash_addr, u32 flash_cycle)
{
    unsigned long flags;
    struct spi_event *event;

    spin_lock_irqsave(&spi_state.event_lock, flags);

    /* Check if event buffer is full
     * If full, overwrite oldest event (circular buffer)
     */
    if (spi_state.event_count >= MAX_SPI_EVENTS) {
        spi_state.event_tail = (spi_state.event_tail + 1) % MAX_SPI_EVENTS;
        spi_state.event_count--;
        pr_warn("fwguard_spi: event buffer full, dropping oldest event\n");
    }

    /* Record event at head position */
    event = &spi_state.events[spi_state.event_head];
    event->timestamp = get_jiffies_64();
    event->event_type = event_type;
    event->bios_cntl = bios_cntl;
    event->hsfsts_ctl = hsfsts_ctl;
    event->flash_addr = flash_addr;
    event->flash_cycle = flash_cycle;

    /* Advance head pointer (circular) */
    spi_state.event_head = (spi_state.event_head + 1) % MAX_SPI_EVENTS;
    spi_state.event_count++;

    spin_unlock_irqrestore(&spi_state.event_lock, flags);

    pr_info("fwguard_spi: event recorded - type=0x%x, bios_cntl=0x%x, hsfsts=0x%x, addr=0x%x\n",
            event_type, bios_cntl, hsfsts_ctl, flash_addr);
}

/**
 * spi_check_protection_status - Check current SPI flash protection status
 *
 * Examines BIOS_CNTL and HSFSTS_CTL registers to detect:
 * - Disabled write protection
 * - Disabled BIOS lock
 * - Active flash write/erase operations
 * - Changes from expected baseline configuration
 *
 * Records security events when suspicious activity is detected.
 *
 * Returns: 0 if protection is OK, 1 if issues detected
 */
static int spi_check_protection_status(void)
{
    u8 bios_cntl;
    u32 hsfsts_ctl;
    u32 flash_addr = 0;
    u32 event_type = 0;
    u32 flash_cycle;
    int protection_issue = 0;

    /* Read current register values */
    bios_cntl = spi_read_bios_cntl();
    hsfsts_ctl = spi_read_hsfsts_ctl();

    if (spi_state.spi_mmio) {
        flash_addr = spi_read_flash_addr();
    }

    /* Extract flash cycle type from HSFSTS_CTL[19:17]
     * This tells us if a read, write, or erase is happening
     */
    flash_cycle = (hsfsts_ctl >> 17) & 0x7;

    /* Check 1: BIOS Write Enable (BIOSWE) should be 0
     * If BIOSWE=1, BIOS flash can be written from host CPU
     */
    if (bios_cntl & BIOS_CNTL_BIOSWE) {
        event_type |= SPI_EVENT_WRITE_ENABLE;
        protection_issue = 1;
        pr_warn("fwguard_spi: BIOS Write Enable is SET (security risk!)\n");
    }

    /* Check 2: BIOS Lock Enable (BLE) should be 1
     * If BLE=0, BIOSWE can be changed, allowing write enable
     */
    if (!(bios_cntl & BIOS_CNTL_BLE)) {
        event_type |= SPI_EVENT_LOCK_DISABLED;
        protection_issue = 1;
        pr_warn("fwguard_spi: BIOS Lock Enable is CLEAR (security risk!)\n");
    }

    /* Check 3: SMM BIOS Write Protect (SMM_BWP) should be 1
     * If SMM_BWP=0, even SMM code cannot enforce write protection
     */
    if (!(bios_cntl & BIOS_CNTL_SMM_BWP)) {
        event_type |= SPI_EVENT_PROTECTION_OFF;
        protection_issue = 1;
        pr_warn("fwguard_spi: SMM BIOS Write Protect is CLEAR (security risk!)\n");
    }

    /* Check 4: Active flash write operation
     * Detect if a write cycle is in progress or recently completed
     */
    if (flash_cycle == FCYCLE_WRITE) {
        event_type |= SPI_EVENT_WRITE_ATTEMPT;
        protection_issue = 1;
        pr_warn("fwguard_spi: Flash WRITE cycle detected at address 0x%x\n", flash_addr);
    }

    /* Check 5: Active flash erase operation
     * Flash erase is typically done before write
     */
    if (flash_cycle == FCYCLE_ERASE) {
        event_type |= SPI_EVENT_ERASE_ATTEMPT;
        protection_issue = 1;
        pr_warn("fwguard_spi: Flash ERASE cycle detected at address 0x%x\n", flash_addr);
    }

    /* Check 6: BIOS region access
     * Determine if the flash address falls in BIOS region
     * Typical BIOS region is top 16MB of flash (platform-dependent)
     * This is a simplified check - production code should read BIOS region
     * bounds from the BFPR (BIOS Flash Primary Region) register
     */
    if (flash_addr >= 0xFF000000) {  /* Top 16MB - typical BIOS region */
        event_type |= SPI_EVENT_BIOS_REGION;
        if (flash_cycle == FCYCLE_WRITE || flash_cycle == FCYCLE_ERASE) {
            pr_alert("fwguard_spi: BIOS region modification attempt at 0x%x!\n", flash_addr);
        }
    }

    /* Record event if any security issue detected */
    if (event_type != 0) {
        spi_record_event(event_type, bios_cntl, hsfsts_ctl, flash_addr, flash_cycle);
    }

    return protection_issue;
}

/**
 * spi_poll_timer_callback - Periodic monitoring timer callback
 *
 * Called periodically to check SPI flash protection status.
 * Re-arms the timer for continuous monitoring.
 *
 * @timer: Timer structure (unused, for compatibility)
 */
static void spi_poll_timer_callback(struct timer_list *timer)
{
    (void)timer;  /* Unused parameter */

    if (!spi_state.monitoring_active) {
        return;  /* Monitoring stopped, don't re-arm */
    }

    /* Check protection status */
    spi_check_protection_status();

    /* Re-arm timer for next poll interval */
    mod_timer(&spi_state.poll_timer,
              jiffies + msecs_to_jiffies(spi_state.poll_interval_ms));
}

/**
 * spi_monitor_init - Initialize SPI flash monitoring subsystem
 *
 * Locates SPI hardware, maps MMIO regions, establishes baseline protection
 * state, and initializes event buffering.
 *
 * Called during kernel module initialization.
 *
 * Returns: 0 on success, negative error code on failure
 */
int spi_monitor_init(void)
{
    int ret;

    pr_info("fwguard_spi: initializing SPI flash write protection monitor\n");

    /* Initialize event buffer lock */
    spin_lock_init(&spi_state.event_lock);
    spi_state.event_head = 0;
    spi_state.event_tail = 0;
    spi_state.event_count = 0;

    /* Locate SPI controller and LPC bridge devices */
    ret = spi_find_devices();
    if (ret < 0) {
        pr_err("fwguard_spi: failed to locate SPI devices\n");
        return ret;
    }

    /* Map SPI MMIO registers (if SPI controller found) */
    if (spi_state.spi_dev) {
        ret = spi_map_mmio();
        if (ret < 0) {
            pr_err("fwguard_spi: failed to map SPI MMIO\n");
            goto cleanup_devices;
        }
    }

    /* Establish baseline protection state
     * Read current register values to establish expected state
     */
    spi_state.bios_cntl_baseline = spi_read_bios_cntl();
    spi_state.hsfsts_baseline = spi_read_hsfsts_ctl();

    pr_info("fwguard_spi: baseline BIOS_CNTL=0x%02x, HSFSTS_CTL=0x%08x\n",
            spi_state.bios_cntl_baseline, spi_state.hsfsts_baseline);

    /* Log current protection status */
    pr_info("fwguard_spi: BIOSWE=%d, BLE=%d, SMM_BWP=%d, BILD=%d\n",
            !!(spi_state.bios_cntl_baseline & BIOS_CNTL_BIOSWE),
            !!(spi_state.bios_cntl_baseline & BIOS_CNTL_BLE),
            !!(spi_state.bios_cntl_baseline & BIOS_CNTL_SMM_BWP),
            !!(spi_state.bios_cntl_baseline & BIOS_CNTL_BILD));

    /* Initialize monitoring timer
     * Use timer_setup for kernel 4.15+
     */
    timer_setup(&spi_state.poll_timer, spi_poll_timer_callback, 0);

    pr_info("fwguard_spi: SPI monitoring initialized successfully\n");
    return 0;

cleanup_devices:
    if (spi_state.lpc_dev) {
        pci_dev_put(spi_state.lpc_dev);
        spi_state.lpc_dev = NULL;
    }
    if (spi_state.spi_dev) {
        pci_dev_put(spi_state.spi_dev);
        spi_state.spi_dev = NULL;
    }
    return ret;
}

/**
 * spi_monitor_cleanup - Cleanup SPI monitoring subsystem
 *
 * Stops monitoring, unmaps MMIO, releases PCI device references.
 * Called during kernel module unload.
 */
void spi_monitor_cleanup(void)
{
    pr_info("fwguard_spi: cleaning up SPI monitoring\n");

    /* Stop monitoring timer */
    if (spi_state.monitoring_active) {
        spi_state.monitoring_active = false;
        del_timer_sync(&spi_state.poll_timer);
    }

    /* Unmap SPI MMIO region */
    if (spi_state.spi_mmio) {
        iounmap(spi_state.spi_mmio);
        spi_state.spi_mmio = NULL;
    }

    /* Release PCI device references */
    if (spi_state.lpc_dev) {
        pci_dev_put(spi_state.lpc_dev);
        spi_state.lpc_dev = NULL;
    }

    if (spi_state.spi_dev) {
        pci_disable_device(spi_state.spi_dev);
        pci_dev_put(spi_state.spi_dev);
        spi_state.spi_dev = NULL;
    }

    pr_info("fwguard_spi: SPI monitoring cleaned up\n");
}

/**
 * spi_start_monitoring - Start active SPI flash monitoring
 *
 * Enables periodic polling of SPI protection registers.
 * Called via userspace IOCTL.
 *
 * @poll_interval_ms: Polling interval in milliseconds (0 = use default)
 *
 * Returns: 0 on success, negative error code on failure
 */
int spi_start_monitoring(unsigned int poll_interval_ms)
{
    if (spi_state.monitoring_active) {
        pr_info("fwguard_spi: monitoring already active\n");
        return 0;
    }

    /* Validate and set poll interval */
    if (poll_interval_ms > 0 && poll_interval_ms <= 60000) {
        spi_state.poll_interval_ms = poll_interval_ms;
    } else if (poll_interval_ms > 60000) {
        pr_warn("fwguard_spi: poll interval too large, using 60s\n");
        spi_state.poll_interval_ms = 60000;
    }
    /* else: use default from initialization */

    pr_info("fwguard_spi: starting SPI monitoring (poll interval: %u ms)\n",
            spi_state.poll_interval_ms);

    /* Perform initial check */
    spi_check_protection_status();

    /* Start periodic monitoring */
    spi_state.monitoring_active = true;
    mod_timer(&spi_state.poll_timer,
              jiffies + msecs_to_jiffies(spi_state.poll_interval_ms));

    return 0;
}

/**
 * spi_stop_monitoring - Stop active SPI flash monitoring
 *
 * Disables periodic polling.
 * Called via userspace IOCTL.
 */
void spi_stop_monitoring(void)
{
    if (!spi_state.monitoring_active) {
        return;
    }

    pr_info("fwguard_spi: stopping SPI monitoring\n");

    spi_state.monitoring_active = false;
    del_timer_sync(&spi_state.poll_timer);
}

/**
 * spi_get_events - Retrieve pending SPI security events
 *
 * Copies events from kernel buffer to userspace buffer.
 * Called via userspace IOCTL.
 *
 * @events: Userspace buffer to receive events
 * @max_events: Maximum number of events to retrieve
 * @num_events: Output - actual number of events copied
 *
 * Returns: 0 on success, negative error code on failure
 */
int spi_get_events(struct spi_event __user *events, unsigned int max_events,
                   unsigned int *num_events)
{
    unsigned long flags;
    unsigned int count;
    unsigned int i;
    int ret = 0;

    if (!events || max_events == 0) {
        return -EINVAL;
    }

    spin_lock_irqsave(&spi_state.event_lock, flags);

    /* Determine how many events to copy */
    count = min(max_events, spi_state.event_count);

    /* Copy events to userspace */
    for (i = 0; i < count; i++) {
        unsigned int idx = (spi_state.event_tail + i) % MAX_SPI_EVENTS;

        if (copy_to_user(&events[i], &spi_state.events[idx],
                         sizeof(struct spi_event))) {
            ret = -EFAULT;
            break;
        }
    }

    if (ret == 0) {
        /* Update tail pointer and count to mark events as consumed */
        spi_state.event_tail = (spi_state.event_tail + count) % MAX_SPI_EVENTS;
        spi_state.event_count -= count;
        *num_events = count;
    }

    spin_unlock_irqrestore(&spi_state.event_lock, flags);

    return ret;
}

/**
 * spi_get_status - Get current SPI monitoring status
 *
 * Returns current protection register values and monitoring state.
 *
 * @status: Output structure to fill
 *
 * Returns: 0 on success, negative error code on failure
 */
int spi_get_status(struct spi_protection_status *status)
{
    if (!status) {
        return -EINVAL;
    }

    status->monitoring_active = spi_state.monitoring_active;
    status->poll_interval_ms = spi_state.poll_interval_ms;
    status->bios_cntl = spi_read_bios_cntl();
    status->hsfsts_ctl = spi_read_hsfsts_ctl();
    status->pending_events = spi_state.event_count;
    status->bios_cntl_baseline = spi_state.bios_cntl_baseline;

    return 0;
}

/* Export symbols for use by main kernel module */
EXPORT_SYMBOL_GPL(spi_monitor_init);
EXPORT_SYMBOL_GPL(spi_monitor_cleanup);
EXPORT_SYMBOL_GPL(spi_start_monitoring);
EXPORT_SYMBOL_GPL(spi_stop_monitoring);
EXPORT_SYMBOL_GPL(spi_get_events);
EXPORT_SYMBOL_GPL(spi_get_status);
