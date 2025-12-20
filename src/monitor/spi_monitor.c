/* FirmwareGuard SPI Flash Write Protection Monitor
 * Userspace Implementation - Communicates with kernel SPI monitoring module
 *
 * SECURITY: OFFLINE-ONLY operation - no network connectivity
 *
 * This implementation provides userspace access to kernel-level SPI flash
 * write protection monitoring. It communicates with the kernel module via
 * IOCTL to retrieve protection status and security events.
 *
 * OPSEC Considerations:
 * - Minimal logging to avoid detection
 * - Direct hardware monitoring (no userspace polling overhead)
 * - Stealth operation mode available
 * - No external dependencies beyond kernel module
 */

#include "spi_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>

/* Kernel module device path */
#define FWGUARD_DEVICE_PATH "/dev/fwguard"

/* IOCTL command definitions
 * Must match kernel module definitions in fwguard_km.h
 */
#define FWGUARD_IOC_MAGIC              'F'
#define FWGUARD_IOC_SPI_GET_STATUS     _IOR(FWGUARD_IOC_MAGIC, 10, struct spi_protection_status)
#define FWGUARD_IOC_SPI_START_MONITOR  _IOW(FWGUARD_IOC_MAGIC, 11, unsigned int)
#define FWGUARD_IOC_SPI_STOP_MONITOR   _IO(FWGUARD_IOC_MAGIC, 12)
#define FWGUARD_IOC_SPI_GET_EVENTS     _IOWR(FWGUARD_IOC_MAGIC, 13, struct spi_event_ioctl)

/* Internal IOCTL structure for event retrieval
 * Wraps event array with count parameters
 */
struct spi_event_ioctl {
    struct spi_event *events;      /* Pointer to userspace event array */
    unsigned int max_events;       /* Maximum events to retrieve */
    unsigned int num_events;       /* Actual events retrieved (output) */
};

/* Module state */
static struct {
    int fd;                        /* File descriptor for /dev/fwguard */
    bool initialized;              /* Has spi_monitor_init() been called? */
} spi_ctx = {
    .fd = -1,
    .initialized = false,
};

/**
 * spi_monitor_init - Initialize SPI monitoring subsystem
 *
 * Opens connection to kernel SPI monitoring module.
 */
int spi_monitor_init(void)
{
    if (spi_ctx.initialized) {
        /* Already initialized */
        return 0;
    }

    /* Open kernel module device
     * O_RDWR: We need both read and write for IOCTL
     * O_CLOEXEC: Close on exec (security best practice)
     */
    spi_ctx.fd = open(FWGUARD_DEVICE_PATH, O_RDWR | O_CLOEXEC);
    if (spi_ctx.fd < 0) {
        /* Preserve errno for caller */
        int saved_errno = errno;

        /* Provide helpful error messages */
        if (errno == ENOENT) {
            fprintf(stderr, "spi_monitor: %s not found - is fwguard_km loaded?\n",
                    FWGUARD_DEVICE_PATH);
            fprintf(stderr, "spi_monitor: Run: sudo modprobe fwguard_km\n");
        } else if (errno == EACCES || errno == EPERM) {
            fprintf(stderr, "spi_monitor: permission denied - need CAP_SYS_RAWIO\n");
            fprintf(stderr, "spi_monitor: Run as root or with appropriate capabilities\n");
        } else {
            fprintf(stderr, "spi_monitor: failed to open %s: %s\n",
                    FWGUARD_DEVICE_PATH, strerror(errno));
        }

        errno = saved_errno;
        return -1;
    }

    spi_ctx.initialized = true;
    return 0;
}

/**
 * spi_monitor_cleanup - Cleanup SPI monitoring subsystem
 *
 * Closes connection to kernel module.
 */
void spi_monitor_cleanup(void)
{
    if (!spi_ctx.initialized) {
        return;
    }

    if (spi_ctx.fd >= 0) {
        close(spi_ctx.fd);
        spi_ctx.fd = -1;
    }

    spi_ctx.initialized = false;
}

/**
 * spi_check_protection - Check current SPI flash protection status
 *
 * Retrieves current protection register values from kernel module.
 */
int spi_check_protection(struct spi_protection_status *status)
{
    if (!status) {
        errno = EINVAL;
        return -1;
    }

    if (!spi_ctx.initialized) {
        fprintf(stderr, "spi_monitor: not initialized - call spi_monitor_init() first\n");
        errno = EINVAL;
        return -1;
    }

    /* Query kernel module for current status via IOCTL */
    if (ioctl(spi_ctx.fd, FWGUARD_IOC_SPI_GET_STATUS, status) < 0) {
        int saved_errno = errno;
        fprintf(stderr, "spi_monitor: failed to get protection status: %s\n",
                strerror(errno));
        errno = saved_errno;
        return -1;
    }

    return 0;
}

/**
 * spi_start_monitoring - Start periodic SPI protection monitoring
 *
 * Enables automatic periodic polling in the kernel.
 */
int spi_start_monitoring(unsigned int poll_interval_ms)
{
    if (!spi_ctx.initialized) {
        fprintf(stderr, "spi_monitor: not initialized - call spi_monitor_init() first\n");
        errno = EINVAL;
        return -1;
    }

    /* Validate poll interval */
    if (poll_interval_ms > 0 && (poll_interval_ms < 100 || poll_interval_ms > 60000)) {
        fprintf(stderr, "spi_monitor: invalid poll interval %u ms (range: 100-60000)\n",
                poll_interval_ms);
        errno = EINVAL;
        return -1;
    }

    /* Request kernel to start monitoring */
    if (ioctl(spi_ctx.fd, FWGUARD_IOC_SPI_START_MONITOR, &poll_interval_ms) < 0) {
        int saved_errno = errno;
        fprintf(stderr, "spi_monitor: failed to start monitoring: %s\n",
                strerror(errno));
        errno = saved_errno;
        return -1;
    }

    return 0;
}

/**
 * spi_stop_monitoring - Stop periodic SPI protection monitoring
 *
 * Disables automatic polling in the kernel.
 */
int spi_stop_monitoring(void)
{
    if (!spi_ctx.initialized) {
        fprintf(stderr, "spi_monitor: not initialized - call spi_monitor_init() first\n");
        errno = EINVAL;
        return -1;
    }

    /* Request kernel to stop monitoring */
    if (ioctl(spi_ctx.fd, FWGUARD_IOC_SPI_STOP_MONITOR, 0) < 0) {
        int saved_errno = errno;
        fprintf(stderr, "spi_monitor: failed to stop monitoring: %s\n",
                strerror(errno));
        errno = saved_errno;
        return -1;
    }

    return 0;
}

/**
 * spi_get_events - Retrieve pending SPI security events
 *
 * Fetches events from kernel buffer via IOCTL.
 */
int spi_get_events(struct spi_event *events, unsigned int max_events,
                   unsigned int *num_events)
{
    struct spi_event_ioctl event_ioctl;

    if (!events || max_events == 0 || !num_events) {
        errno = EINVAL;
        return -1;
    }

    if (!spi_ctx.initialized) {
        fprintf(stderr, "spi_monitor: not initialized - call spi_monitor_init() first\n");
        errno = EINVAL;
        return -1;
    }

    /* Prepare IOCTL structure */
    event_ioctl.events = events;
    event_ioctl.max_events = max_events;
    event_ioctl.num_events = 0;

    /* Retrieve events from kernel */
    if (ioctl(spi_ctx.fd, FWGUARD_IOC_SPI_GET_EVENTS, &event_ioctl) < 0) {
        int saved_errno = errno;
        fprintf(stderr, "spi_monitor: failed to get events: %s\n",
                strerror(errno));
        errno = saved_errno;
        return -1;
    }

    *num_events = event_ioctl.num_events;
    return 0;
}

/**
 * spi_event_type_string - Convert event type bitmask to string
 *
 * Generates human-readable description of event types.
 */
int spi_event_type_string(uint32_t event_type, char *buffer, size_t buffer_size)
{
    int written = 0;
    bool first = true;

    if (!buffer || buffer_size == 0) {
        return 0;
    }

    buffer[0] = '\0';

    /* Build string with active event type flags */
    if (event_type & SPI_EVENT_WRITE_ENABLE) {
        written += snprintf(buffer + written, buffer_size - written,
                           "%sWRITE_ENABLE", first ? "" : " | ");
        first = false;
    }

    if (event_type & SPI_EVENT_LOCK_DISABLED) {
        written += snprintf(buffer + written, buffer_size - written,
                           "%sLOCK_DISABLED", first ? "" : " | ");
        first = false;
    }

    if (event_type & SPI_EVENT_WRITE_ATTEMPT) {
        written += snprintf(buffer + written, buffer_size - written,
                           "%sWRITE_ATTEMPT", first ? "" : " | ");
        first = false;
    }

    if (event_type & SPI_EVENT_ERASE_ATTEMPT) {
        written += snprintf(buffer + written, buffer_size - written,
                           "%sERASE_ATTEMPT", first ? "" : " | ");
        first = false;
    }

    if (event_type & SPI_EVENT_PROTECTION_OFF) {
        written += snprintf(buffer + written, buffer_size - written,
                           "%sPROTECTION_OFF", first ? "" : " | ");
        first = false;
    }

    if (event_type & SPI_EVENT_BIOS_REGION) {
        written += snprintf(buffer + written, buffer_size - written,
                           "%sBIOS_REGION", first ? "" : " | ");
        first = false;
    }

    if (first) {
        /* No flags set */
        written = snprintf(buffer, buffer_size, "NONE");
    }

    return written;
}

/**
 * spi_bios_cntl_string - Convert BIOS_CNTL register to string
 *
 * Decodes BIOS_CNTL register bits into readable format.
 */
int spi_bios_cntl_string(uint8_t bios_cntl, char *buffer, size_t buffer_size)
{
    if (!buffer || buffer_size == 0) {
        return 0;
    }

    return snprintf(buffer, buffer_size,
                   "BIOSWE=%d BLE=%d SMM_BWP=%d BILD=%d",
                   !!(bios_cntl & BIOS_CNTL_BIOSWE),
                   !!(bios_cntl & BIOS_CNTL_BLE),
                   !!(bios_cntl & BIOS_CNTL_SMM_BWP),
                   !!(bios_cntl & BIOS_CNTL_BILD));
}

/**
 * spi_is_protection_secure - Check if protection configuration is secure
 *
 * Analyzes BIOS_CNTL register to determine if flash protection is properly
 * configured according to security best practices.
 *
 * Secure configuration requirements:
 * - BIOSWE = 0 (write disabled from host CPU)
 * - BLE = 1 (lock enabled - prevents changing BIOSWE)
 * - SMM_BWP = 1 (SMM write protection enabled)
 */
bool spi_is_protection_secure(const struct spi_protection_status *status)
{
    if (!status) {
        return false;
    }

    /* Check all security-critical bits */
    bool bioswe_disabled = !(status->bios_cntl & BIOS_CNTL_BIOSWE);
    bool ble_enabled = (status->bios_cntl & BIOS_CNTL_BLE);
    bool smm_bwp_enabled = (status->bios_cntl & BIOS_CNTL_SMM_BWP);

    /* All three conditions must be met for secure configuration */
    return bioswe_disabled && ble_enabled && smm_bwp_enabled;
}

/**
 * spi_get_protection_recommendation - Get security recommendation
 *
 * Provides human-readable security assessment and recommendations.
 */
int spi_get_protection_recommendation(const struct spi_protection_status *status,
                                      char *buffer, size_t buffer_size)
{
    if (!status || !buffer || buffer_size == 0) {
        return 0;
    }

    /* Check individual protection bits and provide specific recommendations */

    if (status->bios_cntl & BIOS_CNTL_BIOSWE) {
        /* CRITICAL: Write enable is active */
        return snprintf(buffer, buffer_size,
                       "CRITICAL: BIOS write is enabled! Flash can be modified by "
                       "software. This is a severe security risk. Expected configuration: "
                       "BIOSWE=0 (write disabled).");
    }

    if (!(status->bios_cntl & BIOS_CNTL_BLE)) {
        /* CRITICAL: Lock is disabled */
        return snprintf(buffer, buffer_size,
                       "CRITICAL: BIOS lock is disabled! BIOSWE can be changed to "
                       "enable flash writes. Protection can be bypassed. Expected "
                       "configuration: BLE=1 (lock enabled).");
    }

    if (!(status->bios_cntl & BIOS_CNTL_SMM_BWP)) {
        /* WARNING: SMM protection disabled */
        return snprintf(buffer, buffer_size,
                       "WARNING: SMM BIOS write protection is disabled. System "
                       "Management Mode code cannot enforce write protection. "
                       "Expected configuration: SMM_BWP=1 (SMM protection enabled).");
    }

    /* All protection bits properly configured */
    return snprintf(buffer, buffer_size,
                   "Flash write protection is properly configured. BIOSWE=0 (write "
                   "disabled), BLE=1 (lock enabled), SMM_BWP=1 (SMM protection enabled). "
                   "System is protected against unauthorized firmware modification.");
}

/**
 * spi_event_timestamp_to_time - Convert kernel jiffies to wall-clock time
 *
 * Converts kernel jiffies timestamp from event to approximate wall-clock time.
 *
 * This is approximate because:
 * 1. Jiffies resolution varies by kernel config (typically 1ms or 10ms)
 * 2. Clock drift between jiffies and wall clock
 * 3. System time adjustments (NTP, manual changes)
 *
 * For precise forensic timing, use the raw jiffies value and correlate
 * with other system logs.
 */
uint64_t spi_event_timestamp_to_time(uint64_t event_timestamp, uint64_t boot_time)
{
    /* Get system tick rate (jiffies per second)
     * Typically 100 (10ms ticks) or 1000 (1ms ticks)
     */
    long ticks_per_sec = sysconf(_SC_CLK_TCK);
    if (ticks_per_sec <= 0) {
        ticks_per_sec = 100;  /* Fallback to common value */
    }

    /* Convert jiffies to seconds since boot */
    uint64_t seconds_since_boot = event_timestamp / ticks_per_sec;

    /* Add to boot time to get wall-clock time */
    return boot_time + seconds_since_boot;
}
