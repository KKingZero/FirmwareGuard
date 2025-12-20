/* FirmwareGuard SPI Flash Write Protection Monitor
 * Userspace Header - Interface to kernel SPI monitoring module
 *
 * SECURITY: OFFLINE-ONLY operation - no network connectivity
 *
 * This module provides userspace access to the kernel's SPI flash write
 * protection monitoring subsystem. It enables detection of unauthorized
 * firmware modification attempts by monitoring SPI controller registers.
 *
 * Key Features:
 * - Monitor BIOS_CNTL register for flash write protection status
 * - Detect SPI controller write enable signals
 * - Alert on unexpected BIOS region modifications
 * - Track flash write/erase operations
 * - Provide forensic event logging
 *
 * Platform Support:
 * - Intel x86/x64 with PCH (Platform Controller Hub)
 * - Requires CAP_SYS_RAWIO capability
 * - AMD and ARM platforms require platform-specific adaptations
 */

#ifndef _SPI_MONITOR_H
#define _SPI_MONITOR_H

#include <stdint.h>
#include <stdbool.h>

/* SPI Event Types
 * Bitmask flags indicating types of SPI security events
 */
#define SPI_EVENT_WRITE_ENABLE      0x01  /* BIOS Write Enable detected */
#define SPI_EVENT_LOCK_DISABLED     0x02  /* BIOS Lock disabled */
#define SPI_EVENT_WRITE_ATTEMPT     0x04  /* Flash write operation attempted */
#define SPI_EVENT_ERASE_ATTEMPT     0x08  /* Flash erase operation attempted */
#define SPI_EVENT_PROTECTION_OFF    0x10  /* SMM write protection disabled */
#define SPI_EVENT_BIOS_REGION       0x20  /* Operation targets BIOS region */

/* BIOS_CNTL Register Bits
 * Control register for BIOS flash write protection
 */
#define BIOS_CNTL_BIOSWE            (1 << 0)  /* BIOS Write Enable */
#define BIOS_CNTL_BLE               (1 << 1)  /* BIOS Lock Enable */
#define BIOS_CNTL_SMM_BWP           (1 << 5)  /* SMM BIOS Write Protect */
#define BIOS_CNTL_BILD              (1 << 7)  /* BIOS Interface Lock Down */

/* Maximum events per retrieval */
#define MAX_SPI_EVENTS_PER_CALL     128

/**
 * struct spi_event - SPI security event record
 *
 * Contains details of a detected SPI flash security event.
 * Userspace receives these events via spi_get_events().
 *
 * @timestamp: Kernel jiffies when event occurred (convert with sysconf(_SC_CLK_TCK))
 * @event_type: Bitmask of SPI_EVENT_* flags
 * @bios_cntl: BIOS_CNTL register value at time of event
 * @hsfsts_ctl: HSFSTS_CTL register value
 * @flash_addr: Flash address being accessed
 * @flash_cycle: Type of flash cycle (0=read, 2=write, 3=erase)
 */
struct spi_event {
    uint64_t timestamp;       /* Kernel jiffies timestamp */
    uint32_t event_type;      /* Bitmask of SPI_EVENT_* flags */
    uint32_t bios_cntl;       /* BIOS_CNTL register snapshot */
    uint32_t hsfsts_ctl;      /* HSFSTS_CTL register snapshot */
    uint32_t flash_addr;      /* Flash address accessed */
    uint32_t flash_cycle;     /* Flash cycle type (0=read, 2=write, 3=erase) */
};

/**
 * struct spi_protection_status - Current SPI protection status
 *
 * Provides snapshot of current SPI flash protection state.
 * Retrieved via spi_check_protection().
 *
 * @monitoring_active: Is periodic monitoring enabled?
 * @poll_interval_ms: Current polling interval in milliseconds
 * @bios_cntl: Current BIOS_CNTL register value
 * @hsfsts_ctl: Current HSFSTS_CTL register value
 * @pending_events: Number of events in kernel buffer
 * @bios_cntl_baseline: Expected BIOS_CNTL value (baseline)
 */
struct spi_protection_status {
    bool monitoring_active;       /* Is monitoring enabled? */
    unsigned int poll_interval_ms; /* Polling interval */
    uint8_t bios_cntl;            /* Current BIOS_CNTL value */
    uint32_t hsfsts_ctl;          /* Current HSFSTS_CTL value */
    unsigned int pending_events;   /* Number of buffered events */
    uint8_t bios_cntl_baseline;   /* Baseline BIOS_CNTL value */
};

/**
 * struct spi_event_buffer - Buffer for retrieving multiple events
 *
 * Convenience structure for batch event retrieval.
 *
 * @events: Array of event structures
 * @count: Number of events in buffer (output)
 * @max_count: Maximum events buffer can hold (input)
 */
struct spi_event_buffer {
    struct spi_event events[MAX_SPI_EVENTS_PER_CALL];
    unsigned int count;       /* Number of events retrieved */
    unsigned int max_count;   /* Maximum capacity */
};

/**
 * spi_monitor_init - Initialize SPI monitoring subsystem
 *
 * Opens connection to kernel SPI monitoring module (/dev/fwguard).
 * Must be called before any other SPI monitoring functions.
 *
 * Requires:
 * - CAP_SYS_RAWIO capability (typically root)
 * - Kernel module fwguard_km loaded
 * - Intel platform with PCH
 *
 * Returns:
 *   0 on success
 *  -1 on error (check errno for details)
 *     ENOENT: /dev/fwguard not found (kernel module not loaded)
 *     EPERM: Insufficient privileges (need CAP_SYS_RAWIO)
 *     ENODEV: SPI hardware not found on this platform
 */
int spi_monitor_init(void);

/**
 * spi_monitor_cleanup - Cleanup SPI monitoring subsystem
 *
 * Closes connection to kernel module and releases resources.
 * Should be called before program exit.
 */
void spi_monitor_cleanup(void);

/**
 * spi_check_protection - Check current SPI flash protection status
 *
 * Queries the kernel module for current protection register values
 * and monitoring state. This is a point-in-time snapshot.
 *
 * @status: Output buffer to receive protection status
 *
 * Returns:
 *   0 on success
 *  -1 on error (check errno)
 *     EINVAL: Invalid status pointer
 *     EIO: Failed to communicate with kernel module
 *
 * Example:
 *   struct spi_protection_status status;
 *   if (spi_check_protection(&status) == 0) {
 *       printf("BIOS Write Enable: %s\n",
 *              (status.bios_cntl & BIOS_CNTL_BIOSWE) ? "YES" : "NO");
 *       printf("BIOS Lock Enable: %s\n",
 *              (status.bios_cntl & BIOS_CNTL_BLE) ? "YES" : "NO");
 *   }
 */
int spi_check_protection(struct spi_protection_status *status);

/**
 * spi_start_monitoring - Start periodic SPI protection monitoring
 *
 * Enables automatic periodic polling of SPI protection registers
 * in the kernel. Events will be buffered for retrieval via spi_get_events().
 *
 * @poll_interval_ms: Polling interval in milliseconds
 *                    Range: 100-60000 ms (0 = use kernel default)
 *
 * Returns:
 *   0 on success
 *  -1 on error (check errno)
 *     EINVAL: Invalid poll interval
 *     EALREADY: Monitoring already active
 *     EIO: Failed to start monitoring
 *
 * Notes:
 * - Lower intervals increase CPU usage but provide faster detection
 * - Recommended: 1000ms (1 second) for normal operation
 * - Monitoring continues until spi_stop_monitoring() or module unload
 * - Events are buffered (max 256), older events discarded if buffer full
 */
int spi_start_monitoring(unsigned int poll_interval_ms);

/**
 * spi_stop_monitoring - Stop periodic SPI protection monitoring
 *
 * Disables automatic polling. Events already in buffer remain
 * available for retrieval.
 *
 * Returns:
 *   0 on success
 *  -1 on error
 */
int spi_stop_monitoring(void);

/**
 * spi_get_events - Retrieve pending SPI security events
 *
 * Retrieves events from the kernel buffer. Events are removed from
 * the kernel buffer upon successful retrieval (consumed).
 *
 * @events: Array to receive events
 * @max_events: Maximum number of events to retrieve (size of array)
 * @num_events: Output - actual number of events retrieved
 *
 * Returns:
 *   0 on success (check *num_events for actual count)
 *  -1 on error (check errno)
 *     EINVAL: Invalid parameters
 *     EFAULT: Memory access error
 *     EIO: Failed to communicate with kernel
 *
 * Notes:
 * - Events are consumed upon retrieval (not repeatable)
 * - If more events exist than max_events, retrieve in batches
 * - Kernel buffer holds max 256 events, oldest discarded if full
 * - Returns 0 with num_events=0 if no events available
 *
 * Example:
 *   struct spi_event events[64];
 *   unsigned int count;
 *   if (spi_get_events(events, 64, &count) == 0) {
 *       for (int i = 0; i < count; i++) {
 *           if (events[i].event_type & SPI_EVENT_WRITE_ATTEMPT) {
 *               printf("Flash write at 0x%x\n", events[i].flash_addr);
 *           }
 *       }
 *   }
 */
int spi_get_events(struct spi_event *events, unsigned int max_events,
                   unsigned int *num_events);

/**
 * spi_event_type_string - Convert event type bitmask to human-readable string
 *
 * Converts SPI_EVENT_* bitmask to descriptive string for logging/display.
 *
 * @event_type: Bitmask of SPI_EVENT_* flags
 * @buffer: Output buffer for string
 * @buffer_size: Size of output buffer
 *
 * Returns: Number of characters written (excluding null terminator)
 *
 * Example output: "WRITE_ENABLE | LOCK_DISABLED | BIOS_REGION"
 */
int spi_event_type_string(uint32_t event_type, char *buffer, size_t buffer_size);

/**
 * spi_bios_cntl_string - Convert BIOS_CNTL register to human-readable string
 *
 * Decodes BIOS_CNTL register bits into descriptive string.
 *
 * @bios_cntl: BIOS_CNTL register value
 * @buffer: Output buffer for string
 * @buffer_size: Size of output buffer
 *
 * Returns: Number of characters written (excluding null terminator)
 *
 * Example output: "BIOSWE=0 BLE=1 SMM_BWP=1 BILD=1"
 */
int spi_bios_cntl_string(uint8_t bios_cntl, char *buffer, size_t buffer_size);

/**
 * spi_is_protection_secure - Check if current protection state is secure
 *
 * Analyzes protection status and returns security assessment.
 *
 * @status: Protection status from spi_check_protection()
 *
 * Returns:
 *   true if protection is properly configured (secure)
 *   false if protection issues detected (insecure)
 *
 * Secure configuration:
 * - BIOSWE = 0 (write disabled)
 * - BLE = 1 (lock enabled)
 * - SMM_BWP = 1 (SMM protection enabled)
 */
bool spi_is_protection_secure(const struct spi_protection_status *status);

/**
 * spi_get_protection_recommendation - Get security recommendation
 *
 * Analyzes protection status and provides human-readable security
 * recommendation or issue description.
 *
 * @status: Protection status from spi_check_protection()
 * @buffer: Output buffer for recommendation string
 * @buffer_size: Size of output buffer
 *
 * Returns: Number of characters written (excluding null terminator)
 *
 * Example outputs:
 * - "Flash write protection is properly configured."
 * - "WARNING: BIOS write is enabled! Flash can be modified."
 * - "CRITICAL: BIOS lock is disabled! Protection can be bypassed."
 */
int spi_get_protection_recommendation(const struct spi_protection_status *status,
                                      char *buffer, size_t buffer_size);

/**
 * spi_event_timestamp_to_time - Convert event timestamp to wall-clock time
 *
 * Converts kernel jiffies timestamp to approximate wall-clock time.
 *
 * @event_timestamp: Timestamp from spi_event structure
 * @boot_time: System boot time (from /proc/uptime or clock_gettime)
 *
 * Returns: Wall-clock time as time_t (seconds since epoch)
 *
 * Note: This is approximate due to jiffies resolution and clock drift
 */
uint64_t spi_event_timestamp_to_time(uint64_t event_timestamp, uint64_t boot_time);

#endif /* _SPI_MONITOR_H */
