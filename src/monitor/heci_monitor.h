#ifndef FG_HECI_MONITOR_H
#define FG_HECI_MONITOR_H

#include "../../include/firmwareguard.h"
#include <pthread.h>
#include <time.h>

/**
 * HECI (Host Embedded Controller Interface) Monitor
 *
 * This module monitors Intel ME/HECI traffic via the MEI driver (/dev/mei0).
 * It captures and analyzes MKHI (ME Kernel Host Interface) messages to detect
 * suspicious ME activity patterns.
 *
 * SECURITY NOTE: This is OFFLINE-ONLY monitoring - no network connectivity.
 * All logging is local and designed for minimal system footprint (OPSEC).
 */

/* MEI device paths to try */
#define MEI_DEVICE_PATH_0       "/dev/mei0"
#define MEI_DEVICE_PATH_1       "/dev/mei"
#define MEI_MAX_MSG_SIZE        4096

/* MKHI (ME Kernel Host Interface) Group IDs */
#define MKHI_GEN_GROUP_ID       0xFF  /* General/Common commands */
#define MKHI_FWCAPS_GROUP_ID    0x03  /* Firmware Capabilities */
#define MKHI_HMRFPO_GROUP_ID    0x05  /* Host ME Region Flash Protection Override */
#define MKHI_MCA_GROUP_ID       0x0A  /* Memory Configuration & Allocation */
#define MKHI_PM_GROUP_ID        0x02  /* Power Management */
#define MKHI_BUP_GROUP_ID       0x00  /* Bring-Up Platform */
#define MKHI_GEN2_GROUP_ID      0xF1  /* General 2 */

/* MKHI Common Commands */
#define MKHI_CMD_GET_FW_VERSION     0x02
#define MKHI_CMD_GET_FW_CAPS        0x02
#define MKHI_CMD_HMRFPO_ENABLE      0x01
#define MKHI_CMD_HMRFPO_LOCK        0x02
#define MKHI_CMD_END_OF_POST        0x0C
#define MKHI_CMD_UNCONFIGURE        0x0D

/* MKHI Message Header (8 bytes) */
typedef struct __attribute__((packed)) {
    uint8_t  group_id;      /* MKHI group identifier */
    uint8_t  command;       /* Command within the group */
    uint8_t  is_response;   /* 0 = request, 1 = response */
    uint8_t  reserved;      /* Reserved, should be 0 */
    uint8_t  result;        /* Command result (for responses) */
    uint8_t  reserved2[3];  /* Additional reserved bytes */
} mkhi_header_t;

/* Full HECI message structure */
typedef struct {
    mkhi_header_t header;               /* MKHI header */
    uint8_t data[MEI_MAX_MSG_SIZE];     /* Message payload */
    size_t data_len;                     /* Actual payload length */
    struct timespec timestamp;           /* Message timestamp */
} heci_message_t;

/* HECI traffic log entry */
typedef struct {
    heci_message_t request;              /* Original request */
    heci_message_t response;             /* Corresponding response */
    bool has_response;                   /* True if response was captured */
    uint64_t latency_us;                 /* Request-response latency in microseconds */
} heci_traffic_entry_t;

/* Suspicious activity patterns */
typedef enum {
    PATTERN_NONE = 0,
    PATTERN_HMRFPO_ENABLE,              /* Flash protection override enabled */
    PATTERN_HMRFPO_LOCK,                /* Flash protection lock */
    PATTERN_UNCONFIGURE,                /* ME unconfigure command (HAP/AltDisable) */
    PATTERN_EXCESSIVE_TRAFFIC,          /* Abnormally high message rate */
    PATTERN_UNUSUAL_TIMING,             /* Unusual request timing patterns */
    PATTERN_UNKNOWN_GROUP,              /* Unknown/undocumented MKHI group */
    PATTERN_FAILED_AUTH,                /* Failed authentication attempts */
    PATTERN_FIRMWARE_UPDATE,            /* Firmware update activity */
    PATTERN_MAX
} heci_pattern_t;

/* Suspicious activity alert */
typedef struct {
    heci_pattern_t pattern;             /* Type of suspicious pattern */
    risk_level_t risk;                  /* Risk level assessment */
    char description[256];              /* Human-readable description */
    struct timespec timestamp;          /* When pattern was detected */
    heci_traffic_entry_t *related_entry; /* Related traffic entry (if any) */
} heci_alert_t;

/* HECI traffic statistics */
typedef struct {
    uint64_t total_messages;            /* Total messages captured */
    uint64_t requests;                  /* Total requests sent */
    uint64_t responses;                 /* Total responses received */
    uint64_t orphaned_requests;         /* Requests without responses */
    uint64_t orphaned_responses;        /* Responses without requests */
    uint64_t avg_latency_us;            /* Average request-response latency */
    uint64_t max_latency_us;            /* Maximum latency observed */
    uint64_t messages_per_group[256];   /* Message count by group ID */
    struct timespec start_time;         /* Monitoring start time */
    struct timespec last_activity;      /* Last message timestamp */
} heci_stats_t;

/* HECI monitor log (circular buffer) */
#define HECI_LOG_MAX_ENTRIES    1024
#define HECI_ALERT_MAX_ENTRIES  256

typedef struct {
    heci_traffic_entry_t entries[HECI_LOG_MAX_ENTRIES];
    size_t count;                       /* Total entries (may exceed max) */
    size_t head;                        /* Current write position (circular) */

    heci_alert_t alerts[HECI_ALERT_MAX_ENTRIES];
    size_t alert_count;                 /* Total alerts */
    size_t alert_head;                  /* Current alert position (circular) */

    heci_stats_t stats;                 /* Traffic statistics */

    pthread_mutex_t lock;               /* Thread safety lock */
} heci_log_t;

/* HECI monitor state */
typedef struct {
    int mei_fd;                         /* MEI device file descriptor */
    bool monitoring;                    /* True if monitoring is active */
    bool initialized;                   /* True if initialized */
    pthread_t monitor_thread;           /* Background monitoring thread */
    heci_log_t log;                     /* Traffic log */
    bool enable_pattern_detection;      /* Enable suspicious pattern detection */
} heci_monitor_t;

/**
 * Initialize the HECI monitor subsystem.
 *
 * This function opens the MEI device, validates ME is accessible,
 * and prepares the monitoring infrastructure.
 *
 * @return FG_SUCCESS on success, error code on failure
 */
int heci_init(void);

/**
 * Start monitoring HECI/MEI traffic.
 *
 * Launches a background thread that captures all HECI messages via /dev/mei0.
 * Messages are logged to a circular buffer for analysis.
 *
 * @param enable_pattern_detection If true, analyze traffic for suspicious patterns
 * @return FG_SUCCESS on success, error code on failure
 */
int heci_start_monitor(bool enable_pattern_detection);

/**
 * Stop monitoring HECI/MEI traffic.
 *
 * Gracefully stops the monitoring thread and flushes any pending logs.
 * The log data is preserved until heci_cleanup() is called.
 *
 * @return FG_SUCCESS on success, error code on failure
 */
int heci_stop_monitor(void);

/**
 * Get a copy of the current HECI traffic log.
 *
 * Retrieves all logged HECI message pairs (request/response) captured
 * since monitoring started. The log is copied to caller-provided buffer.
 *
 * @param log Pointer to caller-allocated heci_log_t structure
 * @return FG_SUCCESS on success, error code on failure
 */
int heci_get_log(heci_log_t *log);

/**
 * Analyze HECI traffic for suspicious patterns.
 *
 * Performs deep analysis of captured traffic to identify potential
 * security concerns, including:
 * - Flash protection override attempts (HMRFPO)
 * - ME unconfigure/disable commands
 * - Unusual traffic patterns or timing
 * - Firmware update activity
 * - Unknown/undocumented command groups
 *
 * @param log The traffic log to analyze (from heci_get_log)
 * @param alerts Output buffer for detected alerts
 * @param max_alerts Maximum number of alerts to return
 * @param num_alerts Pointer to store actual number of alerts found
 * @return FG_SUCCESS on success, error code on failure
 */
int heci_analyze_traffic(const heci_log_t *log, heci_alert_t *alerts,
                         size_t max_alerts, size_t *num_alerts);

/**
 * Cleanup the HECI monitor subsystem.
 *
 * Stops monitoring (if active), closes device handles, frees resources,
 * and clears all logged data.
 */
void heci_cleanup(void);

/**
 * Check if MEI/HECI device is available on this system.
 *
 * @return true if /dev/mei0 or /dev/mei exists and is accessible
 */
bool heci_is_supported(void);

/**
 * Get human-readable description of MKHI group ID.
 *
 * @param group_id MKHI group identifier
 * @return String description of the group
 */
const char* heci_get_group_name(uint8_t group_id);

/**
 * Get human-readable description of suspicious pattern type.
 *
 * @param pattern Pattern type
 * @return String description of the pattern
 */
const char* heci_get_pattern_name(heci_pattern_t pattern);

/**
 * Export HECI traffic log to JSON file (for offline analysis).
 *
 * Exports the complete traffic log including statistics and alerts
 * to a JSON file for later forensic analysis or reporting.
 *
 * OPSEC NOTE: This creates a local file only. Ensure file permissions
 * are appropriate and file is stored on encrypted media.
 *
 * @param log The log to export
 * @param filepath Path to output JSON file
 * @return FG_SUCCESS on success, error code on failure
 */
int heci_export_log_json(const heci_log_t *log, const char *filepath);

/**
 * Print HECI traffic summary to stdout.
 *
 * Displays a human-readable summary of captured traffic including
 * statistics, most common commands, and any detected alerts.
 *
 * @param log The log to summarize
 */
void heci_print_summary(const heci_log_t *log);

#endif /* FG_HECI_MONITOR_H */
