#include "heci_monitor.h"
#include <sys/ioctl.h>
#include <sys/select.h>
#include <poll.h>
#include <signal.h>
#include <time.h>

/**
 * Intel ME/HECI Traffic Monitor Implementation
 *
 * This module provides userspace monitoring of Intel Management Engine (ME)
 * Host Embedded Controller Interface (HECI) traffic via the MEI kernel driver.
 *
 * ARCHITECTURE:
 * - Uses /dev/mei0 device file for ME communication
 * - Background thread polls for HECI messages
 * - Circular buffer stores request/response pairs
 * - Pattern matching engine detects suspicious activity
 * - Entirely offline - no network communication
 *
 * OPSEC CONSIDERATIONS:
 * - Minimal system footprint
 * - Local logging only (no remote telemetry)
 * - Privileged access required (root)
 * - Low overhead monitoring design
 */

/* MEI IOCTL definitions (from Linux kernel mei.h) */
#define IOCTL_MEI_CONNECT_CLIENT _IOWR('H', 0x01, struct mei_connect_client_data)

/* MEI UUID for MKHI interface */
static const uint8_t mei_mkhi_guid[16] = {
    0x8e, 0x6a, 0xa7, 0xf4, 0x57, 0x4b, 0x40, 0x82,
    0xa6, 0x99, 0xfc, 0xb0, 0x54, 0xef, 0x68, 0x13
};

/* MEI client connection structure */
struct mei_client_properties {
    uint8_t  protocol_version;
    uint8_t  max_number_of_connections;
    uint8_t  fixed_address;
    uint8_t  single_recv_buf;
    uint32_t max_msg_length;
};

struct mei_client {
    uint32_t max_msg_length;
    uint8_t  protocol_version;
};

struct mei_connect_client_data {
    union {
        uint8_t guid[16];
        struct mei_client_properties properties;
    } in_client_uuid;
    struct mei_client out_client_properties;
};

/* Global monitor state */
static heci_monitor_t g_monitor = {
    .mei_fd = -1,
    .monitoring = false,
    .initialized = false,
    .enable_pattern_detection = false
};

/* Forward declarations for internal functions */
static void* heci_monitor_thread(void *arg);
static int heci_read_message(heci_message_t *msg);
static void heci_process_message(heci_message_t *msg);
static void heci_detect_patterns(heci_traffic_entry_t *entry);
static void heci_add_alert(heci_pattern_t pattern, risk_level_t risk,
                           const char *description, heci_traffic_entry_t *entry);
static int64_t timespec_diff_us(const struct timespec *start, const struct timespec *end);

/**
 * Initialize the HECI monitor subsystem.
 */
int heci_init(void) {
    struct stat st;
    struct mei_connect_client_data connect_data;
    int ret;

    /* Check for root privileges */
    if (fg_require_root() != FG_SUCCESS) {
        return FG_NO_PERMISSION;
    }

    /* Check if already initialized */
    if (g_monitor.initialized) {
        FG_WARN("HECI monitor already initialized");
        return FG_SUCCESS;
    }

    /* Try primary MEI device path */
    if (stat(MEI_DEVICE_PATH_0, &st) == 0) {
        g_monitor.mei_fd = open(MEI_DEVICE_PATH_0, O_RDWR);
        if (g_monitor.mei_fd < 0) {
            FG_DEBUG("Failed to open %s: %s", MEI_DEVICE_PATH_0, strerror(errno));
        } else {
            FG_DEBUG("Opened MEI device: %s", MEI_DEVICE_PATH_0);
        }
    }

    /* Try alternative MEI device path */
    if (g_monitor.mei_fd < 0 && stat(MEI_DEVICE_PATH_1, &st) == 0) {
        g_monitor.mei_fd = open(MEI_DEVICE_PATH_1, O_RDWR);
        if (g_monitor.mei_fd < 0) {
            FG_DEBUG("Failed to open %s: %s", MEI_DEVICE_PATH_1, strerror(errno));
        } else {
            FG_DEBUG("Opened MEI device: %s", MEI_DEVICE_PATH_1);
        }
    }

    /* Check if we successfully opened a device */
    if (g_monitor.mei_fd < 0) {
        FG_LOG_ERROR("Failed to open MEI device - Intel ME may not be available");
        return FG_NOT_SUPPORTED;
    }

    /* Connect to MKHI client */
    memset(&connect_data, 0, sizeof(connect_data));
    memcpy(connect_data.in_client_uuid.guid, mei_mkhi_guid, 16);

    ret = ioctl(g_monitor.mei_fd, IOCTL_MEI_CONNECT_CLIENT, &connect_data);
    if (ret < 0) {
        FG_DEBUG("MKHI client connect failed: %s (ME may not support MKHI)", strerror(errno));
        /* Don't fail completely - we can still monitor even without MKHI connection */
    } else {
        FG_DEBUG("Connected to MKHI client (max_msg_len=%u)",
                 connect_data.out_client_properties.max_msg_length);
    }

    /* Initialize the log structure */
    memset(&g_monitor.log, 0, sizeof(heci_log_t));
    pthread_mutex_init(&g_monitor.log.lock, NULL);

    /* Initialize statistics */
    clock_gettime(CLOCK_MONOTONIC, &g_monitor.log.stats.start_time);

    g_monitor.initialized = true;
    FG_INFO("HECI monitor initialized successfully");

    return FG_SUCCESS;
}

/**
 * Start monitoring HECI/MEI traffic.
 */
int heci_start_monitor(bool enable_pattern_detection) {
    int ret;

    /* Ensure initialized */
    if (!g_monitor.initialized) {
        FG_LOG_ERROR("HECI monitor not initialized - call heci_init() first");
        return FG_ERROR;
    }

    /* Check if already monitoring */
    if (g_monitor.monitoring) {
        FG_WARN("HECI monitor already running");
        return FG_SUCCESS;
    }

    /* Set pattern detection flag */
    g_monitor.enable_pattern_detection = enable_pattern_detection;

    /* Set monitoring flag BEFORE thread creation to avoid race condition */
    g_monitor.monitoring = true;

    /* Create monitoring thread */
    ret = pthread_create(&g_monitor.monitor_thread, NULL, heci_monitor_thread, NULL);
    if (ret != 0) {
        g_monitor.monitoring = false;  /* Reset flag on failure */
        FG_LOG_ERROR("Failed to create monitoring thread: %s", strerror(ret));
        return FG_ERROR;
    }

    FG_INFO("HECI monitoring started (pattern_detection=%s)",
            enable_pattern_detection ? "enabled" : "disabled");

    return FG_SUCCESS;
}

/**
 * Stop monitoring HECI/MEI traffic.
 */
int heci_stop_monitor(void) {
    void *thread_ret;

    /* Check if monitoring is active */
    if (!g_monitor.monitoring) {
        FG_WARN("HECI monitor not running");
        return FG_SUCCESS;
    }

    /* Signal thread to stop */
    g_monitor.monitoring = false;

    /* Wait for thread to terminate */
    pthread_join(g_monitor.monitor_thread, &thread_ret);

    FG_INFO("HECI monitoring stopped");
    return FG_SUCCESS;
}

/**
 * Get a copy of the current HECI traffic log.
 */
int heci_get_log(heci_log_t *log) {
    if (!log) {
        return FG_ERROR;
    }

    if (!g_monitor.initialized) {
        FG_LOG_ERROR("HECI monitor not initialized");
        return FG_ERROR;
    }

    /* Lock and copy the entire log structure */
    pthread_mutex_lock(&g_monitor.log.lock);
    memcpy(log, &g_monitor.log, sizeof(heci_log_t));
    pthread_mutex_unlock(&g_monitor.log.lock);

    return FG_SUCCESS;
}

/**
 * Analyze HECI traffic for suspicious patterns.
 */
int heci_analyze_traffic(const heci_log_t *log, heci_alert_t *alerts,
                         size_t max_alerts, size_t *num_alerts) {
    size_t alert_idx = 0;
    size_t i;

    if (!log || !alerts || !num_alerts) {
        return FG_ERROR;
    }

    *num_alerts = 0;

    /* Return existing alerts from the log */
    size_t total_alerts = log->alert_count < HECI_ALERT_MAX_ENTRIES ?
                          log->alert_count : HECI_ALERT_MAX_ENTRIES;

    for (i = 0; i < total_alerts && alert_idx < max_alerts; i++) {
        /* Calculate circular buffer position */
        size_t pos = (log->alert_head + HECI_ALERT_MAX_ENTRIES - total_alerts + i) %
                     HECI_ALERT_MAX_ENTRIES;

        /* Copy alert (but clear the related_entry pointer for safety) */
        memcpy(&alerts[alert_idx], &log->alerts[pos], sizeof(heci_alert_t));
        alerts[alert_idx].related_entry = NULL;
        alert_idx++;
    }

    /* Additional analysis: Check for excessive traffic patterns */
    if (log->stats.total_messages > 1000) {
        /* Calculate message rate */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int64_t runtime_us = timespec_diff_us(&log->stats.start_time, &now);

        if (runtime_us > 0) {
            double msg_per_sec = (double)log->stats.total_messages / (runtime_us / 1000000.0);

            /* Flag if more than 100 messages per second sustained */
            if (msg_per_sec > 100.0 && alert_idx < max_alerts) {
                alerts[alert_idx].pattern = PATTERN_EXCESSIVE_TRAFFIC;
                alerts[alert_idx].risk = RISK_MEDIUM;
                snprintf(alerts[alert_idx].description, sizeof(alerts[alert_idx].description),
                        "Excessive ME traffic detected: %.1f msg/sec (threshold: 100)",
                        msg_per_sec);
                clock_gettime(CLOCK_MONOTONIC, &alerts[alert_idx].timestamp);
                alerts[alert_idx].related_entry = NULL;
                alert_idx++;
            }
        }
    }

    /* Check for high orphaned request rate (possible communication issues) */
    if (log->stats.requests > 0) {
        double orphan_rate = (double)log->stats.orphaned_requests / log->stats.requests;
        if (orphan_rate > 0.1 && alert_idx < max_alerts) {
            alerts[alert_idx].pattern = PATTERN_UNUSUAL_TIMING;
            alerts[alert_idx].risk = RISK_LOW;
            snprintf(alerts[alert_idx].description, sizeof(alerts[alert_idx].description),
                    "High orphaned request rate: %.1f%% (threshold: 10%%)",
                    orphan_rate * 100.0);
            clock_gettime(CLOCK_MONOTONIC, &alerts[alert_idx].timestamp);
            alerts[alert_idx].related_entry = NULL;
            alert_idx++;
        }
    }

    *num_alerts = alert_idx;
    return FG_SUCCESS;
}

/**
 * Cleanup the HECI monitor subsystem.
 */
void heci_cleanup(void) {
    /* Stop monitoring if active */
    if (g_monitor.monitoring) {
        heci_stop_monitor();
    }

    /* Close MEI device */
    if (g_monitor.mei_fd >= 0) {
        close(g_monitor.mei_fd);
        g_monitor.mei_fd = -1;
    }

    /* Destroy mutex */
    if (g_monitor.initialized) {
        pthread_mutex_destroy(&g_monitor.log.lock);
    }

    /* Clear state */
    memset(&g_monitor, 0, sizeof(heci_monitor_t));
    g_monitor.mei_fd = -1;

    FG_INFO("HECI monitor cleaned up");
}

/**
 * Check if MEI/HECI device is available.
 */
bool heci_is_supported(void) {
    struct stat st;

    /* Check for MEI device files */
    if (stat(MEI_DEVICE_PATH_0, &st) == 0) {
        return true;
    }

    if (stat(MEI_DEVICE_PATH_1, &st) == 0) {
        return true;
    }

    return false;
}

/**
 * Get human-readable MKHI group name.
 */
const char* heci_get_group_name(uint8_t group_id) {
    switch (group_id) {
        case MKHI_BUP_GROUP_ID:
            return "BUP (Bring-Up Platform)";
        case MKHI_PM_GROUP_ID:
            return "PM (Power Management)";
        case MKHI_FWCAPS_GROUP_ID:
            return "FWCAPS (Firmware Capabilities)";
        case MKHI_HMRFPO_GROUP_ID:
            return "HMRFPO (Flash Protection Override)";
        case MKHI_MCA_GROUP_ID:
            return "MCA (Memory Configuration)";
        case MKHI_GEN2_GROUP_ID:
            return "GEN2 (General 2)";
        case MKHI_GEN_GROUP_ID:
            return "GEN (General/Common)";
        default:
            return "UNKNOWN";
    }
}

/**
 * Get human-readable pattern name.
 */
const char* heci_get_pattern_name(heci_pattern_t pattern) {
    switch (pattern) {
        case PATTERN_NONE:
            return "None";
        case PATTERN_HMRFPO_ENABLE:
            return "Flash Protection Override Enable";
        case PATTERN_HMRFPO_LOCK:
            return "Flash Protection Lock";
        case PATTERN_UNCONFIGURE:
            return "ME Unconfigure (HAP/AltDisable)";
        case PATTERN_EXCESSIVE_TRAFFIC:
            return "Excessive Traffic Rate";
        case PATTERN_UNUSUAL_TIMING:
            return "Unusual Timing Pattern";
        case PATTERN_UNKNOWN_GROUP:
            return "Unknown MKHI Group";
        case PATTERN_FAILED_AUTH:
            return "Failed Authentication";
        case PATTERN_FIRMWARE_UPDATE:
            return "Firmware Update Activity";
        default:
            return "Unknown Pattern";
    }
}

/**
 * Export log to JSON file.
 */
int heci_export_log_json(const heci_log_t *log, const char *filepath) {
    FILE *fp;
    size_t i;

    if (!log || !filepath) {
        return FG_ERROR;
    }

    /* Open output file with restrictive permissions (OPSEC) */
    fp = fopen(filepath, "w");
    if (!fp) {
        FG_LOG_ERROR("Failed to open %s for writing: %s", filepath, strerror(errno));
        return FG_ERROR;
    }

    /* Set restrictive permissions (owner read/write only) */
    chmod(filepath, 0600);

    /* Write JSON header */
    fprintf(fp, "{\n");
    fprintf(fp, "  \"heci_monitor_log\": {\n");
    fprintf(fp, "    \"version\": \"1.0\",\n");
    fprintf(fp, "    \"generated_at\": %ld,\n", time(NULL));

    /* Write statistics */
    fprintf(fp, "    \"statistics\": {\n");
    fprintf(fp, "      \"total_messages\": %lu,\n", log->stats.total_messages);
    fprintf(fp, "      \"requests\": %lu,\n", log->stats.requests);
    fprintf(fp, "      \"responses\": %lu,\n", log->stats.responses);
    fprintf(fp, "      \"orphaned_requests\": %lu,\n", log->stats.orphaned_requests);
    fprintf(fp, "      \"orphaned_responses\": %lu,\n", log->stats.orphaned_responses);
    fprintf(fp, "      \"avg_latency_us\": %lu,\n", log->stats.avg_latency_us);
    fprintf(fp, "      \"max_latency_us\": %lu\n", log->stats.max_latency_us);
    fprintf(fp, "    },\n");

    /* Write message counts by group */
    fprintf(fp, "    \"messages_by_group\": {\n");
    bool first_group = true;
    for (i = 0; i < 256; i++) {
        if (log->stats.messages_per_group[i] > 0) {
            if (!first_group) fprintf(fp, ",\n");
            fprintf(fp, "      \"0x%02x\": %lu", (unsigned int)i,
                    log->stats.messages_per_group[i]);
            first_group = false;
        }
    }
    fprintf(fp, "\n    },\n");

    /* Write alerts */
    fprintf(fp, "    \"alerts\": [\n");
    size_t total_alerts = log->alert_count < HECI_ALERT_MAX_ENTRIES ?
                          log->alert_count : HECI_ALERT_MAX_ENTRIES;

    for (i = 0; i < total_alerts; i++) {
        size_t pos = (log->alert_head + HECI_ALERT_MAX_ENTRIES - total_alerts + i) %
                     HECI_ALERT_MAX_ENTRIES;
        const heci_alert_t *alert = &log->alerts[pos];

        fprintf(fp, "      {\n");
        fprintf(fp, "        \"pattern\": \"%s\",\n", heci_get_pattern_name(alert->pattern));
        fprintf(fp, "        \"risk_level\": %d,\n", alert->risk);
        fprintf(fp, "        \"description\": \"%s\",\n", alert->description);
        fprintf(fp, "        \"timestamp\": %ld\n", alert->timestamp.tv_sec);
        fprintf(fp, "      }%s\n", (i < total_alerts - 1) ? "," : "");
    }
    fprintf(fp, "    ]\n");

    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");

    fclose(fp);
    FG_INFO("Exported HECI log to %s", filepath);

    return FG_SUCCESS;
}

/**
 * Print traffic summary.
 */
void heci_print_summary(const heci_log_t *log) {
    size_t i;

    if (!log) {
        return;
    }

    printf("\n=== HECI Traffic Summary ===\n\n");

    /* Statistics */
    printf("Statistics:\n");
    printf("  Total Messages:     %lu\n", log->stats.total_messages);
    printf("  Requests:           %lu\n", log->stats.requests);
    printf("  Responses:          %lu\n", log->stats.responses);
    printf("  Orphaned Requests:  %lu\n", log->stats.orphaned_requests);
    printf("  Orphaned Responses: %lu\n", log->stats.orphaned_responses);
    printf("  Avg Latency:        %lu us\n", log->stats.avg_latency_us);
    printf("  Max Latency:        %lu us\n", log->stats.max_latency_us);

    /* Top message groups */
    printf("\nTop Message Groups:\n");
    for (i = 0; i < 256; i++) {
        if (log->stats.messages_per_group[i] > 0) {
            printf("  0x%02x (%s): %lu\n", (unsigned int)i,
                   heci_get_group_name((uint8_t)i),
                   log->stats.messages_per_group[i]);
        }
    }

    /* Alerts */
    printf("\nAlerts: %zu total\n", log->alert_count);
    size_t total_alerts = log->alert_count < HECI_ALERT_MAX_ENTRIES ?
                          log->alert_count : HECI_ALERT_MAX_ENTRIES;

    for (i = 0; i < total_alerts; i++) {
        size_t pos = (log->alert_head + HECI_ALERT_MAX_ENTRIES - total_alerts + i) %
                     HECI_ALERT_MAX_ENTRIES;
        const heci_alert_t *alert = &log->alerts[pos];

        printf("  [%s] %s: %s\n",
               alert->risk == RISK_CRITICAL ? "CRITICAL" :
               alert->risk == RISK_HIGH ? "HIGH" :
               alert->risk == RISK_MEDIUM ? "MEDIUM" :
               alert->risk == RISK_LOW ? "LOW" : "INFO",
               heci_get_pattern_name(alert->pattern),
               alert->description);
    }

    printf("\n");
}

/* ============================================================================
 * Internal Implementation Functions
 * ============================================================================ */

/**
 * Background monitoring thread.
 *
 * Continuously polls /dev/mei0 for HECI messages and processes them.
 */
static void* heci_monitor_thread(void *arg) {
    struct pollfd pfd;
    heci_message_t msg;
    int ret;

    (void)arg; /* Unused */

    FG_DEBUG("HECI monitoring thread started");

    pfd.fd = g_monitor.mei_fd;
    pfd.events = POLLIN;

    /* Main monitoring loop */
    while (g_monitor.monitoring) {
        /* Poll for data with 100ms timeout */
        ret = poll(&pfd, 1, 100);

        if (ret < 0) {
            if (errno == EINTR) {
                continue; /* Interrupted by signal, retry */
            }
            FG_LOG_ERROR("poll() failed: %s", strerror(errno));
            break;
        }

        if (ret == 0) {
            /* Timeout - no data available */
            continue;
        }

        /* Data available - read message */
        if (pfd.revents & POLLIN) {
            if (heci_read_message(&msg) == FG_SUCCESS) {
                heci_process_message(&msg);
            }
        }

        if (pfd.revents & (POLLERR | POLLHUP)) {
            FG_LOG_ERROR("MEI device error or hangup");
            break;
        }
    }

    FG_DEBUG("HECI monitoring thread stopped");
    return NULL;
}

/**
 * Read a HECI message from the MEI device.
 */
static int heci_read_message(heci_message_t *msg) {
    ssize_t bytes_read;

    if (!msg) {
        return FG_ERROR;
    }

    memset(msg, 0, sizeof(heci_message_t));

    /* Read MKHI header first */
    bytes_read = read(g_monitor.mei_fd, &msg->header, sizeof(mkhi_header_t));

    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return FG_ERROR; /* No data available */
        }
        FG_DEBUG("Failed to read MKHI header: %s", strerror(errno));
        return FG_ERROR;
    }

    if (bytes_read == 0) {
        return FG_ERROR; /* EOF */
    }

    if (bytes_read < sizeof(mkhi_header_t)) {
        FG_DEBUG("Short read on MKHI header: %zd bytes", bytes_read);
        return FG_ERROR;
    }

    /* Read remaining message data */
    bytes_read = read(g_monitor.mei_fd, msg->data, sizeof(msg->data));

    if (bytes_read < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            FG_DEBUG("Failed to read message data: %s", strerror(errno));
        }
        msg->data_len = 0;
    } else {
        msg->data_len = bytes_read;
    }

    /* Record timestamp */
    clock_gettime(CLOCK_MONOTONIC, &msg->timestamp);

    return FG_SUCCESS;
}

/**
 * Process a received HECI message.
 */
static void heci_process_message(heci_message_t *msg) {
    heci_traffic_entry_t *entry;
    size_t log_idx;

    if (!msg) {
        return;
    }

    pthread_mutex_lock(&g_monitor.log.lock);

    /* Update statistics */
    g_monitor.log.stats.total_messages++;
    g_monitor.log.stats.messages_per_group[msg->header.group_id]++;
    memcpy(&g_monitor.log.stats.last_activity, &msg->timestamp, sizeof(struct timespec));

    if (msg->header.is_response) {
        g_monitor.log.stats.responses++;
    } else {
        g_monitor.log.stats.requests++;
    }

    /* Add to circular log buffer */
    log_idx = g_monitor.log.head;
    entry = &g_monitor.log.entries[log_idx];

    /* Initialize new entry */
    memset(entry, 0, sizeof(heci_traffic_entry_t));

    if (msg->header.is_response) {
        /* This is a response - try to find matching request */
        memcpy(&entry->response, msg, sizeof(heci_message_t));
        entry->has_response = true;

        /* Simple matching: look back for recent request with same group/command */
        /* In production, would use sequence numbers or more sophisticated matching */
        entry->latency_us = 0; /* Calculate if we find matching request */

        g_monitor.log.stats.orphaned_responses++;
    } else {
        /* This is a request */
        memcpy(&entry->request, msg, sizeof(heci_message_t));
        entry->has_response = false;
    }

    /* Pattern detection */
    if (g_monitor.enable_pattern_detection) {
        heci_detect_patterns(entry);
    }

    /* Advance circular buffer */
    g_monitor.log.head = (g_monitor.log.head + 1) % HECI_LOG_MAX_ENTRIES;
    g_monitor.log.count++;

    pthread_mutex_unlock(&g_monitor.log.lock);
}

/**
 * Detect suspicious patterns in traffic.
 */
static void heci_detect_patterns(heci_traffic_entry_t *entry) {
    const mkhi_header_t *hdr;

    if (!entry) {
        return;
    }

    /* Check request header */
    hdr = &entry->request.header;

    /* Pattern: HMRFPO Enable (Flash Protection Override) */
    if (hdr->group_id == MKHI_HMRFPO_GROUP_ID &&
        hdr->command == MKHI_CMD_HMRFPO_ENABLE) {
        heci_add_alert(PATTERN_HMRFPO_ENABLE, RISK_CRITICAL,
                      "Flash protection override enable command detected",
                      entry);
    }

    /* Pattern: HMRFPO Lock */
    if (hdr->group_id == MKHI_HMRFPO_GROUP_ID &&
        hdr->command == MKHI_CMD_HMRFPO_LOCK) {
        heci_add_alert(PATTERN_HMRFPO_LOCK, RISK_HIGH,
                      "Flash protection lock command detected",
                      entry);
    }

    /* Pattern: ME Unconfigure (HAP/AltDisable) */
    if (hdr->group_id == MKHI_GEN_GROUP_ID &&
        hdr->command == MKHI_CMD_UNCONFIGURE) {
        heci_add_alert(PATTERN_UNCONFIGURE, RISK_HIGH,
                      "ME unconfigure command detected (HAP/AltDisable)",
                      entry);
    }

    /* Pattern: Unknown/undocumented group ID */
    const char *group_name = heci_get_group_name(hdr->group_id);
    if (strcmp(group_name, "UNKNOWN") == 0) {
        char desc[256];
        snprintf(desc, sizeof(desc),
                "Unknown MKHI group 0x%02x command 0x%02x",
                hdr->group_id, hdr->command);
        heci_add_alert(PATTERN_UNKNOWN_GROUP, RISK_LOW, desc, entry);
    }

    /* Pattern: Failed authentication (result code in response) */
    if (entry->has_response) {
        const mkhi_header_t *resp_hdr = &entry->response.header;
        /* Non-zero result typically indicates error/failure */
        if (resp_hdr->result != 0) {
            /* Some result codes indicate authentication failure */
            if (resp_hdr->result == 0x10 || resp_hdr->result == 0x11) {
                char desc[256];
                snprintf(desc, sizeof(desc),
                        "Authentication failure (group=0x%02x, cmd=0x%02x, result=0x%02x)",
                        hdr->group_id, hdr->command, resp_hdr->result);
                heci_add_alert(PATTERN_FAILED_AUTH, RISK_MEDIUM, desc, entry);
            }
        }
    }
}

/**
 * Add a suspicious activity alert.
 */
static void heci_add_alert(heci_pattern_t pattern, risk_level_t risk,
                           const char *description, heci_traffic_entry_t *entry) {
    heci_alert_t *alert;
    size_t alert_idx;

    /* Get next alert slot */
    alert_idx = g_monitor.log.alert_head;
    alert = &g_monitor.log.alerts[alert_idx];

    /* Fill alert */
    memset(alert, 0, sizeof(heci_alert_t));
    alert->pattern = pattern;
    alert->risk = risk;
    strncpy(alert->description, description, sizeof(alert->description) - 1);
    clock_gettime(CLOCK_MONOTONIC, &alert->timestamp);
    alert->related_entry = entry; /* Note: pointer only valid while in log */

    /* Advance circular buffer */
    g_monitor.log.alert_head = (g_monitor.log.alert_head + 1) % HECI_ALERT_MAX_ENTRIES;
    g_monitor.log.alert_count++;

    /* Log to console */
    FG_WARN("HECI Alert [%s]: %s",
            heci_get_pattern_name(pattern), description);
}

/**
 * Calculate time difference in microseconds.
 */
static int64_t timespec_diff_us(const struct timespec *start, const struct timespec *end) {
    int64_t sec_diff = end->tv_sec - start->tv_sec;
    int64_t nsec_diff = end->tv_nsec - start->tv_nsec;
    return (sec_diff * 1000000LL) + (nsec_diff / 1000LL);
}
