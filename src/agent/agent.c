#include "agent.h"
#include "../core/probe.h"
#include "../audit/reporter.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>

/* Global flag for graceful shutdown */
static volatile bool g_agent_shutdown = false;

/* Signal handler for graceful shutdown */
static void agent_signal_handler(int signum) {
    if (signum == SIGTERM || signum == SIGINT) {
        g_agent_shutdown = true;
        syslog(LOG_INFO, "fwguard-agent: Received shutdown signal");
    }
}

int agent_init(agent_state_t *state, agent_mode_t mode) {
    if (!state) {
        return FG_ERROR;
    }

    /* Zero out state */
    memset(state, 0, sizeof(agent_state_t));

    state->mode = mode;
    state->comm_state = COMM_STATE_OFFLINE;
    state->running = false;
    state->cached_reports = 0;

    /* Load configuration */
    if (agent_load_config(&state->config, AGENT_CONFIG_FILE) != FG_SUCCESS) {
        FG_WARN("Failed to load agent config, using defaults");

        /* Set default configuration */
        strncpy(state->config.server_url, "https://localhost",
                sizeof(state->config.server_url) - 1);
        state->config.server_port = 8443;
        state->config.use_tls = true;
        state->config.scan_interval_sec = 3600;  /* 1 hour */
        state->config.heartbeat_interval_sec = 300;  /* 5 minutes */
        state->config.offline_cache_enabled = true;
        state->config.max_cache_size_mb = 100;
    }

    /* Generate agent ID if not set */
    if (strlen(state->config.agent_id) == 0) {
        if (agent_generate_id(state->config.agent_id,
                             sizeof(state->config.agent_id)) != FG_SUCCESS) {
            FG_LOG_ERROR("Failed to generate agent ID");
            return FG_ERROR;
        }
    }

    /* Create cache directory if needed */
    if (state->config.offline_cache_enabled) {
        if (mkdir(AGENT_CACHE_DIR, 0700) != 0 && errno != EEXIST) {
            FG_WARN("Failed to create cache directory: %s", AGENT_CACHE_DIR);
        }
    }

    /* Install signal handlers for daemon mode */
    if (mode == AGENT_MODE_DAEMON) {
        signal(SIGTERM, agent_signal_handler);
        signal(SIGINT, agent_signal_handler);
        signal(SIGHUP, SIG_IGN);  /* Ignore HUP */
    }

    FG_INFO("FirmwareGuard Agent initialized (version %s)", AGENT_VERSION);
    FG_INFO("Agent ID: %s", state->config.agent_id);
    FG_INFO("Mode: %s",
            mode == AGENT_MODE_DAEMON ? "daemon" :
            mode == AGENT_MODE_ONESHOT ? "oneshot" : "dryrun");

    return FG_SUCCESS;
}

void agent_cleanup(agent_state_t *state) {
    if (!state) {
        return;
    }

    state->running = false;

    /* Remove PID file if we created it */
    if (state->mode == AGENT_MODE_DAEMON) {
        agent_remove_pidfile();
    }

    FG_INFO("FirmwareGuard Agent cleanup complete");
    closelog();
}

int agent_load_config(agent_config_t *config, const char *config_file) {
    FILE *fp;
    char line[512];
    char key[128], value[256];

    if (!config || !config_file) {
        return FG_ERROR;
    }

    fp = fopen(config_file, "r");
    if (!fp) {
        return FG_NOT_FOUND;
    }

    /* Simple key=value parser */
    while (fgets(line, sizeof(line), fp)) {
        /* Remove newline and comments */
        line[strcspn(line, "\n")] = 0;
        line[strcspn(line, "#")] = 0;

        /* Skip empty lines */
        if (line[0] == '\0') {
            continue;
        }

        /* Parse key=value */
        if (sscanf(line, "%127[^=]=%255s", key, value) == 2) {
            /* Trim whitespace from key */
            char *k = key;
            while (*k == ' ' || *k == '\t') k++;

            if (strcmp(k, "server_url") == 0) {
                strncpy(config->server_url, value, sizeof(config->server_url) - 1);
            } else if (strcmp(k, "agent_id") == 0) {
                strncpy(config->agent_id, value, sizeof(config->agent_id) - 1);
            } else if (strcmp(k, "auth_token") == 0) {
                strncpy(config->auth_token, value, sizeof(config->auth_token) - 1);
            } else if (strcmp(k, "server_port") == 0) {
                config->server_port = (uint16_t)atoi(value);
            } else if (strcmp(k, "use_tls") == 0) {
                config->use_tls = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
            } else if (strcmp(k, "scan_interval_sec") == 0) {
                config->scan_interval_sec = atoi(value);
            } else if (strcmp(k, "heartbeat_interval_sec") == 0) {
                config->heartbeat_interval_sec = atoi(value);
            } else if (strcmp(k, "offline_cache_enabled") == 0) {
                config->offline_cache_enabled = (strcmp(value, "true") == 0);
            } else if (strcmp(k, "max_cache_size_mb") == 0) {
                config->max_cache_size_mb = (size_t)atoi(value);
            } else if (strcmp(k, "ca_cert_path") == 0) {
                strncpy(config->ca_cert_path, value, sizeof(config->ca_cert_path) - 1);
            }
        }
    }

    fclose(fp);
    return FG_SUCCESS;
}

int agent_save_config(const agent_config_t *config, const char *config_file) {
    FILE *fp;

    if (!config || !config_file) {
        return FG_ERROR;
    }

    fp = fopen(config_file, "w");
    if (!fp) {
        FG_LOG_ERROR("Failed to save agent config: %s", strerror(errno));
        return FG_ERROR;
    }

    /* Write configuration in key=value format */
    fprintf(fp, "# FirmwareGuard Agent Configuration\n");
    fprintf(fp, "# Generated: %ld\n\n", (long)time(NULL));

    fprintf(fp, "server_url=%s\n", config->server_url);
    fprintf(fp, "agent_id=%s\n", config->agent_id);
    fprintf(fp, "server_port=%u\n", config->server_port);
    fprintf(fp, "use_tls=%s\n", config->use_tls ? "true" : "false");
    fprintf(fp, "scan_interval_sec=%d\n", config->scan_interval_sec);
    fprintf(fp, "heartbeat_interval_sec=%d\n", config->heartbeat_interval_sec);
    fprintf(fp, "offline_cache_enabled=%s\n",
            config->offline_cache_enabled ? "true" : "false");
    fprintf(fp, "max_cache_size_mb=%zu\n", config->max_cache_size_mb);

    if (strlen(config->ca_cert_path) > 0) {
        fprintf(fp, "ca_cert_path=%s\n", config->ca_cert_path);
    }

    /* Note: We don't save auth_token for security */
    fprintf(fp, "\n# Note: auth_token not saved (set manually)\n");

    fclose(fp);

    /* Set secure permissions */
    chmod(config_file, 0600);

    FG_INFO("Saved agent configuration to: %s", config_file);
    return FG_SUCCESS;
}

int agent_generate_id(char *agent_id, size_t size) {
    FILE *fp;
    char machine_id[64] = {0};
    char hostname[128] = {0};
    uint32_t hash = 0;

    if (!agent_id || size < 33) {  /* Need at least 32 chars + null */
        return FG_ERROR;
    }

    /* Try to read machine-id (systemd) */
    fp = fopen("/etc/machine-id", "r");
    if (!fp) {
        fp = fopen("/var/lib/dbus/machine-id", "r");
    }

    if (fp) {
        if (fgets(machine_id, sizeof(machine_id), fp)) {
            machine_id[strcspn(machine_id, "\n")] = 0;
        }
        fclose(fp);
    }

    /* Get hostname as additional entropy */
    gethostname(hostname, sizeof(hostname) - 1);

    /* Generate hash-based ID */
    const char *id_source = strlen(machine_id) > 0 ? machine_id : hostname;
    for (size_t i = 0; i < strlen(id_source); i++) {
        hash = (hash << 5) + hash + (uint8_t)id_source[i];
    }

    /* Format as hex string */
    snprintf(agent_id, size, "fwg-%08x-%04x", hash, (uint16_t)(time(NULL) & 0xFFFF));

    return FG_SUCCESS;
}

int agent_run_scan(agent_state_t *state) {
    probe_result_t probe;
    audit_result_t audit;
    char report_json[8192];
    FILE *json_stream;
    int ret;

    if (!state) {
        return FG_ERROR;
    }

    FG_INFO("Starting firmware scan...");

    /* Initialize probe subsystem */
    probe_init();
    reporter_init();

    /* Perform hardware scan */
    ret = probe_scan_hardware(&probe);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Hardware scan failed");
        probe_cleanup();
        reporter_cleanup();
        return ret;
    }

    /* Convert to audit format */
    ret = probe_to_audit(&probe, &audit);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to convert probe results");
        probe_cleanup();
        reporter_cleanup();
        return ret;
    }

    /* Generate JSON report to memory */
    json_stream = fmemopen(report_json, sizeof(report_json), "w");
    if (json_stream) {
        reporter_generate_audit_report(&audit, REPORT_FORMAT_JSON, json_stream);
        fclose(json_stream);

        /* Null-terminate */
        report_json[sizeof(report_json) - 1] = '\0';

        /* Try to transmit to server */
        if (state->comm_state == COMM_STATE_ONLINE) {
            ret = agent_transmit_report(state, report_json);
            if (ret != FG_SUCCESS && state->config.offline_cache_enabled) {
                FG_WARN("Transmission failed, caching report");
                agent_cache_report(state, report_json);
            }
        } else if (state->config.offline_cache_enabled) {
            /* Offline mode - cache the report */
            agent_cache_report(state, report_json);
        }
    }

    state->last_scan_time = time(NULL);

    probe_cleanup();
    reporter_cleanup();

    FG_INFO("Firmware scan complete");
    return FG_SUCCESS;
}

int agent_run_daemon(agent_state_t *state) {
    time_t now;
    int scan_due, heartbeat_due;

    if (!state) {
        return FG_ERROR;
    }

    /* Daemonize */
    if (agent_daemonize() != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to daemonize");
        return FG_ERROR;
    }

    /* Write PID file */
    state->daemon_pid = getpid();
    agent_write_pidfile(state->daemon_pid);

    /* Open syslog */
    openlog("fwguard-agent", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "FirmwareGuard Agent daemon started (PID: %d)", state->daemon_pid);

    state->running = true;

    /* Main daemon loop */
    while (state->running && !g_agent_shutdown) {
        now = time(NULL);

        /* Check if scan is due */
        scan_due = (now - state->last_scan_time) >= state->config.scan_interval_sec;

        /* Check if heartbeat is due */
        heartbeat_due = (now - state->last_heartbeat_time) >=
                        state->config.heartbeat_interval_sec;

        /* Perform scan if due */
        if (scan_due || state->last_scan_time == 0) {
            syslog(LOG_INFO, "Performing scheduled scan");
            agent_run_scan(state);
        }

        /* Send heartbeat if due */
        if (heartbeat_due || state->last_heartbeat_time == 0) {
            agent_send_heartbeat(state);
        }

        /* Try to flush cached reports if online */
        if (state->comm_state == COMM_STATE_ONLINE && state->cached_reports > 0) {
            agent_flush_cache(state);
        }

        /* Sleep for a short interval */
        sleep(60);  /* Check every minute */
    }

    syslog(LOG_INFO, "FirmwareGuard Agent daemon shutting down");
    return FG_SUCCESS;
}

int agent_send_heartbeat(agent_state_t *state) {
    /* PLACEHOLDER: Implementation requires HTTP/HTTPS library
     * In production, this would use libcurl or custom HTTP client
     * to send a lightweight heartbeat message to the server
     */

    if (!state) {
        return FG_ERROR;
    }

    FG_DEBUG("Sending heartbeat to server: %s:%u",
             state->config.server_url, state->config.server_port);

    /* TODO: Actual HTTP request to server
     * POST /api/v1/agent/heartbeat
     * Headers: Authorization: Bearer <auth_token>
     * Body: {"agent_id": "...", "timestamp": ..., "status": "online"}
     */

    state->last_heartbeat_time = time(NULL);

    /* For now, assume offline */
    state->comm_state = COMM_STATE_OFFLINE;

    return FG_SUCCESS;
}

int agent_transmit_report(agent_state_t *state, const char *report_json) {
    /* PLACEHOLDER: Implementation requires HTTP/HTTPS library
     * In production, this would POST the JSON report to the server
     */

    if (!state || !report_json) {
        return FG_ERROR;
    }

    FG_DEBUG("Transmitting audit report to server");

    /* TODO: Actual HTTP POST to server
     * POST /api/v1/agent/report
     * Headers: Authorization: Bearer <auth_token>
     * Body: <report_json>
     */

    /* For MVP, we just cache it */
    return FG_NOT_SUPPORTED;
}

int agent_cache_report(agent_state_t *state, const char *report_json) {
    FILE *fp;
    char cache_file[512];
    time_t now;

    if (!state || !report_json) {
        return FG_ERROR;
    }

    if (!state->config.offline_cache_enabled) {
        return FG_NOT_SUPPORTED;
    }

    now = time(NULL);
    snprintf(cache_file, sizeof(cache_file),
             "%s/report_%ld.json", AGENT_CACHE_DIR, (long)now);

    fp = fopen(cache_file, "w");
    if (!fp) {
        FG_LOG_ERROR("Failed to cache report: %s", strerror(errno));
        return FG_ERROR;
    }

    fprintf(fp, "%s", report_json);
    fclose(fp);

    state->cached_reports++;

    FG_INFO("Cached audit report: %s", cache_file);
    return FG_SUCCESS;
}

int agent_flush_cache(agent_state_t *state) {
    /* PLACEHOLDER: Transmit all cached reports to server */

    if (!state) {
        return FG_ERROR;
    }

    FG_DEBUG("Flushing %d cached reports", state->cached_reports);

    /* TODO: Iterate through cache directory and transmit each report */

    return FG_NOT_SUPPORTED;
}

int agent_check_connection(agent_state_t *state) {
    /* PLACEHOLDER: Check connectivity to management server */

    if (!state) {
        return FG_ERROR;
    }

    /* TODO: Simple HTTP GET to /api/v1/health or similar */

    state->comm_state = COMM_STATE_OFFLINE;
    return FG_ERROR;
}

int agent_daemonize(void) {
    pid_t pid, sid;

    /* Fork parent process */
    pid = fork();
    if (pid < 0) {
        return FG_ERROR;
    }

    /* Exit parent process */
    if (pid > 0) {
        exit(0);
    }

    /* Create new session */
    sid = setsid();
    if (sid < 0) {
        return FG_ERROR;
    }

    /* Change working directory to root */
    if (chdir("/") < 0) {
        return FG_ERROR;
    }

    /* Close standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* Redirect standard file descriptors to /dev/null */
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        close(null_fd);
    }

    return FG_SUCCESS;
}

int agent_write_pidfile(pid_t pid) {
    FILE *fp;

    fp = fopen(AGENT_PID_FILE, "w");
    if (!fp) {
        return FG_ERROR;
    }

    fprintf(fp, "%d\n", (int)pid);
    fclose(fp);

    return FG_SUCCESS;
}

int agent_remove_pidfile(void) {
    if (unlink(AGENT_PID_FILE) != 0 && errno != ENOENT) {
        return FG_ERROR;
    }
    return FG_SUCCESS;
}
