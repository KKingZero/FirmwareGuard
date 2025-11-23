#ifndef FG_AGENT_H
#define FG_AGENT_H

#include "../../include/firmwareguard.h"
#include <time.h>
#include <stdbool.h>

/* PHASE 3: Enterprise & Fleet Management Agent
 *
 * This is the lightweight agent component for FirmwareGuard that:
 * - Runs on managed endpoints
 * - Performs scheduled scans
 * - Reports to central management server
 * - Applies policies from central server
 * - Caches audit data offline
 *
 * Target size: < 10MB
 * Target overhead: < 1% CPU, < 50MB RAM
 */

#define AGENT_VERSION "0.3.0-alpha"
#define AGENT_CONFIG_FILE "/etc/firmwareguard/agent.conf"
#define AGENT_CACHE_DIR "/var/lib/firmwareguard/cache"
#define AGENT_PID_FILE "/var/run/firmwareguard-agent.pid"

/* Agent operational modes */
typedef enum {
    AGENT_MODE_DAEMON,      /* Run as background daemon */
    AGENT_MODE_ONESHOT,     /* Run once and exit */
    AGENT_MODE_DRYRUN       /* Test mode - no actual operations */
} agent_mode_t;

/* Agent communication state */
typedef enum {
    COMM_STATE_OFFLINE,     /* No connection to server */
    COMM_STATE_CONNECTING,  /* Attempting to connect */
    COMM_STATE_ONLINE,      /* Connected and authenticated */
    COMM_STATE_ERROR        /* Communication error */
} comm_state_t;

/* Agent configuration */
typedef struct {
    char server_url[256];          /* Central management server URL */
    char agent_id[64];             /* Unique agent identifier */
    char auth_token[128];          /* Authentication token */
    uint16_t server_port;          /* Server port (default: 8443) */
    bool use_tls;                  /* Use TLS 1.3 for communication */
    int scan_interval_sec;         /* Scan interval in seconds */
    int heartbeat_interval_sec;    /* Heartbeat interval */
    bool offline_cache_enabled;    /* Enable offline audit caching */
    size_t max_cache_size_mb;      /* Maximum cache size */
    char ca_cert_path[256];        /* CA certificate for TLS */
} agent_config_t;

/* Agent runtime state */
typedef struct {
    agent_mode_t mode;
    comm_state_t comm_state;
    agent_config_t config;
    time_t last_scan_time;
    time_t last_heartbeat_time;
    time_t last_server_contact;
    int cached_reports;
    bool running;
    pid_t daemon_pid;
} agent_state_t;

/* Cached audit report (for offline mode) */
typedef struct {
    time_t timestamp;
    char report_id[64];
    char report_json[8192];  /* JSON audit report */
    bool transmitted;
} cached_report_t;

/* Initialize agent */
int agent_init(agent_state_t *state, agent_mode_t mode);

/* Cleanup agent */
void agent_cleanup(agent_state_t *state);

/* Load agent configuration from file */
int agent_load_config(agent_config_t *config, const char *config_file);

/* Save agent configuration */
int agent_save_config(const agent_config_t *config, const char *config_file);

/* Run agent in daemon mode */
int agent_run_daemon(agent_state_t *state);

/* Run single scan (oneshot mode) */
int agent_run_scan(agent_state_t *state);

/* Send heartbeat to server */
int agent_send_heartbeat(agent_state_t *state);

/* Transmit audit report to server */
int agent_transmit_report(agent_state_t *state, const char *report_json);

/* Cache audit report for later transmission */
int agent_cache_report(agent_state_t *state, const char *report_json);

/* Flush cached reports to server */
int agent_flush_cache(agent_state_t *state);

/* Check connection to server */
int agent_check_connection(agent_state_t *state);

/* Generate unique agent ID based on hardware */
int agent_generate_id(char *agent_id, size_t size);

/* Daemonize process */
int agent_daemonize(void);

/* Write PID file */
int agent_write_pidfile(pid_t pid);

/* Remove PID file */
int agent_remove_pidfile(void);

#endif /* FG_AGENT_H */
