/**
 * HECI Monitor Test Program
 *
 * This is a standalone test program for the HECI monitoring module.
 * It demonstrates basic usage and validates the implementation.
 *
 * Usage:
 *   sudo ./heci_test [duration_seconds]
 *
 * Example:
 *   sudo ./heci_test 30  # Monitor for 30 seconds
 */

#include "heci_monitor.h"
#include <signal.h>

/* Global flag for signal handling */
static volatile bool keep_running = true;

/**
 * Signal handler for graceful shutdown.
 */
static void signal_handler(int signum) {
    (void)signum;
    keep_running = false;
    printf("\nShutdown signal received...\n");
}

/**
 * Main test program.
 */
int main(int argc, char *argv[]) {
    int ret;
    int duration = 10; /* Default: 10 seconds */
    heci_log_t log;
    heci_alert_t alerts[256];
    size_t num_alerts;

    printf("=== HECI Traffic Monitor Test ===\n\n");

    /* Parse command line arguments */
    if (argc > 1) {
        duration = atoi(argv[1]);
        if (duration <= 0) {
            fprintf(stderr, "Invalid duration: %s\n", argv[1]);
            return 1;
        }
    }

    /* Check if HECI is supported */
    if (!heci_is_supported()) {
        fprintf(stderr, "ERROR: MEI/HECI device not found\n");
        fprintf(stderr, "Possible reasons:\n");
        fprintf(stderr, "  - Not an Intel platform\n");
        fprintf(stderr, "  - MEI driver not loaded (try: modprobe mei_me)\n");
        fprintf(stderr, "  - ME is disabled in BIOS\n");
        fprintf(stderr, "  - /dev/mei0 does not exist\n");
        return 1;
    }

    printf("[+] MEI/HECI device detected\n");

    /* Initialize HECI monitor */
    ret = heci_init();
    if (ret != FG_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize HECI monitor\n");
        if (ret == FG_NO_PERMISSION) {
            fprintf(stderr, "This program requires root privileges\n");
            fprintf(stderr, "Try: sudo %s\n", argv[0]);
        }
        return 1;
    }

    printf("[+] HECI monitor initialized\n");

    /* Setup signal handlers for graceful shutdown */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Start monitoring with pattern detection enabled */
    ret = heci_start_monitor(true);
    if (ret != FG_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to start HECI monitoring\n");
        heci_cleanup();
        return 1;
    }

    printf("[+] HECI monitoring started (pattern detection enabled)\n");
    printf("[+] Monitoring for %d seconds... (Ctrl+C to stop early)\n\n", duration);

    /* Monitor for specified duration */
    for (int i = 0; i < duration && keep_running; i++) {
        sleep(1);

        /* Print progress every 5 seconds */
        if ((i + 1) % 5 == 0) {
            heci_get_log(&log);
            printf("    [%d/%d] Messages: %lu, Requests: %lu, Responses: %lu, Alerts: %zu\n",
                   i + 1, duration,
                   log.stats.total_messages,
                   log.stats.requests,
                   log.stats.responses,
                   log.alert_count);
        }
    }

    printf("\n[+] Stopping monitor...\n");

    /* Stop monitoring */
    heci_stop_monitor();

    /* Get final log */
    heci_get_log(&log);

    printf("[+] Monitoring stopped\n\n");

    /* Print detailed summary */
    heci_print_summary(&log);

    /* Analyze traffic for suspicious patterns */
    ret = heci_analyze_traffic(&log, alerts, 256, &num_alerts);
    if (ret == FG_SUCCESS && num_alerts > 0) {
        printf("\n=== Suspicious Pattern Analysis ===\n\n");

        for (size_t i = 0; i < num_alerts; i++) {
            const char *risk_str;

            switch (alerts[i].risk) {
                case RISK_CRITICAL: risk_str = "CRITICAL"; break;
                case RISK_HIGH:     risk_str = "HIGH";     break;
                case RISK_MEDIUM:   risk_str = "MEDIUM";   break;
                case RISK_LOW:      risk_str = "LOW";      break;
                default:            risk_str = "INFO";     break;
            }

            printf("[%s] %s\n", risk_str, alerts[i].description);
            printf("    Pattern: %s\n", heci_get_pattern_name(alerts[i].pattern));
            printf("    Time: %ld\n\n", alerts[i].timestamp.tv_sec);
        }

        printf("Total alerts: %zu\n\n", num_alerts);
    } else if (num_alerts == 0) {
        printf("\n[+] No suspicious patterns detected\n\n");
    }

    /* Export log to JSON */
    const char *json_path = "/tmp/heci_traffic.json";
    ret = heci_export_log_json(&log, json_path);
    if (ret == FG_SUCCESS) {
        printf("[+] Traffic log exported to: %s\n", json_path);
        printf("    Review with: cat %s | jq .\n", json_path);
    }

    /* Cleanup */
    heci_cleanup();
    printf("\n[+] Cleanup complete\n");

    return 0;
}
