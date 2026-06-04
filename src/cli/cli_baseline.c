/*
 * FirmwareGuard CLI - baseline capture / compare / drift handlers
 */

#include <stdio.h>

#include "cli.h"
#include "../detection/baseline_capture.h"

/* Baseline capture reads x86 CPUID/MSR state; deferred on ARM (see ROADMAP). */
#ifndef FG_BUILD_ARM

int cmd_baseline_capture(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;
    const char *output_file = o->output_file;
    bool history = o->history;

    baseline_snapshot_t snapshot;
    int ret;

    /* Check root for full access */
    if (fg_require_root() != FG_SUCCESS) {
        FG_WARN("Running without root - some features may be limited");
    }

    /* Initialize */
    ret = baseline_init();
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to initialize baseline subsystem");
        return ret;
    }

    /* Capture baseline */
    FG_INFO("Capturing comprehensive system baseline...");
    ret = baseline_capture(&snapshot);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Baseline capture failed");
        baseline_cleanup();
        return ret;
    }

    /* Save into the drift-history store when requested. With --history the
     * -o value (if any) is treated as the store directory, else the default. */
    if (history) {
        char dir[256];
        baseline_history_dir(dir, sizeof(dir), output_file);
        if (baseline_history_save(&snapshot, dir) == FG_SUCCESS) {
            FG_INFO("Baseline added to history store: %s", dir);
        }
    } else if (output_file) {
        /* Save to an explicit file */
        ret = baseline_save(&snapshot, output_file);
        if (ret == FG_SUCCESS) {
            FG_INFO("Baseline saved to: %s", output_file);
        }
    }

    /* Output */
    if (json_output) {
        char json_buffer[16384];
        if (baseline_to_json(&snapshot, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s\n", json_buffer);
        }
    } else {
        baseline_print_snapshot(&snapshot, verbose);
    }

    baseline_cleanup();
    return FG_SUCCESS;
}

int cmd_baseline_drift(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;
    const char *output_file = o->output_file;

    baseline_drift_t drift;
    char dir[256];

    if (baseline_init() != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to initialize baseline subsystem");
        return FG_ERROR;
    }

    /* -o, if given, overrides the history store directory */
    baseline_history_dir(dir, sizeof(dir), output_file);

    int ret = baseline_history_drift(dir, &drift);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to read drift history from: %s", dir);
        baseline_cleanup();
        return ret;
    }

    if (json_output) {
        char json_buffer[65536];
        if (baseline_drift_to_json(&drift, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s\n", json_buffer);
        }
    } else {
        baseline_drift_print(&drift, verbose);
    }

    baseline_cleanup();
    return FG_SUCCESS;
}

int cmd_baseline_compare(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;
    const char *baseline_file = o->output_file;

    baseline_comparison_t result;
    int ret;

    if (!baseline_file) {
        FG_LOG_ERROR("Baseline file required for comparison");
        FG_LOG_ERROR("Usage: firmwareguard baseline-compare -o <baseline_file>");
        return FG_ERROR;
    }

    /* Check root for full access */
    if (fg_require_root() != FG_SUCCESS) {
        FG_WARN("Running without root - some features may be limited");
    }

    /* Initialize */
    ret = baseline_init();
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to initialize baseline subsystem");
        return ret;
    }

    /* Compare against baseline */
    FG_INFO("Comparing current state against baseline: %s", baseline_file);
    ret = baseline_compare_file(baseline_file, &result);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Baseline comparison failed");
        baseline_cleanup();
        return ret;
    }

    /* Output */
    if (json_output) {
        char json_buffer[16384];
        if (baseline_comparison_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s\n", json_buffer);
        }
    } else {
        baseline_print_comparison(&result, verbose);
    }

    baseline_cleanup();
    return FG_SUCCESS;
}

#endif /* !FG_BUILD_ARM */
