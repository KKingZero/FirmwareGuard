/*
 * FirmwareGuard - Ghidra Integration Wrapper
 * Provides C interface to invoke Ghidra analysis scripts
 * OFFLINE-ONLY: No network connectivity
 */

#ifndef GHIDRA_WRAPPER_H
#define GHIDRA_WRAPPER_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* Ghidra analysis types */
typedef enum {
    GHIDRA_ANALYSIS_AUTO = 0,
    GHIDRA_ANALYSIS_UEFI,
    GHIDRA_ANALYSIS_ME,
    GHIDRA_ANALYSIS_FULL
} ghidra_analysis_type_t;

/* Analysis result severity */
typedef enum {
    GHIDRA_SEVERITY_INFO = 0,
    GHIDRA_SEVERITY_LOW,
    GHIDRA_SEVERITY_MEDIUM,
    GHIDRA_SEVERITY_HIGH,
    GHIDRA_SEVERITY_CRITICAL
} ghidra_severity_t;

/* Suspicious indicator */
typedef struct {
    char type[64];
    char name[256];
    char address[32];
    ghidra_severity_t severity;
    char description[512];
} ghidra_indicator_t;

/* Ghidra analysis results */
typedef struct {
    /* Metadata */
    char filename[256];
    char file_hash[65];
    uint64_t file_size;
    char firmware_type[64];
    time_t analysis_time;

    /* Risk assessment */
    int risk_score;
    char risk_level[32];

    /* Findings */
    int num_indicators;
    ghidra_indicator_t *indicators;

    int num_functions;
    int num_strings;
    int num_guids;

    /* Output file path */
    char output_path[512];

    /* Status */
    bool success;
    char error_message[256];
} ghidra_result_t;

/* Configuration */
typedef struct {
    char ghidra_home[512];
    char output_dir[512];
    char scripts_dir[512];
    bool verbose;
    bool keep_project;
    int timeout_seconds;
} ghidra_config_t;

/*
 * Initialize Ghidra wrapper
 * Returns: 0 on success, -1 on error
 */
int ghidra_init(ghidra_config_t *config);

/*
 * Check if Ghidra is available on the system
 * Returns: true if Ghidra is found and usable
 */
bool ghidra_available(void);

/*
 * Get Ghidra installation path
 * Returns: Path to Ghidra home directory, or NULL if not found
 */
const char *ghidra_get_home(void);

/*
 * Analyze firmware file with Ghidra
 *
 * firmware_path: Path to firmware binary
 * type: Analysis type (auto-detect if AUTO)
 * result: Output structure for results
 *
 * Returns: 0 on success, -1 on error
 */
int ghidra_analyze(const char *firmware_path,
                   ghidra_analysis_type_t type,
                   ghidra_result_t *result);

/*
 * Analyze firmware with specific script
 *
 * firmware_path: Path to firmware binary
 * script_name: Name of analysis script to use
 * result: Output structure for results
 *
 * Returns: 0 on success, -1 on error
 */
int ghidra_analyze_with_script(const char *firmware_path,
                               const char *script_name,
                               ghidra_result_t *result);

/*
 * Load analysis results from JSON file
 *
 * json_path: Path to analysis JSON output
 * result: Output structure for results
 *
 * Returns: 0 on success, -1 on error
 */
int ghidra_load_results(const char *json_path, ghidra_result_t *result);

/*
 * Free resources allocated in result structure
 */
void ghidra_free_result(ghidra_result_t *result);

/*
 * Print analysis summary to stdout
 */
void ghidra_print_summary(const ghidra_result_t *result);

/*
 * Get string representation of severity level
 */
const char *ghidra_severity_string(ghidra_severity_t severity);

/*
 * Cleanup Ghidra wrapper
 */
void ghidra_cleanup(void);

#endif /* GHIDRA_WRAPPER_H */
