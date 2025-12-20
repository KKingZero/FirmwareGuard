/*
 * FirmwareGuard - Ghidra Integration Wrapper
 * Provides C interface to invoke Ghidra analysis scripts
 * OFFLINE-ONLY: No network connectivity
 */

#include "ghidra_wrapper.h"
#include "../cJSON.h"
#include "../../include/firmwareguard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>

/* Default paths */
#define DEFAULT_OUTPUT_DIR "/var/lib/firmwareguard/ghidra_analysis"
#define DEFAULT_SCRIPTS_DIR "/usr/share/firmwareguard/ghidra"
#define GHIDRA_RUNNER_SCRIPT "ghidra_runner.sh"

/* Search paths for Ghidra */
static const char *GHIDRA_SEARCH_PATHS[] = {
    "/opt/ghidra",
    "/usr/share/ghidra",
    "/usr/local/ghidra",
    NULL
};

/* Module state */
static ghidra_config_t g_config;
static bool g_initialized = false;
static char g_ghidra_home[512] = {0};

/* Forward declarations */
static int find_ghidra_installation(char *path, size_t path_len);
static int run_ghidra_script(const char *firmware_path, const char *script,
                            const char *output_dir, char *result_path);
static int parse_json_results(const char *json_path, ghidra_result_t *result);
static ghidra_severity_t parse_severity(const char *severity_str);
static bool validate_script_name(const char *script);

/*
 * Validate script name to prevent path traversal attacks
 * Returns true if script name is safe, false otherwise
 */
static bool validate_script_name(const char *script)
{
    if (!script || script[0] == '\0') {
        return false;
    }

    /* Reject absolute paths */
    if (script[0] == '/') {
        FG_WARN("Script name cannot be an absolute path: %s", script);
        return false;
    }

    /* Reject path traversal sequences */
    if (strstr(script, "..") != NULL) {
        FG_WARN("Script name contains path traversal: %s", script);
        return false;
    }

    /* Reject embedded slashes (only allow simple filenames) */
    if (strchr(script, '/') != NULL) {
        FG_WARN("Script name cannot contain path separators: %s", script);
        return false;
    }

    /* Validate extension - must end in .py */
    size_t len = strlen(script);
    if (len < 4 || strcmp(script + len - 3, ".py") != 0) {
        FG_WARN("Script must have .py extension: %s", script);
        return false;
    }

    /* Validate characters - only allow alphanumeric, underscore, hyphen, dot */
    for (size_t i = 0; i < len; i++) {
        char c = script[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) {
            FG_WARN("Script name contains invalid character '%c': %s", c, script);
            return false;
        }
    }

    return true;
}

/*
 * Initialize Ghidra wrapper
 */
int ghidra_init(ghidra_config_t *config)
{
    if (g_initialized) {
        return FG_SUCCESS;
    }

    /* Use provided config or defaults */
    if (config) {
        memcpy(&g_config, config, sizeof(ghidra_config_t));
    } else {
        memset(&g_config, 0, sizeof(ghidra_config_t));
        strncpy(g_config.output_dir, DEFAULT_OUTPUT_DIR, sizeof(g_config.output_dir) - 1);
        strncpy(g_config.scripts_dir, DEFAULT_SCRIPTS_DIR, sizeof(g_config.scripts_dir) - 1);
        g_config.timeout_seconds = 300; /* 5 minutes default */
    }

    /* Find Ghidra if not specified */
    if (g_config.ghidra_home[0] == '\0') {
        if (find_ghidra_installation(g_config.ghidra_home, sizeof(g_config.ghidra_home)) != 0) {
            FG_WARN("Ghidra installation not found - analysis will be unavailable");
        }
    }

    strncpy(g_ghidra_home, g_config.ghidra_home, sizeof(g_ghidra_home) - 1);

    /* Create output directory if it doesn't exist */
    mkdir(g_config.output_dir, 0755);

    g_initialized = true;
    return FG_SUCCESS;
}

/*
 * Check if Ghidra is available
 */
bool ghidra_available(void)
{
    if (!g_initialized) {
        ghidra_init(NULL);
    }

    if (g_ghidra_home[0] == '\0') {
        return false;
    }

    /* Check for analyzeHeadless script */
    char headless_path[768];
    snprintf(headless_path, sizeof(headless_path), "%s/support/analyzeHeadless", g_ghidra_home);

    return access(headless_path, X_OK) == 0;
}

/*
 * Get Ghidra home path
 */
const char *ghidra_get_home(void)
{
    if (!g_initialized) {
        ghidra_init(NULL);
    }

    return g_ghidra_home[0] != '\0' ? g_ghidra_home : NULL;
}

/*
 * Find Ghidra installation
 */
static int find_ghidra_installation(char *path, size_t path_len)
{
    /* Check environment variable first */
    const char *env_home = getenv("GHIDRA_HOME");
    if (env_home) {
        char headless[768];
        snprintf(headless, sizeof(headless), "%s/support/analyzeHeadless", env_home);
        if (access(headless, X_OK) == 0) {
            strncpy(path, env_home, path_len - 1);
            return 0;
        }
    }

    /* Search common paths */
    for (int i = 0; GHIDRA_SEARCH_PATHS[i] != NULL; i++) {
        const char *base = GHIDRA_SEARCH_PATHS[i];
        DIR *dir = opendir(base);

        if (dir) {
            closedir(dir);

            char headless[768];
            snprintf(headless, sizeof(headless), "%s/support/analyzeHeadless", base);
            if (access(headless, X_OK) == 0) {
                strncpy(path, base, path_len - 1);
                return 0;
            }
        }

        /* Check for versioned directories like /opt/ghidra_10.3 */
        char parent[256];
        strncpy(parent, base, sizeof(parent) - 1);
        char *last_slash = strrchr(parent, '/');
        if (last_slash) {
            *last_slash = '\0';
            char prefix[64];
            strncpy(prefix, last_slash + 1, sizeof(prefix) - 1);

            dir = opendir(parent);
            if (dir) {
                struct dirent *entry;
                while ((entry = readdir(dir)) != NULL) {
                    if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0) {
                        char full_path[512];
                        snprintf(full_path, sizeof(full_path), "%s/%s", parent, entry->d_name);

                        char headless[768];
                        snprintf(headless, sizeof(headless), "%s/support/analyzeHeadless", full_path);
                        if (access(headless, X_OK) == 0) {
                            strncpy(path, full_path, path_len - 1);
                            closedir(dir);
                            return 0;
                        }
                    }
                }
                closedir(dir);
            }
        }
    }

    return -1;
}

/*
 * Analyze firmware with Ghidra
 */
int ghidra_analyze(const char *firmware_path,
                   ghidra_analysis_type_t type,
                   ghidra_result_t *result)
{
    if (!g_initialized) {
        ghidra_init(NULL);
    }

    memset(result, 0, sizeof(ghidra_result_t));

    if (!ghidra_available()) {
        strncpy(result->error_message, "Ghidra not available", sizeof(result->error_message) - 1);
        return FG_NOT_FOUND;
    }

    if (access(firmware_path, R_OK) != 0) {
        snprintf(result->error_message, sizeof(result->error_message),
                "Cannot read firmware file: %s", firmware_path);
        return FG_ERROR;
    }

    /* Select appropriate script based on type */
    const char *script;
    switch (type) {
        case GHIDRA_ANALYSIS_UEFI:
            script = "uefi_driver_analysis.py";
            break;
        case GHIDRA_ANALYSIS_ME:
            script = "me_firmware_analysis.py";
            break;
        case GHIDRA_ANALYSIS_FULL:
        case GHIDRA_ANALYSIS_AUTO:
        default:
            script = "fw_analyze.py";
            break;
    }

    char result_path[512];
    int ret = run_ghidra_script(firmware_path, script, g_config.output_dir, result_path);

    if (ret != 0) {
        strncpy(result->error_message, "Ghidra analysis failed", sizeof(result->error_message) - 1);
        return FG_ERROR;
    }

    /* Parse results */
    if (result_path[0] != '\0') {
        ret = parse_json_results(result_path, result);
        if (ret != 0) {
            strncpy(result->error_message, "Failed to parse results", sizeof(result->error_message) - 1);
            return FG_ERROR;
        }
        strncpy(result->output_path, result_path, sizeof(result->output_path) - 1);
    }

    result->success = true;
    return FG_SUCCESS;
}

/*
 * Analyze with specific script
 */
int ghidra_analyze_with_script(const char *firmware_path,
                               const char *script_name,
                               ghidra_result_t *result)
{
    if (!g_initialized) {
        ghidra_init(NULL);
    }

    memset(result, 0, sizeof(ghidra_result_t));

    if (!ghidra_available()) {
        strncpy(result->error_message, "Ghidra not available", sizeof(result->error_message) - 1);
        return FG_NOT_FOUND;
    }

    char result_path[512];
    int ret = run_ghidra_script(firmware_path, script_name, g_config.output_dir, result_path);

    if (ret != 0) {
        strncpy(result->error_message, "Ghidra analysis failed", sizeof(result->error_message) - 1);
        return FG_ERROR;
    }

    if (result_path[0] != '\0') {
        ret = parse_json_results(result_path, result);
        strncpy(result->output_path, result_path, sizeof(result->output_path) - 1);
    }

    result->success = (ret == 0);
    return ret == 0 ? FG_SUCCESS : FG_ERROR;
}

/*
 * Run Ghidra script
 */
static int run_ghidra_script(const char *firmware_path, const char *script,
                            const char *output_dir, char *result_path)
{
    result_path[0] = '\0';

    /* Validate script name to prevent path traversal attacks */
    if (!validate_script_name(script)) {
        FG_ERROR("Invalid script name rejected: %s", script);
        return -1;
    }

    /* Build command */
    char runner_path[768];
    snprintf(runner_path, sizeof(runner_path), "%s/%s", g_config.scripts_dir, GHIDRA_RUNNER_SCRIPT);

    /* Check if runner exists, otherwise use direct analyzeHeadless */
    if (access(runner_path, X_OK) != 0) {
        /* Use analyzeHeadless directly */
        char analyze_path[768];
        snprintf(analyze_path, sizeof(analyze_path), "%s/support/analyzeHeadless", g_ghidra_home);

        char script_path[768];
        snprintf(script_path, sizeof(script_path), "%s/%s", g_config.scripts_dir, script);

        /* Generate unique project name */
        char project_name[128];
        snprintf(project_name, sizeof(project_name), "FWGuard_%ld", (long)time(NULL));

        pid_t pid = fork();
        if (pid == 0) {
            /* Child process */
            char *args[] = {
                (char *)analyze_path,
                (char *)output_dir,
                project_name,
                "-import", (char *)firmware_path,
                "-postScript", (char *)script_path,
                "-deleteProject",
                NULL
            };

            /* Redirect stdout/stderr to /dev/null unless verbose */
            if (!g_config.verbose) {
                freopen("/dev/null", "w", stdout);
                freopen("/dev/null", "w", stderr);
            }

            execv(analyze_path, args);
            _exit(127);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);

            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                /* Find most recent JSON result */
                DIR *dir = opendir(output_dir);
                if (dir) {
                    struct dirent *entry;
                    time_t newest_time = 0;

                    while ((entry = readdir(dir)) != NULL) {
                        if (strstr(entry->d_name, ".json")) {
                            char full_path[768];
                            snprintf(full_path, sizeof(full_path), "%s/%s", output_dir, entry->d_name);

                            struct stat st;
                            if (stat(full_path, &st) == 0) {
                                if (st.st_mtime > newest_time) {
                                    newest_time = st.st_mtime;
                                    strncpy(result_path, full_path, 511);
                                }
                            }
                        }
                    }
                    closedir(dir);
                }
                return 0;
            }
            return -1;
        }
        return -1;
    }

    /* Use runner script */
    char type_arg[32] = "all";
    if (strstr(script, "uefi")) {
        strcpy(type_arg, "uefi");
    } else if (strstr(script, "me")) {
        strcpy(type_arg, "me");
    }

    pid_t pid = fork();
    if (pid == 0) {
        char *args[] = {
            (char *)runner_path,
            "-t", type_arg,
            "-o", (char *)output_dir,
            "-g", (char *)g_ghidra_home,
            (char *)firmware_path,
            NULL
        };

        if (!g_config.verbose) {
            freopen("/dev/null", "w", stdout);
            freopen("/dev/null", "w", stderr);
        }

        execv(runner_path, args);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            /* Find result file */
            DIR *dir = opendir(output_dir);
            if (dir) {
                struct dirent *entry;
                time_t newest_time = 0;

                while ((entry = readdir(dir)) != NULL) {
                    if (strstr(entry->d_name, ".json")) {
                        char full_path[768];
                        snprintf(full_path, sizeof(full_path), "%s/%s", output_dir, entry->d_name);

                        struct stat st;
                        if (stat(full_path, &st) == 0 && st.st_mtime > newest_time) {
                            newest_time = st.st_mtime;
                            strncpy(result_path, full_path, 511);
                        }
                    }
                }
                closedir(dir);
            }
            return 0;
        }
    }

    return -1;
}

/*
 * Parse JSON results
 */
static int parse_json_results(const char *json_path, ghidra_result_t *result)
{
    FILE *fp = fopen(json_path, "r");
    if (!fp) {
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *json_str = malloc(size + 1);
    if (!json_str) {
        fclose(fp);
        return -1;
    }

    fread(json_str, 1, size, fp);
    json_str[size] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(json_str);
    free(json_str);

    if (!root) {
        return -1;
    }

    /* Parse basic fields */
    cJSON *item;

    item = cJSON_GetObjectItem(root, "filename");
    if (item && item->valuestring) {
        strncpy(result->filename, item->valuestring, sizeof(result->filename) - 1);
    }

    item = cJSON_GetObjectItem(root, "file_hash");
    if (item && item->valuestring) {
        strncpy(result->file_hash, item->valuestring, sizeof(result->file_hash) - 1);
    }

    item = cJSON_GetObjectItem(root, "file_size");
    if (item) {
        result->file_size = (uint64_t)item->valuedouble;
    }

    item = cJSON_GetObjectItem(root, "firmware_type");
    if (item && item->valuestring) {
        strncpy(result->firmware_type, item->valuestring, sizeof(result->firmware_type) - 1);
    }

    item = cJSON_GetObjectItem(root, "risk_score");
    if (item) {
        result->risk_score = item->valueint;
    }

    item = cJSON_GetObjectItem(root, "risk_level");
    if (item && item->valuestring) {
        strncpy(result->risk_level, item->valuestring, sizeof(result->risk_level) - 1);
    }

    /* Parse indicators */
    cJSON *indicators = cJSON_GetObjectItem(root, "suspicious_indicators");
    if (indicators && cJSON_IsArray(indicators)) {
        int count = cJSON_GetArraySize(indicators);
        result->num_indicators = count;

        if (count > 0) {
            result->indicators = calloc(count, sizeof(ghidra_indicator_t));
            if (result->indicators) {
                for (int i = 0; i < count; i++) {
                    cJSON *ind = cJSON_GetArrayItem(indicators, i);

                    item = cJSON_GetObjectItem(ind, "type");
                    if (item && item->valuestring) {
                        strncpy(result->indicators[i].type, item->valuestring,
                               sizeof(result->indicators[i].type) - 1);
                    }

                    item = cJSON_GetObjectItem(ind, "name");
                    if (item && item->valuestring) {
                        strncpy(result->indicators[i].name, item->valuestring,
                               sizeof(result->indicators[i].name) - 1);
                    }

                    item = cJSON_GetObjectItem(ind, "address");
                    if (item && item->valuestring) {
                        strncpy(result->indicators[i].address, item->valuestring,
                               sizeof(result->indicators[i].address) - 1);
                    }

                    item = cJSON_GetObjectItem(ind, "severity");
                    if (item && item->valuestring) {
                        result->indicators[i].severity = parse_severity(item->valuestring);
                    }

                    item = cJSON_GetObjectItem(ind, "description");
                    if (item && item->valuestring) {
                        strncpy(result->indicators[i].description, item->valuestring,
                               sizeof(result->indicators[i].description) - 1);
                    }
                }
            }
        }
    }

    /* Parse counts */
    item = cJSON_GetObjectItem(root, "functions_count");
    if (item) {
        result->num_functions = item->valueint;
    }

    item = cJSON_GetObjectItem(root, "strings_count");
    if (item) {
        result->num_strings = item->valueint;
    }

    result->analysis_time = time(NULL);

    cJSON_Delete(root);
    return 0;
}

/*
 * Load results from JSON file
 */
int ghidra_load_results(const char *json_path, ghidra_result_t *result)
{
    memset(result, 0, sizeof(ghidra_result_t));
    return parse_json_results(json_path, result);
}

/*
 * Free result resources
 */
void ghidra_free_result(ghidra_result_t *result)
{
    if (result->indicators) {
        free(result->indicators);
        result->indicators = NULL;
    }
    result->num_indicators = 0;
}

/*
 * Parse severity string
 */
static ghidra_severity_t parse_severity(const char *severity_str)
{
    if (!severity_str) return GHIDRA_SEVERITY_INFO;

    if (strcasecmp(severity_str, "critical") == 0) return GHIDRA_SEVERITY_CRITICAL;
    if (strcasecmp(severity_str, "high") == 0) return GHIDRA_SEVERITY_HIGH;
    if (strcasecmp(severity_str, "medium") == 0) return GHIDRA_SEVERITY_MEDIUM;
    if (strcasecmp(severity_str, "low") == 0) return GHIDRA_SEVERITY_LOW;

    return GHIDRA_SEVERITY_INFO;
}

/*
 * Get severity string
 */
const char *ghidra_severity_string(ghidra_severity_t severity)
{
    switch (severity) {
        case GHIDRA_SEVERITY_CRITICAL: return "CRITICAL";
        case GHIDRA_SEVERITY_HIGH: return "HIGH";
        case GHIDRA_SEVERITY_MEDIUM: return "MEDIUM";
        case GHIDRA_SEVERITY_LOW: return "LOW";
        case GHIDRA_SEVERITY_INFO:
        default: return "INFO";
    }
}

/*
 * Print analysis summary
 */
void ghidra_print_summary(const ghidra_result_t *result)
{
    printf("\n=== Ghidra Analysis Summary ===\n");
    printf("File: %s\n", result->filename);
    printf("Type: %s\n", result->firmware_type);
    printf("Hash: %s\n", result->file_hash);
    printf("Size: %lu bytes\n", (unsigned long)result->file_size);
    printf("\n");
    printf("Risk Level: %s\n", result->risk_level);
    printf("Risk Score: %d/100\n", result->risk_score);
    printf("\n");
    printf("Suspicious Indicators: %d\n", result->num_indicators);

    if (result->num_indicators > 0 && result->indicators) {
        printf("\nTop Indicators:\n");
        int show_count = result->num_indicators > 5 ? 5 : result->num_indicators;

        for (int i = 0; i < show_count; i++) {
            printf("  [%s] %s: %s\n",
                   ghidra_severity_string(result->indicators[i].severity),
                   result->indicators[i].type,
                   result->indicators[i].name);
        }

        if (result->num_indicators > 5) {
            printf("  ... and %d more\n", result->num_indicators - 5);
        }
    }

    if (result->output_path[0] != '\0') {
        printf("\nFull results: %s\n", result->output_path);
    }
}

/*
 * Cleanup
 */
void ghidra_cleanup(void)
{
    g_initialized = false;
    g_ghidra_home[0] = '\0';
    memset(&g_config, 0, sizeof(g_config));
}
