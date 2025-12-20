#include "coreboot_migrate.h"
#include "../core/me_psp.h"
#include "../../include/cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

/* OFFLINE-ONLY: No network connectivity */

/* Global board database */
static coreboot_board_info_t *board_database = NULL;
static int board_database_count = 0;

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

const char* coreboot_compat_to_str(coreboot_compat_t compat) {
    switch (compat) {
        case COMPAT_SUPPORTED:    return "SUPPORTED";
        case COMPAT_LIBREBOOT:    return "LIBREBOOT";
        case COMPAT_PARTIAL:      return "PARTIAL";
        case COMPAT_EXPERIMENTAL: return "EXPERIMENTAL";
        case COMPAT_UNSUPPORTED:  return "UNSUPPORTED";
        case COMPAT_UNKNOWN:      return "UNKNOWN";
        default:                  return "INVALID";
    }
}

const char* coreboot_risk_to_str(migration_risk_t risk) {
    switch (risk) {
        case MIGRATION_RISK_LOW:      return "LOW";
        case MIGRATION_RISK_MEDIUM:   return "MEDIUM";
        case MIGRATION_RISK_HIGH:     return "HIGH";
        case MIGRATION_RISK_CRITICAL: return "CRITICAL";
        default:                      return "UNKNOWN";
    }
}

/* Helper: Read DMI value from sysfs */
static int read_dmi_value(const char *filename, char *buf, size_t size) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/dmi/id/%s", filename);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        return FG_ERROR;
    }

    if (fgets(buf, size, fp)) {
        /* Remove trailing newline */
        buf[strcspn(buf, "\n")] = 0;
        fclose(fp);
        return FG_SUCCESS;
    }

    fclose(fp);
    return FG_ERROR;
}

/* Helper: Case-insensitive string matching */
static bool str_match_case_insensitive(const char *s1, const char *s2) {
    if (!s1 || !s2) return false;
    return strcasecmp(s1, s2) == 0;
}

/* Helper: Partial match (for board name variations) */
static bool str_contains_case_insensitive(const char *haystack, const char *needle) {
    if (!haystack || !needle) return false;

    char *h = strdup(haystack);
    char *n = strdup(needle);

    if (!h || !n) {
        free(h);
        free(n);
        return false;
    }

    /* Convert to lowercase */
    for (char *p = h; *p; p++) *p = tolower(*p);
    for (char *p = n; *p; p++) *p = tolower(*p);

    bool found = strstr(h, n) != NULL;

    free(h);
    free(n);
    return found;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

int coreboot_migrate_init(void) {
    FG_INFO("Initializing Coreboot migration subsystem...");

    /* Database will be loaded separately via coreboot_load_database() */
    board_database = NULL;
    board_database_count = 0;

    return FG_SUCCESS;
}

void coreboot_migrate_cleanup(void) {
    if (board_database) {
        free(board_database);
        board_database = NULL;
    }
    board_database_count = 0;

    FG_INFO("Coreboot migration subsystem cleaned up");
}

/* ============================================================================
 * Database Loading
 * ============================================================================ */

int coreboot_load_database(const char *json_path) {
    FILE *fp = NULL;
    char *json_data = NULL;
    cJSON *root = NULL;
    int ret = FG_ERROR;

    FG_INFO("Loading Coreboot board database from: %s", json_path);

    /* Read JSON file */
    fp = fopen(json_path, "r");
    if (!fp) {
        FG_LOG_ERROR("Failed to open database file: %s", json_path);
        return FG_NOT_FOUND;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 10 * 1024 * 1024) {
        FG_LOG_ERROR("Invalid database file size: %ld", file_size);
        fclose(fp);
        return FG_ERROR;
    }

    /* Allocate buffer and read */
    json_data = malloc(file_size + 1);
    if (!json_data) {
        FG_LOG_ERROR("Memory allocation failed");
        fclose(fp);
        return FG_ERROR;
    }

    size_t read_size = fread(json_data, 1, file_size, fp);
    fclose(fp);
    json_data[read_size] = '\0';

    /* Parse JSON */
    root = cJSON_Parse(json_data);
    if (!root) {
        FG_LOG_ERROR("JSON parse error: %s", cJSON_GetErrorPtr());
        free(json_data);
        return FG_ERROR;
    }

    /* Get boards array */
    cJSON *boards_array = cJSON_GetObjectItem(root, "boards");
    if (!boards_array || !cJSON_IsArray(boards_array)) {
        FG_LOG_ERROR("Invalid database format: 'boards' array not found");
        goto cleanup;
    }

    int board_count = cJSON_GetArraySize(boards_array);
    if (board_count <= 0) {
        FG_WARN("Database contains no boards");
        ret = FG_SUCCESS;
        goto cleanup;
    }

    /* Allocate board database */
    board_database = calloc(board_count, sizeof(coreboot_board_info_t));
    if (!board_database) {
        FG_LOG_ERROR("Memory allocation failed for board database");
        goto cleanup;
    }

    /* Parse each board */
    int parsed_count = 0;
    cJSON *board_json = NULL;
    cJSON_ArrayForEach(board_json, boards_array) {
        if (parsed_count >= board_count) break;

        coreboot_board_info_t *board = &board_database[parsed_count];
        memset(board, 0, sizeof(coreboot_board_info_t));

        /* Parse board fields */
        cJSON *item;

        if ((item = cJSON_GetObjectItem(board_json, "vendor")))
            strncpy(board->vendor, item->valuestring, sizeof(board->vendor) - 1);

        if ((item = cJSON_GetObjectItem(board_json, "board_name")))
            strncpy(board->board_name, item->valuestring, sizeof(board->board_name) - 1);

        if ((item = cJSON_GetObjectItem(board_json, "board_model")))
            strncpy(board->board_model, item->valuestring, sizeof(board->board_model) - 1);

        if ((item = cJSON_GetObjectItem(board_json, "dmi_sys_vendor")))
            strncpy(board->dmi_sys_vendor, item->valuestring, sizeof(board->dmi_sys_vendor) - 1);

        if ((item = cJSON_GetObjectItem(board_json, "dmi_product_name")))
            strncpy(board->dmi_product_name, item->valuestring, sizeof(board->dmi_product_name) - 1);

        if ((item = cJSON_GetObjectItem(board_json, "dmi_board_name")))
            strncpy(board->dmi_board_name, item->valuestring, sizeof(board->dmi_board_name) - 1);

        if ((item = cJSON_GetObjectItem(board_json, "compatibility"))) {
            const char *compat_str = item->valuestring;
            if (strcasecmp(compat_str, "supported") == 0)
                board->compatibility = COMPAT_SUPPORTED;
            else if (strcasecmp(compat_str, "libreboot") == 0)
                board->compatibility = COMPAT_LIBREBOOT;
            else if (strcasecmp(compat_str, "partial") == 0)
                board->compatibility = COMPAT_PARTIAL;
            else if (strcasecmp(compat_str, "experimental") == 0)
                board->compatibility = COMPAT_EXPERIMENTAL;
            else
                board->compatibility = COMPAT_UNSUPPORTED;
        }

        if ((item = cJSON_GetObjectItem(board_json, "coreboot_board_name")))
            strncpy(board->coreboot_board_name, item->valuestring, sizeof(board->coreboot_board_name) - 1);

        if ((item = cJSON_GetObjectItem(board_json, "status_notes")))
            strncpy(board->status_notes, item->valuestring, sizeof(board->status_notes) - 1);

        if ((item = cJSON_GetObjectItem(board_json, "fully_free")))
            board->fully_free = cJSON_IsTrue(item);

        if ((item = cJSON_GetObjectItem(board_json, "requires_external_flash")))
            board->requires_external_flash = cJSON_IsTrue(item);

        if ((item = cJSON_GetObjectItem(board_json, "migration_risk"))) {
            const char *risk_str = item->valuestring;
            if (strcasecmp(risk_str, "low") == 0)
                board->migration_risk = MIGRATION_RISK_LOW;
            else if (strcasecmp(risk_str, "medium") == 0)
                board->migration_risk = MIGRATION_RISK_MEDIUM;
            else if (strcasecmp(risk_str, "high") == 0)
                board->migration_risk = MIGRATION_RISK_HIGH;
            else
                board->migration_risk = MIGRATION_RISK_CRITICAL;
        }

        if ((item = cJSON_GetObjectItem(board_json, "risk_notes")))
            strncpy(board->risk_notes, item->valuestring, sizeof(board->risk_notes) - 1);

        /* Parse migration steps array */
        cJSON *steps = cJSON_GetObjectItem(board_json, "migration_steps");
        if (steps && cJSON_IsArray(steps)) {
            int step_count = cJSON_GetArraySize(steps);
            board->step_count = step_count > 16 ? 16 : step_count;

            cJSON *step_item;
            int idx = 0;
            cJSON_ArrayForEach(step_item, steps) {
                if (idx >= 16) break;
                if (cJSON_IsString(step_item)) {
                    strncpy(board->migration_steps[idx], step_item->valuestring, 255);
                    idx++;
                }
            }
        }

        if ((item = cJSON_GetObjectItem(board_json, "documentation_url")))
            strncpy(board->documentation_url, item->valuestring, sizeof(board->documentation_url) - 1);

        if ((item = cJSON_GetObjectItem(board_json, "known_issues")))
            strncpy(board->known_issues, item->valuestring, sizeof(board->known_issues) - 1);

        parsed_count++;
    }

    board_database_count = parsed_count;
    FG_INFO("Loaded %d boards from database", board_database_count);
    ret = FG_SUCCESS;

cleanup:
    if (root) cJSON_Delete(root);
    if (json_data) free(json_data);

    if (ret != FG_SUCCESS && board_database) {
        free(board_database);
        board_database = NULL;
        board_database_count = 0;
    }

    return ret;
}

/* ============================================================================
 * Board Detection and Matching
 * ============================================================================ */

int coreboot_get_board_info(const dmi_snapshot_t *dmi,
                             coreboot_board_info_t *board_info) {
    if (!dmi || !board_info) {
        return FG_ERROR;
    }

    if (!board_database || board_database_count == 0) {
        FG_WARN("Board database not loaded");
        return FG_NOT_FOUND;
    }

    /* Search for matching board */
    for (int i = 0; i < board_database_count; i++) {
        coreboot_board_info_t *board = &board_database[i];

        /* Match system vendor and product name */
        bool vendor_match = str_match_case_insensitive(dmi->system_manufacturer, board->dmi_sys_vendor);
        bool product_match = str_match_case_insensitive(dmi->system_product, board->dmi_product_name);

        /* Also try partial matching for product name variations */
        if (!product_match) {
            product_match = str_contains_case_insensitive(dmi->system_product, board->dmi_product_name) ||
                            str_contains_case_insensitive(board->dmi_product_name, dmi->system_product);
        }

        /* Try board name match as fallback */
        bool board_match = false;
        if (board->dmi_board_name[0] != '\0') {
            board_match = str_match_case_insensitive(dmi->board_product, board->dmi_board_name);
        }

        if (vendor_match && (product_match || board_match)) {
            /* Found match */
            memcpy(board_info, board, sizeof(coreboot_board_info_t));
            FG_INFO("Board match found: %s %s", board->vendor, board->board_name);
            return FG_SUCCESS;
        }
    }

    FG_INFO("No matching board found in database");
    return FG_NOT_FOUND;
}

/* ============================================================================
 * Compatibility Check
 * ============================================================================ */

int coreboot_check_compatibility(coreboot_compat_result_t *result) {
    if (!result) {
        return FG_ERROR;
    }

    memset(result, 0, sizeof(coreboot_compat_result_t));

    FG_INFO("=== Coreboot Compatibility Check ===");

    /* Capture DMI information */
    if (baseline_capture_dmi(&result->detected_dmi) != FG_SUCCESS) {
        FG_WARN("Failed to capture DMI information");
        strncpy(result->summary, "Failed to detect hardware information",
                sizeof(result->summary) - 1);
        return FG_ERROR;
    }

    /* Capture CPU information */
    if (baseline_capture_cpu(&result->detected_cpu) != FG_SUCCESS) {
        FG_WARN("Failed to capture CPU information");
    }

    /* Copy BIOS info for display */
    strncpy(result->current_bios_vendor, result->detected_dmi.bios_vendor,
            sizeof(result->current_bios_vendor) - 1);
    strncpy(result->current_bios_version, result->detected_dmi.bios_version,
            sizeof(result->current_bios_version) - 1);

    /* Check for Intel ME or AMD PSP */
    intel_me_info_t me_info;
    amd_psp_info_t psp_info;

    if (probe_intel_me(&me_info) == FG_SUCCESS) {
        result->intel_me_present = true;
    }

    if (probe_amd_psp(&psp_info) == FG_SUCCESS) {
        result->amd_psp_present = true;
    }

    /* Look up board in database */
    int lookup_result = coreboot_get_board_info(&result->detected_dmi,
                                                  &result->board_info);

    if (lookup_result == FG_SUCCESS) {
        result->board_found = true;
        result->compatibility = result->board_info.compatibility;
        result->overall_risk = result->board_info.migration_risk;

        /* Assess migration readiness */
        if (result->compatibility == COMPAT_SUPPORTED ||
            result->compatibility == COMPAT_LIBREBOOT) {
            result->can_migrate = true;
            snprintf(result->readiness_reason, sizeof(result->readiness_reason),
                    "Board is %s by %s",
                    result->compatibility == COMPAT_LIBREBOOT ? "supported by Libreboot" : "supported by Coreboot",
                    result->compatibility == COMPAT_LIBREBOOT ? "Libreboot" : "Coreboot");
        } else if (result->compatibility == COMPAT_PARTIAL) {
            result->can_migrate = true;
            snprintf(result->readiness_reason, sizeof(result->readiness_reason),
                    "Partial support available - may require binary blobs");

            snprintf(result->warnings[result->warning_count++], 256,
                    "This board requires binary blobs for full functionality");
        } else if (result->compatibility == COMPAT_EXPERIMENTAL) {
            result->can_migrate = false;
            snprintf(result->readiness_reason, sizeof(result->readiness_reason),
                    "Experimental support only - high risk of issues");

            snprintf(result->warnings[result->warning_count++], 256,
                    "Experimental support may be incomplete or unstable");
        } else {
            result->can_migrate = false;
            snprintf(result->readiness_reason, sizeof(result->readiness_reason),
                    "Board is not supported by Coreboot/Libreboot");
        }

        /* Add warnings based on requirements */
        if (result->board_info.requires_external_flash && result->warning_count < 16) {
            snprintf(result->warnings[result->warning_count++], 256,
                    "Requires external SPI programmer (e.g., CH341A, Raspberry Pi)");
        }

        if (result->board_info.requires_hardware_mod && result->warning_count < 16) {
            snprintf(result->warnings[result->warning_count++], 256,
                    "Hardware modification required: %s",
                    result->board_info.hardware_mod_notes);
        }

        if (result->overall_risk >= MIGRATION_RISK_HIGH && result->warning_count < 16) {
            snprintf(result->warnings[result->warning_count++], 256,
                    "HIGH RISK: %s", result->board_info.risk_notes);
        }

    } else {
        result->board_found = false;
        result->compatibility = COMPAT_UNKNOWN;
        result->can_migrate = false;
        result->overall_risk = MIGRATION_RISK_CRITICAL;

        snprintf(result->readiness_reason, sizeof(result->readiness_reason),
                "Hardware not found in Coreboot/Libreboot database");

        snprintf(result->warnings[result->warning_count++], 256,
                "Unknown hardware - not in Coreboot compatibility database");
    }

    /* Generate summary */
    if (result->board_found) {
        snprintf(result->summary, sizeof(result->summary),
                "Detected: %s %s | Status: %s | Risk: %s | Can Migrate: %s",
                result->detected_dmi.system_manufacturer,
                result->detected_dmi.system_product,
                coreboot_compat_to_str(result->compatibility),
                coreboot_risk_to_str(result->overall_risk),
                result->can_migrate ? "YES" : "NO");
    } else {
        snprintf(result->summary, sizeof(result->summary),
                "Detected: %s %s | Status: NOT IN DATABASE | Cannot migrate",
                result->detected_dmi.system_manufacturer,
                result->detected_dmi.system_product);
    }

    FG_INFO("%s", result->summary);
    return FG_SUCCESS;
}

/* ============================================================================
 * Migration Steps
 * ============================================================================ */

int coreboot_migration_steps(const coreboot_compat_result_t *compat,
                              char *steps_output,
                              size_t output_size) {
    if (!compat || !steps_output || output_size == 0) {
        return FG_ERROR;
    }

    if (!compat->board_found || !compat->can_migrate) {
        snprintf(steps_output, output_size,
                "Migration not possible: %s\n", compat->readiness_reason);
        return FG_NOT_SUPPORTED;
    }

    char *ptr = steps_output;
    size_t remaining = output_size;
    int written;

    written = snprintf(ptr, remaining,
            "\n=== Coreboot Migration Steps for %s %s ===\n\n",
            compat->board_info.vendor, compat->board_info.board_name);
    ptr += written;
    remaining -= written;

    /* Print migration steps */
    for (int i = 0; i < compat->board_info.step_count && remaining > 0; i++) {
        written = snprintf(ptr, remaining, "%d. %s\n",
                i + 1, compat->board_info.migration_steps[i]);
        ptr += written;
        remaining -= written;
    }

    /* Add important warnings */
    if (remaining > 0) {
        written = snprintf(ptr, remaining,
                "\nIMPORTANT WARNINGS:\n");
        ptr += written;
        remaining -= written;
    }

    for (int i = 0; i < compat->warning_count && remaining > 0; i++) {
        written = snprintf(ptr, remaining, "  - %s\n", compat->warnings[i]);
        ptr += written;
        remaining -= written;
    }

    /* Add risk notice */
    if (remaining > 0) {
        written = snprintf(ptr, remaining,
                "\nRISK LEVEL: %s\n%s\n",
                coreboot_risk_to_str(compat->overall_risk),
                compat->board_info.risk_notes);
        ptr += written;
        remaining -= written;
    }

    return FG_SUCCESS;
}

/* ============================================================================
 * Firmware Backup
 * ============================================================================ */

int coreboot_backup_current(firmware_backup_t *backup) {
    if (!backup) {
        return FG_ERROR;
    }

    memset(backup, 0, sizeof(firmware_backup_t));

    FG_INFO("=== Backing Up Current Firmware ===");

    /* Check if flashrom is available */
    if (coreboot_check_flashrom() != FG_SUCCESS) {
        FG_LOG_ERROR("flashrom is not available - cannot backup firmware");
        return FG_NOT_FOUND;
    }

    /* Generate backup filename with timestamp */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    if (tm_info) {
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
    } else {
        /* Fallback to epoch time if localtime fails */
        snprintf(timestamp, sizeof(timestamp), "%ld", (long)now);
    }
    strncpy(backup->timestamp, timestamp, sizeof(backup->timestamp) - 1);

    /* Create backup directory if it doesn't exist */
    const char *backup_dir = "/var/lib/firmwareguard/backups";
    mkdir("/var/lib/firmwareguard", 0700);
    mkdir(backup_dir, 0700);

    snprintf(backup->backup_path, sizeof(backup->backup_path),
            "%s/firmware_backup_%s.bin", backup_dir, timestamp);

    /* Execute flashrom to read firmware */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
            "flashrom -p internal -r \"%s\" 2>&1",
            backup->backup_path);

    FG_INFO("Executing: flashrom -p internal -r %s", backup->backup_path);
    FG_WARN("This may take several minutes...");

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        FG_LOG_ERROR("Failed to execute flashrom");
        return FG_ERROR;
    }

    /* Read flashrom output */
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        FG_DEBUG("%s", line);
    }

    int status = pclose(fp);
    if (status != 0) {
        FG_LOG_ERROR("flashrom failed with status %d", status);
        return FG_ERROR;
    }

    /* Verify backup file exists and get size */
    struct stat st;
    if (stat(backup->backup_path, &st) != 0) {
        FG_LOG_ERROR("Backup file not created: %s", backup->backup_path);
        return FG_ERROR;
    }

    backup->flash_size = st.st_size;
    FG_INFO("Firmware backup created: %s (%llu bytes)",
            backup->backup_path, (unsigned long long)backup->flash_size);

    /* Calculate SHA-256 hash */
    snprintf(cmd, sizeof(cmd), "sha256sum \"%s\" 2>/dev/null", backup->backup_path);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            /* Extract hash (first field) */
            char *space = strchr(line, ' ');
            if (space) {
                *space = '\0';
                strncpy(backup->hash_sha256, line, sizeof(backup->hash_sha256) - 1);
            }
        }
        pclose(fp);
    }

    if (backup->hash_sha256[0] != '\0') {
        FG_INFO("Backup SHA-256: %s", backup->hash_sha256);
        backup->verified = true;
    } else {
        FG_WARN("Could not calculate backup hash");
        backup->verified = false;
    }

    snprintf(backup->notes, sizeof(backup->notes),
            "Backup created before Coreboot migration");

    FG_INFO("=== Firmware Backup Complete ===");
    return FG_SUCCESS;
}

int coreboot_verify_backup(const firmware_backup_t *backup) {
    if (!backup || backup->backup_path[0] == '\0') {
        return FG_ERROR;
    }

    FG_INFO("Verifying firmware backup: %s", backup->backup_path);

    /* Check file exists */
    struct stat st;
    if (stat(backup->backup_path, &st) != 0) {
        FG_LOG_ERROR("Backup file not found: %s", backup->backup_path);
        return FG_NOT_FOUND;
    }

    /* Verify size matches */
    if (backup->flash_size > 0 && (uint64_t)st.st_size != backup->flash_size) {
        FG_LOG_ERROR("Backup file size mismatch: expected %llu, got %lld",
                (unsigned long long)backup->flash_size, (long long)st.st_size);
        return FG_ERROR;
    }

    /* Verify hash if available */
    if (backup->hash_sha256[0] != '\0') {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "sha256sum \"%s\" 2>/dev/null", backup->backup_path);

        FILE *fp = popen(cmd, "r");
        if (fp) {
            char line[256];
            if (fgets(line, sizeof(line), fp)) {
                char hash[65] = {0};
                char *space = strchr(line, ' ');
                if (space) {
                    *space = '\0';
                    strncpy(hash, line, sizeof(hash) - 1);
                }

                if (strcmp(hash, backup->hash_sha256) == 0) {
                    FG_INFO("Backup verification successful");
                    pclose(fp);
                    return FG_SUCCESS;
                } else {
                    FG_LOG_ERROR("Hash mismatch - backup may be corrupted");
                    pclose(fp);
                    return FG_ERROR;
                }
            }
            pclose(fp);
        }
    }

    FG_INFO("Backup file exists and size is correct");
    return FG_SUCCESS;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

int coreboot_check_flashrom(void) {
    /* Check if flashrom is installed */
    int ret = system("which flashrom >/dev/null 2>&1");
    if (ret != 0) {
        FG_WARN("flashrom is not installed");
        FG_INFO("Install with: sudo apt install flashrom");
        return FG_NOT_FOUND;
    }

    /* Check if we have permissions */
    ret = system("flashrom --version >/dev/null 2>&1");
    if (ret != 0) {
        FG_WARN("Cannot execute flashrom");
        return FG_NO_PERMISSION;
    }

    return FG_SUCCESS;
}

int coreboot_detect_flash_chip(flash_chip_info_t *chip) {
    if (!chip) {
        return FG_ERROR;
    }

    memset(chip, 0, sizeof(flash_chip_info_t));

    /* Execute flashrom to detect chip */
    FILE *fp = popen("flashrom -p internal 2>&1", "r");
    if (!fp) {
        return FG_ERROR;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        /* Look for flash chip detection */
        if (strstr(line, "Found") && strstr(line, "flash chip")) {
            /* Try to extract chip name */
            char *start = strstr(line, "\"");
            if (start) {
                start++;
                char *end = strstr(start, "\"");
                if (end) {
                    size_t len = end - start;
                    if (len < sizeof(chip->model)) {
                        strncpy(chip->model, start, len);
                        chip->model[len] = '\0';
                    }
                }
            }
        }
    }

    pclose(fp);

    if (chip->model[0] != '\0') {
        strncpy(chip->interface, "SPI", sizeof(chip->interface) - 1);
        chip->internal_programmer = true;
        FG_INFO("Detected flash chip: %s", chip->model);
        return FG_SUCCESS;
    }

    return FG_NOT_FOUND;
}

void coreboot_print_warning_banner(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════════╗\n");
    printf("║                    ⚠️  CRITICAL WARNING ⚠️                         ║\n");
    printf("╠═══════════════════════════════════════════════════════════════════╣\n");
    printf("║                                                                   ║\n");
    printf("║  Flashing Coreboot/Libreboot can PERMANENTLY BRICK your device!  ║\n");
    printf("║                                                                   ║\n");
    printf("║  RISKS:                                                           ║\n");
    printf("║  • Device may become completely unbootable                        ║\n");
    printf("║  • Data loss is possible                                          ║\n");
    printf("║  • Hardware damage in extreme cases                               ║\n");
    printf("║  • Warranty will be VOID                                          ║\n");
    printf("║                                                                   ║\n");
    printf("║  REQUIREMENTS:                                                    ║\n");
    printf("║  • ALWAYS create a backup first (use --backup command)            ║\n");
    printf("║  • Have external SPI programmer ready for recovery                ║\n");
    printf("║  • Read ALL documentation before proceeding                       ║\n");
    printf("║  • Ensure stable power supply during flashing                     ║\n");
    printf("║                                                                   ║\n");
    printf("║  FirmwareGuard provides guidance only - YOU assume all risk!      ║\n");
    printf("║                                                                   ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

/* ============================================================================
 * Display Functions
 * ============================================================================ */

void coreboot_print_compatibility(const coreboot_compat_result_t *result,
                                   bool verbose) {
    if (!result) return;

    printf("\n");
    printf("=== Coreboot/Libreboot Compatibility Report ===\n\n");

    /* Detected Hardware */
    printf("Detected Hardware:\n");
    printf("  Manufacturer: %s\n", result->detected_dmi.system_manufacturer);
    printf("  Product:      %s\n", result->detected_dmi.system_product);
    printf("  Board:        %s\n", result->detected_dmi.board_product);
    printf("  BIOS:         %s %s (%s)\n",
           result->current_bios_vendor,
           result->current_bios_version,
           result->detected_dmi.bios_date);
    printf("  CPU:          %s\n", result->detected_cpu.model_name);

    if (result->intel_me_present) {
        printf("  Intel ME:     Present\n");
    }
    if (result->amd_psp_present) {
        printf("  AMD PSP:      Present\n");
    }
    printf("\n");

    /* Compatibility Status */
    printf("Compatibility Status:\n");
    printf("  Database Match:  %s\n", result->board_found ? "YES" : "NO");

    if (result->board_found) {
        printf("  Compatibility:   %s\n", coreboot_compat_to_str(result->compatibility));
        printf("  Coreboot Board:  %s\n", result->board_info.coreboot_board_name);
        printf("  Migration Risk:  %s\n", coreboot_risk_to_str(result->overall_risk));
        printf("  Can Migrate:     %s\n", result->can_migrate ? "YES" : "NO");
        printf("  Status:          %s\n", result->readiness_reason);

        if (result->board_info.fully_free) {
            printf("  Fully Free:      YES (Libreboot compatible)\n");
        }
    } else {
        printf("  Status:          NOT IN DATABASE\n");
        printf("  Can Migrate:     NO\n");
    }
    printf("\n");

    /* Warnings */
    if (result->warning_count > 0) {
        printf("Warnings:\n");
        for (int i = 0; i < result->warning_count; i++) {
            printf("  ⚠️  %s\n", result->warnings[i]);
        }
        printf("\n");
    }

    /* Verbose details */
    if (verbose && result->board_found) {
        printf("Additional Information:\n");
        if (result->board_info.status_notes[0] != '\0') {
            printf("  Notes: %s\n", result->board_info.status_notes);
        }
        if (result->board_info.documentation_url[0] != '\0') {
            printf("  Documentation: %s\n", result->board_info.documentation_url);
        }
        if (result->board_info.known_issues[0] != '\0') {
            printf("  Known Issues: %s\n", result->board_info.known_issues);
        }
        printf("\n");
    }

    printf("Summary: %s\n", result->summary);
    printf("\n");
}

void coreboot_print_board_info(const coreboot_board_info_t *board,
                                bool verbose) {
    if (!board) return;

    printf("\n=== Board Information ===\n\n");
    printf("Board: %s %s\n", board->vendor, board->board_name);
    printf("Coreboot Name: %s\n", board->coreboot_board_name);
    printf("Compatibility: %s\n", coreboot_compat_to_str(board->compatibility));
    printf("Migration Risk: %s\n", coreboot_risk_to_str(board->migration_risk));
    printf("Fully Free: %s\n", board->fully_free ? "YES (Libreboot)" : "NO");
    printf("\n");

    if (board->status_notes[0] != '\0') {
        printf("Status: %s\n\n", board->status_notes);
    }

    if (board->requires_external_flash) {
        printf("⚠️  Requires external SPI programmer\n");
    }

    if (board->risk_notes[0] != '\0') {
        printf("Risk Notes: %s\n\n", board->risk_notes);
    }

    if (verbose) {
        if (board->documentation_url[0] != '\0') {
            printf("Documentation: %s\n", board->documentation_url);
        }
        if (board->known_issues[0] != '\0') {
            printf("Known Issues: %s\n", board->known_issues);
        }
    }
}

void coreboot_print_migration_steps(const coreboot_board_info_t *board) {
    if (!board || board->step_count == 0) {
        printf("No migration steps available.\n");
        return;
    }

    printf("\n=== Migration Steps for %s %s ===\n\n",
           board->vendor, board->board_name);

    for (int i = 0; i < board->step_count; i++) {
        printf("%d. %s\n", i + 1, board->migration_steps[i]);
    }

    printf("\n");
    printf("IMPORTANT:\n");
    printf("  Risk Level: %s\n", coreboot_risk_to_str(board->migration_risk));
    if (board->risk_notes[0] != '\0') {
        printf("  %s\n", board->risk_notes);
    }
    printf("\n");
}
