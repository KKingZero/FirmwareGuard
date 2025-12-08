#include "pattern_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <glob.h>
#include <regex.h>

/* Forward declarations of detection helpers */
static bool match_pci_device(const pci_criteria_t *crit, char *details, size_t details_len);
static bool match_msr_register(const msr_criteria_t *crit, char *details, size_t details_len);
static bool match_file_exists(const file_criteria_t *crit, char *details, size_t details_len);
static bool match_file_content(const file_criteria_t *crit, char *details, size_t details_len);
static bool match_acpi_table(const acpi_criteria_t *crit, char *details, size_t details_len);
static bool match_sysfs_value(const sysfs_criteria_t *crit, char *details, size_t details_len);

/**
 * Match a single pattern against the system
 */
bool pattern_match(const pattern_t *pattern, pattern_match_t *result) {
    if (!pattern || !result) {
        return false;
    }

    // Initialize result
    result->pattern = pattern;
    result->matched = false;
    result->match_details[0] = '\0';
    result->confidence_score = pattern->confidence;

    // Skip disabled patterns
    if (!pattern->enabled) {
        return false;
    }

    // Match based on detection method
    bool matched = false;
    switch (pattern->detection.method) {
        case DETECTION_METHOD_PCI_DEVICE:
            matched = match_pci_device(&pattern->detection.criteria.pci,
                                       result->match_details,
                                       sizeof(result->match_details));
            break;

        case DETECTION_METHOD_MSR_REGISTER:
            matched = match_msr_register(&pattern->detection.criteria.msr,
                                         result->match_details,
                                         sizeof(result->match_details));
            break;

        case DETECTION_METHOD_FILE_EXISTS:
            matched = match_file_exists(&pattern->detection.criteria.file,
                                        result->match_details,
                                        sizeof(result->match_details));
            break;

        case DETECTION_METHOD_FILE_CONTENT:
            matched = match_file_content(&pattern->detection.criteria.file,
                                         result->match_details,
                                         sizeof(result->match_details));
            break;

        case DETECTION_METHOD_ACPI_TABLE:
            matched = match_acpi_table(&pattern->detection.criteria.acpi,
                                       result->match_details,
                                       sizeof(result->match_details));
            break;

        case DETECTION_METHOD_SYSFS_VALUE:
            matched = match_sysfs_value(&pattern->detection.criteria.sysfs,
                                        result->match_details,
                                        sizeof(result->match_details));
            break;

        case DETECTION_METHOD_COMBINATION:
            // TODO: Implement combination matching
            snprintf(result->match_details, sizeof(result->match_details),
                    "Combination matching not yet implemented");
            matched = false;
            break;

        default:
            snprintf(result->match_details, sizeof(result->match_details),
                    "Unknown detection method: %d", pattern->detection.method);
            matched = false;
            break;
    }

    result->matched = matched;
    return matched;
}

/**
 * Match all patterns in the database
 */
int pattern_match_all(pattern_db_t *db, pattern_match_t **results) {
    if (!db || !results) {
        return -1;
    }

    // Allocate results array
    pattern_match_t *matches = calloc(db->count, sizeof(pattern_match_t));
    if (!matches) {
        fprintf(stderr, "Failed to allocate pattern match results\n");
        return -1;
    }

    int match_count = 0;
    printf("[Pattern Match] Checking %d patterns...\n", db->count);

    for (int i = 0; i < db->count; i++) {
        if (pattern_match(&db->patterns[i], &matches[match_count])) {
            printf("[Pattern Match] ✓ MATCH: %s - %s\n",
                   db->patterns[i].id, db->patterns[i].name);
            match_count++;
        }
    }

    printf("[Pattern Match] Found %d matches out of %d patterns\n", match_count, db->count);

    *results = matches;
    return match_count;
}

/* ============================================================================
 * Detection Helper Functions
 * ============================================================================ */

static bool match_pci_device(const pci_criteria_t *crit, char *details, size_t details_len) {
    char pci_path[256];

    // If full bus/device/function specified, check that specific device
    if (crit->has_bus && crit->has_dev && crit->has_func) {
        snprintf(pci_path, sizeof(pci_path),
                "/sys/bus/pci/devices/0000:%02x:%02x.%x",
                crit->bus, crit->device, crit->function);

        if (access(pci_path, F_OK) != 0) {
            return false;  // Device doesn't exist
        }

        // Read vendor ID
        char vendor_path[300];
        snprintf(vendor_path, sizeof(vendor_path), "%s/vendor", pci_path);

        FILE *fp = fopen(vendor_path, "r");
        if (!fp) {
            return false;
        }

        uint16_t vendor_id = 0;
        fscanf(fp, "0x%hx", &vendor_id);
        fclose(fp);

        // Check vendor match
        if (crit->has_vendor && vendor_id != crit->vendor_id) {
            return false;
        }

        // Read device ID
        char device_path[300];
        snprintf(device_path, sizeof(device_path), "%s/device", pci_path);

        fp = fopen(device_path, "r");
        if (!fp) {
            return false;
        }

        uint16_t device_id = 0;
        fscanf(fp, "0x%hx", &device_id);
        fclose(fp);

        // Check device match
        if (crit->has_device && device_id != crit->device_id) {
            return false;
        }

        snprintf(details, details_len,
                "PCI device found at %02x:%02x.%x (vendor=0x%04x, device=0x%04x)",
                crit->bus, crit->device, crit->function, vendor_id, device_id);

        return true;
    } else {
        // Search all PCI devices for vendor/device ID match
        glob_t glob_result;
        int ret = glob("/sys/bus/pci/devices/*/vendor", 0, NULL, &glob_result);

        if (ret != 0) {
            globfree(&glob_result);
            return false;
        }

        for (size_t i = 0; i < glob_result.gl_pathc; i++) {
            FILE *fp = fopen(glob_result.gl_pathv[i], "r");
            if (!fp) continue;

            uint16_t vendor_id = 0;
            fscanf(fp, "0x%hx", &vendor_id);
            fclose(fp);

            if (crit->has_vendor && vendor_id != crit->vendor_id) {
                continue;
            }

            // Read device ID from same directory
            char device_path[512];
            strncpy(device_path, glob_result.gl_pathv[i], sizeof(device_path) - 1);
            char *last_slash = strrchr(device_path, '/');
            if (last_slash) {
                strcpy(last_slash + 1, "device");

                fp = fopen(device_path, "r");
                if (!fp) continue;

                uint16_t device_id = 0;
                fscanf(fp, "0x%hx", &device_id);
                fclose(fp);

                if (crit->has_device && device_id != crit->device_id) {
                    continue;
                }

                // Match found!
                snprintf(details, details_len,
                        "PCI device found (vendor=0x%04x, device=0x%04x)",
                        vendor_id, device_id);

                globfree(&glob_result);
                return true;
            }
        }

        globfree(&glob_result);
        return false;
    }
}

static bool match_msr_register(const msr_criteria_t *crit, char *details, size_t details_len) {
    // MSR reading requires root and msr module
    // For now, return false with explanation
    // TODO: Implement MSR reading via /dev/cpu/0/msr

    snprintf(details, details_len,
            "MSR matching not yet implemented (register=0x%lx)",
            crit->register_addr);

    return false;
}

static bool match_file_exists(const file_criteria_t *crit, char *details, size_t details_len) {
    if (!crit->path[0]) {
        return false;
    }

    // Check if path contains wildcard
    if (strchr(crit->path, '*') || strchr(crit->path, '?')) {
        // Use glob to match
        glob_t glob_result;
        int ret = glob(crit->path, 0, NULL, &glob_result);

        if (ret == 0 && glob_result.gl_pathc > 0) {
            snprintf(details, details_len,
                    "File exists: %s (matched %zu files)",
                    glob_result.gl_pathv[0], glob_result.gl_pathc);
            globfree(&glob_result);
            return true;
        }

        globfree(&glob_result);
        return false;
    } else {
        // Direct file check
        if (access(crit->path, F_OK) == 0) {
            snprintf(details, details_len, "File exists: %s", crit->path);
            return true;
        }
        return false;
    }
}

static bool match_file_content(const file_criteria_t *crit, char *details, size_t details_len) {
    if (!crit->path[0]) {
        return false;
    }

    FILE *fp = fopen(crit->path, "r");
    if (!fp) {
        return false;
    }

    char buffer[4096];
    bool match_found = false;

    // If regex is specified
    if (crit->regex[0]) {
        regex_t regex;
        int ret = regcomp(&regex, crit->regex, REG_EXTENDED | REG_NOSUB);
        if (ret != 0) {
            fclose(fp);
            return false;
        }

        while (fgets(buffer, sizeof(buffer), fp)) {
            if (regexec(&regex, buffer, 0, NULL, 0) == 0) {
                match_found = true;
                snprintf(details, details_len,
                        "File content matches regex: %s", crit->regex);
                break;
            }
        }

        regfree(&regex);
    }
    // If contains string is specified
    else if (crit->contains[0]) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, crit->contains)) {
                match_found = true;
                snprintf(details, details_len,
                        "File contains: '%s'", crit->contains);
                break;
            }
        }
    }

    fclose(fp);
    return match_found;
}

static bool match_acpi_table(const acpi_criteria_t *crit, char *details, size_t details_len) {
    if (!crit->path[0]) {
        // Use default path based on signature
        char path[256];
        snprintf(path, sizeof(path), "/sys/firmware/acpi/tables/%s", crit->signature);

        if (access(path, F_OK) == 0) {
            snprintf(details, details_len,
                    "ACPI table found: %s", crit->signature);
            return true;
        }
        return false;
    } else {
        // Use specified path
        if (access(crit->path, F_OK) == 0) {
            snprintf(details, details_len,
                    "ACPI table found: %s", crit->path);
            return true;
        }
        return false;
    }
}

static bool match_sysfs_value(const sysfs_criteria_t *crit, char *details, size_t details_len) {
    if (!crit->path[0]) {
        return false;
    }

    // Handle wildcards in path
    if (strchr(crit->path, '*') || strchr(crit->path, '?')) {
        glob_t glob_result;
        int ret = glob(crit->path, 0, NULL, &glob_result);

        if (ret != 0) {
            globfree(&glob_result);
            return false;
        }

        // Check each matched file
        for (size_t i = 0; i < glob_result.gl_pathc; i++) {
            FILE *fp = fopen(glob_result.gl_pathv[i], "r");
            if (!fp) continue;

            char value[256];
            if (fgets(value, sizeof(value), fp)) {
                // Remove trailing newline
                value[strcspn(value, "\n")] = 0;

                // Check if value matches expected
                if (crit->expected_value[0]) {
                    if (strcmp(value, crit->expected_value) == 0) {
                        snprintf(details, details_len,
                                "Sysfs value matches: %s = %s",
                                glob_result.gl_pathv[i], value);
                        fclose(fp);
                        globfree(&glob_result);
                        return true;
                    }
                } else {
                    // Just check if file is readable and has content
                    snprintf(details, details_len,
                            "Sysfs attribute exists: %s", glob_result.gl_pathv[i]);
                    fclose(fp);
                    globfree(&glob_result);
                    return true;
                }
            }

            fclose(fp);
        }

        globfree(&glob_result);
        return false;
    } else {
        // Direct path check
        FILE *fp = fopen(crit->path, "r");
        if (!fp) {
            return false;
        }

        char value[256];
        if (fgets(value, sizeof(value), fp)) {
            value[strcspn(value, "\n")] = 0;

            if (crit->expected_value[0]) {
                if (strcmp(value, crit->expected_value) == 0) {
                    snprintf(details, details_len,
                            "Sysfs value matches: %s = %s",
                            crit->path, value);
                    fclose(fp);
                    return true;
                }
            } else {
                snprintf(details, details_len,
                        "Sysfs attribute readable: %s", crit->path);
                fclose(fp);
                return true;
            }
        }

        fclose(fp);
        return false;
    }
}
