#include "uefi_extract.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define EFIVARS_PATH "/sys/firmware/efi/efivars"
#define INITIAL_VAR_CAPACITY 256

/* Forward declarations */
static void add_finding(uefi_analysis_result_t *result, const char *finding);
static void compute_simple_hash(const uint8_t *data, size_t len, uint8_t *hash, char *hex_out);
static bool is_boot_variable(const char *name);
static bool is_secure_boot_variable(const char *name);
static bool is_driver_variable(const char *name);

int uefi_extract_init(void) {
    FG_INFO("Initializing UEFI extraction subsystem...");

    /* Check if EFI variables are accessible */
    struct stat st;
    if (stat(EFIVARS_PATH, &st) != 0) {
        FG_WARN("EFI variables not accessible at %s", EFIVARS_PATH);
        FG_WARN("System may not be booted in UEFI mode");
        return FG_NOT_SUPPORTED;
    }

    FG_INFO("UEFI extraction subsystem initialized");
    return FG_SUCCESS;
}

void uefi_extract_cleanup(void) {
    FG_INFO("UEFI extraction subsystem cleaned up");
}

/* Simple FNV-1a based hash (not cryptographic, just for fingerprinting) */
static void compute_simple_hash(const uint8_t *data, size_t len, uint8_t *hash, char *hex_out) {
    /* FNV-1a 256-bit hash approximation using multiple 64-bit hashes */
    uint64_t h[4] = {0xcbf29ce484222325ULL, 0xcbf29ce484222325ULL,
                     0xcbf29ce484222325ULL, 0xcbf29ce484222325ULL};
    const uint64_t prime = 0x100000001b3ULL;

    for (size_t i = 0; i < len; i++) {
        int idx = i % 4;
        h[idx] ^= data[i];
        h[idx] *= prime;
    }

    /* Store as 32 bytes */
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            hash[i * 8 + j] = (h[i] >> (j * 8)) & 0xFF;
        }
    }

    if (hex_out) {
        for (int i = 0; i < 32; i++) {
            sprintf(hex_out + (i * 2), "%02x", hash[i]);
        }
        hex_out[64] = '\0';
    }
}

static bool is_boot_variable(const char *name) {
    return (strncmp(name, "Boot", 4) == 0 ||
            strncmp(name, "Driver", 6) == 0 ||
            strncmp(name, "Key", 3) == 0 ||
            strcmp(name, "BootOrder") == 0 ||
            strcmp(name, "BootNext") == 0 ||
            strcmp(name, "BootCurrent") == 0 ||
            strcmp(name, "Timeout") == 0);
}

static bool is_secure_boot_variable(const char *name) {
    return (strcmp(name, "SecureBoot") == 0 ||
            strcmp(name, "SetupMode") == 0 ||
            strcmp(name, "PK") == 0 ||
            strcmp(name, "KEK") == 0 ||
            strcmp(name, "db") == 0 ||
            strcmp(name, "dbx") == 0 ||
            strcmp(name, "dbt") == 0 ||
            strcmp(name, "dbr") == 0 ||
            strcmp(name, "AuditMode") == 0 ||
            strcmp(name, "DeployedMode") == 0 ||
            strstr(name, "SecureBoot") != NULL);
}

static bool is_driver_variable(const char *name) {
    return (strncmp(name, "Driver", 6) == 0 ||
            strstr(name, "DXE") != NULL ||
            strstr(name, "Driver") != NULL ||
            strstr(name, "Protocol") != NULL);
}

static void add_finding(uefi_analysis_result_t *result, const char *finding) {
    if (result->finding_count < 32) {
        strncpy(result->findings[result->finding_count], finding,
                sizeof(result->findings[0]) - 1);
        result->finding_count++;
    }
}

int uefi_get_variable(const char *name, const char *guid, uefi_var_info_t *var) {
    char path[768];
    struct stat st;
    FILE *fp;
    uint8_t *data = NULL;
    size_t data_size;

    if (!name || !guid || !var) {
        return FG_ERROR;
    }

    memset(var, 0, sizeof(uefi_var_info_t));

    /* Build path */
    snprintf(path, sizeof(path), "%s/%s-%s", EFIVARS_PATH, name, guid);

    if (stat(path, &st) != 0) {
        return FG_NOT_FOUND;
    }

    /* Store basic info */
    strncpy(var->name, name, sizeof(var->name) - 1);
    strncpy(var->guid, guid, sizeof(var->guid) - 1);
    strncpy(var->full_path, path, sizeof(var->full_path) - 1);
    var->data_size = st.st_size > 4 ? st.st_size - 4 : 0; /* Subtract attributes */

    /* Categorize */
    var->is_boot_variable = is_boot_variable(name);
    var->is_secure_boot_related = is_secure_boot_variable(name);
    var->is_driver_related = is_driver_variable(name);

    /* Read attributes and compute hash */
    fp = fopen(path, "rb");
    if (fp) {
        /* First 4 bytes are attributes */
        if (fread(&var->attributes, sizeof(uint32_t), 1, fp) == 1) {
            /* Read rest for hashing */
            data_size = st.st_size - 4;
            if (data_size > 0) {
                data = malloc(data_size);
                if (data) {
                    if (fread(data, 1, data_size, fp) == data_size) {
                        compute_simple_hash(data, data_size, var->sha256, var->sha256_hex);
                    }
                    free(data);
                }
            }
        }
        fclose(fp);
    }

    return FG_SUCCESS;
}

int uefi_enumerate_variables(uefi_enum_result_t *result) {
    DIR *dir;
    struct dirent *entry;
    char name[256];
    char guid[64];
    int count = 0;

    if (!result) {
        return FG_ERROR;
    }

    memset(result, 0, sizeof(uefi_enum_result_t));

    FG_INFO("Enumerating UEFI variables from %s...", EFIVARS_PATH);

    dir = opendir(EFIVARS_PATH);
    if (!dir) {
        FG_LOG_ERROR("Cannot open %s: %s", EFIVARS_PATH, strerror(errno));
        return FG_ERROR;
    }

    /* Allocate initial capacity */
    result->variables_capacity = INITIAL_VAR_CAPACITY;
    result->variables = calloc(result->variables_capacity, sizeof(uefi_var_info_t));
    if (!result->variables) {
        closedir(dir);
        return FG_ERROR;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        /* Parse name and GUID from filename (format: Name-GUID) */
        char *dash = strrchr(entry->d_name, '-');
        if (!dash || (dash - entry->d_name) < 1) continue;

        /* Skip if it looks like a GUID component (8-4-4-4-12 format) */
        /* Find the GUID start (last 36 chars including dashes) */
        size_t len = strlen(entry->d_name);
        if (len < 38) continue; /* minimum: X-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx */

        /* Find GUID position (36 chars from end, after a dash) */
        char *guid_start = entry->d_name + len - 36;
        if (guid_start <= entry->d_name || *(guid_start - 1) != '-') continue;

        /* Extract name (everything before the GUID dash) */
        size_t name_len = guid_start - entry->d_name - 1;
        if (name_len >= sizeof(name)) name_len = sizeof(name) - 1;
        strncpy(name, entry->d_name, name_len);
        name[name_len] = '\0';

        /* Extract GUID */
        strncpy(guid, guid_start, sizeof(guid) - 1);
        guid[sizeof(guid) - 1] = '\0';

        /* Get variable info */
        if (result->var_count >= result->variables_capacity) {
            /* Expand capacity */
            int new_capacity = result->variables_capacity * 2;
            uefi_var_info_t *new_vars = realloc(result->variables,
                                                 new_capacity * sizeof(uefi_var_info_t));
            if (!new_vars) {
                FG_WARN("Cannot expand variable array, stopping enumeration");
                break;
            }
            result->variables = new_vars;
            result->variables_capacity = new_capacity;
        }

        if (uefi_get_variable(name, guid, &result->variables[result->var_count]) == FG_SUCCESS) {
            uefi_var_info_t *v = &result->variables[result->var_count];

            if (v->is_boot_variable) result->boot_var_count++;
            if (v->is_secure_boot_related) result->secure_boot_count++;
            if (v->is_driver_related) result->driver_count++;

            result->var_count++;
            count++;
        }
    }

    closedir(dir);

    /* Check Secure Boot status */
    uefi_check_secure_boot(result);

    /* Generate summary */
    snprintf(result->summary, sizeof(result->summary),
            "UEFI Enumeration: %d variables found (%d boot, %d secure boot, %d driver-related). "
            "Secure Boot: %s, Setup Mode: %s",
            result->var_count, result->boot_var_count,
            result->secure_boot_count, result->driver_count,
            result->secure_boot_enabled ? "Enabled" : "Disabled",
            result->setup_mode ? "Yes" : "No");

    FG_INFO("%s", result->summary);

    return FG_SUCCESS;
}

int uefi_check_secure_boot(uefi_enum_result_t *result) {
    uefi_var_info_t var;
    char path[768];
    FILE *fp;
    uint32_t attrs;
    uint8_t value;

    if (!result) return FG_ERROR;

    /* Check SecureBoot variable */
    snprintf(path, sizeof(path), "%s/SecureBoot-%s", EFIVARS_PATH, UEFI_GLOBAL_VARIABLE_GUID);
    fp = fopen(path, "rb");
    if (fp) {
        if (fread(&attrs, sizeof(uint32_t), 1, fp) == 1 &&
            fread(&value, sizeof(uint8_t), 1, fp) == 1) {
            result->secure_boot_enabled = (value == 1);
        }
        fclose(fp);
    }

    /* Check SetupMode variable */
    snprintf(path, sizeof(path), "%s/SetupMode-%s", EFIVARS_PATH, UEFI_GLOBAL_VARIABLE_GUID);
    fp = fopen(path, "rb");
    if (fp) {
        if (fread(&attrs, sizeof(uint32_t), 1, fp) == 1 &&
            fread(&value, sizeof(uint8_t), 1, fp) == 1) {
            result->setup_mode = (value == 1);
        }
        fclose(fp);
    }

    /* Check AuditMode */
    snprintf(path, sizeof(path), "%s/AuditMode-%s", EFIVARS_PATH, UEFI_GLOBAL_VARIABLE_GUID);
    fp = fopen(path, "rb");
    if (fp) {
        if (fread(&attrs, sizeof(uint32_t), 1, fp) == 1 &&
            fread(&value, sizeof(uint8_t), 1, fp) == 1) {
            result->audit_mode = (value == 1);
        }
        fclose(fp);
    }

    /* Check DeployedMode */
    snprintf(path, sizeof(path), "%s/DeployedMode-%s", EFIVARS_PATH, UEFI_GLOBAL_VARIABLE_GUID);
    fp = fopen(path, "rb");
    if (fp) {
        if (fread(&attrs, sizeof(uint32_t), 1, fp) == 1 &&
            fread(&value, sizeof(uint8_t), 1, fp) == 1) {
            result->deployed_mode = (value == 1);
        }
        fclose(fp);
    }

    return FG_SUCCESS;
}

int spi_check_flashrom(void) {
    int ret = system("which flashrom >/dev/null 2>&1");
    if (ret != 0) {
        FG_WARN("flashrom not found - SPI extraction unavailable");
        FG_WARN("Install with: sudo apt install flashrom");
        return FG_NOT_FOUND;
    }
    return FG_SUCCESS;
}

int spi_detect_chip(spi_extract_result_t *result) {
    FILE *fp;
    char buffer[512];

    if (!result) return FG_ERROR;

    memset(result, 0, sizeof(spi_extract_result_t));

    if (spi_check_flashrom() != FG_SUCCESS) {
        result->flashrom_available = false;
        return FG_NOT_FOUND;
    }

    result->flashrom_available = true;

    /* Run flashrom to detect chip */
    fp = popen("flashrom -p internal 2>&1", "r");
    if (!fp) {
        FG_LOG_ERROR("Failed to run flashrom");
        return FG_ERROR;
    }

    while (fgets(buffer, sizeof(buffer), fp)) {
        /* Look for chip detection line */
        if (strstr(buffer, "Found") && strstr(buffer, "flash chip")) {
            /* Extract chip name */
            char *start = strstr(buffer, "\"");
            if (start) {
                start++;
                char *end = strstr(start, "\"");
                if (end) {
                    size_t len = end - start;
                    if (len >= sizeof(result->chip_name)) {
                        len = sizeof(result->chip_name) - 1;
                    }
                    strncpy(result->chip_name, start, len);
                    result->chip_name[len] = '\0';
                }
            }
        }
        /* Look for size */
        if (strstr(buffer, "kB") || strstr(buffer, "MB")) {
            char *size_str = strstr(buffer, "(");
            if (size_str) {
                unsigned long size;
                if (sscanf(size_str, "(%lu kB)", &size) == 1) {
                    result->flash_size = size * 1024;
                } else if (sscanf(size_str, "(%lu MB)", &size) == 1) {
                    result->flash_size = size * 1024 * 1024;
                }
            }
        }
    }

    pclose(fp);

    if (result->chip_name[0]) {
        FG_INFO("Detected flash chip: %s (%lu bytes)", result->chip_name, result->flash_size);
        return FG_SUCCESS;
    }

    FG_WARN("No flash chip detected - may require root or specific programmer");
    return FG_NOT_FOUND;
}

int spi_dump_flash(const char *output_path, spi_extract_result_t *result) {
    char cmd[1024];
    int ret;

    if (!output_path || !result) return FG_ERROR;

    if (!result->flashrom_available) {
        if (spi_check_flashrom() != FG_SUCCESS) {
            return FG_NOT_FOUND;
        }
        result->flashrom_available = true;
    }

    FG_INFO("Dumping full SPI flash to %s...", output_path);
    FG_WARN("This may take several minutes...");

    snprintf(cmd, sizeof(cmd), "flashrom -p internal -r \"%s\" 2>&1", output_path);

    ret = system(cmd);
    if (ret != 0) {
        FG_LOG_ERROR("flashrom dump failed (exit code %d)", ret);
        return FG_ERROR;
    }

    strncpy(result->full_dump_path, output_path, sizeof(result->full_dump_path) - 1);
    result->extraction_successful = true;

    /* Compute hash of dump */
    struct stat st;
    if (stat(output_path, &st) == 0) {
        result->flash_size = st.st_size;
        FG_INFO("Flash dump complete: %lu bytes", result->flash_size);
    }

    return FG_SUCCESS;
}

int spi_dump_region(const char *region, const char *output_path, spi_extract_result_t *result) {
    char cmd[1024];
    int ret;

    if (!region || !output_path || !result) return FG_ERROR;

    if (!result->flashrom_available) {
        if (spi_check_flashrom() != FG_SUCCESS) {
            return FG_NOT_FOUND;
        }
        result->flashrom_available = true;
    }

    FG_INFO("Dumping %s region to %s...", region, output_path);

    snprintf(cmd, sizeof(cmd), "flashrom -p internal --ifd -i %s -r \"%s\" 2>&1",
             region, output_path);

    ret = system(cmd);
    if (ret != 0) {
        FG_WARN("Region dump failed - IFD may not be supported");
        return FG_ERROR;
    }

    return FG_SUCCESS;
}

int spi_extract_regions(const char *dump_path, const char *output_dir, spi_extract_result_t *result) {
    /* This would use ifdtool or similar to parse the Intel Flash Descriptor */
    /* For now, just note that we'd need external tools */

    if (!dump_path || !output_dir || !result) return FG_ERROR;

    FG_INFO("Region extraction from %s to %s", dump_path, output_dir);
    FG_WARN("Full region parsing requires ifdtool - checking availability...");

    int ret = system("which ifdtool >/dev/null 2>&1");
    if (ret != 0) {
        FG_WARN("ifdtool not found - region parsing unavailable");
        FG_WARN("Install from coreboot utils or build from source");
        return FG_NOT_SUPPORTED;
    }

    strncpy(result->output_dir, output_dir, sizeof(result->output_dir) - 1);

    /* Run ifdtool to extract regions */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "cd \"%s\" && ifdtool -x \"%s\" 2>&1", output_dir, dump_path);

    ret = system(cmd);
    if (ret != 0) {
        FG_WARN("ifdtool extraction failed");
        return FG_ERROR;
    }

    FG_INFO("Regions extracted to %s", output_dir);
    return FG_SUCCESS;
}

int uefi_full_analysis(uefi_analysis_result_t *result, bool include_spi) {
    int ret;

    if (!result) return FG_ERROR;

    memset(result, 0, sizeof(uefi_analysis_result_t));

    FG_INFO("Starting full UEFI analysis...");

    /* Runtime enumeration */
    ret = uefi_enumerate_variables(&result->runtime);
    if (ret == FG_SUCCESS) {
        result->runtime_scan_done = true;
        add_finding(result, "Runtime UEFI variable enumeration completed");

        char finding[256];
        snprintf(finding, sizeof(finding), "Found %d UEFI variables",
                 result->runtime.var_count);
        add_finding(result, finding);

        if (result->runtime.secure_boot_enabled) {
            add_finding(result, "Secure Boot is ENABLED");
        } else {
            add_finding(result, "WARNING: Secure Boot is DISABLED");
        }

        if (result->runtime.setup_mode) {
            add_finding(result, "WARNING: System is in Setup Mode");
        }
    } else {
        add_finding(result, "Runtime UEFI enumeration failed or not supported");
    }

    /* SPI extraction (if requested and available) */
    if (include_spi) {
        ret = spi_detect_chip(&result->spi);
        if (ret == FG_SUCCESS) {
            result->spi_scan_done = true;
            char finding[256];
            snprintf(finding, sizeof(finding), "SPI flash chip detected: %s",
                     result->spi.chip_name);
            add_finding(result, finding);
        } else {
            add_finding(result, "SPI flash detection unavailable");
        }
    }

    /* Risk assessment */
    result->risk_level = uefi_assess_risk(result);

    /* Generate risk reason */
    if (result->risk_level >= RISK_HIGH) {
        if (!result->runtime.secure_boot_enabled) {
            strncpy(result->risk_reason, "Secure Boot disabled - system vulnerable to bootkits",
                    sizeof(result->risk_reason) - 1);
        } else if (result->runtime.setup_mode) {
            strncpy(result->risk_reason, "System in Setup Mode - Secure Boot keys can be modified",
                    sizeof(result->risk_reason) - 1);
        }
    } else {
        strncpy(result->risk_reason, "UEFI configuration appears secure",
                sizeof(result->risk_reason) - 1);
    }

    return FG_SUCCESS;
}

risk_level_t uefi_assess_risk(const uefi_analysis_result_t *result) {
    int risk_score = 0;

    if (!result) return RISK_NONE;

    /* Secure Boot disabled: HIGH */
    if (result->runtime_scan_done && !result->runtime.secure_boot_enabled) {
        risk_score += 3;
    }

    /* Setup Mode enabled: HIGH */
    if (result->runtime.setup_mode) {
        risk_score += 3;
    }

    /* Audit Mode: MEDIUM */
    if (result->runtime.audit_mode) {
        risk_score += 2;
    }

    /* Many boot variables (could indicate persistence): LOW */
    if (result->runtime.boot_var_count > 20) {
        risk_score += 1;
    }

    if (risk_score >= 5) return RISK_CRITICAL;
    if (risk_score >= 3) return RISK_HIGH;
    if (risk_score >= 2) return RISK_MEDIUM;
    if (risk_score >= 1) return RISK_LOW;

    return RISK_NONE;
}

void uefi_enum_print_result(const uefi_enum_result_t *result, bool verbose) {
    if (!result) return;

    printf("\n");
    printf("==========================================\n");
    printf("  UEFI Variable Enumeration Results\n");
    printf("==========================================\n");
    printf("\n");

    printf("Summary:\n");
    printf("  Total Variables: %d\n", result->var_count);
    printf("  Boot Variables: %d\n", result->boot_var_count);
    printf("  Secure Boot Related: %d\n", result->secure_boot_count);
    printf("  Driver Related: %d\n", result->driver_count);
    printf("\n");

    printf("Secure Boot Status:\n");
    printf("  Secure Boot: %s\n", result->secure_boot_enabled ? "ENABLED" : "DISABLED");
    printf("  Setup Mode: %s\n", result->setup_mode ? "YES (keys can be modified)" : "No");
    printf("  Audit Mode: %s\n", result->audit_mode ? "Yes" : "No");
    printf("  Deployed Mode: %s\n", result->deployed_mode ? "Yes" : "No");
    printf("\n");

    if (verbose && result->var_count > 0) {
        printf("Variables (first 50):\n");
        int show_count = result->var_count < 50 ? result->var_count : 50;
        for (int i = 0; i < show_count; i++) {
            uefi_var_info_t *v = &result->variables[i];
            printf("  [%3d] %s\n", i + 1, v->name);
            printf("        GUID: %s\n", v->guid);
            printf("        Size: %zu bytes, Attrs: 0x%08x\n", v->data_size, v->attributes);
            if (v->is_secure_boot_related) printf("        [SECURE BOOT]\n");
            if (v->is_boot_variable) printf("        [BOOT]\n");
            if (v->is_driver_related) printf("        [DRIVER]\n");
        }
        if (result->var_count > 50) {
            printf("  ... and %d more variables\n", result->var_count - 50);
        }
        printf("\n");
    }

    printf("Summary: %s\n", result->summary);
    printf("\n");
}

void spi_print_result(const spi_extract_result_t *result, bool verbose) {
    if (!result) return;

    printf("\n");
    printf("==========================================\n");
    printf("  SPI Flash Extraction Results\n");
    printf("==========================================\n");
    printf("\n");

    printf("flashrom Available: %s\n", result->flashrom_available ? "Yes" : "No");

    if (result->chip_name[0]) {
        printf("Flash Chip: %s\n", result->chip_name);
        printf("Flash Size: %lu bytes (%lu MB)\n",
               result->flash_size, result->flash_size / (1024 * 1024));
    }

    if (result->extraction_successful) {
        printf("Full Dump: %s\n", result->full_dump_path);
    }

    printf("\n");
}

void uefi_analysis_print_result(const uefi_analysis_result_t *result, bool verbose) {
    const char *risk_str;

    if (!result) return;

    printf("\n");
    printf("==========================================\n");
    printf("  UEFI Full Analysis Results\n");
    printf("==========================================\n");
    printf("\n");

    /* Print runtime results */
    if (result->runtime_scan_done) {
        printf("=== Runtime Enumeration ===\n");
        printf("Total Variables: %d\n", result->runtime.var_count);
        printf("Secure Boot: %s\n", result->runtime.secure_boot_enabled ? "ENABLED" : "DISABLED");
        printf("Setup Mode: %s\n", result->runtime.setup_mode ? "YES" : "No");
        printf("\n");
    }

    /* Print SPI results */
    if (result->spi_scan_done) {
        printf("=== SPI Flash Detection ===\n");
        if (result->spi.chip_name[0]) {
            printf("Chip: %s (%lu MB)\n", result->spi.chip_name,
                   result->spi.flash_size / (1024 * 1024));
        }
        printf("\n");
    }

    /* Risk assessment */
    switch (result->risk_level) {
        case RISK_CRITICAL: risk_str = "CRITICAL"; break;
        case RISK_HIGH:     risk_str = "HIGH"; break;
        case RISK_MEDIUM:   risk_str = "MEDIUM"; break;
        case RISK_LOW:      risk_str = "LOW"; break;
        default:            risk_str = "NONE"; break;
    }

    printf("Risk Assessment:\n");
    printf("  Level: %s\n", risk_str);
    printf("  Reason: %s\n", result->risk_reason);
    printf("\n");

    /* Findings */
    if (result->finding_count > 0) {
        printf("Findings:\n");
        for (int i = 0; i < result->finding_count; i++) {
            printf("  [%d] %s\n", i + 1, result->findings[i]);
        }
        printf("\n");
    }

    /* Recommendations */
    if (result->risk_level >= RISK_HIGH) {
        printf("Recommendations:\n");
        if (!result->runtime.secure_boot_enabled) {
            printf("  - Enable Secure Boot in BIOS/UEFI settings\n");
            printf("  - Enroll Platform Key (PK) and Key Exchange Keys (KEK)\n");
        }
        if (result->runtime.setup_mode) {
            printf("  - Exit Setup Mode by enrolling Secure Boot keys\n");
            printf("  - Use sbsigntools or mokutil to manage keys\n");
        }
        printf("\n");
    }
}

int uefi_enum_to_json(const uefi_enum_result_t *result, char *buffer, size_t size) {
    if (!result || !buffer || size == 0) return FG_ERROR;

    int written = snprintf(buffer, size,
        "{\n"
        "  \"var_count\": %d,\n"
        "  \"boot_var_count\": %d,\n"
        "  \"secure_boot_count\": %d,\n"
        "  \"driver_count\": %d,\n"
        "  \"secure_boot_enabled\": %s,\n"
        "  \"setup_mode\": %s,\n"
        "  \"audit_mode\": %s,\n"
        "  \"deployed_mode\": %s,\n"
        "  \"summary\": \"%s\"\n"
        "}\n",
        result->var_count,
        result->boot_var_count,
        result->secure_boot_count,
        result->driver_count,
        result->secure_boot_enabled ? "true" : "false",
        result->setup_mode ? "true" : "false",
        result->audit_mode ? "true" : "false",
        result->deployed_mode ? "true" : "false",
        result->summary
    );

    return (written > 0 && (size_t)written < size) ? FG_SUCCESS : FG_ERROR;
}

int spi_result_to_json(const spi_extract_result_t *result, char *buffer, size_t size) {
    if (!result || !buffer || size == 0) return FG_ERROR;

    int written = snprintf(buffer, size,
        "{\n"
        "  \"flashrom_available\": %s,\n"
        "  \"chip_name\": \"%s\",\n"
        "  \"flash_size\": %lu,\n"
        "  \"extraction_successful\": %s,\n"
        "  \"full_dump_path\": \"%s\"\n"
        "}\n",
        result->flashrom_available ? "true" : "false",
        result->chip_name,
        result->flash_size,
        result->extraction_successful ? "true" : "false",
        result->full_dump_path
    );

    return (written > 0 && (size_t)written < size) ? FG_SUCCESS : FG_ERROR;
}

int uefi_analysis_to_json(const uefi_analysis_result_t *result, char *buffer, size_t size) {
    const char *risk_str;

    if (!result || !buffer || size == 0) return FG_ERROR;

    switch (result->risk_level) {
        case RISK_CRITICAL: risk_str = "CRITICAL"; break;
        case RISK_HIGH:     risk_str = "HIGH"; break;
        case RISK_MEDIUM:   risk_str = "MEDIUM"; break;
        case RISK_LOW:      risk_str = "LOW"; break;
        default:            risk_str = "NONE"; break;
    }

    int written = snprintf(buffer, size,
        "{\n"
        "  \"runtime_scan_done\": %s,\n"
        "  \"spi_scan_done\": %s,\n"
        "  \"runtime\": {\n"
        "    \"var_count\": %d,\n"
        "    \"secure_boot_enabled\": %s,\n"
        "    \"setup_mode\": %s\n"
        "  },\n"
        "  \"spi\": {\n"
        "    \"flashrom_available\": %s,\n"
        "    \"chip_name\": \"%s\"\n"
        "  },\n"
        "  \"risk\": {\n"
        "    \"level\": \"%s\",\n"
        "    \"reason\": \"%s\"\n"
        "  },\n"
        "  \"finding_count\": %d\n"
        "}\n",
        result->runtime_scan_done ? "true" : "false",
        result->spi_scan_done ? "true" : "false",
        result->runtime.var_count,
        result->runtime.secure_boot_enabled ? "true" : "false",
        result->runtime.setup_mode ? "true" : "false",
        result->spi.flashrom_available ? "true" : "false",
        result->spi.chip_name,
        risk_str,
        result->risk_reason,
        result->finding_count
    );

    return (written > 0 && (size_t)written < size) ? FG_SUCCESS : FG_ERROR;
}

void uefi_enum_free(uefi_enum_result_t *result) {
    if (result && result->variables) {
        free(result->variables);
        result->variables = NULL;
        result->var_count = 0;
        result->variables_capacity = 0;
    }
}

void uefi_analysis_free(uefi_analysis_result_t *result) {
    if (result) {
        uefi_enum_free(&result->runtime);
    }
}
