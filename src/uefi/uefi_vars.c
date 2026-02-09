#include "uefi_vars.h"
#include <sys/stat.h>
#include <dirent.h>
#include <sys/mount.h>
#include <errno.h>

int uefi_init(uefi_state_t *state) {
    struct stat st;

    if (!state) {
        return FG_ERROR;
    }

    memset(state, 0, sizeof(uefi_state_t));

    /* Check if EFI is supported */
    state->efi_supported = uefi_is_supported();
    if (!state->efi_supported) {
        FG_INFO("UEFI not supported on this system");
        return FG_NOT_SUPPORTED;
    }

    /* Determine which vars path to use */
    if (stat(UEFI_VARS_PATH, &st) == 0 && S_ISDIR(st.st_mode)) {
        strncpy(state->vars_path, UEFI_VARS_PATH, sizeof(state->vars_path) - 1);
        state->vars_accessible = true;
        state->efivars_mounted = true;
    } else if (stat(UEFI_VARS_ALT_PATH, &st) == 0 && S_ISDIR(st.st_mode)) {
        strncpy(state->vars_path, UEFI_VARS_ALT_PATH, sizeof(state->vars_path) - 1);
        state->vars_accessible = true;
        state->efivars_mounted = true;
    } else {
        FG_WARN("UEFI variables not accessible (efivars not mounted?)");
        state->vars_accessible = false;
        return FG_ERROR;
    }

    FG_INFO("UEFI subsystem initialized (vars: %s)", state->vars_path);
    return FG_SUCCESS;
}

void uefi_cleanup(uefi_state_t *state) {
    if (state) {
        memset(state, 0, sizeof(uefi_state_t));
    }
}

bool uefi_is_supported(void) {
    struct stat st;

    /* Check for /sys/firmware/efi directory */
    if (stat("/sys/firmware/efi", &st) == 0 && S_ISDIR(st.st_mode)) {
        return true;
    }

    return false;
}

bool uefi_vars_is_writable(void) {
    struct stat st;

    /* Check if efivars is mounted and writable */
    if (stat(UEFI_VARS_PATH, &st) == 0) {
        return (access(UEFI_VARS_PATH, W_OK) == 0);
    }

    if (stat(UEFI_VARS_ALT_PATH, &st) == 0) {
        return (access(UEFI_VARS_ALT_PATH, W_OK) == 0);
    }

    return false;
}

int uefi_read_variable(const char *name, const char *guid,
                       uefi_variable_t *var) {
    char path[512];
    FILE *fp;
    struct stat st;
    uint32_t attributes;
    size_t data_offset;

    if (!name || !guid || !var) {
        return FG_ERROR;
    }

    memset(var, 0, sizeof(uefi_variable_t));

    /* Build variable path: name-guid */
    snprintf(path, sizeof(path), "%s/%s-%s", UEFI_VARS_PATH, name, guid);

    /* Check if variable exists */
    if (stat(path, &st) != 0) {
        /* Try alternative path */
        snprintf(path, sizeof(path), "%s/%s-%s", UEFI_VARS_ALT_PATH, name, guid);
        if (stat(path, &st) != 0) {
            return FG_NOT_FOUND;
        }
    }

    /* Open variable file */
    fp = fopen(path, "rb");
    if (!fp) {
        FG_LOG_ERROR("Failed to open UEFI variable: %s", path);
        return FG_NO_PERMISSION;
    }

    /* Read attributes (first 4 bytes) */
    if (fread(&attributes, sizeof(uint32_t), 1, fp) != 1) {
        FG_LOG_ERROR("Failed to read UEFI variable attributes");
        fclose(fp);
        return FG_ERROR;
    }

    /* Calculate data size */
    if (fseek(fp, 0, SEEK_END) != 0) {
        FG_LOG_ERROR("Failed to seek to end of UEFI variable file");
        fclose(fp);
        return FG_ERROR;
    }

    long file_size = ftell(fp);
    if (file_size < 0) {
        FG_LOG_ERROR("Failed to get UEFI variable file size: %s", strerror(errno));
        fclose(fp);
        return FG_ERROR;
    }

    if (file_size < (long)sizeof(uint32_t)) {
        FG_LOG_ERROR("UEFI variable file too small: %ld bytes", file_size);
        fclose(fp);
        return FG_ERROR;
    }

    var->data_size = (size_t)(file_size - sizeof(uint32_t));

    if (fseek(fp, sizeof(uint32_t), SEEK_SET) != 0) {
        FG_LOG_ERROR("Failed to seek in UEFI variable file");
        fclose(fp);
        return FG_ERROR;
    }

    /* Allocate and read data */
    if (var->data_size > 0) {
        var->data = (uint8_t *)malloc(var->data_size);
        if (!var->data) {
            FG_LOG_ERROR("Failed to allocate memory for UEFI variable data");
            fclose(fp);
            return FG_ERROR;
        }

        if (fread(var->data, 1, var->data_size, fp) != var->data_size) {
            FG_LOG_ERROR("Failed to read UEFI variable data");
            free(var->data);
            fclose(fp);
            return FG_ERROR;
        }
    }

    fclose(fp);

    /* Fill in variable metadata */
    strncpy(var->name, name, sizeof(var->name) - 1);
    strncpy(var->guid, guid, sizeof(var->guid) - 1);
    strncpy(var->full_path, path, sizeof(var->full_path) - 1);
    var->attributes = attributes;
    var->exists = true;

    FG_DEBUG("Read UEFI variable: %s-%s (size: %zu, attr: 0x%x)",
             name, guid, var->data_size, attributes);

    return FG_SUCCESS;
}

int uefi_write_variable(safety_context_t *safety_ctx,
                        const char *name, const char *guid,
                        uint32_t attributes, const void *data, size_t data_size) {
    char path[512];
    FILE *fp;
    uefi_variable_t old_var;
    int ret;

    if (!name || !guid || !data || data_size == 0) {
        return FG_ERROR;
    }

    /* Validate name and GUID to prevent path traversal */
    if (strchr(name, '/') || strchr(name, '\\') || strstr(name, "..") ||
        strchr(guid, '/') || strchr(guid, '\\') || strstr(guid, "..")) {
        FG_LOG_ERROR("Invalid UEFI variable name or GUID (path traversal attempt)");
        return FG_ERROR;
    }

    /* Check if writable */
    if (!uefi_vars_is_writable()) {
        FG_LOG_ERROR("UEFI variables are not writable");
        return FG_NO_PERMISSION;
    }

    /* PHASE 3: Check Secure Boot compatibility before attempting modification */
    if (!uefi_can_modify_vars_with_secureboot()) {
        FG_LOG_ERROR("UEFI variable modification blocked: Secure Boot is enabled");
        FG_LOG_ERROR("Disable Secure Boot in BIOS/UEFI settings before using FirmwareGuard");
        return FG_NO_PERMISSION;
    }

    /* Dry-run mode */
    if (safety_ctx && safety_is_dry_run(safety_ctx)) {
        FG_INFO("[DRY-RUN] Would write UEFI variable: %s-%s (size: %zu)",
                name, guid, data_size);
        return FG_SUCCESS;
    }

    /* Backup existing variable if it exists */
    if (uefi_read_variable(name, guid, &old_var) == FG_SUCCESS) {
        FG_INFO("Backing up existing UEFI variable: %s-%s", name, guid);
        if (safety_ctx) {
            ret = uefi_backup_variable(safety_ctx, &old_var);
            uefi_free_variable(&old_var);

            if (ret != FG_SUCCESS) {
                FG_LOG_ERROR("Failed to backup UEFI variable before modification");
                return FG_ERROR;
            }
        }
    }

    /* Build variable path */
    snprintf(path, sizeof(path), "%s/%s-%s", UEFI_VARS_PATH, name, guid);

    /* Open variable file for writing */
    fp = fopen(path, "wb");
    if (!fp) {
        /* Try with root helper or alternative method */
        FG_LOG_ERROR("Failed to open UEFI variable for writing: %s", path);
        return FG_NO_PERMISSION;
    }

    /* Write attributes */
    if (fwrite(&attributes, sizeof(uint32_t), 1, fp) != 1) {
        FG_LOG_ERROR("Failed to write UEFI variable attributes");
        fclose(fp);
        return FG_ERROR;
    }

    /* Write data */
    if (fwrite(data, 1, data_size, fp) != data_size) {
        FG_LOG_ERROR("Failed to write UEFI variable data");
        fclose(fp);
        return FG_ERROR;
    }

    fclose(fp);

    FG_INFO("Wrote UEFI variable: %s-%s (size: %zu, attr: 0x%x)",
            name, guid, data_size, attributes);

    if (safety_ctx) {
        safety_log_operation(safety_ctx, "uefi_var_write", true, path);
    }

    return FG_SUCCESS;
}

int uefi_delete_variable(safety_context_t *safety_ctx,
                         const char *name, const char *guid) {
    char path[512];
    uefi_variable_t var;
    int ret;

    if (!name || !guid) {
        return FG_ERROR;
    }

    /* Validate name and GUID */
    if (strchr(name, '/') || strchr(name, '\\') || strstr(name, "..") ||
        strchr(guid, '/') || strchr(guid, '\\') || strstr(guid, "..")) {
        FG_LOG_ERROR("Invalid UEFI variable name or GUID");
        return FG_ERROR;
    }

    /* Check Secure Boot compatibility before attempting deletion */
    if (!uefi_can_modify_vars_with_secureboot()) {
        FG_LOG_ERROR("UEFI variable deletion blocked: Secure Boot is enabled");
        return FG_NO_PERMISSION;
    }

    /* Dry-run mode */
    if (safety_ctx && safety_is_dry_run(safety_ctx)) {
        FG_INFO("[DRY-RUN] Would delete UEFI variable: %s-%s", name, guid);
        return FG_SUCCESS;
    }

    /* Backup variable before deletion */
    if (uefi_read_variable(name, guid, &var) == FG_SUCCESS) {
        if (safety_ctx) {
            ret = uefi_backup_variable(safety_ctx, &var);
            uefi_free_variable(&var);

            if (ret != FG_SUCCESS) {
                FG_LOG_ERROR("Failed to backup UEFI variable before deletion");
                return FG_ERROR;
            }
        }
    }

    /* Build path */
    snprintf(path, sizeof(path), "%s/%s-%s", UEFI_VARS_PATH, name, guid);

    /* Delete variable file */
    if (unlink(path) != 0) {
        FG_LOG_ERROR("Failed to delete UEFI variable: %s (%s)", path, strerror(errno));
        return FG_ERROR;
    }

    FG_INFO("Deleted UEFI variable: %s-%s", name, guid);

    if (safety_ctx) {
        safety_log_operation(safety_ctx, "uefi_var_delete", true, path);
    }

    return FG_SUCCESS;
}

int uefi_backup_variable(safety_context_t *safety_ctx,
                         const uefi_variable_t *var) {
    char backup_name[512];
    uint8_t *backup_data;
    size_t backup_size;
    int ret;

    if (!safety_ctx || !var || !var->exists) {
        return FG_ERROR;
    }

    /* Create backup name */
    snprintf(backup_name, sizeof(backup_name), "uefi_%s_%s", var->name, var->guid);

    /* Allocate backup data (attributes + data) */
    backup_size = sizeof(uint32_t) + var->data_size;
    backup_data = (uint8_t *)malloc(backup_size);
    if (!backup_data) {
        return FG_ERROR;
    }

    /* Copy attributes and data */
    memcpy(backup_data, &var->attributes, sizeof(uint32_t));
    if (var->data_size > 0 && var->data) {
        memcpy(backup_data + sizeof(uint32_t), var->data, var->data_size);
    }

    /* Create backup */
    ret = safety_create_backup(safety_ctx, BACKUP_TYPE_UEFI_VAR,
                               backup_name, backup_data, backup_size);

    free(backup_data);
    return ret;
}

int uefi_restore_variable(safety_context_t *safety_ctx,
                          const char *backup_name) {
    /* This would be implemented by reading from backup registry
     * and calling uefi_write_variable with the backed-up data */
    if (!safety_ctx || !backup_name) {
        return FG_ERROR;
    }

    FG_INFO("UEFI variable restore: %s (requires backup module integration)", backup_name);
    return FG_NOT_SUPPORTED; /* Placeholder */
}

int uefi_list_variables(FILE *output) {
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    if (!output) {
        return FG_ERROR;
    }

    dir = opendir(UEFI_VARS_PATH);
    if (!dir) {
        dir = opendir(UEFI_VARS_ALT_PATH);
        if (!dir) {
            fprintf(output, "UEFI variables not accessible\n");
            return FG_ERROR;
        }
    }

    fprintf(output, "\n");
    fprintf(output, "========================================\n");
    fprintf(output, "  UEFI VARIABLES\n");
    fprintf(output, "========================================\n\n");

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue; /* Skip . and .. */
        }

        fprintf(output, "%s\n", entry->d_name);
        count++;
    }

    closedir(dir);

    fprintf(output, "\nTotal: %d variables\n\n", count);
    return FG_SUCCESS;
}

bool uefi_is_me_hap_available(void) {
    uefi_variable_t var;

    /* Check platform support first to avoid false positives on pre-Skylake */
    if (!uefi_check_hap_platform_support()) {
        return false;
    }

    /* Try to read ME-related UEFI variables */
    /* This is vendor-specific; common names include: */
    /* - MeSetup, MEBx, IntelAMT, etc. */

    if (uefi_read_variable("MeSetup", INTEL_ME_SETUP_GUID, &var) == FG_SUCCESS) {
        uefi_free_variable(&var);
        return true;
    }

    /* Try alternative names */
    if (uefi_read_variable("MEBx", INTEL_ME_SETUP_GUID, &var) == FG_SUCCESS) {
        uefi_free_variable(&var);
        return true;
    }

    return false;
}

int uefi_parse_me_hap_variable(const uefi_variable_t *var, bool *hap_enabled) {
    if (!var || !hap_enabled || !var->data || var->data_size == 0) {
        return FG_ERROR;
    }

    /* HAP bit is usually in a specific offset within the ME setup variable
     * This is highly vendor-specific. Common pattern:
     * - Byte 0: ME enabled/disabled
     * - Byte 1 or bit field: HAP/AltMeDisable
     */

    /* For demonstration, check first byte */
    if (var->data_size > 0) {
        *hap_enabled = (var->data[0] & 0x01) != 0;
        return FG_SUCCESS;
    }

    return FG_ERROR;
}

bool uefi_check_hap_platform_support(void) {
    FILE *fp;
    char line[256];
    char vendor[64] = {0};
    int cpu_family = -1;
    int cpu_model = -1;

    fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        FG_LOG_ERROR("Failed to open /proc/cpuinfo: %s", strerror(errno));
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "vendor_id", 9) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                colon++;
                while (*colon == ' ' || *colon == '\t') colon++;
                char *nl = strchr(colon, '\n');
                if (nl) *nl = '\0';
                strncpy(vendor, colon, sizeof(vendor) - 1);
            }
        } else if (strncmp(line, "cpu family", 10) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                cpu_family = atoi(colon + 1);
            }
        } else if (strncmp(line, "model\t", 6) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                cpu_model = atoi(colon + 1);
            }
        }

        /* Stop after first CPU core — all cores share the same model */
        if (vendor[0] && cpu_family >= 0 && cpu_model >= 0)
            break;
    }

    fclose(fp);

    if (!vendor[0] || cpu_family < 0 || cpu_model < 0) {
        FG_LOG_ERROR("Failed to parse CPU info from /proc/cpuinfo");
        return false;
    }

    /* HAP is Intel-only */
    if (strcmp(vendor, "GenuineIntel") != 0) {
        FG_LOG_ERROR("HAP bit is Intel-only (detected vendor: %s)", vendor);
        return false;
    }

    /* Require Family 6, Model >= 0x4E (Skylake and newer)
     * Models below 0x4E are pre-Skylake:
     *   Broadwell = 0x3D/0x47, Haswell = 0x3C/0x45/0x46
     * Skylake client = 0x4E/0x5E — earliest HAP-supporting platform
     */
    if (cpu_family != 6 || cpu_model < 0x4E) {
        FG_LOG_ERROR("HAP bit requires Intel Skylake or newer "
                     "(detected: family %d, model 0x%02X)", cpu_family, cpu_model);
        return false;
    }

    FG_DEBUG("Platform supports HAP (Intel family %d, model 0x%02X)",
             cpu_family, cpu_model);
    return true;
}

int uefi_set_me_hap_bit(safety_context_t *safety_ctx, bool enable) {
    uefi_variable_t var;
    uint8_t *new_data;
    int ret;

    /* This is a CRITICAL operation that can brick the system */
    if (!safety_ctx) {
        FG_LOG_ERROR("Safety context required for ME HAP bit manipulation");
        return FG_ERROR;
    }

    /* Validate platform supports HAP before proceeding */
    if (!uefi_check_hap_platform_support()) {
        FG_LOG_ERROR("HAP bit modification aborted: unsupported platform");
        return FG_NOT_SUPPORTED;
    }

    /* Check Secure Boot early — fail before the scary confirmation dialog */
    if (uefi_is_secure_boot_enabled()) {
        FG_LOG_ERROR("HAP bit modification blocked: Secure Boot is enabled");
        FG_LOG_ERROR("Disable Secure Boot in BIOS/UEFI settings before modifying ME HAP bit");
        return FG_NO_PERMISSION;
    }

    FG_WARN("HAP bit modification is a CRITICAL operation");

    /* Check if user confirmation is required */
    if (safety_ctx->require_confirmation) {
        const char *warning =
            "This will modify UEFI firmware settings to enable/disable Intel ME.\n"
            "This operation is IRREVERSIBLE without BIOS access.\n"
            "If your system does not support HAP, this may BRICK your system.\n"
            "Ensure you have:\n"
            "  1. A backup of your BIOS/UEFI firmware\n"
            "  2. Physical access to clear CMOS\n"
            "  3. Verified HAP support for your platform";

        if (!safety_confirm_action("Set Intel ME HAP bit", warning, RISK_CRITICAL)) {
            FG_INFO("User cancelled ME HAP bit operation");
            return FG_ERROR;
        }
    }

    /* Try to read ME setup variable */
    ret = uefi_read_variable("MeSetup", INTEL_ME_SETUP_GUID, &var);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to read ME setup variable (HAP may not be supported)");
        return FG_NOT_SUPPORTED;
    }

    if (var.data_size == 0 || !var.data) {
        FG_LOG_ERROR("ME setup variable has no data");
        uefi_free_variable(&var);
        return FG_ERROR;
    }

    /* Create rollback point */
    safety_create_rollback_point(safety_ctx, "Before ME HAP bit modification");

    /* Modify HAP bit (vendor-specific implementation) */
    new_data = (uint8_t *)malloc(var.data_size);
    if (!new_data) {
        uefi_free_variable(&var);
        return FG_ERROR;
    }

    memcpy(new_data, var.data, var.data_size);

    /* Set or clear HAP bit (example: bit 0 of byte 0) */
    if (enable) {
        new_data[0] |= 0x01;  /* Set HAP bit */
    } else {
        new_data[0] &= ~0x01; /* Clear HAP bit */
    }

    /* Write modified variable */
    ret = uefi_write_variable(safety_ctx, var.name, var.guid,
                              var.attributes, new_data, var.data_size);

    free(new_data);
    uefi_free_variable(&var);

    if (ret == FG_SUCCESS) {
        FG_INFO("Intel ME HAP bit %s", enable ? "enabled" : "disabled");
        FG_INFO("REBOOT REQUIRED for changes to take effect");
    }

    return ret;
}

void uefi_free_variable(uefi_variable_t *var) {
    if (var && var->data) {
        free(var->data);
        var->data = NULL;
        var->data_size = 0;
    }
}

/* PHASE 3: Secure Boot Detection Functions */

bool uefi_is_secure_boot_enabled(void) {
    uefi_variable_t var;
    bool enabled = false;

    /* Read SecureBoot variable from EFI global namespace
     * This variable is defined in UEFI spec section 3.3
     * Value: 1 = enabled, 0 = disabled
     */
    if (uefi_read_variable("SecureBoot", EFI_GLOBAL_VARIABLE_GUID, &var) == FG_SUCCESS) {
        if (var.data_size >= 1 && var.data) {
            enabled = (var.data[0] == 1);
            FG_DEBUG("Secure Boot variable found: %s", enabled ? "enabled" : "disabled");
        }
        uefi_free_variable(&var);
    } else {
        FG_DEBUG("SecureBoot UEFI variable not found (system may not support Secure Boot)");
    }

    return enabled;
}

int uefi_get_secure_boot_state(bool *enabled, bool *setup_mode) {
    uefi_variable_t sb_var, setup_var;
    int ret = FG_SUCCESS;

    if (!enabled || !setup_mode) {
        return FG_ERROR;
    }

    /* Initialize to safe defaults */
    *enabled = false;
    *setup_mode = false;

    /* Read SecureBoot variable */
    if (uefi_read_variable("SecureBoot", EFI_GLOBAL_VARIABLE_GUID, &sb_var) == FG_SUCCESS) {
        if (sb_var.data_size >= 1 && sb_var.data) {
            *enabled = (sb_var.data[0] == 1);
        }
        uefi_free_variable(&sb_var);
    } else {
        /* SecureBoot variable not found - system may not support Secure Boot */
        ret = FG_NOT_FOUND;
    }

    /* Read SetupMode variable
     * SetupMode = 1 means system is in Setup Mode (keys not enrolled)
     * SetupMode = 0 means User Mode (keys enrolled, Secure Boot can be active)
     */
    if (uefi_read_variable("SetupMode", EFI_GLOBAL_VARIABLE_GUID, &setup_var) == FG_SUCCESS) {
        if (setup_var.data_size >= 1 && setup_var.data) {
            *setup_mode = (setup_var.data[0] == 1);
        }
        uefi_free_variable(&setup_var);
    }

    FG_DEBUG("Secure Boot state: enabled=%d, setup_mode=%d", *enabled, *setup_mode);
    return ret;
}

bool uefi_can_modify_vars_with_secureboot(void) {
    bool sb_enabled = false;
    bool setup_mode = false;

    /* Get Secure Boot state */
    if (uefi_get_secure_boot_state(&sb_enabled, &setup_mode) != FG_SUCCESS) {
        /* Cannot determine state, assume modification might fail */
        return false;
    }

    /* SECURITY NOTE: UEFI variable modification behavior with Secure Boot:
     *
     * 1. When Secure Boot is ENABLED (User Mode):
     *    - Most authenticated variables cannot be modified
     *    - Writes require proper cryptographic signatures
     *    - ME-related variables may be locked down
     *    - Modification will likely FAIL without signed updates
     *
     * 2. When in Setup Mode:
     *    - Variables can be modified more freely
     *    - This is the enrollment phase before Secure Boot activation
     *
     * 3. When Secure Boot is DISABLED (User Mode):
     *    - Variable modification is generally allowed
     *    - This is the safest state for FirmwareGuard operations
     */

    if (sb_enabled && !setup_mode) {
        /* Secure Boot active in User Mode - modification will likely fail */
        FG_WARN("Secure Boot is ENABLED - UEFI variable modification may fail");
        FG_WARN("To modify UEFI variables, you may need to:");
        FG_WARN("  1. Disable Secure Boot in BIOS/UEFI settings, OR");
        FG_WARN("  2. Use cryptographically signed updates (requires vendor keys)");
        return false;
    }

    /* Safe to proceed: either Secure Boot disabled or in Setup Mode */
    return true;
}
