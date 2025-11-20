#include "config.h"
#include "../safety/safety.h"
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>

/* Maximum line length for config file */
#define MAX_LINE_LENGTH 512

int config_init(void) {
    struct stat st;

    /* Create config directory if it doesn't exist */
    if (stat(CONFIG_DIR, &st) != 0) {
        if (mkdir(CONFIG_DIR, 0755) != 0 && errno != EEXIST) {
            FG_WARN("Failed to create config directory: %s", strerror(errno));
            return FG_ERROR;
        }
        FG_INFO("Created config directory: %s", CONFIG_DIR);
    }

    /* Create state directory */
    if (stat("/var/lib/firmwareguard", &st) != 0) {
        if (mkdir("/var/lib/firmwareguard", 0700) != 0 && errno != EEXIST) {
            FG_WARN("Failed to create state directory");
        }
    }

    /* Check if config file exists, create default if not */
    if (stat(CONFIG_FILE, &st) != 0) {
        FG_INFO("Configuration file not found, creating default");
        return config_create_default_file();
    }

    return FG_SUCCESS;
}

void config_get_defaults(fg_config_t *config) {
    if (!config) {
        return;
    }

    memset(config, 0, sizeof(fg_config_t));

    /* Safe defaults - nothing blocked by default */
    config->block_intel_me = false;
    config->me_use_hap_bit = true;  /* Prefer HAP bit over me_cleaner */
    config->me_use_me_cleaner = false;

    config->block_amd_psp = false;
    config->psp_kernel_param = true;
    config->psp_disable_ftpm = false;

    config->block_nic_wol = false;
    config->block_intel_amt = false;
    config->persistent_nic_config = true;

    config->block_fpdt = false;
    config->block_custom_tables = false;

    /* Safety settings */
    config->auto_apply_on_boot = false;
    config->reapply_after_update = false;
    config->safety_mode = SAFETY_MODE_CONFIRM;
    config->require_confirmation = true;

    /* Failsafe enabled by default */
    config->enable_failsafe = true;
    config->boot_timeout_seconds = 120;

    /* Logging */
    config->verbose_logging = false;
    strncpy(config->log_file, "/var/log/firmwareguard.log",
            sizeof(config->log_file) - 1);
}

static void trim_whitespace(char *str) {
    char *start = str;
    char *end;

    /* Trim leading space */
    while (isspace((unsigned char)*start)) {
        start++;
    }

    if (*start == 0) {
        *str = 0;
        return;
    }

    /* Trim trailing space */
    end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }
    end[1] = '\0';

    /* Move trimmed string to start */
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

static bool parse_bool(const char *value) {
    if (!value) {
        return false;
    }

    if (strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 ||
        strcasecmp(value, "1") == 0) {
        return true;
    }

    return false;
}

int config_parse_option(fg_config_t *config, const char *key, const char *value) {
    if (!config || !key || !value) {
        return FG_ERROR;
    }

    /* Intel ME options */
    if (strcmp(key, "block_intel_me") == 0) {
        config->block_intel_me = parse_bool(value);
    } else if (strcmp(key, "me_use_hap_bit") == 0) {
        config->me_use_hap_bit = parse_bool(value);
    } else if (strcmp(key, "me_use_me_cleaner") == 0) {
        config->me_use_me_cleaner = parse_bool(value);
    }
    /* AMD PSP options */
    else if (strcmp(key, "block_amd_psp") == 0) {
        config->block_amd_psp = parse_bool(value);
    } else if (strcmp(key, "psp_kernel_param") == 0) {
        config->psp_kernel_param = parse_bool(value);
    } else if (strcmp(key, "psp_disable_ftpm") == 0) {
        config->psp_disable_ftpm = parse_bool(value);
    }
    /* NIC options */
    else if (strcmp(key, "block_nic_wol") == 0) {
        config->block_nic_wol = parse_bool(value);
    } else if (strcmp(key, "block_intel_amt") == 0) {
        config->block_intel_amt = parse_bool(value);
    } else if (strcmp(key, "persistent_nic_config") == 0) {
        config->persistent_nic_config = parse_bool(value);
    }
    /* ACPI options */
    else if (strcmp(key, "block_fpdt") == 0) {
        config->block_fpdt = parse_bool(value);
    } else if (strcmp(key, "block_custom_tables") == 0) {
        config->block_custom_tables = parse_bool(value);
    }
    /* General options */
    else if (strcmp(key, "auto_apply_on_boot") == 0) {
        config->auto_apply_on_boot = parse_bool(value);
    } else if (strcmp(key, "reapply_after_update") == 0) {
        config->reapply_after_update = parse_bool(value);
    } else if (strcmp(key, "safety_mode") == 0) {
        if (strcasecmp(value, "dry-run") == 0) {
            config->safety_mode = SAFETY_MODE_DRY_RUN;
        } else if (strcasecmp(value, "confirm") == 0) {
            config->safety_mode = SAFETY_MODE_CONFIRM;
        } else if (strcasecmp(value, "auto") == 0) {
            config->safety_mode = SAFETY_MODE_AUTO;
        }
    } else if (strcmp(key, "require_confirmation") == 0) {
        config->require_confirmation = parse_bool(value);
    } else if (strcmp(key, "enable_failsafe") == 0) {
        config->enable_failsafe = parse_bool(value);
    } else if (strcmp(key, "boot_timeout_seconds") == 0) {
        config->boot_timeout_seconds = atoi(value);
    } else if (strcmp(key, "verbose_logging") == 0) {
        config->verbose_logging = parse_bool(value);
    } else if (strcmp(key, "log_file") == 0) {
        strncpy(config->log_file, value, sizeof(config->log_file) - 1);
    } else {
        FG_WARN("Unknown configuration option: %s", key);
        return FG_ERROR;
    }

    return FG_SUCCESS;
}

int config_load(fg_config_t *config) {
    FILE *fp;
    char line[MAX_LINE_LENGTH];
    char key[128], value[128];
    int line_num = 0;

    if (!config) {
        return FG_ERROR;
    }

    /* Start with defaults */
    config_get_defaults(config);

    fp = fopen(CONFIG_FILE, "r");
    if (!fp) {
        FG_WARN("Could not open config file: %s (using defaults)", CONFIG_FILE);
        return FG_NOT_FOUND;
    }

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* Remove newline */
        line[strcspn(line, "\n")] = 0;

        /* Trim whitespace */
        trim_whitespace(line);

        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        /* Parse key=value */
        if (sscanf(line, "%127[^=]=%127[^\n]", key, value) == 2) {
            trim_whitespace(key);
            trim_whitespace(value);

            if (config_parse_option(config, key, value) != FG_SUCCESS) {
                FG_WARN("Invalid config at line %d: %s", line_num, line);
            }
        } else {
            FG_WARN("Malformed config line %d: %s", line_num, line);
        }
    }

    fclose(fp);
    FG_INFO("Loaded configuration from: %s", CONFIG_FILE);

    return FG_SUCCESS;
}

int config_save(const fg_config_t *config) {
    FILE *fp;

    if (!config) {
        return FG_ERROR;
    }

    fp = fopen(CONFIG_FILE, "w");
    if (!fp) {
        FG_LOG_ERROR("Failed to open config file for writing: %s", CONFIG_FILE);
        return FG_ERROR;
    }

    fprintf(fp, "# FirmwareGuard Configuration File\n");
    fprintf(fp, "# Auto-generated - edit carefully\n\n");

    fprintf(fp, "[Intel ME]\n");
    fprintf(fp, "block_intel_me=%s\n", config->block_intel_me ? "true" : "false");
    fprintf(fp, "me_use_hap_bit=%s\n", config->me_use_hap_bit ? "true" : "false");
    fprintf(fp, "me_use_me_cleaner=%s\n\n", config->me_use_me_cleaner ? "true" : "false");

    fprintf(fp, "[AMD PSP]\n");
    fprintf(fp, "block_amd_psp=%s\n", config->block_amd_psp ? "true" : "false");
    fprintf(fp, "psp_kernel_param=%s\n", config->psp_kernel_param ? "true" : "false");
    fprintf(fp, "psp_disable_ftpm=%s\n\n", config->psp_disable_ftpm ? "true" : "false");

    fprintf(fp, "[Network Interfaces]\n");
    fprintf(fp, "block_nic_wol=%s\n", config->block_nic_wol ? "true" : "false");
    fprintf(fp, "block_intel_amt=%s\n", config->block_intel_amt ? "true" : "false");
    fprintf(fp, "persistent_nic_config=%s\n\n", config->persistent_nic_config ? "true" : "false");

    fprintf(fp, "[ACPI]\n");
    fprintf(fp, "block_fpdt=%s\n", config->block_fpdt ? "true" : "false");
    fprintf(fp, "block_custom_tables=%s\n\n", config->block_custom_tables ? "true" : "false");

    fprintf(fp, "[General]\n");
    fprintf(fp, "auto_apply_on_boot=%s\n", config->auto_apply_on_boot ? "true" : "false");
    fprintf(fp, "reapply_after_update=%s\n", config->reapply_after_update ? "true" : "false");
    fprintf(fp, "safety_mode=%s\n",
            config->safety_mode == SAFETY_MODE_DRY_RUN ? "dry-run" :
            config->safety_mode == SAFETY_MODE_CONFIRM ? "confirm" : "auto");
    fprintf(fp, "require_confirmation=%s\n\n", config->require_confirmation ? "true" : "false");

    fprintf(fp, "[Failsafe]\n");
    fprintf(fp, "enable_failsafe=%s\n", config->enable_failsafe ? "true" : "false");
    fprintf(fp, "boot_timeout_seconds=%d\n\n", config->boot_timeout_seconds);

    fprintf(fp, "[Logging]\n");
    fprintf(fp, "verbose_logging=%s\n", config->verbose_logging ? "true" : "false");
    fprintf(fp, "log_file=%s\n", config->log_file);

    fclose(fp);

    /* Set secure permissions (root read/write only) */
    chmod(CONFIG_FILE, 0600);

    FG_INFO("Configuration saved to: %s", CONFIG_FILE);
    return FG_SUCCESS;
}

int config_load_state(fg_state_t *state) {
    FILE *fp;
    struct stat st;

    if (!state) {
        return FG_ERROR;
    }

    memset(state, 0, sizeof(fg_state_t));

    if (stat(STATE_FILE, &st) != 0) {
        /* State file doesn't exist yet */
        return FG_NOT_FOUND;
    }

    fp = fopen(STATE_FILE, "rb");
    if (!fp) {
        return FG_ERROR;
    }

    if (fread(state, sizeof(fg_state_t), 1, fp) != 1) {
        FG_WARN("Failed to read state file");
        fclose(fp);
        return FG_ERROR;
    }

    fclose(fp);

    /* Validate state fields to prevent logic errors from corrupted data */
    if (state->boot_failure_count < 0 || state->boot_failure_count > 1000) {
        FG_WARN("Corrupted state: invalid boot_failure_count (%d), resetting to 0",
                state->boot_failure_count);
        state->boot_failure_count = 0;
    }

    if (state->last_apply_timestamp < 0) {
        FG_WARN("Corrupted state: invalid last_apply_timestamp (%d), resetting to 0",
                state->last_apply_timestamp);
        state->last_apply_timestamp = 0;
    }

    /* Ensure last_error is null-terminated */
    state->last_error[sizeof(state->last_error) - 1] = '\0';

    return FG_SUCCESS;
}

int config_save_state(const fg_state_t *state) {
    FILE *fp;

    if (!state) {
        return FG_ERROR;
    }

    fp = fopen(STATE_FILE, "wb");
    if (!fp) {
        FG_LOG_ERROR("Failed to save state file: %s", strerror(errno));
        return FG_ERROR;
    }

    if (fwrite(state, sizeof(fg_state_t), 1, fp) != 1) {
        FG_LOG_ERROR("Failed to write state file");
        fclose(fp);
        return FG_ERROR;
    }

    fclose(fp);
    chmod(STATE_FILE, 0600);

    return FG_SUCCESS;
}

bool config_validate(const fg_config_t *config) {
    if (!config) {
        return false;
    }

    /* Validate boot timeout */
    if (config->boot_timeout_seconds < 30 || config->boot_timeout_seconds > 600) {
        FG_WARN("Invalid boot_timeout_seconds: %d (must be 30-600)",
                config->boot_timeout_seconds);
        return false;
    }

    /* Validate log file path */
    if (strlen(config->log_file) == 0) {
        FG_WARN("log_file cannot be empty");
        return false;
    }

    /* Warn about dangerous combinations */
    if (config->me_use_me_cleaner && config->safety_mode == SAFETY_MODE_AUTO) {
        FG_WARN("WARNING: me_cleaner in AUTO mode is dangerous!");
    }

    if (config->auto_apply_on_boot && !config->enable_failsafe) {
        FG_WARN("WARNING: auto_apply_on_boot without failsafe is risky!");
    }

    return true;
}

int config_print(const fg_config_t *config, FILE *output) {
    if (!config || !output) {
        return FG_ERROR;
    }

    fprintf(output, "\n");
    fprintf(output, "========================================\n");
    fprintf(output, "  FIRMWAREGUARD CONFIGURATION\n");
    fprintf(output, "========================================\n\n");

    fprintf(output, "Intel ME:\n");
    fprintf(output, "  Block:          %s\n", config->block_intel_me ? "Yes" : "No");
    fprintf(output, "  Use HAP bit:    %s\n", config->me_use_hap_bit ? "Yes" : "No");
    fprintf(output, "  Use me_cleaner: %s\n\n", config->me_use_me_cleaner ? "Yes" : "No");

    fprintf(output, "AMD PSP:\n");
    fprintf(output, "  Block:          %s\n", config->block_amd_psp ? "Yes" : "No");
    fprintf(output, "  Kernel param:   %s\n", config->psp_kernel_param ? "Yes" : "No");
    fprintf(output, "  Disable fTPM:   %s\n\n", config->psp_disable_ftpm ? "Yes" : "No");

    fprintf(output, "Network:\n");
    fprintf(output, "  Block WoL:      %s\n", config->block_nic_wol ? "Yes" : "No");
    fprintf(output, "  Block AMT:      %s\n", config->block_intel_amt ? "Yes" : "No");
    fprintf(output, "  Persistent:     %s\n\n", config->persistent_nic_config ? "Yes" : "No");

    fprintf(output, "General:\n");
    fprintf(output, "  Auto-apply:     %s\n", config->auto_apply_on_boot ? "Yes" : "No");
    fprintf(output, "  Safety mode:    %s\n",
            config->safety_mode == SAFETY_MODE_DRY_RUN ? "Dry-run" :
            config->safety_mode == SAFETY_MODE_CONFIRM ? "Confirm" : "Auto");
    fprintf(output, "  Failsafe:       %s\n", config->enable_failsafe ? "Yes" : "No");
    fprintf(output, "  Verbose log:    %s\n\n", config->verbose_logging ? "Yes" : "No");

    return FG_SUCCESS;
}

int config_create_default_file(void) {
    fg_config_t config;

    config_get_defaults(&config);

    if (config_save(&config) != FG_SUCCESS) {
        return FG_ERROR;
    }

    FG_INFO("Created default configuration file: %s", CONFIG_FILE);
    return FG_SUCCESS;
}
