#ifndef FG_CONFIG_H
#define FG_CONFIG_H

#include "../../include/firmwareguard.h"
#include "../safety/safety.h"
#include <stdbool.h>

/* Configuration file paths */
#define CONFIG_DIR "/etc/firmwareguard"
#define CONFIG_FILE CONFIG_DIR "/config.conf"
#define STATE_FILE "/var/lib/firmwareguard/state.dat"

/* Configuration options */
typedef struct {
    /* Intel ME settings */
    bool block_intel_me;
    bool me_use_hap_bit;
    bool me_use_me_cleaner;

    /* AMD PSP settings */
    bool block_amd_psp;
    bool psp_kernel_param;
    bool psp_disable_ftpm;

    /* NIC settings */
    bool block_nic_wol;
    bool block_intel_amt;
    bool persistent_nic_config;

    /* ACPI settings */
    bool block_fpdt;
    bool block_custom_tables;

    /* General settings */
    bool auto_apply_on_boot;
    bool reapply_after_update;
    safety_mode_t safety_mode;
    bool require_confirmation;

    /* Boot failure handling */
    bool enable_failsafe;
    int boot_timeout_seconds;

    /* Logging */
    bool verbose_logging;
    char log_file[256];
} fg_config_t;

/* System state */
typedef struct {
    bool me_blocked;
    bool psp_blocked;
    bool nic_wol_blocked;
    int last_apply_timestamp;
    int boot_failure_count;
    char last_error[512];
} fg_state_t;

/* Initialize configuration subsystem */
int config_init(void);

/* Load configuration from file */
int config_load(fg_config_t *config);

/* Save configuration to file */
int config_save(const fg_config_t *config);

/* Load system state */
int config_load_state(fg_state_t *state);

/* Save system state */
int config_save_state(const fg_state_t *state);

/* Get default configuration */
void config_get_defaults(fg_config_t *config);

/* Validate configuration */
bool config_validate(const fg_config_t *config);

/* Print configuration to file */
int config_print(const fg_config_t *config, FILE *output);

/* Parse configuration from string (for CLI) */
int config_parse_option(fg_config_t *config, const char *key, const char *value);

/* Create default configuration file */
int config_create_default_file(void);

#endif /* FG_CONFIG_H */
