#ifndef FG_COREBOOT_MIGRATE_H
#define FG_COREBOOT_MIGRATE_H

#include "../../include/firmwareguard.h"
#include "../detection/baseline_capture.h"
#include <stdbool.h>
#include <stdint.h>

/* Coreboot compatibility status */
typedef enum {
    COMPAT_SUPPORTED = 0,      /* Fully supported by Coreboot */
    COMPAT_LIBREBOOT,          /* Supported by Libreboot (fully free) */
    COMPAT_PARTIAL,            /* Partial support (may need blobs) */
    COMPAT_EXPERIMENTAL,       /* Experimental/WIP support */
    COMPAT_UNSUPPORTED,        /* Not supported */
    COMPAT_UNKNOWN             /* Unknown hardware */
} coreboot_compat_t;

/* Risk level for migration */
typedef enum {
    MIGRATION_RISK_LOW = 0,    /* Low risk, well-tested */
    MIGRATION_RISK_MEDIUM,     /* Medium risk, requires care */
    MIGRATION_RISK_HIGH,       /* High risk of bricking */
    MIGRATION_RISK_CRITICAL    /* Very high risk, not recommended */
} migration_risk_t;

/* Flash chip information */
typedef struct {
    char model[64];
    uint32_t size_kb;
    char interface[32];        /* SPI, LPC, etc */
    bool write_protected;
    bool internal_programmer;  /* Can use internal flashrom */
    bool external_required;    /* Requires external programmer */
} flash_chip_info_t;

/* Board support information */
typedef struct {
    /* Board identification */
    char vendor[64];
    char board_name[128];
    char board_model[64];

    /* DMI identifiers for matching */
    char dmi_sys_vendor[64];
    char dmi_product_name[128];
    char dmi_board_name[128];

    /* Compatibility status */
    coreboot_compat_t compatibility;
    char coreboot_board_name[128];  /* Name in Coreboot tree */
    char status_notes[512];

    /* Version information */
    char min_coreboot_version[32];
    char recommended_version[32];
    char tested_version[32];

    /* Flash chip support */
    int flash_chip_count;
    flash_chip_info_t flash_chips[4];

    /* Migration requirements */
    bool requires_me_cleaner;
    bool requires_external_flash;
    bool requires_hardware_mod;
    char hardware_mod_notes[256];

    /* Blob requirements */
    bool fully_free;               /* Libreboot: no blobs */
    bool requires_cpu_microcode;
    bool requires_vga_bios;
    bool requires_me_stub;
    char blob_notes[256];

    /* Risk assessment */
    migration_risk_t migration_risk;
    char risk_notes[512];

    /* Migration steps */
    int step_count;
    char migration_steps[16][256];

    /* Community support */
    char documentation_url[256];
    char community_notes[512];
    bool actively_maintained;

    /* Known issues */
    char known_issues[1024];
} coreboot_board_info_t;

/* Compatibility check result */
typedef struct {
    /* Detected hardware */
    dmi_snapshot_t detected_dmi;
    cpu_snapshot_t detected_cpu;

    /* Compatibility assessment */
    bool board_found;
    coreboot_compat_t compatibility;
    coreboot_board_info_t board_info;

    /* Current firmware state */
    char current_bios_vendor[64];
    char current_bios_version[64];
    bool intel_me_present;
    bool amd_psp_present;

    /* Migration readiness */
    bool can_migrate;
    char readiness_reason[512];
    migration_risk_t overall_risk;

    /* Warnings */
    int warning_count;
    char warnings[16][256];

    /* Summary */
    char summary[2048];
} coreboot_compat_result_t;

/* Backup information */
typedef struct {
    char backup_path[512];
    char timestamp[32];
    uint64_t flash_size;
    char hash_sha256[65];
    bool verified;
    char notes[256];
} firmware_backup_t;

/* Initialize Coreboot migration subsystem */
int coreboot_migrate_init(void);
void coreboot_migrate_cleanup(void);

/* Load Coreboot board database from JSON */
int coreboot_load_database(const char *json_path);

/* Check if current hardware is compatible with Coreboot/Libreboot */
int coreboot_check_compatibility(coreboot_compat_result_t *result);

/* Get detailed board information for detected hardware */
int coreboot_get_board_info(const dmi_snapshot_t *dmi,
                             coreboot_board_info_t *board_info);

/* Get migration steps for current hardware */
int coreboot_migration_steps(const coreboot_compat_result_t *compat,
                              char *steps_output,
                              size_t output_size);

/* Backup current firmware before migration */
int coreboot_backup_current(firmware_backup_t *backup);

/* Verify firmware backup integrity */
int coreboot_verify_backup(const firmware_backup_t *backup);

/* Display compatibility check results */
void coreboot_print_compatibility(const coreboot_compat_result_t *result,
                                   bool verbose);

/* Display detailed board information */
void coreboot_print_board_info(const coreboot_board_info_t *board,
                                bool verbose);

/* Display migration steps in user-friendly format */
void coreboot_print_migration_steps(const coreboot_board_info_t *board);

/* Check if flashrom is available and working */
int coreboot_check_flashrom(void);

/* Detect current flash chip */
int coreboot_detect_flash_chip(flash_chip_info_t *chip);

/* Generate migration warning banner */
void coreboot_print_warning_banner(void);

/* Helper: Convert compatibility enum to string */
const char* coreboot_compat_to_str(coreboot_compat_t compat);

/* Helper: Convert migration risk to string */
const char* coreboot_risk_to_str(migration_risk_t risk);

#endif /* FG_COREBOOT_MIGRATE_H */
