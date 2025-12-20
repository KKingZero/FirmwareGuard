/*
 * FirmwareGuard - Live Firmware Memory Dump
 * Safe extraction of ME, SMRAM, and Option ROM contents
 * OFFLINE-ONLY: No network connectivity
 */

#ifndef LIVE_DUMP_H
#define LIVE_DUMP_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* Dump region types */
typedef enum {
    DUMP_REGION_ME = 0,        /* Intel ME memory */
    DUMP_REGION_PSP,           /* AMD PSP memory */
    DUMP_REGION_SMRAM,         /* System Management RAM */
    DUMP_REGION_OPTIONROM,     /* PCI Option ROMs */
    DUMP_REGION_UEFI_RT,       /* UEFI Runtime Services */
    DUMP_REGION_ACPI,          /* ACPI tables */
    DUMP_REGION_SPI_FLASH,     /* SPI Flash (via flashrom) */
    DUMP_REGION_MAX
} dump_region_t;

/* Dump safety level */
typedef enum {
    DUMP_SAFE_ONLY = 0,        /* Only safe methods, abort on risk */
    DUMP_SAFE_WITH_FALLBACK,   /* Try safe first, warn before risky */
    DUMP_AGGRESSIVE            /* Use all available methods */
} dump_safety_t;

/* Dump status */
typedef enum {
    DUMP_STATUS_SUCCESS = 0,
    DUMP_STATUS_PARTIAL,       /* Some data extracted */
    DUMP_STATUS_FAILED,
    DUMP_STATUS_NO_PERMISSION,
    DUMP_STATUS_NOT_SUPPORTED,
    DUMP_STATUS_UNSAFE_ABORT   /* Aborted due to safety */
} dump_status_t;

/* Region dump result */
typedef struct {
    dump_region_t region;
    dump_status_t status;
    char output_path[512];
    uint64_t size;
    char sha256[65];
    char method_used[64];
    char error[256];
    time_t dump_time;
} region_dump_t;

/* Dump session result */
typedef struct {
    int num_regions;
    region_dump_t regions[DUMP_REGION_MAX];
    char output_dir[512];
    time_t session_start;
    time_t session_end;
    bool requires_reboot;
    char warnings[1024];
} dump_session_t;

/* Dump options */
typedef struct {
    dump_safety_t safety_level;
    const char *output_dir;
    bool dump_me;
    bool dump_psp;
    bool dump_smram;
    bool dump_optionrom;
    bool dump_uefi_rt;
    bool dump_acpi;
    bool dump_spi;
    bool dry_run;              /* Don't actually dump, just check capabilities */
    bool verbose;
} dump_options_t;

/* Default options */
#define DUMP_OPTS_DEFAULT { \
    .safety_level = DUMP_SAFE_WITH_FALLBACK, \
    .output_dir = "/var/lib/firmwareguard/dumps", \
    .dump_me = true, \
    .dump_psp = true, \
    .dump_smram = false, \
    .dump_optionrom = true, \
    .dump_uefi_rt = false, \
    .dump_acpi = true, \
    .dump_spi = false, \
    .dry_run = false, \
    .verbose = false \
}

/*
 * Initialize dump subsystem
 * Checks for required kernel modules and permissions
 *
 * Returns: 0 on success, -1 on error
 */
int dump_init(void);

/*
 * Check what dump capabilities are available
 *
 * capabilities: Output bitmask of available regions
 *
 * Returns: 0 on success
 */
int dump_check_capabilities(uint32_t *capabilities);

/*
 * Get human-readable capability description
 */
const char *dump_region_name(dump_region_t region);

/*
 * Check if specific region can be dumped
 */
bool dump_region_available(dump_region_t region);

/*
 * Get risk level for dumping a region (0-10)
 * Higher values = more risky
 */
int dump_region_risk_level(dump_region_t region);

/*
 * Dump Intel ME memory region
 *
 * output_path: Where to save the dump
 * result: Output result
 *
 * Returns: 0 on success
 */
int dump_me_memory(const char *output_path, region_dump_t *result);

/*
 * Dump AMD PSP memory region
 */
int dump_psp_memory(const char *output_path, region_dump_t *result);

/*
 * Dump SMRAM (requires kernel module, dangerous)
 *
 * output_path: Where to save the dump
 * safety: Safety level
 * result: Output result
 *
 * Returns: 0 on success
 */
int dump_smram(const char *output_path, dump_safety_t safety, region_dump_t *result);

/*
 * Dump all PCI Option ROMs
 *
 * output_dir: Directory to save Option ROMs
 * result: Output result (one per Option ROM found)
 * count: Output count of Option ROMs
 *
 * Returns: 0 on success
 */
int dump_option_roms(const char *output_dir, region_dump_t **results, int *count);

/*
 * Dump UEFI Runtime Services memory
 * (Requires kernel cooperation, risky)
 */
int dump_uefi_runtime(const char *output_path, region_dump_t *result);

/*
 * Dump all ACPI tables
 */
int dump_acpi_tables(const char *output_dir, region_dump_t *result);

/*
 * Dump SPI flash via flashrom
 *
 * output_path: Where to save the dump
 * region: Optional specific region ("bios", "me", "all")
 * result: Output result
 *
 * Returns: 0 on success
 */
int dump_spi_flash(const char *output_path, const char *region, region_dump_t *result);

/*
 * Run full dump session with specified options
 *
 * opts: Dump options
 * session: Output session result
 *
 * Returns: 0 on success
 */
int dump_session(const dump_options_t *opts, dump_session_t *session);

/*
 * Print session summary
 */
void dump_print_session(const dump_session_t *session);

/*
 * Verify dump integrity
 *
 * dump_path: Path to dump file
 * expected_sha256: Expected hash (NULL to just compute)
 * computed_sha256: Output computed hash
 *
 * Returns: 0 if matches, 1 if mismatch, -1 on error
 */
int dump_verify(const char *dump_path, const char *expected_sha256, char *computed_sha256);

/*
 * Get status string
 */
const char *dump_status_string(dump_status_t status);

/*
 * Cleanup dump subsystem
 */
void dump_cleanup(void);

#endif /* LIVE_DUMP_H */
