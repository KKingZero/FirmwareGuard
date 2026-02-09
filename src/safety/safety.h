#ifndef FG_SAFETY_H
#define FG_SAFETY_H

#include "../../include/firmwareguard.h"
#include <time.h>

/* Safety operation modes */
typedef enum {
    SAFETY_MODE_DRY_RUN = 0,    /* Simulate operations without executing */
    SAFETY_MODE_CONFIRM,         /* Require user confirmation */
    SAFETY_MODE_AUTO             /* Execute without confirmation (dangerous) */
} safety_mode_t;

/* Backup types */
typedef enum {
    BACKUP_TYPE_UEFI_VAR = 0,
    BACKUP_TYPE_GRUB_CONFIG,
    BACKUP_TYPE_NIC_CONFIG,
    BACKUP_TYPE_SYSTEM_STATE,
    BACKUP_TYPE_MAX
} backup_type_t;

/* Backup entry */
typedef struct {
    backup_type_t type;
    char name[256];
    char backup_path[512];
    time_t timestamp;
    uint8_t checksum[32];
    uint8_t checksum_version;
    bool valid;
} backup_entry_t;

/* Maximum size limits to prevent DoS attacks */
#define MAX_BACKUP_SIZE (50 * 1024 * 1024)  /* 50 MB */
#define MAX_CHECKSUM_SIZE (100 * 1024 * 1024)  /* 100 MB */

/* Backup registry */
#define MAX_BACKUPS 32
typedef struct {
    int num_backups;
    backup_entry_t backups[MAX_BACKUPS];
    char backup_dir[256];
} backup_registry_t;

/* Rollback point */
typedef struct {
    char description[256];
    time_t timestamp;
    int num_backups;
    backup_entry_t backups[MAX_BACKUPS];
} rollback_point_t;

/* Safety context */
typedef struct {
    safety_mode_t mode;
    bool dry_run;
    bool require_confirmation;
    backup_registry_t registry;
    rollback_point_t rollback_point;
    char last_error[512];
} safety_context_t;

/* Initialize safety subsystem */
int safety_init(safety_context_t *ctx, safety_mode_t mode);

/* Cleanup safety subsystem */
void safety_cleanup(safety_context_t *ctx);

/* Set safety mode */
int safety_set_mode(safety_context_t *ctx, safety_mode_t mode);

/* Create backup directory structure */
int safety_create_backup_dir(safety_context_t *ctx);

/* Create backup of a file/data */
int safety_create_backup(safety_context_t *ctx, backup_type_t type,
                         const char *name, const void *data, size_t size);

/* Restore from backup */
int safety_restore_backup(safety_context_t *ctx, const backup_entry_t *backup);

/* Create rollback point (checkpoint before destructive operations) */
int safety_create_rollback_point(safety_context_t *ctx, const char *description);

/* Restore to rollback point */
int safety_rollback(safety_context_t *ctx);

/* Verify backup integrity */
bool safety_verify_backup(const backup_entry_t *backup);

/* Ask user for confirmation */
bool safety_confirm_action(const char *action, const char *warning,
                           risk_level_t risk);

/* Log safety operation */
void safety_log_operation(safety_context_t *ctx, const char *operation,
                         bool success, const char *details);

/* Calculate checksum for data */
int safety_calculate_hash(const void *data, size_t size, uint8_t hash_out[32]);

/* Check if running in dry-run mode */
static inline bool safety_is_dry_run(const safety_context_t *ctx) {
    return ctx && ctx->dry_run;
}

/* Get backup registry */
const backup_registry_t* safety_get_registry(const safety_context_t *ctx);

/* Save backup registry to disk */
int safety_save_registry(const safety_context_t *ctx);

/* Load backup registry from disk */
int safety_load_registry(safety_context_t *ctx);

/* List all available backups */
int safety_list_backups(const safety_context_t *ctx, FILE *output);

#endif /* FG_SAFETY_H */
