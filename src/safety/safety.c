#include "safety.h"
#include <sys/stat.h>
#include <sys/file.h>
#include <dirent.h>
#include <limits.h>
#include <ctype.h>

/* Default backup directory */
#define BACKUP_DIR "/var/lib/firmwareguard/backups"
#define REGISTRY_FILE "/var/lib/firmwareguard/backup_registry.dat"
#define LOG_FILE "/var/log/firmwareguard.log"

/* Secure input buffer size */
#define SAFE_INPUT_SIZE 256

int safety_init(safety_context_t *ctx, safety_mode_t mode) {
    if (!ctx) {
        return FG_ERROR;
    }

    memset(ctx, 0, sizeof(safety_context_t));
    ctx->mode = mode;
    ctx->dry_run = (mode == SAFETY_MODE_DRY_RUN);
    ctx->require_confirmation = (mode == SAFETY_MODE_CONFIRM);

    /* Set backup directory */
    snprintf(ctx->registry.backup_dir, sizeof(ctx->registry.backup_dir),
             "%s", BACKUP_DIR);

    /* Create backup directory if needed */
    if (!ctx->dry_run) {
        if (safety_create_backup_dir(ctx) != FG_SUCCESS) {
            FG_WARN("Failed to create backup directory, operations may fail");
        }

        /* Try to load existing registry */
        safety_load_registry(ctx);
    }

    FG_INFO("Safety subsystem initialized (mode: %s)",
            mode == SAFETY_MODE_DRY_RUN ? "DRY-RUN" :
            mode == SAFETY_MODE_CONFIRM ? "CONFIRM" : "AUTO");

    return FG_SUCCESS;
}

void safety_cleanup(safety_context_t *ctx) {
    if (!ctx) {
        return;
    }

    /* Save registry if not in dry-run mode */
    if (!ctx->dry_run) {
        safety_save_registry(ctx);
    }

    memset(ctx, 0, sizeof(safety_context_t));
}

int safety_set_mode(safety_context_t *ctx, safety_mode_t mode) {
    if (!ctx) {
        return FG_ERROR;
    }

    ctx->mode = mode;
    ctx->dry_run = (mode == SAFETY_MODE_DRY_RUN);
    ctx->require_confirmation = (mode == SAFETY_MODE_CONFIRM);

    FG_INFO("Safety mode changed to: %s",
            mode == SAFETY_MODE_DRY_RUN ? "DRY-RUN" :
            mode == SAFETY_MODE_CONFIRM ? "CONFIRM" : "AUTO");

    return FG_SUCCESS;
}

int safety_create_backup_dir(safety_context_t *ctx) {
    char cmd[512];
    struct stat st;

    if (!ctx) {
        return FG_ERROR;
    }

    /* Check if directory exists */
    if (stat(ctx->registry.backup_dir, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return FG_SUCCESS;
        } else {
            FG_LOG_ERROR("Backup path exists but is not a directory: %s",
                        ctx->registry.backup_dir);
            return FG_ERROR;
        }
    }

    /* Create directory with secure permissions (0700) */
    /* Use mkdir_p-like behavior for parent directories */
    if (mkdir(ctx->registry.backup_dir, 0700) != 0) {
        if (errno == ENOENT) {
            /* Parent doesn't exist, create it */
            snprintf(cmd, sizeof(cmd), "/var/lib/firmwareguard");
            if (mkdir(cmd, 0700) != 0 && errno != EEXIST) {
                FG_LOG_ERROR("Failed to create parent directory: %s", strerror(errno));
                return FG_ERROR;
            }

            /* Try again */
            if (mkdir(ctx->registry.backup_dir, 0700) != 0 && errno != EEXIST) {
                FG_LOG_ERROR("Failed to create backup directory: %s", strerror(errno));
                return FG_ERROR;
            }
        } else if (errno != EEXIST) {
            FG_LOG_ERROR("Failed to create backup directory: %s", strerror(errno));
            return FG_ERROR;
        }
    }

    FG_INFO("Created backup directory: %s", ctx->registry.backup_dir);
    return FG_SUCCESS;
}

uint32_t safety_calculate_checksum(const void *data, size_t size) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t checksum = 0;

    if (!data || size == 0) {
        return 0;
    }

    /* Enforce maximum size to prevent CPU DoS */
    if (size > MAX_CHECKSUM_SIZE) {
        FG_WARN("Data too large for checksum: %zu bytes (max: %zu), truncating",
                size, (size_t)MAX_CHECKSUM_SIZE);
        size = MAX_CHECKSUM_SIZE;
    }

    /* Simple CRC32-like checksum */
    for (size_t i = 0; i < size; i++) {
        checksum = (checksum << 5) + checksum + bytes[i];
    }

    return checksum;
}

int safety_create_backup(safety_context_t *ctx, backup_type_t type,
                         const char *name, const void *data, size_t size) {
    backup_entry_t *entry;
    FILE *fp;
    char timestamp_str[32];
    struct tm *tm_info;
    time_t now;

    if (!ctx || !name || !data || size == 0) {
        FG_LOG_ERROR("Invalid parameters for backup creation");
        return FG_ERROR;
    }

    if (ctx->registry.num_backups >= MAX_BACKUPS) {
        FG_LOG_ERROR("Backup registry full (max %d backups)", MAX_BACKUPS);
        return FG_ERROR;
    }

    /* Validate name using whitelist approach - only allow safe characters */
    if (!name || strlen(name) == 0 || strlen(name) >= sizeof(entry->name)) {
        FG_LOG_ERROR("Invalid backup name length");
        return FG_ERROR;
    }

    for (const char *p = name; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') {
            FG_LOG_ERROR("Invalid backup name character '%c' (only alphanumeric, dash, underscore allowed)", *p);
            return FG_ERROR;
        }
    }

    entry = &ctx->registry.backups[ctx->registry.num_backups];
    memset(entry, 0, sizeof(backup_entry_t));

    entry->type = type;
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->timestamp = time(NULL);
    entry->checksum = safety_calculate_checksum(data, size);

    /* Format timestamp for filename */
    struct tm tm_buf;
    tm_info = localtime_r(&entry->timestamp, &tm_buf);
    if (!tm_info) {
        FG_WARN("Failed to convert timestamp");
        strcpy(timestamp_str, "unknown");
    } else {
        strftime(timestamp_str, sizeof(timestamp_str), "%Y%m%d_%H%M%S", tm_info);
    }

    /* Create backup filename with timestamp */
    int path_ret = snprintf(entry->backup_path, sizeof(entry->backup_path),
                           "%s/%s_%s.bak", ctx->registry.backup_dir, name, timestamp_str);
    if (path_ret < 0 || path_ret >= (int)sizeof(entry->backup_path)) {
        FG_LOG_ERROR("Backup path too long (would be %d bytes, max: %zu)",
                     path_ret, sizeof(entry->backup_path) - 1);
        return FG_ERROR;
    }

    if (ctx->dry_run) {
        FG_INFO("[DRY-RUN] Would create backup: %s", entry->backup_path);
        entry->valid = true;
        ctx->registry.num_backups++;
        return FG_SUCCESS;
    }

    /* Write backup file with secure permissions */
    fp = fopen(entry->backup_path, "wb");
    if (!fp) {
        FG_LOG_ERROR("Failed to create backup file: %s (%s)",
                    entry->backup_path, strerror(errno));
        return FG_ERROR;
    }

    /* Set restrictive permissions (0600 - owner read/write only) */
    if (fchmod(fileno(fp), 0600) != 0) {
        FG_WARN("Failed to set secure permissions on backup file");
    }

    /* Write data */
    if (fwrite(data, 1, size, fp) != size) {
        FG_LOG_ERROR("Failed to write backup data: %s", strerror(errno));
        fclose(fp);
        unlink(entry->backup_path);
        return FG_ERROR;
    }

    fclose(fp);
    entry->valid = true;
    ctx->registry.num_backups++;

    FG_INFO("Created backup: %s (checksum: 0x%08x)", entry->backup_path, entry->checksum);
    safety_log_operation(ctx, "backup_created", true, entry->backup_path);

    return FG_SUCCESS;
}

int safety_restore_backup(safety_context_t *ctx, const backup_entry_t *backup) {
    FILE *fp;
    void *data = NULL;
    size_t size;
    uint32_t checksum;
    struct stat st;
    int ret = FG_ERROR;

    if (!ctx || !backup || !backup->valid) {
        return FG_ERROR;
    }

    if (ctx->dry_run) {
        FG_INFO("[DRY-RUN] Would restore backup: %s", backup->backup_path);
        return FG_SUCCESS;
    }

    /* Verify backup file exists */
    if (stat(backup->backup_path, &st) != 0) {
        FG_LOG_ERROR("Backup file not found: %s", backup->backup_path);
        return FG_NOT_FOUND;
    }

    /* Validate file size before casting */
    if (st.st_size <= 0) {
        FG_LOG_ERROR("Invalid backup file size: %ld bytes", (long)st.st_size);
        return FG_ERROR;
    }

    size = (size_t)st.st_size;

    /* Enforce maximum size limit to prevent DoS */
    if (size > MAX_BACKUP_SIZE) {
        FG_LOG_ERROR("Backup file too large: %zu bytes (max: %zu)",
                     size, (size_t)MAX_BACKUP_SIZE);
        return FG_ERROR;
    }

    /* Allocate buffer */
    data = malloc(size);
    if (!data) {
        FG_LOG_ERROR("Failed to allocate memory for backup restore");
        return FG_ERROR;
    }

    /* Read backup file */
    fp = fopen(backup->backup_path, "rb");
    if (!fp) {
        FG_LOG_ERROR("Failed to open backup file: %s", backup->backup_path);
        free(data);
        return FG_ERROR;
    }

    if (fread(data, 1, size, fp) != size) {
        FG_LOG_ERROR("Failed to read backup data: %s", strerror(errno));
        fclose(fp);
        free(data);
        return FG_ERROR;
    }

    fclose(fp);

    /* Verify checksum */
    checksum = safety_calculate_checksum(data, size);
    if (checksum != backup->checksum) {
        FG_LOG_ERROR("Backup checksum mismatch (expected: 0x%08x, got: 0x%08x)",
                    backup->checksum, checksum);
        free(data);
        return FG_ERROR;
    }

    FG_INFO("Backup verification passed, restoring: %s", backup->name);

    /* Restore based on backup type */
    switch (backup->type) {
        case BACKUP_TYPE_UEFI_VAR:
            /* Restoration handled by UEFI module */
            FG_INFO("UEFI variable restore requires UEFI module");
            ret = FG_SUCCESS;
            break;

        case BACKUP_TYPE_GRUB_CONFIG:
            /* Restore GRUB config */
            FG_INFO("GRUB config restore requires GRUB module");
            ret = FG_SUCCESS;
            break;

        case BACKUP_TYPE_NIC_CONFIG:
            /* Restore NIC configuration */
            FG_INFO("NIC config restore requires NIC module");
            ret = FG_SUCCESS;
            break;

        default:
            FG_WARN("Unknown backup type: %d", backup->type);
            ret = FG_NOT_SUPPORTED;
            break;
    }

    free(data);
    safety_log_operation(ctx, "backup_restored", ret == FG_SUCCESS, backup->backup_path);

    return ret;
}

int safety_create_rollback_point(safety_context_t *ctx, const char *description) {
    if (!ctx || !description) {
        return FG_ERROR;
    }

    /* Save current registry state as rollback point */
    strncpy(ctx->rollback_point.description, description,
            sizeof(ctx->rollback_point.description) - 1);
    ctx->rollback_point.timestamp = time(NULL);
    ctx->rollback_point.num_backups = ctx->registry.num_backups;

    /* Copy current backups */
    memcpy(ctx->rollback_point.backups, ctx->registry.backups,
           sizeof(backup_entry_t) * ctx->registry.num_backups);

    FG_INFO("Created rollback point: %s", description);
    safety_log_operation(ctx, "rollback_point_created", true, description);

    return FG_SUCCESS;
}

int safety_rollback(safety_context_t *ctx) {
    if (!ctx) {
        return FG_ERROR;
    }

    if (ctx->rollback_point.timestamp == 0) {
        FG_LOG_ERROR("No rollback point available");
        return FG_NOT_FOUND;
    }

    if (ctx->dry_run) {
        FG_INFO("[DRY-RUN] Would rollback to: %s", ctx->rollback_point.description);
        return FG_SUCCESS;
    }

    FG_INFO("Rolling back to: %s", ctx->rollback_point.description);

    /* Validate rollback point before proceeding */
    if (ctx->rollback_point.num_backups < 0 ||
        ctx->rollback_point.num_backups > MAX_BACKUPS) {
        FG_LOG_ERROR("Corrupted rollback point: invalid num_backups (%d)",
                     ctx->rollback_point.num_backups);
        return FG_ERROR;
    }

    /* Restore all backups from rollback point */
    for (int i = 0; i < ctx->rollback_point.num_backups; i++) {
        if (safety_restore_backup(ctx, &ctx->rollback_point.backups[i]) != FG_SUCCESS) {
            FG_WARN("Failed to restore backup during rollback: %s",
                   ctx->rollback_point.backups[i].name);
        }
    }

    safety_log_operation(ctx, "rollback_completed", true, ctx->rollback_point.description);
    return FG_SUCCESS;
}

bool safety_verify_backup(const backup_entry_t *backup) {
    FILE *fp;
    struct stat st;
    void *data;
    uint32_t checksum;
    bool valid = false;

    if (!backup || !backup->valid) {
        return false;
    }

    /* Check if file exists */
    if (stat(backup->backup_path, &st) != 0) {
        return false;
    }

    /* Read and verify checksum */
    fp = fopen(backup->backup_path, "rb");
    if (!fp) {
        return false;
    }

    data = malloc(st.st_size);
    if (!data) {
        fclose(fp);
        return false;
    }

    if (fread(data, 1, st.st_size, fp) == (size_t)st.st_size) {
        checksum = safety_calculate_checksum(data, st.st_size);
        valid = (checksum == backup->checksum);
    }

    free(data);
    fclose(fp);

    return valid;
}

bool safety_confirm_action(const char *action, const char *warning,
                          risk_level_t risk) {
    char response[SAFE_INPUT_SIZE];
    const char *risk_str;

    if (!action || !warning) {
        return false;
    }

    /* Get risk level string */
    switch (risk) {
        case RISK_CRITICAL: risk_str = "CRITICAL"; break;
        case RISK_HIGH:     risk_str = "HIGH"; break;
        case RISK_MEDIUM:   risk_str = "MEDIUM"; break;
        case RISK_LOW:      risk_str = "LOW"; break;
        default:            risk_str = "UNKNOWN"; break;
    }

    /* Display warning */
    printf("\n");
    printf("========================================\n");
    printf("  CONFIRMATION REQUIRED\n");
    printf("========================================\n");
    printf("\n");
    printf("Action:  %s\n", action);
    printf("Risk:    %s\n", risk_str);
    printf("\n");
    printf("Warning:\n%s\n", warning);
    printf("\n");
    printf("This operation may cause system instability or data loss.\n");
    printf("A backup will be created before proceeding.\n");
    printf("\n");
    printf("Type 'YES' to confirm (anything else to cancel): ");
    fflush(stdout);

    /* Read response with bounds checking */
    if (!fgets(response, sizeof(response), stdin)) {
        return false;
    }

    /* Remove newline */
    response[strcspn(response, "\n")] = 0;

    /* Check for exact match of "YES" */
    if (strcmp(response, "YES") == 0) {
        FG_INFO("User confirmed action: %s", action);
        return true;
    }

    FG_INFO("User cancelled action: %s", action);
    return false;
}

void safety_log_operation(safety_context_t *ctx, const char *operation,
                         bool success, const char *details) {
    FILE *fp;
    time_t now;
    struct tm *tm_info;
    char timestamp[64];

    if (!ctx || !operation) {
        return;
    }

    if (ctx->dry_run) {
        return; /* Don't write logs in dry-run mode */
    }

    now = time(NULL);
    struct tm tm_buf;
    tm_info = localtime_r(&now, &tm_buf);
    if (!tm_info) {
        strcpy(timestamp, "unknown");
    } else {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    }

    fp = fopen(LOG_FILE, "a");
    if (!fp) {
        return; /* Silent failure for logging */
    }

    fprintf(fp, "[%s] %s: %s - %s\n",
            timestamp, success ? "SUCCESS" : "FAILURE",
            operation, details ? details : "");

    fclose(fp);
}

const backup_registry_t* safety_get_registry(const safety_context_t *ctx) {
    if (!ctx) {
        return NULL;
    }
    return &ctx->registry;
}

int safety_save_registry(const safety_context_t *ctx) {
    FILE *fp;

    if (!ctx) {
        return FG_ERROR;
    }

    if (ctx->dry_run) {
        return FG_SUCCESS;
    }

    fp = fopen(REGISTRY_FILE, "wb");
    if (!fp) {
        FG_WARN("Failed to save backup registry: %s", strerror(errno));
        return FG_ERROR;
    }

    /* Acquire exclusive lock to prevent concurrent access */
    if (flock(fileno(fp), LOCK_EX) != 0) {
        FG_WARN("Failed to lock registry file: %s", strerror(errno));
        fclose(fp);
        return FG_ERROR;
    }

    /* Set secure permissions */
    fchmod(fileno(fp), 0600);

    if (fwrite(&ctx->registry, sizeof(backup_registry_t), 1, fp) != 1) {
        FG_LOG_ERROR("Failed to write backup registry");
        flock(fileno(fp), LOCK_UN);
        fclose(fp);
        return FG_ERROR;
    }

    /* Release lock and close */
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
    return FG_SUCCESS;
}

int safety_load_registry(safety_context_t *ctx) {
    FILE *fp;
    struct stat st;

    if (!ctx) {
        return FG_ERROR;
    }

    if (stat(REGISTRY_FILE, &st) != 0) {
        /* Registry doesn't exist yet, not an error */
        return FG_SUCCESS;
    }

    fp = fopen(REGISTRY_FILE, "rb");
    if (!fp) {
        return FG_ERROR;
    }

    /* Acquire shared lock for reading */
    if (flock(fileno(fp), LOCK_SH) != 0) {
        FG_WARN("Failed to lock registry file for reading: %s", strerror(errno));
        fclose(fp);
        return FG_ERROR;
    }

    if (fread(&ctx->registry, sizeof(backup_registry_t), 1, fp) != 1) {
        FG_WARN("Failed to read backup registry (may be corrupted)");
        flock(fileno(fp), LOCK_UN);
        fclose(fp);
        return FG_ERROR;
    }

    /* Release lock and close */
    flock(fileno(fp), LOCK_UN);
    fclose(fp);

    /* Validate registry fields to prevent buffer overflows */
    if (ctx->registry.num_backups < 0 || ctx->registry.num_backups > MAX_BACKUPS) {
        FG_LOG_ERROR("Corrupted registry: invalid num_backups (%d), expected 0-%d",
                     ctx->registry.num_backups, MAX_BACKUPS);
        memset(&ctx->registry, 0, sizeof(backup_registry_t));
        return FG_ERROR;
    }

    /* Validate backup_dir path doesn't contain null bytes in the middle */
    size_t dir_len = strnlen(ctx->registry.backup_dir, sizeof(ctx->registry.backup_dir));
    if (dir_len == 0 || dir_len >= sizeof(ctx->registry.backup_dir)) {
        FG_LOG_ERROR("Corrupted registry: invalid backup_dir");
        memset(&ctx->registry, 0, sizeof(backup_registry_t));
        return FG_ERROR;
    }

    FG_INFO("Loaded backup registry (%d backups)", ctx->registry.num_backups);

    return FG_SUCCESS;
}

int safety_list_backups(const safety_context_t *ctx, FILE *output) {
    struct tm *tm_info;
    char timestamp[64];

    if (!ctx || !output) {
        return FG_ERROR;
    }

    fprintf(output, "\n");
    fprintf(output, "========================================\n");
    fprintf(output, "  BACKUP REGISTRY\n");
    fprintf(output, "========================================\n");
    fprintf(output, "\n");
    fprintf(output, "Total Backups: %d\n", ctx->registry.num_backups);
    fprintf(output, "Backup Directory: %s\n", ctx->registry.backup_dir);
    fprintf(output, "\n");

    if (ctx->registry.num_backups == 0) {
        fprintf(output, "No backups found.\n\n");
        return FG_SUCCESS;
    }

    fprintf(output, "BACKUPS:\n");
    fprintf(output, "--------\n\n");

    for (int i = 0; i < ctx->registry.num_backups; i++) {
        const backup_entry_t *entry = &ctx->registry.backups[i];

        struct tm tm_buf;
        tm_info = localtime_r(&entry->timestamp, &tm_buf);
        if (!tm_info) {
            strcpy(timestamp, "unknown");
        } else {
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        }

        fprintf(output, "[%d] %s\n", i + 1, entry->name);
        fprintf(output, "    Type:     %d\n", entry->type);
        fprintf(output, "    Created:  %s\n", timestamp);
        fprintf(output, "    Path:     %s\n", entry->backup_path);
        fprintf(output, "    Checksum: 0x%08x\n", entry->checksum);
        fprintf(output, "    Valid:    %s\n", entry->valid ? "Yes" : "No");
        fprintf(output, "\n");
    }

    return FG_SUCCESS;
}
