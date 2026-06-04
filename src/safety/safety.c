#include "safety.h"
#include "../grub/grub_config.h"
#include "../uefi/uefi_vars.h"
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <dirent.h>
#include <limits.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <openssl/evp.h>

/* Default backup directory */
#define BACKUP_DIR "/var/lib/firmwareguard/backups"
#define REGISTRY_FILE "/var/lib/firmwareguard/backup_registry.dat"
#define ROLLBACK_FILE "/var/lib/firmwareguard/rollback_point.dat"
#define LOG_FILE "/var/log/firmwareguard.log"

/* Secure input buffer size */
#define SAFE_INPUT_SIZE 256

static int safety_secure_execute(const char *program, char *const argv[]) {
    char *clean_env[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0) {
        FG_LOG_ERROR("fork() failed: %s", strerror(errno));
        return FG_ERROR;
    }

    if (pid == 0) {
        execve(program, argv, clean_env);
        _exit(127);
    }

    if (waitpid(pid, &status, 0) < 0) {
        FG_LOG_ERROR("waitpid() failed: %s", strerror(errno));
        return FG_ERROR;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status) == 0 ? FG_SUCCESS : FG_ERROR;
    }

    return FG_ERROR;
}

static bool safety_valid_iface(const char *iface) {
    size_t len;

    if (!iface || !*iface) {
        return false;
    }

    len = strlen(iface);
    if (len > 15) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        char c = iface[i];
        if (!isalnum((unsigned char)c) && c != '-' && c != '_' &&
            c != ':' && c != '.') {
            return false;
        }
    }

    return true;
}

static int safety_atomic_write_file(const char *path, const void *data,
                                    size_t size, mode_t mode) {
    char temp_file[512];
    int fd;
    ssize_t written;

    if (!path || !data || size == 0) {
        return FG_ERROR;
    }

    int ret = snprintf(temp_file, sizeof(temp_file), "%s.fwguard-XXXXXX", path);
    if (ret < 0 || ret >= (int)sizeof(temp_file)) {
        FG_LOG_ERROR("Restore path too long: %s", path);
        return FG_ERROR;
    }

    fd = mkstemp(temp_file);
    if (fd < 0) {
        FG_LOG_ERROR("Failed to create restore temp file: %s", strerror(errno));
        return FG_ERROR;
    }

    if (fchmod(fd, mode) != 0) {
        FG_WARN("Failed to set restored file permissions: %s", strerror(errno));
    }

    written = write(fd, data, size);
    if (written != (ssize_t)size) {
        FG_LOG_ERROR("Failed to write restore data: %s", strerror(errno));
        close(fd);
        unlink(temp_file);
        return FG_ERROR;
    }

    if (fsync(fd) != 0) {
        FG_WARN("Failed to fsync restore temp file: %s", strerror(errno));
    }

    close(fd);

    if (rename(temp_file, path) != 0) {
        FG_LOG_ERROR("Failed to replace restored file %s: %s",
                     path, strerror(errno));
        unlink(temp_file);
        return FG_ERROR;
    }

    return FG_SUCCESS;
}

static const char *safety_grub_restore_path(void) {
#ifdef FG_TESTING
    const char *test_path = getenv("FG_TEST_GRUB_FILE");
#endif
    grub_config_t grub;

#ifdef FG_TESTING
    if (test_path && *test_path) {
        return test_path;
    }
#endif

    if (grub_init(&grub) == FG_SUCCESS) {
        static char path[256];
        snprintf(path, sizeof(path), "%s", grub.grub_file);
        grub_cleanup(&grub);
        return path;
    }

    return GRUB_DEFAULT_FILE;
}

static int safety_restore_grub_bytes(safety_context_t *ctx,
                                     const void *data, size_t size) {
    const char *path = safety_grub_restore_path();

    if (safety_atomic_write_file(path, data, size, 0600) != FG_SUCCESS) {
        return FG_ERROR;
    }

    FG_INFO("Restored GRUB configuration: %s", path);

#ifdef FG_TESTING
    if (getenv("FG_TEST_SKIP_GRUB_UPDATE")) {
        return FG_SUCCESS;
    }
#endif

    return grub_update(ctx);
}

static int safety_parse_field(const char *text, const char *key,
                              char *out, size_t out_size) {
    size_t key_len;
    const char *p;
    const char *end;
    size_t len;

    if (!text || !key || !out || out_size == 0) {
        return FG_ERROR;
    }

    key_len = strlen(key);
    p = text;
    while (*p) {
        if (strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
            p += key_len + 1;
            end = strpbrk(p, "\r\n");
            len = end ? (size_t)(end - p) : strlen(p);
            if (len >= out_size) {
                return FG_ERROR;
            }
            memcpy(out, p, len);
            out[len] = '\0';
            return FG_SUCCESS;
        }
        p = strchr(p, '\n');
        if (!p) {
            break;
        }
        p++;
    }

    return FG_NOT_FOUND;
}

static int safety_restore_nic_config(const char *text) {
    char iface[32];
    char wol[32];
    char unit[96];

    if (safety_parse_field(text, "iface", iface, sizeof(iface)) != FG_SUCCESS ||
        safety_parse_field(text, "wol", wol, sizeof(wol)) != FG_SUCCESS) {
        FG_LOG_ERROR("Invalid NIC backup payload");
        return FG_ERROR;
    }

    if (!safety_valid_iface(iface)) {
        FG_LOG_ERROR("Invalid interface in NIC backup: %s", iface);
        return FG_ERROR;
    }

    if (strcmp(wol, "enabled") == 0) {
        strcpy(wol, "g");
    } else if (strcmp(wol, "disabled") == 0) {
        strcpy(wol, "d");
    } else {
        size_t wol_len = strlen(wol);
        if (wol_len == 0 || wol_len > 16) {
            FG_LOG_ERROR("Invalid WoL mode in NIC backup: %s", wol);
            return FG_ERROR;
        }
        for (size_t i = 0; i < wol_len; i++) {
            if (!strchr("dpgumbas", wol[i])) {
                FG_LOG_ERROR("Invalid WoL mode in NIC backup: %s", wol);
                return FG_ERROR;
            }
        }
    }

    char *ethargv[] = { "/usr/sbin/ethtool", "-s", iface, "wol", wol, NULL };
    int ret = safety_secure_execute("/usr/sbin/ethtool", ethargv);

    snprintf(unit, sizeof(unit), "fwguard-wol@%s.service", iface);
    char *dis[] = { "/usr/bin/systemctl", "disable", "--now", unit, NULL };
    safety_secure_execute("/usr/bin/systemctl", dis);
    unlink("/etc/systemd/system/fwguard-wol@.service");
    char *reload[] = { "/usr/bin/systemctl", "daemon-reload", NULL };
    safety_secure_execute("/usr/bin/systemctl", reload);

    return ret;
}

static int safety_restore_system_state(const char *text) {
    char service[128];
    char masked[8] = "0";
    char enabled[8] = "0";
    char active[8] = "0";

    if (safety_parse_field(text, "service", service, sizeof(service)) != FG_SUCCESS) {
        FG_LOG_ERROR("Invalid system-state backup payload");
        return FG_ERROR;
    }

    if (strchr(service, '/') || strstr(service, "..") ||
        !strstr(service, ".service")) {
        FG_LOG_ERROR("Invalid service in backup: %s", service);
        return FG_ERROR;
    }

    safety_parse_field(text, "masked", masked, sizeof(masked));
    safety_parse_field(text, "enabled", enabled, sizeof(enabled));
    safety_parse_field(text, "active", active, sizeof(active));

    if (strcmp(masked, "1") == 0) {
        char *mask[] = { "/usr/bin/systemctl", "mask", service, NULL };
        safety_secure_execute("/usr/bin/systemctl", mask);
    } else {
        char *unmask[] = { "/usr/bin/systemctl", "unmask", service, NULL };
        safety_secure_execute("/usr/bin/systemctl", unmask);
    }

    if (strcmp(enabled, "1") == 0) {
        char *enable[] = { "/usr/bin/systemctl", "enable", service, NULL };
        safety_secure_execute("/usr/bin/systemctl", enable);
    } else {
        char *disable[] = { "/usr/bin/systemctl", "disable", service, NULL };
        safety_secure_execute("/usr/bin/systemctl", disable);
    }

    if (strcmp(active, "1") == 0) {
        char *start[] = { "/usr/bin/systemctl", "start", service, NULL };
        safety_secure_execute("/usr/bin/systemctl", start);
    } else {
        char *stop[] = { "/usr/bin/systemctl", "stop", service, NULL };
        safety_secure_execute("/usr/bin/systemctl", stop);
    }

    return FG_SUCCESS;
}

static int safety_restore_uefi_payload(safety_context_t *ctx,
                                       const char *text, size_t size) {
    char name[256];
    char guid[64];
    char attr_text[32];
    char data_size_text[32];
    uint32_t attrs;
    size_t data_size;
    const char *data_marker;
    const uint8_t *var_data;

    if (safety_parse_field(text, "name", name, sizeof(name)) != FG_SUCCESS ||
        safety_parse_field(text, "guid", guid, sizeof(guid)) != FG_SUCCESS ||
        safety_parse_field(text, "attributes", attr_text, sizeof(attr_text)) != FG_SUCCESS ||
        safety_parse_field(text, "data_size", data_size_text, sizeof(data_size_text)) != FG_SUCCESS) {
        FG_LOG_ERROR("Invalid UEFI backup metadata");
        return FG_ERROR;
    }

    attrs = (uint32_t)strtoul(attr_text, NULL, 0);
    data_size = (size_t)strtoull(data_size_text, NULL, 10);
    data_marker = strstr(text, "\n--DATA--\n");
    if (!data_marker) {
        FG_LOG_ERROR("Invalid UEFI backup payload");
        return FG_ERROR;
    }

    data_marker += strlen("\n--DATA--\n");
    if ((size_t)(data_marker - text) + data_size > size) {
        FG_LOG_ERROR("UEFI backup payload is truncated");
        return FG_ERROR;
    }

    var_data = (const uint8_t *)data_marker;
    return uefi_write_variable(ctx, name, guid, attrs, var_data, data_size);
}

static int safety_save_rollback_point(const safety_context_t *ctx) {
    FILE *fp;

    if (!ctx || ctx->dry_run || ctx->rollback_point.timestamp == 0) {
        return FG_SUCCESS;
    }

    fp = fopen(ROLLBACK_FILE, "wb");
    if (!fp) {
        FG_WARN("Failed to save rollback point: %s", strerror(errno));
        return FG_ERROR;
    }

    if (flock(fileno(fp), LOCK_EX) != 0) {
        fclose(fp);
        return FG_ERROR;
    }

    fchmod(fileno(fp), 0600);
    if (fwrite(&ctx->rollback_point, sizeof(rollback_point_t), 1, fp) != 1) {
        flock(fileno(fp), LOCK_UN);
        fclose(fp);
        return FG_ERROR;
    }

    flock(fileno(fp), LOCK_UN);
    fclose(fp);
    return FG_SUCCESS;
}

static int safety_load_rollback_point(safety_context_t *ctx) {
    FILE *fp;

    if (!ctx) {
        return FG_ERROR;
    }

    fp = fopen(ROLLBACK_FILE, "rb");
    if (!fp) {
        return FG_SUCCESS;
    }

    if (flock(fileno(fp), LOCK_SH) != 0) {
        fclose(fp);
        return FG_ERROR;
    }

    if (fread(&ctx->rollback_point, sizeof(rollback_point_t), 1, fp) != 1) {
        memset(&ctx->rollback_point, 0, sizeof(ctx->rollback_point));
        flock(fileno(fp), LOCK_UN);
        fclose(fp);
        return FG_ERROR;
    }

    flock(fileno(fp), LOCK_UN);
    fclose(fp);

    if (ctx->rollback_point.num_backups < 0 ||
        ctx->rollback_point.num_backups > MAX_BACKUPS) {
        memset(&ctx->rollback_point, 0, sizeof(ctx->rollback_point));
        return FG_ERROR;
    }

    ctx->rollback_point.description[sizeof(ctx->rollback_point.description) - 1] = '\0';
    return FG_SUCCESS;
}

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
        safety_load_rollback_point(ctx);
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
        safety_save_rollback_point(ctx);
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

int safety_calculate_hash(const void *data, size_t size, uint8_t hash_out[32]) {
    EVP_MD_CTX *ctx;
    unsigned int hash_len = 0;
    int ret = FG_ERROR;

    if (!data || size == 0 || !hash_out) {
        return FG_ERROR;
    }

    /* Enforce maximum size to prevent CPU DoS */
    if (size > MAX_CHECKSUM_SIZE) {
        FG_WARN("Data too large for hash: %zu bytes (max: %zu), truncating",
                size, (size_t)MAX_CHECKSUM_SIZE);
        size = MAX_CHECKSUM_SIZE;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        FG_LOG_ERROR("EVP_MD_CTX_new failed");
        return FG_ERROR;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        FG_LOG_ERROR("EVP_DigestInit_ex failed");
        goto cleanup;
    }

    if (EVP_DigestUpdate(ctx, data, size) != 1) {
        FG_LOG_ERROR("EVP_DigestUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestFinal_ex(ctx, hash_out, &hash_len) != 1) {
        FG_LOG_ERROR("EVP_DigestFinal_ex failed");
        goto cleanup;
    }

    ret = FG_SUCCESS;

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

int safety_create_backup(safety_context_t *ctx, backup_type_t type,
                         const char *name, const void *data, size_t size) {
    backup_entry_t *entry;
    FILE *fp;
    char timestamp_str[32];
    struct tm *tm_info;

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
    safety_calculate_hash(data, size, entry->checksum);

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

    {
        char hex[65];
        for (int i = 0; i < 32; i++)
            snprintf(hex + i * 2, 3, "%02x", entry->checksum[i]);
        FG_INFO("Created backup: %s (sha256: %s)", entry->backup_path, hex);
    }
    safety_log_operation(ctx, "backup_created", true, entry->backup_path);

    return FG_SUCCESS;
}

int safety_restore_backup(safety_context_t *ctx, const backup_entry_t *backup) {
    FILE *fp;
    void *data = NULL;
    size_t size;
    uint8_t computed_hash[32];
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
    data = calloc(1, size + 1);
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

    /* Verify hash */
    if (safety_calculate_hash(data, size, computed_hash) != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to compute hash for backup verification");
        free(data);
        return FG_ERROR;
    }
    if (memcmp(computed_hash, backup->checksum, 32) != 0) {
        FG_LOG_ERROR("Backup SHA-256 hash mismatch for: %s", backup->name);
        free(data);
        return FG_ERROR;
    }

    FG_INFO("Backup verification passed, restoring: %s", backup->name);

    /* Restore based on backup type */
    switch (backup->type) {
        case BACKUP_TYPE_UEFI_VAR:
            ret = safety_restore_uefi_payload(ctx, (const char *)data, size);
            break;

        case BACKUP_TYPE_GRUB_CONFIG:
            ret = safety_restore_grub_bytes(ctx, data, size);
            break;

        case BACKUP_TYPE_NIC_CONFIG:
            ret = safety_restore_nic_config((const char *)data);
            break;

        case BACKUP_TYPE_SYSTEM_STATE:
            ret = safety_restore_system_state((const char *)data);
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
    safety_save_rollback_point(ctx);

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

    /* Restore newest first so earlier pre-change backups win last. */
    for (int i = ctx->rollback_point.num_backups - 1; i >= 0; i--) {
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
    uint8_t computed_hash[32];
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
        if (safety_calculate_hash(data, st.st_size, computed_hash) == FG_SUCCESS) {
            valid = (memcmp(computed_hash, backup->checksum, 32) == 0);
        }
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
        {
            char hex[65];
            for (int j = 0; j < 32; j++)
                snprintf(hex + j * 2, 3, "%02x", entry->checksum[j]);
            fprintf(output, "    SHA-256:  %s\n", hex);
        }
        fprintf(output, "    Valid:    %s\n", entry->valid ? "Yes" : "No");
        fprintf(output, "\n");
    }

    return FG_SUCCESS;
}
