/*
 * FirmwareGuard - Supply Chain Checksum Database
 * Offline firmware integrity verification via known-good checksums
 * OFFLINE-ONLY: No network connectivity
 */

#include "checksum_db.h"
#include "../cJSON.h"
#include "../../include/firmwareguard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

/* Use bundled SQLite or system SQLite */
#ifdef USE_BUNDLED_SQLITE
#include "sqlite3.h"
#else
#include <sqlite3.h>
#endif

/* SHA-256 implementation (minimal, for offline use) */
#include <openssl/sha.h>

/* Database handle */
static sqlite3 *g_db = NULL;
static char g_db_path[512] = {0};

/* Prepared statements cache */
static sqlite3_stmt *g_stmt_insert = NULL;
static sqlite3_stmt *g_stmt_verify = NULL;
static sqlite3_stmt *g_stmt_search = NULL;

/* SQL Schema */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS firmware ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  vendor TEXT NOT NULL,"
    "  model TEXT NOT NULL,"
    "  version TEXT NOT NULL,"
    "  region TEXT DEFAULT 'full',"
    "  sha256 TEXT NOT NULL,"
    "  sha512 TEXT,"
    "  source TEXT DEFAULT 'community',"
    "  verified INTEGER DEFAULT 0,"
    "  notes TEXT,"
    "  created_at INTEGER DEFAULT (strftime('%s', 'now')),"
    "  updated_at INTEGER DEFAULT (strftime('%s', 'now')),"
    "  UNIQUE(vendor, model, version, region, sha256)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_firmware_vendor ON firmware(vendor);"
    "CREATE INDEX IF NOT EXISTS idx_firmware_sha256 ON firmware(sha256);"
    "CREATE INDEX IF NOT EXISTS idx_firmware_model ON firmware(model);";

/* Forward declarations */
static int compute_file_hashes(const char *path, char *sha256_out, char *sha512_out);
static int prepare_statements(void);
static void finalize_statements(void);

/*
 * Initialize database
 */
int checksum_db_init(const char *db_path)
{
    if (g_db) {
        /* Already open - check if same path */
        if (strcmp(g_db_path, db_path) == 0) {
            return FG_SUCCESS;
        }
        checksum_db_close();
    }

    int rc = sqlite3_open(db_path, &g_db);
    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("Cannot open database: %s", sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return FG_ERROR;
    }

    strncpy(g_db_path, db_path, sizeof(g_db_path) - 1);

    /* Enable WAL mode for better performance */
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(g_db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);

    /* Create schema */
    char *err_msg = NULL;
    rc = sqlite3_exec(g_db, SCHEMA_SQL, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("Schema creation failed: %s", err_msg);
        sqlite3_free(err_msg);
        checksum_db_close();
        return FG_ERROR;
    }

    /* Prepare commonly used statements */
    if (prepare_statements() != 0) {
        checksum_db_close();
        return FG_ERROR;
    }

    FG_INFO("Checksum database initialized: %s", db_path);
    return FG_SUCCESS;
}

/*
 * Close database
 */
void checksum_db_close(void)
{
    finalize_statements();

    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }

    g_db_path[0] = '\0';
}

/*
 * Check if open
 */
bool checksum_db_is_open(void)
{
    return g_db != NULL;
}

/*
 * Prepare cached statements
 */
static int prepare_statements(void)
{
    const char *insert_sql =
        "INSERT INTO firmware (vendor, model, version, region, sha256, sha512, source, verified, notes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT DO NOTHING;";

    const char *verify_sql =
        "SELECT id, vendor, model, version, region, sha256, sha512, source, verified, notes, created_at "
        "FROM firmware WHERE sha256 = ?;";

    if (sqlite3_prepare_v2(g_db, insert_sql, -1, &g_stmt_insert, NULL) != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare insert statement");
        return -1;
    }

    if (sqlite3_prepare_v2(g_db, verify_sql, -1, &g_stmt_verify, NULL) != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare verify statement");
        return -1;
    }

    return 0;
}

/*
 * Finalize statements
 */
static void finalize_statements(void)
{
    if (g_stmt_insert) {
        sqlite3_finalize(g_stmt_insert);
        g_stmt_insert = NULL;
    }
    if (g_stmt_verify) {
        sqlite3_finalize(g_stmt_verify);
        g_stmt_verify = NULL;
    }
    if (g_stmt_search) {
        sqlite3_finalize(g_stmt_search);
        g_stmt_search = NULL;
    }
}

/*
 * Compute file hashes
 */
static int compute_file_hashes(const char *path, char *sha256_out, char *sha512_out)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }

    SHA256_CTX sha256_ctx;
    SHA512_CTX sha512_ctx;
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    unsigned char sha512_hash[SHA512_DIGEST_LENGTH];
    unsigned char buffer[8192];
    size_t bytes_read;

    SHA256_Init(&sha256_ctx);
    SHA512_Init(&sha512_ctx);

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        SHA256_Update(&sha256_ctx, buffer, bytes_read);
        SHA512_Update(&sha512_ctx, buffer, bytes_read);
    }

    fclose(fp);

    SHA256_Final(sha256_hash, &sha256_ctx);
    SHA512_Final(sha512_hash, &sha512_ctx);

    /* Convert to hex strings */
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(sha256_out + (i * 2), "%02x", sha256_hash[i]);
    }
    sha256_out[64] = '\0';

    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(sha512_out + (i * 2), "%02x", sha512_hash[i]);
    }
    sha512_out[128] = '\0';

    return 0;
}

/*
 * Verify firmware file
 */
int checksum_db_verify(const char *firmware_path,
                       const char *vendor,
                       const char *model,
                       const char *region,
                       fw_verify_result_t *result)
{
    memset(result, 0, sizeof(fw_verify_result_t));

    if (!g_db) {
        result->status = FW_VERIFY_DB_ERROR;
        strncpy(result->message, "Database not initialized", sizeof(result->message) - 1);
        return FG_ERROR;
    }

    /* Compute hashes */
    char sha512[129];
    if (compute_file_hashes(firmware_path, result->computed_sha256, sha512) != 0) {
        result->status = FW_VERIFY_UNKNOWN;
        snprintf(result->message, sizeof(result->message),
                "Cannot read file: %s", firmware_path);
        return FG_ERROR;
    }
    strncpy(result->computed_sha512, sha512, sizeof(result->computed_sha512) - 1);

    /* Look up in database */
    sqlite3_reset(g_stmt_verify);
    sqlite3_bind_text(g_stmt_verify, 1, result->computed_sha256, -1, SQLITE_STATIC);

    int rc = sqlite3_step(g_stmt_verify);

    if (rc == SQLITE_ROW) {
        /* Found a match */
        result->status = FW_VERIFY_MATCH;
        result->matched_entry = calloc(1, sizeof(fw_entry_t));

        if (result->matched_entry) {
            result->matched_entry->id = sqlite3_column_int64(g_stmt_verify, 0);
            strncpy(result->matched_entry->vendor,
                   (const char *)sqlite3_column_text(g_stmt_verify, 1),
                   sizeof(result->matched_entry->vendor) - 1);
            strncpy(result->matched_entry->model,
                   (const char *)sqlite3_column_text(g_stmt_verify, 2),
                   sizeof(result->matched_entry->model) - 1);
            strncpy(result->matched_entry->version,
                   (const char *)sqlite3_column_text(g_stmt_verify, 3),
                   sizeof(result->matched_entry->version) - 1);

            const char *reg = (const char *)sqlite3_column_text(g_stmt_verify, 4);
            if (reg) {
                strncpy(result->matched_entry->region, reg,
                       sizeof(result->matched_entry->region) - 1);
            }

            strncpy(result->matched_entry->sha256,
                   (const char *)sqlite3_column_text(g_stmt_verify, 5),
                   sizeof(result->matched_entry->sha256) - 1);

            const char *sha512_db = (const char *)sqlite3_column_text(g_stmt_verify, 6);
            if (sha512_db) {
                strncpy(result->matched_entry->sha512, sha512_db,
                       sizeof(result->matched_entry->sha512) - 1);
            }

            const char *source = (const char *)sqlite3_column_text(g_stmt_verify, 7);
            if (source) {
                strncpy(result->matched_entry->source, source,
                       sizeof(result->matched_entry->source) - 1);
            }

            result->matched_entry->verified = sqlite3_column_int(g_stmt_verify, 8);
            result->matched_entry->created_at = sqlite3_column_int64(g_stmt_verify, 10);
        }

        snprintf(result->message, sizeof(result->message),
                "Firmware matches known-good: %s %s v%s",
                result->matched_entry->vendor,
                result->matched_entry->model,
                result->matched_entry->version);
    } else {
        /* No match - check if we have entries for this vendor/model */
        result->status = FW_VERIFY_NOT_FOUND;

        if (vendor && model) {
            const char *count_sql =
                "SELECT COUNT(*) FROM firmware WHERE vendor = ? AND model = ?;";
            sqlite3_stmt *stmt;

            if (sqlite3_prepare_v2(g_db, count_sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, vendor, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, model, -1, SQLITE_STATIC);

                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    result->similar_entries = sqlite3_column_int(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }

            if (result->similar_entries > 0) {
                result->status = FW_VERIFY_MISMATCH;
                snprintf(result->message, sizeof(result->message),
                        "Hash does not match any of %d known entries for %s %s",
                        result->similar_entries, vendor, model);
            } else {
                snprintf(result->message, sizeof(result->message),
                        "No entries found for %s %s", vendor, model);
            }
        } else {
            strncpy(result->message, "Hash not found in database",
                   sizeof(result->message) - 1);
        }
    }

    return FG_SUCCESS;
}

/*
 * Verify by hash
 */
int checksum_db_verify_hash(const char *sha256,
                            const char *vendor,
                            const char *model,
                            fw_verify_result_t *result)
{
    memset(result, 0, sizeof(fw_verify_result_t));
    strncpy(result->computed_sha256, sha256, sizeof(result->computed_sha256) - 1);

    if (!g_db) {
        result->status = FW_VERIFY_DB_ERROR;
        return FG_ERROR;
    }

    sqlite3_reset(g_stmt_verify);
    sqlite3_bind_text(g_stmt_verify, 1, sha256, -1, SQLITE_STATIC);

    int rc = sqlite3_step(g_stmt_verify);

    if (rc == SQLITE_ROW) {
        result->status = FW_VERIFY_MATCH;
        result->matched_entry = calloc(1, sizeof(fw_entry_t));

        if (result->matched_entry) {
            result->matched_entry->id = sqlite3_column_int64(g_stmt_verify, 0);
            strncpy(result->matched_entry->vendor,
                   (const char *)sqlite3_column_text(g_stmt_verify, 1),
                   sizeof(result->matched_entry->vendor) - 1);
            strncpy(result->matched_entry->model,
                   (const char *)sqlite3_column_text(g_stmt_verify, 2),
                   sizeof(result->matched_entry->model) - 1);
            strncpy(result->matched_entry->version,
                   (const char *)sqlite3_column_text(g_stmt_verify, 3),
                   sizeof(result->matched_entry->version) - 1);
            result->matched_entry->verified = sqlite3_column_int(g_stmt_verify, 8);
        }

        snprintf(result->message, sizeof(result->message), "Hash matches known-good firmware");
    } else {
        result->status = FW_VERIFY_NOT_FOUND;
        strncpy(result->message, "Hash not found in database", sizeof(result->message) - 1);
    }

    return FG_SUCCESS;
}

/*
 * Add entry
 */
int64_t checksum_db_add(const fw_entry_t *entry)
{
    if (!g_db || !entry) {
        return -1;
    }

    sqlite3_reset(g_stmt_insert);
    sqlite3_bind_text(g_stmt_insert, 1, entry->vendor, -1, SQLITE_STATIC);
    sqlite3_bind_text(g_stmt_insert, 2, entry->model, -1, SQLITE_STATIC);
    sqlite3_bind_text(g_stmt_insert, 3, entry->version, -1, SQLITE_STATIC);
    sqlite3_bind_text(g_stmt_insert, 4, entry->region[0] ? entry->region : "full", -1, SQLITE_STATIC);
    sqlite3_bind_text(g_stmt_insert, 5, entry->sha256, -1, SQLITE_STATIC);
    sqlite3_bind_text(g_stmt_insert, 6, entry->sha512[0] ? entry->sha512 : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_text(g_stmt_insert, 7, entry->source[0] ? entry->source : "community", -1, SQLITE_STATIC);
    sqlite3_bind_int(g_stmt_insert, 8, entry->verified ? 1 : 0);
    sqlite3_bind_text(g_stmt_insert, 9, entry->notes[0] ? entry->notes : NULL, -1, SQLITE_STATIC);

    int rc = sqlite3_step(g_stmt_insert);

    if (rc != SQLITE_DONE) {
        if (rc == SQLITE_CONSTRAINT) {
            /* Duplicate entry */
            return 0;
        }
        FG_LOG_ERROR("Insert failed: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    return sqlite3_last_insert_rowid(g_db);
}

/*
 * Add from file
 */
int64_t checksum_db_add_file(const char *firmware_path,
                              const char *vendor,
                              const char *model,
                              const char *version,
                              const char *region,
                              const char *source)
{
    fw_entry_t entry;
    memset(&entry, 0, sizeof(entry));

    strncpy(entry.vendor, vendor, sizeof(entry.vendor) - 1);
    strncpy(entry.model, model, sizeof(entry.model) - 1);
    strncpy(entry.version, version, sizeof(entry.version) - 1);
    strncpy(entry.region, region ? region : "full", sizeof(entry.region) - 1);
    strncpy(entry.source, source ? source : "community", sizeof(entry.source) - 1);

    if (compute_file_hashes(firmware_path, entry.sha256, entry.sha512) != 0) {
        FG_LOG_ERROR("Cannot compute hashes for: %s", firmware_path);
        return -1;
    }

    return checksum_db_add(&entry);
}

/*
 * Import from JSON
 */
int checksum_db_import_json(const char *json_path, int *imported, int *skipped)
{
    *imported = 0;
    *skipped = 0;

    FILE *fp = fopen(json_path, "r");
    if (!fp) {
        FG_LOG_ERROR("Cannot open JSON file: %s", json_path);
        return FG_ERROR;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *json_str = malloc(size + 1);
    if (!json_str) {
        fclose(fp);
        return FG_ERROR;
    }

    fread(json_str, 1, size, fp);
    json_str[size] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(json_str);
    free(json_str);

    if (!root) {
        FG_LOG_ERROR("Invalid JSON in file: %s", json_path);
        return FG_ERROR;
    }

    /* Start transaction for performance */
    sqlite3_exec(g_db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    /* Get firmware array */
    cJSON *firmware = cJSON_GetObjectItem(root, "firmware");
    if (!firmware) {
        firmware = root; /* Try root as array */
    }

    if (!cJSON_IsArray(firmware)) {
        cJSON_Delete(root);
        sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
        return FG_ERROR;
    }

    cJSON *item;
    cJSON_ArrayForEach(item, firmware) {
        fw_entry_t entry;
        memset(&entry, 0, sizeof(entry));

        cJSON *field;

        field = cJSON_GetObjectItem(item, "vendor");
        if (field && field->valuestring) {
            strncpy(entry.vendor, field->valuestring, sizeof(entry.vendor) - 1);
        }

        field = cJSON_GetObjectItem(item, "model");
        if (field && field->valuestring) {
            strncpy(entry.model, field->valuestring, sizeof(entry.model) - 1);
        }

        field = cJSON_GetObjectItem(item, "version");
        if (field && field->valuestring) {
            strncpy(entry.version, field->valuestring, sizeof(entry.version) - 1);
        }

        field = cJSON_GetObjectItem(item, "region");
        if (field && field->valuestring) {
            strncpy(entry.region, field->valuestring, sizeof(entry.region) - 1);
        }

        field = cJSON_GetObjectItem(item, "sha256");
        if (field && field->valuestring) {
            strncpy(entry.sha256, field->valuestring, sizeof(entry.sha256) - 1);
        }

        field = cJSON_GetObjectItem(item, "sha512");
        if (field && field->valuestring) {
            strncpy(entry.sha512, field->valuestring, sizeof(entry.sha512) - 1);
        }

        field = cJSON_GetObjectItem(item, "source");
        if (field && field->valuestring) {
            strncpy(entry.source, field->valuestring, sizeof(entry.source) - 1);
        }

        field = cJSON_GetObjectItem(item, "verified");
        if (field) {
            entry.verified = cJSON_IsTrue(field);
        }

        field = cJSON_GetObjectItem(item, "notes");
        if (field && field->valuestring) {
            strncpy(entry.notes, field->valuestring, sizeof(entry.notes) - 1);
        }

        /* Validate required fields */
        if (entry.vendor[0] && entry.model[0] && entry.version[0] && entry.sha256[0]) {
            int64_t id = checksum_db_add(&entry);
            if (id > 0) {
                (*imported)++;
            } else if (id == 0) {
                (*skipped)++; /* Duplicate */
            }
        } else {
            (*skipped)++;
        }
    }

    sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL);

    cJSON_Delete(root);

    FG_INFO("Imported %d entries, skipped %d", *imported, *skipped);
    return FG_SUCCESS;
}

/*
 * Export to JSON
 */
int checksum_db_export_json(const char *json_path, const fw_query_opts_t *opts)
{
    if (!g_db) {
        return -1;
    }

    /* Build query */
    char sql[1024] = "SELECT id, vendor, model, version, region, sha256, sha512, source, verified, notes, created_at FROM firmware";
    char where[512] = "";
    int param_count = 0;

    if (opts) {
        if (opts->vendor) {
            strcat(where, param_count ? " AND " : " WHERE ");
            strcat(where, "vendor = ?");
            param_count++;
        }
        if (opts->model) {
            strcat(where, param_count ? " AND " : " WHERE ");
            strcat(where, "model = ?");
            param_count++;
        }
        if (opts->verified_only) {
            strcat(where, param_count ? " AND " : " WHERE ");
            strcat(where, "verified = 1");
        }
    }

    strcat(sql, where);
    strcat(sql, " ORDER BY vendor, model, version;");

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    /* Bind parameters */
    int bind_idx = 1;
    if (opts) {
        if (opts->vendor) {
            sqlite3_bind_text(stmt, bind_idx++, opts->vendor, -1, SQLITE_STATIC);
        }
        if (opts->model) {
            sqlite3_bind_text(stmt, bind_idx++, opts->model, -1, SQLITE_STATIC);
        }
    }

    /* Build JSON */
    cJSON *root = cJSON_CreateObject();
    cJSON *firmware = cJSON_CreateArray();

    int count = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cJSON *entry = cJSON_CreateObject();

        cJSON_AddNumberToObject(entry, "id", sqlite3_column_int64(stmt, 0));
        cJSON_AddStringToObject(entry, "vendor", (const char *)sqlite3_column_text(stmt, 1));
        cJSON_AddStringToObject(entry, "model", (const char *)sqlite3_column_text(stmt, 2));
        cJSON_AddStringToObject(entry, "version", (const char *)sqlite3_column_text(stmt, 3));

        const char *region = (const char *)sqlite3_column_text(stmt, 4);
        if (region) cJSON_AddStringToObject(entry, "region", region);

        cJSON_AddStringToObject(entry, "sha256", (const char *)sqlite3_column_text(stmt, 5));

        const char *sha512 = (const char *)sqlite3_column_text(stmt, 6);
        if (sha512) cJSON_AddStringToObject(entry, "sha512", sha512);

        const char *source = (const char *)sqlite3_column_text(stmt, 7);
        if (source) cJSON_AddStringToObject(entry, "source", source);

        cJSON_AddBoolToObject(entry, "verified", sqlite3_column_int(stmt, 8) != 0);

        const char *notes = (const char *)sqlite3_column_text(stmt, 9);
        if (notes) cJSON_AddStringToObject(entry, "notes", notes);

        cJSON_AddItemToArray(firmware, entry);
        count++;
    }

    sqlite3_finalize(stmt);

    cJSON_AddItemToObject(root, "firmware", firmware);
    cJSON_AddNumberToObject(root, "count", count);
    cJSON_AddStringToObject(root, "exported_at", __DATE__ " " __TIME__);

    /* Write to file */
    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    if (!json_str) {
        return -1;
    }

    FILE *fp = fopen(json_path, "w");
    if (!fp) {
        free(json_str);
        return -1;
    }

    fprintf(fp, "%s\n", json_str);
    fclose(fp);
    free(json_str);

    return count;
}

/*
 * Get database statistics
 */
int checksum_db_stats(fw_db_stats_t *stats)
{
    memset(stats, 0, sizeof(fw_db_stats_t));

    if (!g_db) {
        return FG_ERROR;
    }

    strncpy(stats->db_path, g_db_path, sizeof(stats->db_path) - 1);

    /* Get file size */
    struct stat st;
    if (stat(g_db_path, &st) == 0) {
        stats->db_size_bytes = st.st_size;
    }

    /* Get counts */
    sqlite3_stmt *stmt;

    if (sqlite3_prepare_v2(g_db, "SELECT COUNT(*) FROM firmware;", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats->total_entries = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    if (sqlite3_prepare_v2(g_db, "SELECT COUNT(*) FROM firmware WHERE verified = 1;", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats->verified_entries = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    if (sqlite3_prepare_v2(g_db, "SELECT COUNT(DISTINCT vendor) FROM firmware;", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats->vendor_count = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    if (sqlite3_prepare_v2(g_db, "SELECT MIN(created_at), MAX(created_at) FROM firmware;", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats->oldest_entry = sqlite3_column_int64(stmt, 0);
            stats->newest_entry = sqlite3_column_int64(stmt, 1);
        }
        sqlite3_finalize(stmt);
    }

    return FG_SUCCESS;
}

/*
 * Free result
 */
void checksum_db_free_result(fw_verify_result_t *result)
{
    if (result->matched_entry) {
        free(result->matched_entry);
        result->matched_entry = NULL;
    }
}

/*
 * Get status string
 */
const char *checksum_db_status_string(fw_verify_status_t status)
{
    switch (status) {
        case FW_VERIFY_MATCH: return "MATCH";
        case FW_VERIFY_MISMATCH: return "MISMATCH";
        case FW_VERIFY_NOT_FOUND: return "NOT_FOUND";
        case FW_VERIFY_DB_ERROR: return "DB_ERROR";
        case FW_VERIFY_UNKNOWN:
        default: return "UNKNOWN";
    }
}

/*
 * Vacuum database
 */
int checksum_db_vacuum(void)
{
    if (!g_db) {
        return FG_ERROR;
    }

    return sqlite3_exec(g_db, "VACUUM;", NULL, NULL, NULL) == SQLITE_OK ? FG_SUCCESS : FG_ERROR;
}
