/*
 * FirmwareGuard - Threat Intelligence Database Implementation
 * Offline IOC tracking and malware family identification
 * OFFLINE-ONLY: No network connectivity, manual JSON imports only
 */

#include "threat_intel.h"
#include "../../include/cJSON.h"
#include "../../include/firmwareguard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

/* Use bundled SQLite or system SQLite */
#ifdef USE_BUNDLED_SQLITE
#include "sqlite3.h"
#else
#include <sqlite3.h>
#endif

/* Database handle */
static sqlite3 *g_db = NULL;
static char g_db_path[512] = {0};

/* Prepared statements cache for performance */
static sqlite3_stmt *g_stmt_insert_family = NULL;
static sqlite3_stmt *g_stmt_insert_ioc = NULL;
static sqlite3_stmt *g_stmt_check_hash = NULL;
static sqlite3_stmt *g_stmt_check_pattern = NULL;
static sqlite3_stmt *g_stmt_get_family = NULL;

/* SQL Schema */
static const char *SCHEMA_SQL =
    /* Malware families table */
    "CREATE TABLE IF NOT EXISTS malware_families ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  name TEXT NOT NULL UNIQUE,"
    "  type INTEGER NOT NULL,"
    "  description TEXT,"
    "  first_seen TEXT,"
    "  last_seen TEXT,"
    "  target_platforms TEXT,"
    "  target_vendors TEXT,"
    "  active INTEGER DEFAULT 1,"
    "  references TEXT,"
    "  created_at INTEGER DEFAULT (strftime('%s', 'now')),"
    "  updated_at INTEGER DEFAULT (strftime('%s', 'now'))"
    ");"

    /* MITRE ATT&CK techniques junction table */
    "CREATE TABLE IF NOT EXISTS family_mitre ("
    "  family_id INTEGER NOT NULL,"
    "  technique TEXT NOT NULL,"
    "  PRIMARY KEY (family_id, technique),"
    "  FOREIGN KEY (family_id) REFERENCES malware_families(id) ON DELETE CASCADE"
    ");"

    /* IOCs table */
    "CREATE TABLE IF NOT EXISTS threat_iocs ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  family_id INTEGER NOT NULL,"
    "  ioc_type INTEGER NOT NULL,"
    "  value TEXT NOT NULL,"
    "  description TEXT,"
    "  confidence INTEGER NOT NULL,"
    "  source TEXT,"
    "  verified INTEGER DEFAULT 0,"
    "  context TEXT,"
    "  created_at INTEGER DEFAULT (strftime('%s', 'now')),"
    "  updated_at INTEGER DEFAULT (strftime('%s', 'now')),"
    "  UNIQUE(family_id, ioc_type, value),"
    "  FOREIGN KEY (family_id) REFERENCES malware_families(id) ON DELETE CASCADE"
    ");"

    /* Indexes for fast lookups */
    "CREATE INDEX IF NOT EXISTS idx_iocs_value ON threat_iocs(value);"
    "CREATE INDEX IF NOT EXISTS idx_iocs_type ON threat_iocs(ioc_type);"
    "CREATE INDEX IF NOT EXISTS idx_iocs_family ON threat_iocs(family_id);"
    "CREATE INDEX IF NOT EXISTS idx_families_name ON malware_families(name);"
    "CREATE INDEX IF NOT EXISTS idx_families_type ON malware_families(type);"
    "CREATE INDEX IF NOT EXISTS idx_mitre_technique ON family_mitre(technique);";

/* Forward declarations */
static int prepare_statements(void);
static void finalize_statements(void);
static int load_family_from_stmt(sqlite3_stmt *stmt, malware_family_t *family);
static int load_ioc_from_stmt(sqlite3_stmt *stmt, threat_ioc_t *ioc);
static int load_mitre_techniques(int64_t family_id, char techniques[][TI_MITRE_MAX], int *count);
static int save_mitre_techniques(int64_t family_id, const char techniques[][TI_MITRE_MAX], int count);
static void normalize_hash(const char *input, char *output, size_t output_size);

/*
 * Initialize database
 */
int threat_intel_init(const char *db_path)
{
    if (g_db) {
        /* Already open - check if same path */
        if (strcmp(g_db_path, db_path) == 0) {
            return FG_SUCCESS;
        }
        threat_intel_close();
    }

    /* Open database */
    int rc = sqlite3_open(db_path, &g_db);
    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("Cannot open threat intel database: %s", sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return FG_ERROR;
    }

    strncpy(g_db_path, db_path, sizeof(g_db_path) - 1);

    /* Enable WAL mode for better concurrency and performance */
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(g_db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);
    sqlite3_exec(g_db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

    /* Create schema */
    char *err_msg = NULL;
    rc = sqlite3_exec(g_db, SCHEMA_SQL, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("Threat intel schema creation failed: %s", err_msg);
        sqlite3_free(err_msg);
        threat_intel_close();
        return FG_ERROR;
    }

    /* Prepare commonly used statements */
    if (prepare_statements() != 0) {
        threat_intel_close();
        return FG_ERROR;
    }

    FG_INFO("Threat intelligence database initialized: %s", db_path);
    return FG_SUCCESS;
}

/*
 * Close database
 */
void threat_intel_close(void)
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
bool threat_intel_is_open(void)
{
    return g_db != NULL;
}

/*
 * Prepare cached statements for performance
 */
static int prepare_statements(void)
{
    /* Insert family statement */
    const char *insert_family_sql =
        "INSERT INTO malware_families (name, type, description, first_seen, last_seen, "
        "target_platforms, target_vendors, active, references) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(name) DO UPDATE SET updated_at = strftime('%s', 'now');";

    /* Insert IOC statement */
    const char *insert_ioc_sql =
        "INSERT INTO threat_iocs (family_id, ioc_type, value, description, confidence, source, verified, context) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(family_id, ioc_type, value) DO UPDATE SET updated_at = strftime('%s', 'now');";

    /* Check hash statement - joins with family info */
    const char *check_hash_sql =
        "SELECT i.id, i.family_id, i.ioc_type, i.value, i.description, i.confidence, "
        "       i.source, i.verified, i.context, "
        "       f.name, f.type, f.description, f.active, f.references "
        "FROM threat_iocs i "
        "JOIN malware_families f ON i.family_id = f.id "
        "WHERE i.ioc_type = ? AND (i.value = ? OR i.value = ?) "
        "ORDER BY i.confidence DESC "
        "LIMIT 1;";

    /* Check pattern statement - uses LIKE for pattern matching */
    const char *check_pattern_sql =
        "SELECT i.id, i.family_id, i.ioc_type, i.value, i.description, i.confidence, "
        "       i.source, i.verified, i.context, "
        "       f.name, f.type, f.description, f.active, f.references "
        "FROM threat_iocs i "
        "JOIN malware_families f ON i.family_id = f.id "
        "WHERE i.ioc_type = ? AND ? LIKE '%' || i.value || '%' "
        "ORDER BY i.confidence DESC "
        "LIMIT 1;";

    /* Get family by name */
    const char *get_family_sql =
        "SELECT id, name, type, description, first_seen, last_seen, "
        "       target_platforms, target_vendors, active, references, "
        "       created_at, updated_at "
        "FROM malware_families WHERE name = ?;";

    /* Prepare all statements */
    if (sqlite3_prepare_v2(g_db, insert_family_sql, -1, &g_stmt_insert_family, NULL) != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare insert_family statement: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    if (sqlite3_prepare_v2(g_db, insert_ioc_sql, -1, &g_stmt_insert_ioc, NULL) != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare insert_ioc statement: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    if (sqlite3_prepare_v2(g_db, check_hash_sql, -1, &g_stmt_check_hash, NULL) != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare check_hash statement: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    if (sqlite3_prepare_v2(g_db, check_pattern_sql, -1, &g_stmt_check_pattern, NULL) != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare check_pattern statement: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    if (sqlite3_prepare_v2(g_db, get_family_sql, -1, &g_stmt_get_family, NULL) != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare get_family statement: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

/*
 * Finalize all prepared statements
 */
static void finalize_statements(void)
{
    if (g_stmt_insert_family) {
        sqlite3_finalize(g_stmt_insert_family);
        g_stmt_insert_family = NULL;
    }
    if (g_stmt_insert_ioc) {
        sqlite3_finalize(g_stmt_insert_ioc);
        g_stmt_insert_ioc = NULL;
    }
    if (g_stmt_check_hash) {
        sqlite3_finalize(g_stmt_check_hash);
        g_stmt_check_hash = NULL;
    }
    if (g_stmt_check_pattern) {
        sqlite3_finalize(g_stmt_check_pattern);
        g_stmt_check_pattern = NULL;
    }
    if (g_stmt_get_family) {
        sqlite3_finalize(g_stmt_get_family);
        g_stmt_get_family = NULL;
    }
}

/*
 * Normalize hash string (lowercase, trim whitespace)
 */
static void normalize_hash(const char *input, char *output, size_t output_size)
{
    if (!input || !output || output_size == 0) {
        if (output && output_size > 0) {
            output[0] = '\0';
        }
        return;
    }

    size_t i = 0, j = 0;

    /* Skip leading whitespace */
    while (input[i] && isspace((unsigned char)input[i])) i++;

    /* Copy and convert to lowercase, respecting output buffer size */
    while (input[i] && !isspace((unsigned char)input[i]) && j < output_size - 1) {
        output[j++] = tolower((unsigned char)input[i++]);
    }

    output[j] = '\0';
}

/*
 * Check a file hash against IOC database
 */
int threat_intel_check_hash(const char *sha256,
                             const char *sha512,
                             threat_match_t *result)
{
    if (!g_db || !sha256 || !result) {
        FG_LOG_ERROR("Invalid parameters for threat_intel_check_hash");
        return FG_ERROR;
    }

    /* Initialize result */
    memset(result, 0, sizeof(threat_match_t));
    result->matched = false;
    result->match_time = time(NULL);

    /* Normalize hashes */
    char normalized_sha256[TI_HASH_MAX] = {0};
    char normalized_sha512[TI_HASH_MAX] = {0};
    normalize_hash(sha256, normalized_sha256, sizeof(normalized_sha256));
    if (sha512) {
        normalize_hash(sha512, normalized_sha512, sizeof(normalized_sha512));
    }

    /* Bind parameters */
    sqlite3_reset(g_stmt_check_hash);
    sqlite3_bind_int(g_stmt_check_hash, 1, IOC_TYPE_FILE_HASH);
    sqlite3_bind_text(g_stmt_check_hash, 2, normalized_sha256, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_stmt_check_hash, 3,
                      sha512 ? normalized_sha512 : "", -1, SQLITE_TRANSIENT);

    /* Execute query */
    int rc = sqlite3_step(g_stmt_check_hash);
    if (rc == SQLITE_ROW) {
        /* Match found! */
        result->matched = true;
        result->ioc_id = sqlite3_column_int64(g_stmt_check_hash, 0);
        result->family_id = sqlite3_column_int64(g_stmt_check_hash, 1);
        result->ioc_type = (ioc_type_t)sqlite3_column_int(g_stmt_check_hash, 2);

        const char *value = (const char *)sqlite3_column_text(g_stmt_check_hash, 3);
        if (value) strncpy(result->ioc_value, value, TI_PATTERN_MAX - 1);

        const char *desc = (const char *)sqlite3_column_text(g_stmt_check_hash, 4);
        if (desc) strncpy(result->description, desc, TI_DESCRIPTION_MAX - 1);

        result->confidence = (confidence_level_t)sqlite3_column_int(g_stmt_check_hash, 5);

        /* Family information */
        const char *family_name = (const char *)sqlite3_column_text(g_stmt_check_hash, 9);
        if (family_name) strncpy(result->family_name, family_name, TI_FAMILY_MAX - 1);

        result->threat_type = (threat_type_t)sqlite3_column_int(g_stmt_check_hash, 10);

        /* Load MITRE techniques */
        load_mitre_techniques(result->family_id, result->mitre_techniques,
                             &result->num_mitre_techniques);

        /* Set match details */
        snprintf(result->match_details, sizeof(result->match_details),
                 "Hash matched known IOC for %s (confidence: %d%%)",
                 result->family_name, result->confidence);

        strncpy(result->matched_value, sha256, TI_PATTERN_MAX - 1);

        /* Generate remediation advice */
        snprintf(result->remediation, sizeof(result->remediation),
                 "CRITICAL: Malicious firmware detected (%s). "
                 "Immediately isolate system, capture forensic image, "
                 "and perform firmware reflash from known-good source.",
                 result->family_name);

        FG_LOG_WARN("Threat detected! Hash matches %s", result->family_name);
    } else if (rc != SQLITE_DONE) {
        FG_LOG_ERROR("Database error during hash check: %s", sqlite3_errmsg(g_db));
        return FG_ERROR;
    }

    return FG_SUCCESS;
}

/*
 * Check a behavioral pattern against IOC database
 */
int threat_intel_check_pattern(const char *pattern,
                                const char *context,
                                threat_match_t *result)
{
    if (!g_db || !pattern || !result) {
        FG_LOG_ERROR("Invalid parameters for threat_intel_check_pattern");
        return FG_ERROR;
    }

    /* Initialize result */
    memset(result, 0, sizeof(threat_match_t));
    result->matched = false;
    result->match_time = time(NULL);

    /* Bind parameters */
    sqlite3_reset(g_stmt_check_pattern);
    sqlite3_bind_int(g_stmt_check_pattern, 1, IOC_TYPE_PATTERN);
    sqlite3_bind_text(g_stmt_check_pattern, 2, pattern, -1, SQLITE_TRANSIENT);

    /* Execute query */
    int rc = sqlite3_step(g_stmt_check_pattern);
    if (rc == SQLITE_ROW) {
        /* Match found! */
        result->matched = true;
        result->ioc_id = sqlite3_column_int64(g_stmt_check_pattern, 0);
        result->family_id = sqlite3_column_int64(g_stmt_check_pattern, 1);
        result->ioc_type = (ioc_type_t)sqlite3_column_int(g_stmt_check_pattern, 2);

        const char *value = (const char *)sqlite3_column_text(g_stmt_check_pattern, 3);
        if (value) strncpy(result->ioc_value, value, TI_PATTERN_MAX - 1);

        const char *desc = (const char *)sqlite3_column_text(g_stmt_check_pattern, 4);
        if (desc) strncpy(result->description, desc, TI_DESCRIPTION_MAX - 1);

        result->confidence = (confidence_level_t)sqlite3_column_int(g_stmt_check_pattern, 5);

        /* Family information */
        const char *family_name = (const char *)sqlite3_column_text(g_stmt_check_pattern, 9);
        if (family_name) strncpy(result->family_name, family_name, TI_FAMILY_MAX - 1);

        result->threat_type = (threat_type_t)sqlite3_column_int(g_stmt_check_pattern, 10);

        /* Load MITRE techniques */
        load_mitre_techniques(result->family_id, result->mitre_techniques,
                             &result->num_mitre_techniques);

        /* Set match details */
        snprintf(result->match_details, sizeof(result->match_details),
                 "Pattern matched known behavior for %s (confidence: %d%%)",
                 result->family_name, result->confidence);

        strncpy(result->matched_value, pattern, TI_PATTERN_MAX - 1);

        /* Generate remediation based on threat type */
        switch (result->threat_type) {
            case THREAT_TYPE_BOOTKIT:
                snprintf(result->remediation, sizeof(result->remediation),
                         "Bootkit detected. Secure Boot should be enabled. "
                         "Reflash firmware from trusted source.");
                break;
            case THREAT_TYPE_UEFI_ROOTKIT:
                snprintf(result->remediation, sizeof(result->remediation),
                         "UEFI rootkit detected. Examine SPI flash dump. "
                         "Consider hardware replacement if persistent.");
                break;
            case THREAT_TYPE_SMM_IMPLANT:
                snprintf(result->remediation, sizeof(result->remediation),
                         "SMM implant detected. Check SMM memory ranges. "
                         "Update firmware and BIOS.");
                break;
            default:
                snprintf(result->remediation, sizeof(result->remediation),
                         "Suspicious behavior detected. Investigate further. "
                         "Compare against known-good baseline.");
                break;
        }

        FG_LOG_WARN("Threat pattern detected! Matches %s", result->family_name);
    } else if (rc != SQLITE_DONE) {
        FG_LOG_ERROR("Database error during pattern check: %s", sqlite3_errmsg(g_db));
        return FG_ERROR;
    }

    return FG_SUCCESS;
}

/*
 * Check multiple patterns for correlation
 */
int threat_intel_check_patterns_batch(const char **patterns,
                                       int num_patterns,
                                       threat_match_t *results,
                                       int *matched_count)
{
    if (!g_db || !patterns || !results || !matched_count) {
        FG_LOG_ERROR("Invalid parameters for threat_intel_check_patterns_batch");
        return FG_ERROR;
    }

    *matched_count = 0;

    /* Check each pattern */
    for (int i = 0; i < num_patterns; i++) {
        threat_match_t temp_result;
        if (threat_intel_check_pattern(patterns[i], NULL, &temp_result) == FG_SUCCESS) {
            if (temp_result.matched) {
                memcpy(&results[*matched_count], &temp_result, sizeof(threat_match_t));
                (*matched_count)++;
            }
        }
    }

    /* If multiple patterns matched from same family, increase confidence */
    if (*matched_count > 1) {
        /* Check if they're from the same family */
        int64_t first_family = results[0].family_id;
        bool same_family = true;

        for (int i = 1; i < *matched_count; i++) {
            if (results[i].family_id != first_family) {
                same_family = false;
                break;
            }
        }

        /* Boost confidence if correlated */
        if (same_family) {
            for (int i = 0; i < *matched_count; i++) {
                /* Increase confidence, but cap at 100 */
                int boosted = results[i].confidence + ((*matched_count - 1) * 10);
                results[i].confidence = (boosted > 100) ? 100 : boosted;

                snprintf(results[i].match_details, sizeof(results[i].match_details),
                         "Correlated pattern match (%d indicators) for %s (confidence: %d%%)",
                         *matched_count, results[i].family_name, results[i].confidence);
            }

            FG_LOG_WARN("Correlated threats detected! %d patterns match %s",
                       *matched_count, results[0].family_name);
        }
    }

    return FG_SUCCESS;
}

/*
 * Import threat intelligence from JSON
 */
int threat_intel_import_json(const char *json_path,
                              int *imported_families,
                              int *imported_iocs,
                              int *skipped)
{
    if (!g_db || !json_path) {
        FG_LOG_ERROR("Invalid parameters for threat_intel_import_json");
        return FG_ERROR;
    }

    *imported_families = 0;
    *imported_iocs = 0;
    *skipped = 0;

    /* Read JSON file */
    FILE *fp = fopen(json_path, "r");
    if (!fp) {
        FG_LOG_ERROR("Cannot open JSON file: %s", json_path);
        return FG_ERROR;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Read entire file */
    char *json_data = malloc(fsize + 1);
    if (!json_data) {
        fclose(fp);
        return FG_ERROR;
    }

    fread(json_data, 1, fsize, fp);
    json_data[fsize] = '\0';
    fclose(fp);

    /* Parse JSON */
    cJSON *root = cJSON_Parse(json_data);
    free(json_data);

    if (!root) {
        FG_LOG_ERROR("Failed to parse JSON: %s", cJSON_GetErrorPtr());
        return FG_ERROR;
    }

    /* Begin transaction for performance */
    sqlite3_exec(g_db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    /* Process malware families */
    cJSON *families = cJSON_GetObjectItem(root, "malware_families");
    if (families && cJSON_IsArray(families)) {
        cJSON *family_item = NULL;
        cJSON_ArrayForEach(family_item, families) {
            malware_family_t family = {0};

            /* Parse family data */
            cJSON *name = cJSON_GetObjectItem(family_item, "name");
            if (name && cJSON_IsString(name)) {
                strncpy(family.name, name->valuestring, TI_FAMILY_MAX - 1);
            }

            cJSON *type = cJSON_GetObjectItem(family_item, "type");
            if (type && cJSON_IsString(type)) {
                family.type = str_to_threat_type(type->valuestring);
            }

            cJSON *desc = cJSON_GetObjectItem(family_item, "description");
            if (desc && cJSON_IsString(desc)) {
                strncpy(family.description, desc->valuestring, TI_DESCRIPTION_MAX - 1);
            }

            cJSON *first_seen = cJSON_GetObjectItem(family_item, "first_seen");
            if (first_seen && cJSON_IsString(first_seen)) {
                strncpy(family.first_seen, first_seen->valuestring, 31);
            }

            cJSON *last_seen = cJSON_GetObjectItem(family_item, "last_seen");
            if (last_seen && cJSON_IsString(last_seen)) {
                strncpy(family.last_seen, last_seen->valuestring, 31);
            }

            cJSON *platforms = cJSON_GetObjectItem(family_item, "target_platforms");
            if (platforms && cJSON_IsString(platforms)) {
                strncpy(family.target_platforms, platforms->valuestring, 255);
            }

            cJSON *vendors = cJSON_GetObjectItem(family_item, "target_vendors");
            if (vendors && cJSON_IsString(vendors)) {
                strncpy(family.target_vendors, vendors->valuestring, 255);
            }

            cJSON *active = cJSON_GetObjectItem(family_item, "active");
            family.active = (!active || cJSON_IsTrue(active));

            cJSON *refs = cJSON_GetObjectItem(family_item, "references");
            if (refs && cJSON_IsString(refs)) {
                strncpy(family.references, refs->valuestring, 511);
            }

            /* Parse MITRE techniques */
            cJSON *mitre = cJSON_GetObjectItem(family_item, "mitre_techniques");
            if (mitre && cJSON_IsArray(mitre)) {
                family.num_mitre_techniques = 0;
                cJSON *tech = NULL;
                cJSON_ArrayForEach(tech, mitre) {
                    if (cJSON_IsString(tech) && family.num_mitre_techniques < 10) {
                        strncpy(family.mitre_techniques[family.num_mitre_techniques],
                               tech->valuestring, TI_MITRE_MAX - 1);
                        family.num_mitre_techniques++;
                    }
                }
            }

            /* Add family to database */
            int64_t family_id = threat_intel_add_family(&family);
            if (family_id > 0) {
                (*imported_families)++;

                /* Save MITRE techniques */
                if (family.num_mitre_techniques > 0) {
                    save_mitre_techniques(family_id, family.mitre_techniques,
                                         family.num_mitre_techniques);
                }

                /* Process IOCs for this family */
                cJSON *iocs = cJSON_GetObjectItem(family_item, "iocs");
                if (iocs && cJSON_IsArray(iocs)) {
                    cJSON *ioc_item = NULL;
                    cJSON_ArrayForEach(ioc_item, iocs) {
                        threat_ioc_t ioc = {0};
                        ioc.family_id = family_id;

                        cJSON *ioc_type = cJSON_GetObjectItem(ioc_item, "type");
                        if (ioc_type && cJSON_IsString(ioc_type)) {
                            ioc.ioc_type = str_to_ioc_type(ioc_type->valuestring);
                        }

                        cJSON *value = cJSON_GetObjectItem(ioc_item, "value");
                        if (value && cJSON_IsString(value)) {
                            strncpy(ioc.value, value->valuestring, TI_PATTERN_MAX - 1);
                        }

                        cJSON *ioc_desc = cJSON_GetObjectItem(ioc_item, "description");
                        if (ioc_desc && cJSON_IsString(ioc_desc)) {
                            strncpy(ioc.description, ioc_desc->valuestring, TI_DESCRIPTION_MAX - 1);
                        }

                        cJSON *confidence = cJSON_GetObjectItem(ioc_item, "confidence");
                        if (confidence && cJSON_IsNumber(confidence)) {
                            ioc.confidence = (confidence_level_t)confidence->valueint;
                        } else {
                            ioc.confidence = CONFIDENCE_MEDIUM;
                        }

                        cJSON *source = cJSON_GetObjectItem(ioc_item, "source");
                        if (source && cJSON_IsString(source)) {
                            strncpy(ioc.source, source->valuestring, TI_SOURCE_MAX - 1);
                        } else {
                            strncpy(ioc.source, "imported", TI_SOURCE_MAX - 1);
                        }

                        cJSON *verified = cJSON_GetObjectItem(ioc_item, "verified");
                        ioc.verified = (verified && cJSON_IsTrue(verified));

                        cJSON *context = cJSON_GetObjectItem(ioc_item, "context");
                        if (context && cJSON_IsString(context)) {
                            strncpy(ioc.context, context->valuestring, 511);
                        }

                        /* Add IOC to database */
                        if (threat_intel_add_ioc(&ioc) > 0) {
                            (*imported_iocs)++;
                        } else {
                            (*skipped)++;
                        }
                    }
                }
            } else {
                (*skipped)++;
            }
        }
    }

    /* Commit transaction */
    sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL);

    cJSON_Delete(root);

    FG_INFO("Imported %d families, %d IOCs, skipped %d entries from %s",
           *imported_families, *imported_iocs, *skipped, json_path);

    return FG_SUCCESS;
}

/*
 * Get family information
 */
int threat_intel_get_family_info(const char *family_name,
                                  malware_family_t *family,
                                  threat_ioc_t **iocs,
                                  int *ioc_count)
{
    if (!g_db || !family_name || !family) {
        FG_LOG_ERROR("Invalid parameters for threat_intel_get_family_info");
        return FG_ERROR;
    }

    /* Query family */
    sqlite3_reset(g_stmt_get_family);
    sqlite3_bind_text(g_stmt_get_family, 1, family_name, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(g_stmt_get_family);
    if (rc != SQLITE_ROW) {
        FG_LOG_ERROR("Family not found: %s", family_name);
        return FG_ERROR;
    }

    /* Load family data */
    if (load_family_from_stmt(g_stmt_get_family, family) != 0) {
        return FG_ERROR;
    }

    /* Load MITRE techniques */
    load_mitre_techniques(family->id, family->mitre_techniques,
                         &family->num_mitre_techniques);

    /* Load associated IOCs if requested */
    if (iocs && ioc_count) {
        const char *ioc_sql =
            "SELECT id, family_id, ioc_type, value, description, confidence, "
            "       source, verified, context, created_at, updated_at "
            "FROM threat_iocs WHERE family_id = ?;";

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(g_db, ioc_sql, -1, &stmt, NULL) != SQLITE_OK) {
            return FG_ERROR;
        }

        sqlite3_bind_int64(stmt, 1, family->id);

        /* Count IOCs first */
        int count = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            count++;
        }

        if (count > 0) {
            *iocs = calloc(count, sizeof(threat_ioc_t));
            if (!*iocs) {
                sqlite3_finalize(stmt);
                return FG_ERROR;
            }

            /* Reset and load IOCs */
            sqlite3_reset(stmt);
            sqlite3_bind_int64(stmt, 1, family->id);

            int i = 0;
            while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
                load_ioc_from_stmt(stmt, &(*iocs)[i]);
                i++;
            }

            *ioc_count = count;
        } else {
            *iocs = NULL;
            *ioc_count = 0;
        }

        sqlite3_finalize(stmt);
    }

    return FG_SUCCESS;
}

/*
 * Add malware family
 */
int64_t threat_intel_add_family(const malware_family_t *family)
{
    if (!g_db || !family) {
        return -1;
    }

    /* Bind parameters */
    sqlite3_reset(g_stmt_insert_family);
    sqlite3_bind_text(g_stmt_insert_family, 1, family->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_stmt_insert_family, 2, family->type);
    sqlite3_bind_text(g_stmt_insert_family, 3, family->description, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_stmt_insert_family, 4, family->first_seen, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_stmt_insert_family, 5, family->last_seen, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_stmt_insert_family, 6, family->target_platforms, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_stmt_insert_family, 7, family->target_vendors, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_stmt_insert_family, 8, family->active ? 1 : 0);
    sqlite3_bind_text(g_stmt_insert_family, 9, family->references, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(g_stmt_insert_family);
    if (rc != SQLITE_DONE) {
        FG_LOG_ERROR("Failed to insert family: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    return sqlite3_last_insert_rowid(g_db);
}

/*
 * Add IOC
 */
int64_t threat_intel_add_ioc(const threat_ioc_t *ioc)
{
    if (!g_db || !ioc) {
        return -1;
    }

    /* Bind parameters */
    sqlite3_reset(g_stmt_insert_ioc);
    sqlite3_bind_int64(g_stmt_insert_ioc, 1, ioc->family_id);
    sqlite3_bind_int(g_stmt_insert_ioc, 2, ioc->ioc_type);
    sqlite3_bind_text(g_stmt_insert_ioc, 3, ioc->value, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_stmt_insert_ioc, 4, ioc->description, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_stmt_insert_ioc, 5, ioc->confidence);
    sqlite3_bind_text(g_stmt_insert_ioc, 6, ioc->source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_stmt_insert_ioc, 7, ioc->verified ? 1 : 0);
    sqlite3_bind_text(g_stmt_insert_ioc, 8, ioc->context, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(g_stmt_insert_ioc);
    if (rc != SQLITE_DONE) {
        /* Could be duplicate - not necessarily an error */
        return -1;
    }

    return sqlite3_last_insert_rowid(g_db);
}

/*
 * Get database statistics
 */
int threat_intel_stats(threat_intel_stats_t *stats)
{
    if (!g_db || !stats) {
        return FG_ERROR;
    }

    memset(stats, 0, sizeof(threat_intel_stats_t));
    strncpy(stats->db_path, g_db_path, sizeof(stats->db_path) - 1);

    /* Get file size */
    struct stat st;
    if (stat(g_db_path, &st) == 0) {
        stats->db_size_bytes = st.st_size;
    }

    /* Query statistics */
    const char *stats_sql =
        "SELECT "
        "(SELECT COUNT(*) FROM malware_families) as total_families, "
        "(SELECT COUNT(*) FROM malware_families WHERE active = 1) as active_families, "
        "(SELECT COUNT(*) FROM threat_iocs) as total_iocs, "
        "(SELECT COUNT(*) FROM threat_iocs WHERE ioc_type = 0) as hash_iocs, "
        "(SELECT COUNT(*) FROM threat_iocs WHERE ioc_type = 1) as pattern_iocs, "
        "(SELECT COUNT(*) FROM threat_iocs WHERE verified = 1) as verified_iocs, "
        "(SELECT MIN(created_at) FROM threat_iocs) as oldest, "
        "(SELECT MAX(created_at) FROM threat_iocs) as newest;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, stats_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return FG_ERROR;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        stats->total_families = sqlite3_column_int64(stmt, 0);
        stats->active_families = sqlite3_column_int64(stmt, 1);
        stats->total_iocs = sqlite3_column_int64(stmt, 2);
        stats->hash_iocs = sqlite3_column_int64(stmt, 3);
        stats->pattern_iocs = sqlite3_column_int64(stmt, 4);
        stats->verified_iocs = sqlite3_column_int64(stmt, 5);
        stats->oldest_ioc = (time_t)sqlite3_column_int64(stmt, 6);
        stats->newest_ioc = (time_t)sqlite3_column_int64(stmt, 7);
    }

    sqlite3_finalize(stmt);
    return FG_SUCCESS;
}

/*
 * Load family from statement result
 */
static int load_family_from_stmt(sqlite3_stmt *stmt, malware_family_t *family)
{
    memset(family, 0, sizeof(malware_family_t));

    family->id = sqlite3_column_int64(stmt, 0);

    const char *name = (const char *)sqlite3_column_text(stmt, 1);
    if (name) strncpy(family->name, name, TI_FAMILY_MAX - 1);

    family->type = (threat_type_t)sqlite3_column_int(stmt, 2);

    const char *desc = (const char *)sqlite3_column_text(stmt, 3);
    if (desc) strncpy(family->description, desc, TI_DESCRIPTION_MAX - 1);

    const char *first = (const char *)sqlite3_column_text(stmt, 4);
    if (first) strncpy(family->first_seen, first, 31);

    const char *last = (const char *)sqlite3_column_text(stmt, 5);
    if (last) strncpy(family->last_seen, last, 31);

    const char *platforms = (const char *)sqlite3_column_text(stmt, 6);
    if (platforms) strncpy(family->target_platforms, platforms, 255);

    const char *vendors = (const char *)sqlite3_column_text(stmt, 7);
    if (vendors) strncpy(family->target_vendors, vendors, 255);

    family->active = sqlite3_column_int(stmt, 8) != 0;

    const char *refs = (const char *)sqlite3_column_text(stmt, 9);
    if (refs) strncpy(family->references, refs, 511);

    family->created_at = (time_t)sqlite3_column_int64(stmt, 10);
    family->updated_at = (time_t)sqlite3_column_int64(stmt, 11);

    return 0;
}

/*
 * Load IOC from statement result
 */
static int load_ioc_from_stmt(sqlite3_stmt *stmt, threat_ioc_t *ioc)
{
    memset(ioc, 0, sizeof(threat_ioc_t));

    ioc->id = sqlite3_column_int64(stmt, 0);
    ioc->family_id = sqlite3_column_int64(stmt, 1);
    ioc->ioc_type = (ioc_type_t)sqlite3_column_int(stmt, 2);

    const char *value = (const char *)sqlite3_column_text(stmt, 3);
    if (value) strncpy(ioc->value, value, TI_PATTERN_MAX - 1);

    const char *desc = (const char *)sqlite3_column_text(stmt, 4);
    if (desc) strncpy(ioc->description, desc, TI_DESCRIPTION_MAX - 1);

    ioc->confidence = (confidence_level_t)sqlite3_column_int(stmt, 5);

    const char *source = (const char *)sqlite3_column_text(stmt, 6);
    if (source) strncpy(ioc->source, source, TI_SOURCE_MAX - 1);

    ioc->verified = sqlite3_column_int(stmt, 7) != 0;

    const char *context = (const char *)sqlite3_column_text(stmt, 8);
    if (context) strncpy(ioc->context, context, 511);

    ioc->created_at = (time_t)sqlite3_column_int64(stmt, 9);
    ioc->updated_at = (time_t)sqlite3_column_int64(stmt, 10);

    return 0;
}

/*
 * Load MITRE techniques for a family
 */
static int load_mitre_techniques(int64_t family_id, char techniques[][TI_MITRE_MAX], int *count)
{
    if (!g_db || !count) {
        return -1;
    }

    *count = 0;

    const char *sql = "SELECT technique FROM family_mitre WHERE family_id = ?;";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, family_id);

    while (sqlite3_step(stmt) == SQLITE_ROW && *count < 10) {
        const char *tech = (const char *)sqlite3_column_text(stmt, 0);
        if (tech) {
            strncpy(techniques[*count], tech, TI_MITRE_MAX - 1);
            (*count)++;
        }
    }

    sqlite3_finalize(stmt);
    return 0;
}

/*
 * Save MITRE techniques for a family
 */
static int save_mitre_techniques(int64_t family_id, const char techniques[][TI_MITRE_MAX], int count)
{
    if (!g_db || count <= 0) {
        return -1;
    }

    /* Delete existing first */
    const char *del_sql = "DELETE FROM family_mitre WHERE family_id = ?;";
    sqlite3_stmt *del_stmt = NULL;

    if (sqlite3_prepare_v2(g_db, del_sql, -1, &del_stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(del_stmt, 1, family_id);
        sqlite3_step(del_stmt);
        sqlite3_finalize(del_stmt);
    }

    /* Insert new techniques */
    const char *ins_sql = "INSERT INTO family_mitre (family_id, technique) VALUES (?, ?);";
    sqlite3_stmt *ins_stmt = NULL;

    if (sqlite3_prepare_v2(g_db, ins_sql, -1, &ins_stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    for (int i = 0; i < count; i++) {
        sqlite3_reset(ins_stmt);
        sqlite3_bind_int64(ins_stmt, 1, family_id);
        sqlite3_bind_text(ins_stmt, 2, techniques[i], -1, SQLITE_TRANSIENT);
        sqlite3_step(ins_stmt);
    }

    sqlite3_finalize(ins_stmt);
    return 0;
}

/*
 * Free resources
 */
void threat_intel_free_match(threat_match_t *result)
{
    /* Currently no dynamic allocation in match result */
    (void)result;
}

void threat_intel_free_iocs(threat_ioc_t *iocs, int count)
{
    (void)count;
    if (iocs) {
        free(iocs);
    }
}

void threat_intel_free_families(malware_family_t *families, int count)
{
    (void)count;
    if (families) {
        free(families);
    }
}

/*
 * Helper functions for type conversion
 */
threat_type_t str_to_threat_type(const char *str)
{
    if (!str) return THREAT_TYPE_UNKNOWN;

    if (strcasecmp(str, "bootkit") == 0) return THREAT_TYPE_BOOTKIT;
    if (strcasecmp(str, "uefi_rootkit") == 0) return THREAT_TYPE_UEFI_ROOTKIT;
    if (strcasecmp(str, "smm_implant") == 0) return THREAT_TYPE_SMM_IMPLANT;
    if (strcasecmp(str, "firmware_backdoor") == 0) return THREAT_TYPE_FIRMWARE_BACKDOOR;
    if (strcasecmp(str, "supply_chain") == 0) return THREAT_TYPE_SUPPLY_CHAIN;
    if (strcasecmp(str, "evil_maid") == 0) return THREAT_TYPE_EVIL_MAID;
    if (strcasecmp(str, "dma_attack") == 0) return THREAT_TYPE_DMA_ATTACK;

    return THREAT_TYPE_UNKNOWN;
}

const char *threat_type_to_str(threat_type_t type)
{
    switch (type) {
        case THREAT_TYPE_BOOTKIT: return "bootkit";
        case THREAT_TYPE_UEFI_ROOTKIT: return "uefi_rootkit";
        case THREAT_TYPE_SMM_IMPLANT: return "smm_implant";
        case THREAT_TYPE_FIRMWARE_BACKDOOR: return "firmware_backdoor";
        case THREAT_TYPE_SUPPLY_CHAIN: return "supply_chain";
        case THREAT_TYPE_EVIL_MAID: return "evil_maid";
        case THREAT_TYPE_DMA_ATTACK: return "dma_attack";
        default: return "unknown";
    }
}

ioc_type_t str_to_ioc_type(const char *str)
{
    if (!str) return IOC_TYPE_UNKNOWN;

    if (strcasecmp(str, "file_hash") == 0) return IOC_TYPE_FILE_HASH;
    if (strcasecmp(str, "pattern") == 0) return IOC_TYPE_PATTERN;
    if (strcasecmp(str, "pci_id") == 0) return IOC_TYPE_PCI_ID;
    if (strcasecmp(str, "memory_signature") == 0) return IOC_TYPE_MEMORY_SIGNATURE;
    if (strcasecmp(str, "registry_key") == 0) return IOC_TYPE_REGISTRY_KEY;
    if (strcasecmp(str, "mutex") == 0) return IOC_TYPE_MUTEX;

    return IOC_TYPE_UNKNOWN;
}

const char *ioc_type_to_str(ioc_type_t type)
{
    switch (type) {
        case IOC_TYPE_FILE_HASH: return "file_hash";
        case IOC_TYPE_PATTERN: return "pattern";
        case IOC_TYPE_PCI_ID: return "pci_id";
        case IOC_TYPE_MEMORY_SIGNATURE: return "memory_signature";
        case IOC_TYPE_REGISTRY_KEY: return "registry_key";
        case IOC_TYPE_MUTEX: return "mutex";
        default: return "unknown";
    }
}

const char *confidence_level_to_str(confidence_level_t level)
{
    if (level >= CONFIDENCE_CONFIRMED) return "confirmed";
    if (level >= CONFIDENCE_HIGH) return "high";
    if (level >= CONFIDENCE_MEDIUM) return "medium";
    if (level >= CONFIDENCE_LOW) return "low";
    return "info";
}

confidence_level_t calculate_confidence(int num_indicators, int num_matches)
{
    if (num_indicators == 0) return CONFIDENCE_INFO;

    /* Calculate percentage of matches */
    int percent = (num_matches * 100) / num_indicators;

    if (percent >= 90) return CONFIDENCE_CONFIRMED;
    if (percent >= 70) return CONFIDENCE_HIGH;
    if (percent >= 50) return CONFIDENCE_MEDIUM;
    if (percent >= 30) return CONFIDENCE_LOW;

    return CONFIDENCE_INFO;
}

/*
 * Vacuum database
 */
int threat_intel_vacuum(void)
{
    if (!g_db) {
        return FG_ERROR;
    }

    char *err_msg = NULL;
    int rc = sqlite3_exec(g_db, "VACUUM;", NULL, NULL, &err_msg);

    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("Vacuum failed: %s", err_msg);
        sqlite3_free(err_msg);
        return FG_ERROR;
    }

    FG_INFO("Database vacuumed successfully");
    return FG_SUCCESS;
}
