/*
 * FirmwareGuard - CVE Correlation Database Implementation
 * Offline CVE tracking and version correlation for firmware components
 * OFFLINE-ONLY: No network connectivity, manual JSON imports only
 */

#include "cve_db.h"
#include "cJSON.h"
#include "firmwareguard.h"

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
static sqlite3_stmt *g_stmt_insert = NULL;
static sqlite3_stmt *g_stmt_get_by_id = NULL;
static sqlite3_stmt *g_stmt_search = NULL;
static sqlite3_stmt *g_stmt_check_version = NULL;

/* SQL Schema - OFFLINE-ONLY database structure */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS cve_entries ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  cve_id TEXT NOT NULL UNIQUE,"
    "  component TEXT NOT NULL,"
    "  component_type INTEGER NOT NULL,"
    "  vendor TEXT NOT NULL,"
    "  description TEXT,"
    "  remediation TEXT,"
    "  version_affected_start TEXT,"
    "  version_affected_end TEXT,"
    "  version_fixed TEXT,"
    "  cvss_score REAL DEFAULT 0.0,"
    "  severity INTEGER DEFAULT 4,"
    "  cvss_vector TEXT,"
    "  published_date INTEGER,"
    "  modified_date INTEGER,"
    "  exploited_in_wild INTEGER DEFAULT 0,"
    "  patch_available INTEGER DEFAULT 0,"
    "  created_at INTEGER DEFAULT (strftime('%s', 'now')),"
    "  updated_at INTEGER DEFAULT (strftime('%s', 'now'))"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_cve_id ON cve_entries(cve_id);"
    "CREATE INDEX IF NOT EXISTS idx_component ON cve_entries(component);"
    "CREATE INDEX IF NOT EXISTS idx_component_type ON cve_entries(component_type);"
    "CREATE INDEX IF NOT EXISTS idx_vendor ON cve_entries(vendor);"
    "CREATE INDEX IF NOT EXISTS idx_severity ON cve_entries(severity);"
    "CREATE INDEX IF NOT EXISTS idx_cvss_score ON cve_entries(cvss_score DESC);"
    "CREATE TABLE IF NOT EXISTS cve_references ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  cve_entry_id INTEGER NOT NULL,"
    "  reference_url TEXT NOT NULL,"
    "  FOREIGN KEY(cve_entry_id) REFERENCES cve_entries(id) ON DELETE CASCADE"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_cve_ref ON cve_references(cve_entry_id);";

/* Forward declarations */
static int prepare_statements(void);
static void finalize_statements(void);
static int parse_cve_json(cJSON *cve_obj, cve_entry_t *entry);
static int insert_cve_references(int64_t cve_entry_id, const cve_entry_t *entry);
static int fetch_cve_references(int64_t cve_entry_id, cve_entry_t *entry);
static void row_to_cve_entry(sqlite3_stmt *stmt, cve_entry_t *entry);

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

/*
 * Initialize CVE database
 */
int cve_db_init(const char *db_path)
{
    /* Input validation */
    if (!db_path || strlen(db_path) == 0) {
        FG_LOG_ERROR("Invalid database path");
        return FG_ERROR;
    }

    /* Check if already open */
    if (g_db) {
        if (strcmp(g_db_path, db_path) == 0) {
            return FG_SUCCESS;
        }
        cve_db_close();
    }

    /* Open database */
    int rc = sqlite3_open(db_path, &g_db);
    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("Cannot open CVE database: %s", sqlite3_errmsg(g_db));
        if (g_db) {
            sqlite3_close(g_db);
            g_db = NULL;
        }
        return FG_ERROR;
    }

    /* Store path - use strncpy with explicit null termination */
    strncpy(g_db_path, db_path, sizeof(g_db_path) - 1);
    g_db_path[sizeof(g_db_path) - 1] = '\0';

    /* Enable security features */
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(g_db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);
    sqlite3_exec(g_db, "PRAGMA secure_delete=ON;", NULL, NULL, NULL);

    /* Create schema */
    char *err_msg = NULL;
    rc = sqlite3_exec(g_db, SCHEMA_SQL, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("CVE schema creation failed: %s", err_msg);
        sqlite3_free(err_msg);
        cve_db_close();
        return FG_ERROR;
    }

    /* Prepare commonly used statements */
    if (prepare_statements() != 0) {
        FG_LOG_ERROR("Failed to prepare CVE database statements");
        cve_db_close();
        return FG_ERROR;
    }

    FG_LOG_INFO("CVE database initialized: %s", db_path);
    return FG_SUCCESS;
}

/*
 * Close CVE database
 */
void cve_db_close(void)
{
    if (!g_db) {
        return;
    }

    finalize_statements();
    sqlite3_close(g_db);
    g_db = NULL;
    memset(g_db_path, 0, sizeof(g_db_path));
}

/*
 * Check if database is open
 */
bool cve_db_is_open(void)
{
    return (g_db != NULL);
}

/*
 * Get CVE by ID
 */
int cve_db_get_by_id(const char *cve_id, cve_entry_t *entry)
{
    if (!g_db || !cve_id || !entry) {
        return FG_ERROR;
    }

    /* Validate CVE ID format (basic check) */
    if (strncmp(cve_id, "CVE-", 4) != 0 || strlen(cve_id) < 9) {
        FG_LOG_ERROR("Invalid CVE ID format: %s", cve_id);
        return FG_ERROR;
    }

    memset(entry, 0, sizeof(cve_entry_t));

    const char *sql = "SELECT * FROM cve_entries WHERE cve_id = ? LIMIT 1;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare CVE lookup: %s", sqlite3_errmsg(g_db));
        return FG_ERROR;
    }

    sqlite3_bind_text(stmt, 1, cve_id, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        row_to_cve_entry(stmt, entry);
        sqlite3_finalize(stmt);

        /* Fetch references */
        fetch_cve_references(entry->id, entry);
        return FG_SUCCESS;
    }

    sqlite3_finalize(stmt);
    return FG_ERROR;
}

/*
 * Search for CVEs matching criteria
 */
int cve_db_search(const cve_query_opts_t *opts,
                  cve_match_t **results,
                  int *count)
{
    if (!g_db || !results || !count) {
        return FG_ERROR;
    }

    *results = NULL;
    *count = 0;

    /* Build dynamic SQL query based on options */
    char sql[2048];
    int sql_len = 0;
    bool has_where = false;

    sql_len = snprintf(sql, sizeof(sql), "SELECT * FROM cve_entries");

    /* Add WHERE clauses */
    if (opts) {
        if (opts->cve_id) {
            sql_len += snprintf(sql + sql_len, sizeof(sql) - sql_len,
                               "%s cve_id = ?", has_where ? " AND" : " WHERE");
            has_where = true;
        }
        if (opts->component) {
            sql_len += snprintf(sql + sql_len, sizeof(sql) - sql_len,
                               "%s component LIKE ?", has_where ? " AND" : " WHERE");
            has_where = true;
        }
        if (opts->component_type != CVE_COMPONENT_UNKNOWN) {
            sql_len += snprintf(sql + sql_len, sizeof(sql) - sql_len,
                               "%s component_type = ?", has_where ? " AND" : " WHERE");
            has_where = true;
        }
        if (opts->vendor) {
            sql_len += snprintf(sql + sql_len, sizeof(sql) - sql_len,
                               "%s vendor LIKE ?", has_where ? " AND" : " WHERE");
            has_where = true;
        }
        if (opts->min_severity != CVE_SEVERITY_UNKNOWN) {
            sql_len += snprintf(sql + sql_len, sizeof(sql) - sql_len,
                               "%s severity <= ?", has_where ? " AND" : " WHERE");
            has_where = true;
        }
        if (opts->only_exploited) {
            sql_len += snprintf(sql + sql_len, sizeof(sql) - sql_len,
                               "%s exploited_in_wild = 1", has_where ? " AND" : " WHERE");
            has_where = true;
        }
        if (opts->only_unpatched) {
            sql_len += snprintf(sql + sql_len, sizeof(sql) - sql_len,
                               "%s patch_available = 0", has_where ? " AND" : " WHERE");
            has_where = true;
        }
    }

    /* Order by severity and CVSS score */
    sql_len += snprintf(sql + sql_len, sizeof(sql) - sql_len,
                       " ORDER BY severity ASC, cvss_score DESC");

    /* Add limit and offset */
    if (opts && opts->limit > 0) {
        sql_len += snprintf(sql + sql_len, sizeof(sql) - sql_len,
                           " LIMIT %d", opts->limit);
        if (opts->offset > 0) {
            sql_len += snprintf(sql + sql_len, sizeof(sql) - sql_len,
                               " OFFSET %d", opts->offset);
        }
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare CVE search: %s", sqlite3_errmsg(g_db));
        return FG_ERROR;
    }

    /* Bind parameters */
    int param_idx = 1;
    if (opts) {
        if (opts->cve_id) {
            sqlite3_bind_text(stmt, param_idx++, opts->cve_id, -1, SQLITE_STATIC);
        }
        if (opts->component) {
            char pattern[CVE_COMPONENT_MAX + 2];
            snprintf(pattern, sizeof(pattern), "%%%s%%", opts->component);
            sqlite3_bind_text(stmt, param_idx++, pattern, -1, SQLITE_TRANSIENT);
        }
        if (opts->component_type != CVE_COMPONENT_UNKNOWN) {
            sqlite3_bind_int(stmt, param_idx++, opts->component_type);
        }
        if (opts->vendor) {
            char pattern[CVE_VENDOR_MAX + 2];
            snprintf(pattern, sizeof(pattern), "%%%s%%", opts->vendor);
            sqlite3_bind_text(stmt, param_idx++, pattern, -1, SQLITE_TRANSIENT);
        }
        if (opts->min_severity != CVE_SEVERITY_UNKNOWN) {
            sqlite3_bind_int(stmt, param_idx++, opts->min_severity);
        }
    }

    /* Fetch results */
    int capacity = 100;
    cve_match_t *matches = calloc(capacity, sizeof(cve_match_t));
    if (!matches) {
        sqlite3_finalize(stmt);
        return FG_ERROR;
    }

    int match_count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        /* Expand array if needed */
        if (match_count >= capacity) {
            capacity *= 2;
            cve_match_t *new_matches = realloc(matches, capacity * sizeof(cve_match_t));
            if (!new_matches) {
                free(matches);
                sqlite3_finalize(stmt);
                return FG_ERROR;
            }
            matches = new_matches;
        }

        /* Allocate CVE entry */
        matches[match_count].cve = calloc(1, sizeof(cve_entry_t));
        if (!matches[match_count].cve) {
            /* Cleanup on allocation failure */
            for (int i = 0; i < match_count; i++) {
                free(matches[i].cve);
            }
            free(matches);
            sqlite3_finalize(stmt);
            return FG_ERROR;
        }

        row_to_cve_entry(stmt, matches[match_count].cve);
        fetch_cve_references(matches[match_count].cve->id, matches[match_count].cve);
        matches[match_count].confidence = 100;
        snprintf(matches[match_count].match_reason, sizeof(matches[match_count].match_reason),
                "Database query match");

        match_count++;
    }

    sqlite3_finalize(stmt);

    *results = matches;
    *count = match_count;

    return FG_SUCCESS;
}

/*
 * Check if a specific version is vulnerable
 */
int cve_db_check_version(const char *component,
                         const char *version,
                         cve_match_t **matches,
                         int *count)
{
    if (!g_db || !component || !version || !matches || !count) {
        return FG_ERROR;
    }

    *matches = NULL;
    *count = 0;

    const char *sql =
        "SELECT * FROM cve_entries "
        "WHERE component LIKE ? "
        "ORDER BY cvss_score DESC;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare version check: %s", sqlite3_errmsg(g_db));
        return FG_ERROR;
    }

    char pattern[CVE_COMPONENT_MAX + 2];
    snprintf(pattern, sizeof(pattern), "%%%s%%", component);
    sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_TRANSIENT);

    /* Fetch and filter by version */
    int capacity = 50;
    cve_match_t *results = calloc(capacity, sizeof(cve_match_t));
    if (!results) {
        sqlite3_finalize(stmt);
        return FG_ERROR;
    }

    int match_count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cve_entry_t temp_entry;
        memset(&temp_entry, 0, sizeof(temp_entry));
        row_to_cve_entry(stmt, &temp_entry);

        /* Check if version is in affected range */
        bool in_range = cve_version_in_range(version,
                                              temp_entry.version_affected_start,
                                              temp_entry.version_affected_end);

        if (in_range) {
            /* Expand array if needed */
            if (match_count >= capacity) {
                capacity *= 2;
                cve_match_t *new_results = realloc(results, capacity * sizeof(cve_match_t));
                if (!new_results) {
                    for (int i = 0; i < match_count; i++) {
                        free(results[i].cve);
                    }
                    free(results);
                    sqlite3_finalize(stmt);
                    return FG_ERROR;
                }
                results = new_results;
            }

            results[match_count].cve = calloc(1, sizeof(cve_entry_t));
            if (!results[match_count].cve) {
                for (int i = 0; i < match_count; i++) {
                    free(results[i].cve);
                }
                free(results);
                sqlite3_finalize(stmt);
                return FG_ERROR;
            }

            memcpy(results[match_count].cve, &temp_entry, sizeof(cve_entry_t));
            fetch_cve_references(results[match_count].cve->id, results[match_count].cve);
            results[match_count].confidence = 95;
            snprintf(results[match_count].match_reason, sizeof(results[match_count].match_reason),
                    "Version %s in affected range [%s - %s]",
                    version, temp_entry.version_affected_start, temp_entry.version_affected_end);

            match_count++;
        }
    }

    sqlite3_finalize(stmt);

    *matches = results;
    *count = match_count;

    return FG_SUCCESS;
}

/*
 * Get all CVEs for a component type
 */
int cve_db_get_by_component(cve_component_type_t component_type,
                            cve_entry_t **entries,
                            int *count)
{
    if (!g_db || !entries || !count) {
        return FG_ERROR;
    }

    *entries = NULL;
    *count = 0;

    const char *sql =
        "SELECT * FROM cve_entries "
        "WHERE component_type = ? "
        "ORDER BY cvss_score DESC;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare component query: %s", sqlite3_errmsg(g_db));
        return FG_ERROR;
    }

    sqlite3_bind_int(stmt, 1, component_type);

    /* Fetch results */
    int capacity = 100;
    cve_entry_t *results = calloc(capacity, sizeof(cve_entry_t));
    if (!results) {
        sqlite3_finalize(stmt);
        return FG_ERROR;
    }

    int entry_count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (entry_count >= capacity) {
            capacity *= 2;
            cve_entry_t *new_results = realloc(results, capacity * sizeof(cve_entry_t));
            if (!new_results) {
                free(results);
                sqlite3_finalize(stmt);
                return FG_ERROR;
            }
            results = new_results;
        }

        row_to_cve_entry(stmt, &results[entry_count]);
        fetch_cve_references(results[entry_count].id, &results[entry_count]);
        entry_count++;
    }

    sqlite3_finalize(stmt);

    *entries = results;
    *count = entry_count;

    return FG_SUCCESS;
}

/*
 * Add a CVE entry to the database
 */
int64_t cve_db_add(const cve_entry_t *entry)
{
    if (!g_db || !entry) {
        return -1;
    }

    /* Validate CVE ID */
    if (strncmp(entry->cve_id, "CVE-", 4) != 0) {
        FG_LOG_ERROR("Invalid CVE ID format: %s", entry->cve_id);
        return -1;
    }

    const char *sql =
        "INSERT INTO cve_entries ("
        "  cve_id, component, component_type, vendor, description, remediation,"
        "  version_affected_start, version_affected_end, version_fixed,"
        "  cvss_score, severity, cvss_vector,"
        "  published_date, modified_date,"
        "  exploited_in_wild, patch_available"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare CVE insert: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    /* Bind parameters with bounds checking */
    sqlite3_bind_text(stmt, 1, entry->cve_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, entry->component, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, entry->component_type);
    sqlite3_bind_text(stmt, 4, entry->vendor, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, entry->description, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, entry->remediation, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, entry->version_affected_start, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, entry->version_affected_end, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, entry->version_fixed, -1, SQLITE_STATIC);
    sqlite3_bind_double(stmt, 10, entry->cvss_score);
    sqlite3_bind_int(stmt, 11, entry->severity);
    sqlite3_bind_text(stmt, 12, entry->cvss_vector, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 13, entry->published_date);
    sqlite3_bind_int64(stmt, 14, entry->modified_date);
    sqlite3_bind_int(stmt, 15, entry->exploited_in_wild ? 1 : 0);
    sqlite3_bind_int(stmt, 16, entry->patch_available ? 1 : 0);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        FG_LOG_ERROR("Failed to insert CVE: %s", sqlite3_errmsg(g_db));
        sqlite3_finalize(stmt);
        return -1;
    }

    int64_t entry_id = sqlite3_last_insert_rowid(g_db);
    sqlite3_finalize(stmt);

    /* Insert references */
    if (insert_cve_references(entry_id, entry) != 0) {
        FG_LOG_ERROR("Failed to insert CVE references");
    }

    return entry_id;
}

/*
 * Update a CVE entry
 */
int cve_db_update(const cve_entry_t *entry)
{
    if (!g_db || !entry || entry->id <= 0) {
        return FG_ERROR;
    }

    const char *sql =
        "UPDATE cve_entries SET "
        "  component = ?, component_type = ?, vendor = ?,"
        "  description = ?, remediation = ?,"
        "  version_affected_start = ?, version_affected_end = ?, version_fixed = ?,"
        "  cvss_score = ?, severity = ?, cvss_vector = ?,"
        "  published_date = ?, modified_date = ?,"
        "  exploited_in_wild = ?, patch_available = ?,"
        "  updated_at = strftime('%s', 'now')"
        " WHERE id = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare CVE update: %s", sqlite3_errmsg(g_db));
        return FG_ERROR;
    }

    sqlite3_bind_text(stmt, 1, entry->component, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, entry->component_type);
    sqlite3_bind_text(stmt, 3, entry->vendor, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, entry->description, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, entry->remediation, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, entry->version_affected_start, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, entry->version_affected_end, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, entry->version_fixed, -1, SQLITE_STATIC);
    sqlite3_bind_double(stmt, 9, entry->cvss_score);
    sqlite3_bind_int(stmt, 10, entry->severity);
    sqlite3_bind_text(stmt, 11, entry->cvss_vector, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 12, entry->published_date);
    sqlite3_bind_int64(stmt, 13, entry->modified_date);
    sqlite3_bind_int(stmt, 14, entry->exploited_in_wild ? 1 : 0);
    sqlite3_bind_int(stmt, 15, entry->patch_available ? 1 : 0);
    sqlite3_bind_int64(stmt, 16, entry->id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        FG_LOG_ERROR("Failed to update CVE: %s", sqlite3_errmsg(g_db));
        return FG_ERROR;
    }

    return FG_SUCCESS;
}

/*
 * Delete a CVE entry
 */
int cve_db_delete(const char *cve_id)
{
    if (!g_db || !cve_id) {
        return FG_ERROR;
    }

    const char *sql = "DELETE FROM cve_entries WHERE cve_id = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        FG_LOG_ERROR("Failed to prepare CVE delete: %s", sqlite3_errmsg(g_db));
        return FG_ERROR;
    }

    sqlite3_bind_text(stmt, 1, cve_id, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        FG_LOG_ERROR("Failed to delete CVE: %s", sqlite3_errmsg(g_db));
        return FG_ERROR;
    }

    return FG_SUCCESS;
}

/*
 * Get database statistics
 */
int cve_db_stats(cve_db_stats_t *stats)
{
    if (!g_db || !stats) {
        return FG_ERROR;
    }

    memset(stats, 0, sizeof(cve_db_stats_t));
    strncpy(stats->db_path, g_db_path, sizeof(stats->db_path) - 1);

    /* Get database file size */
    struct stat st;
    if (stat(g_db_path, &st) == 0) {
        stats->db_size_bytes = st.st_size;
    }

    /* Total CVEs */
    const char *sql_total = "SELECT COUNT(*) FROM cve_entries;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql_total, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats->total_cves = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    /* Count by severity */
    const char *sql_severity = "SELECT severity, COUNT(*) FROM cve_entries GROUP BY severity;";
    if (sqlite3_prepare_v2(g_db, sql_severity, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int severity = sqlite3_column_int(stmt, 0);
            int64_t count = sqlite3_column_int64(stmt, 1);
            switch (severity) {
                case CVE_SEVERITY_CRITICAL: stats->critical_cves = count; break;
                case CVE_SEVERITY_HIGH: stats->high_cves = count; break;
                case CVE_SEVERITY_MEDIUM: stats->medium_cves = count; break;
                case CVE_SEVERITY_LOW: stats->low_cves = count; break;
            }
        }
        sqlite3_finalize(stmt);
    }

    /* Exploited CVEs */
    const char *sql_exploited = "SELECT COUNT(*) FROM cve_entries WHERE exploited_in_wild = 1;";
    if (sqlite3_prepare_v2(g_db, sql_exploited, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats->exploited_cves = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    /* Unpatched CVEs */
    const char *sql_unpatched = "SELECT COUNT(*) FROM cve_entries WHERE patch_available = 0;";
    if (sqlite3_prepare_v2(g_db, sql_unpatched, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats->unpatched_cves = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    /* Component type counts */
    const char *sql_intel = "SELECT COUNT(*) FROM cve_entries WHERE component_type IN (0, 1, 2);";
    if (sqlite3_prepare_v2(g_db, sql_intel, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats->intel_me_cves = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    const char *sql_amd = "SELECT COUNT(*) FROM cve_entries WHERE component_type IN (3, 4);";
    if (sqlite3_prepare_v2(g_db, sql_amd, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats->amd_psp_cves = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    const char *sql_uefi = "SELECT COUNT(*) FROM cve_entries WHERE component_type IN (5, 6, 7);";
    if (sqlite3_prepare_v2(g_db, sql_uefi, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats->uefi_cves = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    /* Date range */
    const char *sql_dates = "SELECT MIN(published_date), MAX(published_date) FROM cve_entries;";
    if (sqlite3_prepare_v2(g_db, sql_dates, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats->oldest_cve = sqlite3_column_int64(stmt, 0);
            stats->newest_cve = sqlite3_column_int64(stmt, 1);
        }
        sqlite3_finalize(stmt);
    }

    return FG_SUCCESS;
}

/*
 * Mark CVE as exploited
 */
int cve_db_mark_exploited(const char *cve_id, bool exploited)
{
    if (!g_db || !cve_id) {
        return FG_ERROR;
    }

    const char *sql = "UPDATE cve_entries SET exploited_in_wild = ?, updated_at = strftime('%s', 'now') WHERE cve_id = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return FG_ERROR;
    }

    sqlite3_bind_int(stmt, 1, exploited ? 1 : 0);
    sqlite3_bind_text(stmt, 2, cve_id, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? FG_SUCCESS : FG_ERROR;
}

/*
 * Mark CVE patch availability
 */
int cve_db_mark_patched(const char *cve_id, bool patched)
{
    if (!g_db || !cve_id) {
        return FG_ERROR;
    }

    const char *sql = "UPDATE cve_entries SET patch_available = ?, updated_at = strftime('%s', 'now') WHERE cve_id = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return FG_ERROR;
    }

    sqlite3_bind_int(stmt, 1, patched ? 1 : 0);
    sqlite3_bind_text(stmt, 2, cve_id, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? FG_SUCCESS : FG_ERROR;
}

/*
 * Vacuum database
 */
int cve_db_vacuum(void)
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

    return FG_SUCCESS;
}

/*
 * Import CVEs from JSON file (OFFLINE-ONLY)
 */
int cve_db_import_json(const char *json_path, int *imported, int *skipped)
{
    if (!g_db || !json_path || !imported || !skipped) {
        return FG_ERROR;
    }

    *imported = 0;
    *skipped = 0;

    /* Read JSON file with size limit for security */
    FILE *fp = fopen(json_path, "r");
    if (!fp) {
        FG_LOG_ERROR("Cannot open JSON file: %s", json_path);
        return FG_ERROR;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Security: Limit JSON file size to 10MB */
    if (size <= 0 || size > 10 * 1024 * 1024) {
        FG_LOG_ERROR("Invalid or excessive JSON file size: %ld bytes", size);
        fclose(fp);
        return FG_ERROR;
    }

    /* Allocate buffer */
    char *json_data = malloc(size + 1);
    if (!json_data) {
        fclose(fp);
        return FG_ERROR;
    }

    size_t read_size = fread(json_data, 1, size, fp);
    json_data[read_size] = '\0';
    fclose(fp);

    /* Parse JSON */
    cJSON *root = cJSON_Parse(json_data);
    free(json_data);

    if (!root) {
        FG_LOG_ERROR("JSON parse error: %s", cJSON_GetErrorPtr());
        return FG_ERROR;
    }

    /* Expect array of CVEs */
    if (!cJSON_IsArray(root)) {
        FG_LOG_ERROR("JSON root must be an array");
        cJSON_Delete(root);
        return FG_ERROR;
    }

    /* Begin transaction for performance */
    sqlite3_exec(g_db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    int array_size = cJSON_GetArraySize(root);
    for (int i = 0; i < array_size; i++) {
        cJSON *cve_obj = cJSON_GetArrayItem(root, i);
        if (!cJSON_IsObject(cve_obj)) {
            continue;
        }

        cve_entry_t entry;
        memset(&entry, 0, sizeof(entry));

        if (parse_cve_json(cve_obj, &entry) == 0) {
            int64_t entry_id = cve_db_add(&entry);
            if (entry_id > 0) {
                (*imported)++;
            } else {
                (*skipped)++;
            }
        } else {
            (*skipped)++;
        }
    }

    /* Commit transaction */
    sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL);

    cJSON_Delete(root);

    FG_LOG_INFO("CVE import complete: %d imported, %d skipped", *imported, *skipped);
    return FG_SUCCESS;
}

/*
 * Export CVEs to JSON file
 */
int cve_db_export_json(const char *json_path, const cve_query_opts_t *opts)
{
    if (!g_db || !json_path) {
        return -1;
    }

    /* Get CVEs to export */
    cve_match_t *matches = NULL;
    int count = 0;

    if (cve_db_search(opts, &matches, &count) != FG_SUCCESS) {
        return -1;
    }

    /* Create JSON array */
    cJSON *root = cJSON_CreateArray();
    if (!root) {
        cve_db_free_results(matches, count);
        return -1;
    }

    for (int i = 0; i < count; i++) {
        cJSON *cve_obj = cJSON_CreateObject();
        if (!cve_obj) continue;

        cJSON_AddStringToObject(cve_obj, "cve_id", matches[i].cve->cve_id);
        cJSON_AddStringToObject(cve_obj, "component", matches[i].cve->component);
        cJSON_AddStringToObject(cve_obj, "component_type",
                                cve_component_type_to_str(matches[i].cve->component_type));
        cJSON_AddStringToObject(cve_obj, "vendor", matches[i].cve->vendor);
        cJSON_AddStringToObject(cve_obj, "description", matches[i].cve->description);
        cJSON_AddStringToObject(cve_obj, "remediation", matches[i].cve->remediation);
        cJSON_AddStringToObject(cve_obj, "version_affected_start", matches[i].cve->version_affected_start);
        cJSON_AddStringToObject(cve_obj, "version_affected_end", matches[i].cve->version_affected_end);
        cJSON_AddStringToObject(cve_obj, "version_fixed", matches[i].cve->version_fixed);
        cJSON_AddNumberToObject(cve_obj, "cvss_score", matches[i].cve->cvss_score);
        cJSON_AddStringToObject(cve_obj, "severity", cve_severity_to_str(matches[i].cve->severity));
        cJSON_AddStringToObject(cve_obj, "cvss_vector", matches[i].cve->cvss_vector);
        cJSON_AddBoolToObject(cve_obj, "exploited_in_wild", matches[i].cve->exploited_in_wild);
        cJSON_AddBoolToObject(cve_obj, "patch_available", matches[i].cve->patch_available);

        /* Add references array */
        cJSON *refs_array = cJSON_CreateArray();
        for (int j = 0; j < matches[i].cve->num_references; j++) {
            cJSON_AddItemToArray(refs_array, cJSON_CreateString(matches[i].cve->references[j]));
        }
        cJSON_AddItemToObject(cve_obj, "references", refs_array);

        cJSON_AddItemToArray(root, cve_obj);
    }

    /* Write to file */
    char *json_str = cJSON_Print(root);
    if (!json_str) {
        cJSON_Delete(root);
        cve_db_free_results(matches, count);
        return -1;
    }

    FILE *fp = fopen(json_path, "w");
    if (!fp) {
        free(json_str);
        cJSON_Delete(root);
        cve_db_free_results(matches, count);
        return -1;
    }

    fprintf(fp, "%s", json_str);
    fclose(fp);

    free(json_str);
    cJSON_Delete(root);
    cve_db_free_results(matches, count);

    return count;
}

/*
 * Free CVE search results
 */
void cve_db_free_results(cve_match_t *results, int count)
{
    if (!results) return;

    for (int i = 0; i < count; i++) {
        if (results[i].cve) {
            free(results[i].cve);
        }
    }
    free(results);
}

/*
 * Free CVE entry array
 */
void cve_db_free_entries(cve_entry_t *entries, int count)
{
    (void)count;  /* Unused - entries are contiguous array */
    if (entries) {
        free(entries);
    }
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/*
 * Prepare commonly used statements
 */
static int prepare_statements(void)
{
    /* Insert statement prepared on demand to avoid stale handles */
    return 0;
}

/*
 * Finalize prepared statements
 */
static void finalize_statements(void)
{
    if (g_stmt_insert) {
        sqlite3_finalize(g_stmt_insert);
        g_stmt_insert = NULL;
    }
    if (g_stmt_get_by_id) {
        sqlite3_finalize(g_stmt_get_by_id);
        g_stmt_get_by_id = NULL;
    }
    if (g_stmt_search) {
        sqlite3_finalize(g_stmt_search);
        g_stmt_search = NULL;
    }
    if (g_stmt_check_version) {
        sqlite3_finalize(g_stmt_check_version);
        g_stmt_check_version = NULL;
    }
}

/*
 * Convert database row to CVE entry
 */
static void row_to_cve_entry(sqlite3_stmt *stmt, cve_entry_t *entry)
{
    entry->id = sqlite3_column_int64(stmt, 0);

    const unsigned char *text;

    text = sqlite3_column_text(stmt, 1);
    if (text) strncpy(entry->cve_id, (const char *)text, CVE_ID_MAX - 1);

    text = sqlite3_column_text(stmt, 2);
    if (text) strncpy(entry->component, (const char *)text, CVE_COMPONENT_MAX - 1);

    entry->component_type = sqlite3_column_int(stmt, 3);

    text = sqlite3_column_text(stmt, 4);
    if (text) strncpy(entry->vendor, (const char *)text, CVE_VENDOR_MAX - 1);

    text = sqlite3_column_text(stmt, 5);
    if (text) strncpy(entry->description, (const char *)text, CVE_DESCRIPTION_MAX - 1);

    text = sqlite3_column_text(stmt, 6);
    if (text) strncpy(entry->remediation, (const char *)text, CVE_REMEDIATION_MAX - 1);

    text = sqlite3_column_text(stmt, 7);
    if (text) strncpy(entry->version_affected_start, (const char *)text, CVE_VERSION_MAX - 1);

    text = sqlite3_column_text(stmt, 8);
    if (text) strncpy(entry->version_affected_end, (const char *)text, CVE_VERSION_MAX - 1);

    text = sqlite3_column_text(stmt, 9);
    if (text) strncpy(entry->version_fixed, (const char *)text, CVE_VERSION_MAX - 1);

    entry->cvss_score = sqlite3_column_double(stmt, 10);
    entry->severity = sqlite3_column_int(stmt, 11);

    text = sqlite3_column_text(stmt, 12);
    if (text) strncpy(entry->cvss_vector, (const char *)text, sizeof(entry->cvss_vector) - 1);

    entry->published_date = sqlite3_column_int64(stmt, 13);
    entry->modified_date = sqlite3_column_int64(stmt, 14);
    entry->exploited_in_wild = sqlite3_column_int(stmt, 15) != 0;
    entry->patch_available = sqlite3_column_int(stmt, 16) != 0;
    entry->created_at = sqlite3_column_int64(stmt, 17);
    entry->updated_at = sqlite3_column_int64(stmt, 18);
}

/*
 * Insert CVE references
 */
static int insert_cve_references(int64_t cve_entry_id, const cve_entry_t *entry)
{
    if (!g_db || !entry || cve_entry_id <= 0) {
        return -1;
    }

    const char *sql = "INSERT INTO cve_references (cve_entry_id, reference_url) VALUES (?, ?);";
    sqlite3_stmt *stmt = NULL;

    for (int i = 0; i < entry->num_references && i < CVE_REFERENCES_MAX; i++) {
        if (strlen(entry->references[i]) == 0) continue;

        if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            return -1;
        }

        sqlite3_bind_int64(stmt, 1, cve_entry_id);
        sqlite3_bind_text(stmt, 2, entry->references[i], -1, SQLITE_STATIC);

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    return 0;
}

/*
 * Fetch CVE references
 */
static int fetch_cve_references(int64_t cve_entry_id, cve_entry_t *entry)
{
    if (!g_db || !entry || cve_entry_id <= 0) {
        return -1;
    }

    const char *sql = "SELECT reference_url FROM cve_references WHERE cve_entry_id = ? LIMIT ?;";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, cve_entry_id);
    sqlite3_bind_int(stmt, 2, CVE_REFERENCES_MAX);

    entry->num_references = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && entry->num_references < CVE_REFERENCES_MAX) {
        const unsigned char *url = sqlite3_column_text(stmt, 0);
        if (url) {
            strncpy(entry->references[entry->num_references], (const char *)url, CVE_REFERENCE_LEN - 1);
            entry->references[entry->num_references][CVE_REFERENCE_LEN - 1] = '\0';
            entry->num_references++;
        }
    }

    sqlite3_finalize(stmt);
    return 0;
}

/*
 * Parse CVE from JSON object
 */
static int parse_cve_json(cJSON *cve_obj, cve_entry_t *entry)
{
    if (!cve_obj || !entry) {
        return -1;
    }

    /* Required: cve_id */
    cJSON *cve_id = cJSON_GetObjectItem(cve_obj, "cve_id");
    if (!cJSON_IsString(cve_id)) {
        return -1;
    }
    strncpy(entry->cve_id, cve_id->valuestring, CVE_ID_MAX - 1);

    /* Required: component */
    cJSON *component = cJSON_GetObjectItem(cve_obj, "component");
    if (cJSON_IsString(component)) {
        strncpy(entry->component, component->valuestring, CVE_COMPONENT_MAX - 1);
    }

    /* Component type */
    cJSON *comp_type = cJSON_GetObjectItem(cve_obj, "component_type");
    if (cJSON_IsString(comp_type)) {
        entry->component_type = cve_str_to_component_type(comp_type->valuestring);
    }

    /* Vendor */
    cJSON *vendor = cJSON_GetObjectItem(cve_obj, "vendor");
    if (cJSON_IsString(vendor)) {
        strncpy(entry->vendor, vendor->valuestring, CVE_VENDOR_MAX - 1);
    }

    /* Description */
    cJSON *desc = cJSON_GetObjectItem(cve_obj, "description");
    if (cJSON_IsString(desc)) {
        strncpy(entry->description, desc->valuestring, CVE_DESCRIPTION_MAX - 1);
    }

    /* Remediation */
    cJSON *remedy = cJSON_GetObjectItem(cve_obj, "remediation");
    if (cJSON_IsString(remedy)) {
        strncpy(entry->remediation, remedy->valuestring, CVE_REMEDIATION_MAX - 1);
    }

    /* Version information */
    cJSON *ver_start = cJSON_GetObjectItem(cve_obj, "version_affected_start");
    if (cJSON_IsString(ver_start)) {
        strncpy(entry->version_affected_start, ver_start->valuestring, CVE_VERSION_MAX - 1);
    }

    cJSON *ver_end = cJSON_GetObjectItem(cve_obj, "version_affected_end");
    if (cJSON_IsString(ver_end)) {
        strncpy(entry->version_affected_end, ver_end->valuestring, CVE_VERSION_MAX - 1);
    }

    cJSON *ver_fixed = cJSON_GetObjectItem(cve_obj, "version_fixed");
    if (cJSON_IsString(ver_fixed)) {
        strncpy(entry->version_fixed, ver_fixed->valuestring, CVE_VERSION_MAX - 1);
    }

    /* CVSS score */
    cJSON *cvss = cJSON_GetObjectItem(cve_obj, "cvss_score");
    if (cJSON_IsNumber(cvss)) {
        entry->cvss_score = (float)cvss->valuedouble;
        entry->severity = cve_cvss_to_severity(entry->cvss_score);
    }

    /* Severity override */
    cJSON *severity = cJSON_GetObjectItem(cve_obj, "severity");
    if (cJSON_IsString(severity)) {
        entry->severity = cve_str_to_severity(severity->valuestring);
    }

    /* CVSS vector */
    cJSON *cvss_vec = cJSON_GetObjectItem(cve_obj, "cvss_vector");
    if (cJSON_IsString(cvss_vec)) {
        strncpy(entry->cvss_vector, cvss_vec->valuestring, sizeof(entry->cvss_vector) - 1);
    }

    /* Dates - expect Unix timestamps */
    cJSON *pub_date = cJSON_GetObjectItem(cve_obj, "published_date");
    if (cJSON_IsNumber(pub_date)) {
        entry->published_date = (time_t)pub_date->valuedouble;
    }

    cJSON *mod_date = cJSON_GetObjectItem(cve_obj, "modified_date");
    if (cJSON_IsNumber(mod_date)) {
        entry->modified_date = (time_t)mod_date->valuedouble;
    }

    /* Boolean flags */
    cJSON *exploited = cJSON_GetObjectItem(cve_obj, "exploited_in_wild");
    if (cJSON_IsBool(exploited)) {
        entry->exploited_in_wild = cJSON_IsTrue(exploited);
    }

    cJSON *patched = cJSON_GetObjectItem(cve_obj, "patch_available");
    if (cJSON_IsBool(patched)) {
        entry->patch_available = cJSON_IsTrue(patched);
    }

    /* References array */
    cJSON *refs = cJSON_GetObjectItem(cve_obj, "references");
    if (cJSON_IsArray(refs)) {
        int ref_count = cJSON_GetArraySize(refs);
        entry->num_references = (ref_count > CVE_REFERENCES_MAX) ? CVE_REFERENCES_MAX : ref_count;

        for (int i = 0; i < entry->num_references; i++) {
            cJSON *ref = cJSON_GetArrayItem(refs, i);
            if (cJSON_IsString(ref)) {
                strncpy(entry->references[i], ref->valuestring, CVE_REFERENCE_LEN - 1);
                entry->references[i][CVE_REFERENCE_LEN - 1] = '\0';
            }
        }
    }

    return 0;
}

/* ============================================================================
 * Type Conversion Helpers
 * ============================================================================ */

cve_component_type_t cve_str_to_component_type(const char *str)
{
    if (!str) return CVE_COMPONENT_UNKNOWN;

    if (strcasecmp(str, "Intel ME") == 0) return CVE_COMPONENT_INTEL_ME;
    if (strcasecmp(str, "Intel CSME") == 0) return CVE_COMPONENT_INTEL_CSME;
    if (strcasecmp(str, "Intel TXM") == 0) return CVE_COMPONENT_INTEL_TXM;
    if (strcasecmp(str, "AMD PSP") == 0) return CVE_COMPONENT_AMD_PSP;
    if (strcasecmp(str, "AMD ASP") == 0) return CVE_COMPONENT_AMD_ASP;
    if (strcasecmp(str, "UEFI BIOS") == 0) return CVE_COMPONENT_UEFI_BIOS;
    if (strcasecmp(str, "UEFI SecureBoot") == 0) return CVE_COMPONENT_UEFI_SECUREBOOT;
    if (strcasecmp(str, "UEFI Bootloader") == 0) return CVE_COMPONENT_UEFI_BOOTLOADER;
    if (strcasecmp(str, "TPM") == 0) return CVE_COMPONENT_TPM;
    if (strcasecmp(str, "BMC") == 0) return CVE_COMPONENT_BMC;
    if (strcasecmp(str, "EC") == 0) return CVE_COMPONENT_EC;
    if (strcasecmp(str, "NIC Firmware") == 0) return CVE_COMPONENT_NIC_FIRMWARE;

    return CVE_COMPONENT_UNKNOWN;
}

const char *cve_component_type_to_str(cve_component_type_t type)
{
    switch (type) {
        case CVE_COMPONENT_INTEL_ME: return "Intel ME";
        case CVE_COMPONENT_INTEL_CSME: return "Intel CSME";
        case CVE_COMPONENT_INTEL_TXM: return "Intel TXM";
        case CVE_COMPONENT_AMD_PSP: return "AMD PSP";
        case CVE_COMPONENT_AMD_ASP: return "AMD ASP";
        case CVE_COMPONENT_UEFI_BIOS: return "UEFI BIOS";
        case CVE_COMPONENT_UEFI_SECUREBOOT: return "UEFI SecureBoot";
        case CVE_COMPONENT_UEFI_BOOTLOADER: return "UEFI Bootloader";
        case CVE_COMPONENT_TPM: return "TPM";
        case CVE_COMPONENT_BMC: return "BMC";
        case CVE_COMPONENT_EC: return "EC";
        case CVE_COMPONENT_NIC_FIRMWARE: return "NIC Firmware";
        default: return "Unknown";
    }
}

cve_severity_t cve_str_to_severity(const char *str)
{
    if (!str) return CVE_SEVERITY_UNKNOWN;

    if (strcasecmp(str, "CRITICAL") == 0) return CVE_SEVERITY_CRITICAL;
    if (strcasecmp(str, "HIGH") == 0) return CVE_SEVERITY_HIGH;
    if (strcasecmp(str, "MEDIUM") == 0) return CVE_SEVERITY_MEDIUM;
    if (strcasecmp(str, "LOW") == 0) return CVE_SEVERITY_LOW;

    return CVE_SEVERITY_UNKNOWN;
}

const char *cve_severity_to_str(cve_severity_t severity)
{
    switch (severity) {
        case CVE_SEVERITY_CRITICAL: return "CRITICAL";
        case CVE_SEVERITY_HIGH: return "HIGH";
        case CVE_SEVERITY_MEDIUM: return "MEDIUM";
        case CVE_SEVERITY_LOW: return "LOW";
        default: return "UNKNOWN";
    }
}

cve_severity_t cve_cvss_to_severity(float cvss_score)
{
    if (cvss_score >= 9.0f) return CVE_SEVERITY_CRITICAL;
    if (cvss_score >= 7.0f) return CVE_SEVERITY_HIGH;
    if (cvss_score >= 4.0f) return CVE_SEVERITY_MEDIUM;
    if (cvss_score > 0.0f) return CVE_SEVERITY_LOW;
    return CVE_SEVERITY_UNKNOWN;
}

/* ============================================================================
 * Version Comparison Helpers
 * ============================================================================ */

/*
 * Compare two version strings
 * Supports formats: X.Y.Z, X.Y.Z.W, X.Y.Z-suffix
 */
int cve_version_compare(const char *v1, const char *v2)
{
    if (!v1 || !v2) return 0;
    if (strcmp(v1, v2) == 0) return 0;

    /* Parse versions into components */
    int v1_parts[4] = {0, 0, 0, 0};
    int v2_parts[4] = {0, 0, 0, 0};

    sscanf(v1, "%d.%d.%d.%d", &v1_parts[0], &v1_parts[1], &v1_parts[2], &v1_parts[3]);
    sscanf(v2, "%d.%d.%d.%d", &v2_parts[0], &v2_parts[1], &v2_parts[2], &v2_parts[3]);

    /* Compare each component */
    for (int i = 0; i < 4; i++) {
        if (v1_parts[i] < v2_parts[i]) return -1;
        if (v1_parts[i] > v2_parts[i]) return 1;
    }

    return 0;
}

/*
 * Check if version is in range [start, end]
 */
bool cve_version_in_range(const char *version,
                          const char *range_start,
                          const char *range_end)
{
    if (!version || strlen(version) == 0) {
        return false;
    }

    /* If no range specified, assume all versions affected */
    if ((!range_start || strlen(range_start) == 0) &&
        (!range_end || strlen(range_end) == 0)) {
        return true;
    }

    /* Check lower bound */
    if (range_start && strlen(range_start) > 0) {
        if (cve_version_compare(version, range_start) < 0) {
            return false;
        }
    }

    /* Check upper bound */
    if (range_end && strlen(range_end) > 0) {
        if (cve_version_compare(version, range_end) > 0) {
            return false;
        }
    }

    return true;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

void cve_print_entry(const cve_entry_t *entry)
{
    if (!entry) return;

    printf("\n========================================\n");
    printf("CVE ID: %s\n", entry->cve_id);
    printf("========================================\n");
    printf("Component:      %s (%s)\n", entry->component,
           cve_component_type_to_str(entry->component_type));
    printf("Vendor:         %s\n", entry->vendor);
    printf("Severity:       %s (CVSS %.1f)\n",
           cve_severity_to_str(entry->severity), entry->cvss_score);
    printf("Affected:       %s - %s\n",
           entry->version_affected_start, entry->version_affected_end);
    printf("Fixed in:       %s\n", entry->version_fixed);
    printf("Exploited:      %s\n", entry->exploited_in_wild ? "YES" : "No");
    printf("Patch Available: %s\n", entry->patch_available ? "YES" : "No");
    printf("\nDescription:\n%s\n", entry->description);
    printf("\nRemediation:\n%s\n", entry->remediation);

    if (entry->num_references > 0) {
        printf("\nReferences:\n");
        for (int i = 0; i < entry->num_references; i++) {
            printf("  [%d] %s\n", i + 1, entry->references[i]);
        }
    }
    printf("========================================\n\n");
}

void cve_print_stats(const cve_db_stats_t *stats)
{
    if (!stats) return;

    printf("\n========================================\n");
    printf("  CVE DATABASE STATISTICS\n");
    printf("========================================\n\n");
    printf("Database:        %s\n", stats->db_path);
    printf("Size:            %ld bytes\n", stats->db_size_bytes);
    printf("Total CVEs:      %ld\n\n", stats->total_cves);

    printf("By Severity:\n");
    printf("  CRITICAL:      %ld\n", stats->critical_cves);
    printf("  HIGH:          %ld\n", stats->high_cves);
    printf("  MEDIUM:        %ld\n", stats->medium_cves);
    printf("  LOW:           %ld\n\n", stats->low_cves);

    printf("By Component:\n");
    printf("  Intel ME/CSME: %ld\n", stats->intel_me_cves);
    printf("  AMD PSP:       %ld\n", stats->amd_psp_cves);
    printf("  UEFI:          %ld\n\n", stats->uefi_cves);

    printf("Status:\n");
    printf("  Exploited:     %ld\n", stats->exploited_cves);
    printf("  Unpatched:     %ld\n", stats->unpatched_cves);

    printf("\n========================================\n\n");
}
