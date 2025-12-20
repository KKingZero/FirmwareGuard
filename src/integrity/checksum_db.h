/*
 * FirmwareGuard - Supply Chain Checksum Database
 * Offline firmware integrity verification via known-good checksums
 * OFFLINE-ONLY: No network connectivity
 */

#ifndef CHECKSUM_DB_H
#define CHECKSUM_DB_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* Maximum string lengths */
#define FW_VENDOR_MAX       128
#define FW_MODEL_MAX        256
#define FW_VERSION_MAX      64
#define FW_HASH_MAX         129   /* SHA-512 hex + null */
#define FW_SOURCE_MAX       64
#define FW_REGION_MAX       32

/* Firmware verification status */
typedef enum {
    FW_VERIFY_UNKNOWN = 0,
    FW_VERIFY_MATCH,          /* Matches known-good checksum */
    FW_VERIFY_MISMATCH,       /* Does not match */
    FW_VERIFY_NOT_FOUND,      /* No entry in database */
    FW_VERIFY_DB_ERROR        /* Database error */
} fw_verify_status_t;

/* Firmware entry */
typedef struct {
    int64_t id;
    char vendor[FW_VENDOR_MAX];
    char model[FW_MODEL_MAX];
    char version[FW_VERSION_MAX];
    char region[FW_REGION_MAX];      /* "bios", "me", "psp", "full" */
    char sha256[65];
    char sha512[FW_HASH_MAX];
    char source[FW_SOURCE_MAX];      /* "vendor", "community", "research" */
    bool verified;
    time_t created_at;
    time_t updated_at;
    char notes[512];
} fw_entry_t;

/* Verification result */
typedef struct {
    fw_verify_status_t status;
    char computed_sha256[65];
    char computed_sha512[FW_HASH_MAX];
    fw_entry_t *matched_entry;       /* NULL if no match */
    int similar_entries;             /* Count of entries with same vendor/model */
    char message[256];
} fw_verify_result_t;

/* Database statistics */
typedef struct {
    int64_t total_entries;
    int64_t verified_entries;
    int64_t vendor_count;
    time_t oldest_entry;
    time_t newest_entry;
    char db_path[512];
    int64_t db_size_bytes;
} fw_db_stats_t;

/* Query options */
typedef struct {
    const char *vendor;
    const char *model;
    const char *version;
    const char *region;
    bool verified_only;
    int limit;
    int offset;
} fw_query_opts_t;

/*
 * Initialize the checksum database
 *
 * db_path: Path to SQLite database file (created if doesn't exist)
 *
 * Returns: 0 on success, -1 on error
 */
int checksum_db_init(const char *db_path);

/*
 * Close the checksum database
 */
void checksum_db_close(void);

/*
 * Check if database is initialized
 */
bool checksum_db_is_open(void);

/*
 * Verify a firmware file against the database
 *
 * firmware_path: Path to firmware file
 * vendor: Vendor name (optional, helps narrow search)
 * model: Model name (optional)
 * region: Firmware region (optional: "bios", "me", "psp", "full")
 * result: Output verification result
 *
 * Returns: 0 on success, -1 on error
 */
int checksum_db_verify(const char *firmware_path,
                       const char *vendor,
                       const char *model,
                       const char *region,
                       fw_verify_result_t *result);

/*
 * Verify by hash (when file already hashed)
 */
int checksum_db_verify_hash(const char *sha256,
                            const char *vendor,
                            const char *model,
                            fw_verify_result_t *result);

/*
 * Add a firmware entry to the database
 *
 * entry: Firmware entry to add
 *
 * Returns: Entry ID on success, -1 on error
 */
int64_t checksum_db_add(const fw_entry_t *entry);

/*
 * Add from firmware file (computes hashes automatically)
 *
 * firmware_path: Path to firmware file
 * vendor: Vendor name
 * model: Model name
 * version: Firmware version
 * region: Firmware region
 * source: Source of the entry ("vendor", "community", "research")
 *
 * Returns: Entry ID on success, -1 on error
 */
int64_t checksum_db_add_file(const char *firmware_path,
                              const char *vendor,
                              const char *model,
                              const char *version,
                              const char *region,
                              const char *source);

/*
 * Import entries from JSON file
 *
 * json_path: Path to JSON file with firmware entries
 * imported: Output count of successfully imported entries
 * skipped: Output count of skipped/duplicate entries
 *
 * Returns: 0 on success, -1 on error
 */
int checksum_db_import_json(const char *json_path, int *imported, int *skipped);

/*
 * Export entries to JSON file
 *
 * json_path: Output JSON file path
 * opts: Query options (NULL for all entries)
 *
 * Returns: Number of entries exported, -1 on error
 */
int checksum_db_export_json(const char *json_path, const fw_query_opts_t *opts);

/*
 * Search entries
 *
 * opts: Search options
 * entries: Output array (caller must free)
 * count: Output count of entries
 *
 * Returns: 0 on success, -1 on error
 */
int checksum_db_search(const fw_query_opts_t *opts,
                       fw_entry_t **entries,
                       int *count);

/*
 * Get entry by ID
 */
int checksum_db_get(int64_t id, fw_entry_t *entry);

/*
 * Delete entry by ID
 */
int checksum_db_delete(int64_t id);

/*
 * Update entry
 */
int checksum_db_update(const fw_entry_t *entry);

/*
 * Mark entry as verified
 */
int checksum_db_mark_verified(int64_t id, bool verified);

/*
 * Get database statistics
 */
int checksum_db_stats(fw_db_stats_t *stats);

/*
 * List all vendors in database
 *
 * vendors: Output array of vendor names (caller must free each and array)
 * count: Output count
 */
int checksum_db_list_vendors(char ***vendors, int *count);

/*
 * List models for a vendor
 */
int checksum_db_list_models(const char *vendor, char ***models, int *count);

/*
 * Vacuum/optimize database
 */
int checksum_db_vacuum(void);

/*
 * Free verification result resources
 */
void checksum_db_free_result(fw_verify_result_t *result);

/*
 * Free entry array from search
 */
void checksum_db_free_entries(fw_entry_t *entries, int count);

/*
 * Get status string
 */
const char *checksum_db_status_string(fw_verify_status_t status);

#endif /* CHECKSUM_DB_H */
