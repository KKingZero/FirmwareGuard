/*
 * FirmwareGuard - Threat Intelligence Database
 * Offline IOC (Indicators of Compromise) tracking for firmware threats
 * OFFLINE-ONLY: No network connectivity, manual JSON imports only
 */

#ifndef THREAT_INTEL_H
#define THREAT_INTEL_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* Maximum string lengths */
#define TI_HASH_MAX         129   /* SHA-512 hex + null */
#define TI_FAMILY_MAX       128
#define TI_PATTERN_MAX      512
#define TI_DESCRIPTION_MAX  2048
#define TI_MITRE_MAX        32    /* ATT&CK technique ID */
#define TI_SOURCE_MAX       128

/* Threat types */
typedef enum {
    THREAT_TYPE_BOOTKIT = 0,
    THREAT_TYPE_UEFI_ROOTKIT,
    THREAT_TYPE_SMM_IMPLANT,
    THREAT_TYPE_FIRMWARE_BACKDOOR,
    THREAT_TYPE_SUPPLY_CHAIN,
    THREAT_TYPE_EVIL_MAID,
    THREAT_TYPE_DMA_ATTACK,
    THREAT_TYPE_UNKNOWN
} threat_type_t;

/* IOC types */
typedef enum {
    IOC_TYPE_FILE_HASH = 0,      /* SHA-256/SHA-512 of malicious firmware */
    IOC_TYPE_PATTERN,            /* Behavioral pattern or signature */
    IOC_TYPE_PCI_ID,             /* Suspicious PCI vendor/device ID */
    IOC_TYPE_MEMORY_SIGNATURE,   /* Memory pattern */
    IOC_TYPE_REGISTRY_KEY,       /* UEFI variable or registry artifact */
    IOC_TYPE_MUTEX,              /* Named mutex or synchronization object */
    IOC_TYPE_UNKNOWN
} ioc_type_t;

/* Confidence levels for IOC matches */
typedef enum {
    CONFIDENCE_CONFIRMED = 100,   /* 100% - Known malicious */
    CONFIDENCE_HIGH = 90,         /* 90% - Very likely malicious */
    CONFIDENCE_MEDIUM = 70,       /* 70% - Suspicious behavior */
    CONFIDENCE_LOW = 50,          /* 50% - Potentially suspicious */
    CONFIDENCE_INFO = 25          /* 25% - Informational only */
} confidence_level_t;

/* Malware family information */
typedef struct {
    int64_t id;
    char name[TI_FAMILY_MAX];              /* LoJax, MosaicRegressor, etc. */
    threat_type_t type;
    char description[TI_DESCRIPTION_MAX];
    char first_seen[32];                   /* ISO 8601 date */
    char last_seen[32];
    char mitre_techniques[10][TI_MITRE_MAX]; /* ATT&CK technique IDs */
    int num_mitre_techniques;
    char target_platforms[256];            /* "UEFI", "BIOS", "SMM" */
    char target_vendors[256];              /* "Lenovo", "HP", "Dell" */
    bool active;                           /* Still in the wild */
    char references[512];                  /* URLs, CVEs, research papers */
    time_t created_at;
    time_t updated_at;
} malware_family_t;

/* Individual IOC entry */
typedef struct {
    int64_t id;
    int64_t family_id;                     /* Foreign key to malware_family */
    ioc_type_t ioc_type;
    char value[TI_PATTERN_MAX];            /* Hash, pattern, or identifier */
    char description[TI_DESCRIPTION_MAX];
    confidence_level_t confidence;
    char source[TI_SOURCE_MAX];            /* "vendor", "research", "community" */
    bool verified;                         /* Manually verified by analyst */
    char context[512];                     /* Additional context */
    time_t created_at;
    time_t updated_at;
} threat_ioc_t;

/* Match result when checking against IOCs */
typedef struct {
    bool matched;
    int64_t ioc_id;
    int64_t family_id;
    ioc_type_t ioc_type;
    char ioc_value[TI_PATTERN_MAX];
    char family_name[TI_FAMILY_MAX];
    threat_type_t threat_type;
    confidence_level_t confidence;
    char description[TI_DESCRIPTION_MAX];
    char mitre_techniques[10][TI_MITRE_MAX];
    int num_mitre_techniques;
    char remediation[TI_DESCRIPTION_MAX];
    char matched_value[TI_PATTERN_MAX];    /* What actually matched */
    char match_details[512];
    time_t match_time;
} threat_match_t;

/* Database statistics */
typedef struct {
    int64_t total_families;
    int64_t active_families;
    int64_t total_iocs;
    int64_t hash_iocs;
    int64_t pattern_iocs;
    int64_t verified_iocs;
    time_t oldest_ioc;
    time_t newest_ioc;
    char db_path[512];
    int64_t db_size_bytes;
} threat_intel_stats_t;

/* Query options */
typedef struct {
    const char *family_name;
    threat_type_t threat_type;
    ioc_type_t ioc_type;
    confidence_level_t min_confidence;
    bool verified_only;
    bool active_only;
    int limit;
    int offset;
} threat_query_opts_t;

/*
 * Initialize the threat intelligence database
 *
 * db_path: Path to SQLite database file (created if doesn't exist)
 *
 * Returns: 0 on success, -1 on error
 */
int threat_intel_init(const char *db_path);

/*
 * Close the threat intelligence database
 */
void threat_intel_close(void);

/*
 * Check if database is initialized
 */
bool threat_intel_is_open(void);

/*
 * Check a file hash against IOC database
 *
 * sha256: SHA-256 hash to check (hex string)
 * sha512: SHA-512 hash to check (optional, can be NULL)
 * result: Output match result
 *
 * Returns: 0 on success, -1 on error
 * Note: result->matched will be true if IOC found
 */
int threat_intel_check_hash(const char *sha256,
                             const char *sha512,
                             threat_match_t *result);

/*
 * Check a behavioral pattern against IOC database
 *
 * pattern: Pattern to check (e.g., "SMM hook at 0x7FFFE000")
 * context: Additional context (optional)
 * result: Output match result
 *
 * Returns: 0 on success, -1 on error
 */
int threat_intel_check_pattern(const char *pattern,
                                const char *context,
                                threat_match_t *result);

/*
 * Check multiple patterns at once for correlation
 *
 * patterns: Array of patterns to check
 * num_patterns: Number of patterns
 * results: Output array of match results (caller must allocate)
 * matched_count: Output count of matches
 *
 * Returns: 0 on success, -1 on error
 */
int threat_intel_check_patterns_batch(const char **patterns,
                                       int num_patterns,
                                       threat_match_t *results,
                                       int *matched_count);

/*
 * Import threat intelligence from JSON file
 *
 * json_path: Path to JSON file with threat data
 * imported_families: Output count of imported families
 * imported_iocs: Output count of imported IOCs
 * skipped: Output count of skipped/duplicate entries
 *
 * Returns: 0 on success, -1 on error
 */
int threat_intel_import_json(const char *json_path,
                              int *imported_families,
                              int *imported_iocs,
                              int *skipped);

/*
 * Export threat intelligence to JSON file
 *
 * json_path: Output JSON file path
 * opts: Query options (NULL for all entries)
 *
 * Returns: Number of entries exported, -1 on error
 */
int threat_intel_export_json(const char *json_path,
                              const threat_query_opts_t *opts);

/*
 * Get detailed information about a malware family
 *
 * family_name: Name of the malware family
 * family: Output family information
 * iocs: Output array of IOCs (caller must free)
 * ioc_count: Output count of IOCs
 *
 * Returns: 0 on success, -1 on error
 */
int threat_intel_get_family_info(const char *family_name,
                                  malware_family_t *family,
                                  threat_ioc_t **iocs,
                                  int *ioc_count);

/*
 * Add a malware family
 *
 * family: Family information to add
 *
 * Returns: Family ID on success, -1 on error
 */
int64_t threat_intel_add_family(const malware_family_t *family);

/*
 * Add an IOC
 *
 * ioc: IOC to add
 *
 * Returns: IOC ID on success, -1 on error
 */
int64_t threat_intel_add_ioc(const threat_ioc_t *ioc);

/*
 * Update malware family
 */
int threat_intel_update_family(const malware_family_t *family);

/*
 * Update IOC
 */
int threat_intel_update_ioc(const threat_ioc_t *ioc);

/*
 * Mark IOC as verified
 */
int threat_intel_mark_verified(int64_t ioc_id, bool verified);

/*
 * Mark family as active/inactive
 */
int threat_intel_mark_active(int64_t family_id, bool active);

/*
 * Search IOCs
 *
 * opts: Search options
 * iocs: Output array (caller must free)
 * count: Output count
 *
 * Returns: 0 on success, -1 on error
 */
int threat_intel_search_iocs(const threat_query_opts_t *opts,
                              threat_ioc_t **iocs,
                              int *count);

/*
 * Search malware families
 */
int threat_intel_search_families(const threat_query_opts_t *opts,
                                  malware_family_t **families,
                                  int *count);

/*
 * Get database statistics
 */
int threat_intel_stats(threat_intel_stats_t *stats);

/*
 * List all malware families
 *
 * families: Output array of family names (caller must free each and array)
 * count: Output count
 */
int threat_intel_list_families(char ***families, int *count);

/*
 * List MITRE ATT&CK techniques used
 */
int threat_intel_list_mitre_techniques(char ***techniques, int *count);

/*
 * Get IOCs for a specific MITRE technique
 */
int threat_intel_get_by_mitre(const char *technique,
                               threat_ioc_t **iocs,
                               int *count);

/*
 * Delete family and all associated IOCs
 */
int threat_intel_delete_family(int64_t family_id);

/*
 * Delete IOC
 */
int threat_intel_delete_ioc(int64_t ioc_id);

/*
 * Vacuum/optimize database
 */
int threat_intel_vacuum(void);

/*
 * Free match result resources
 */
void threat_intel_free_match(threat_match_t *result);

/*
 * Free IOC array
 */
void threat_intel_free_iocs(threat_ioc_t *iocs, int count);

/*
 * Free family array
 */
void threat_intel_free_families(malware_family_t *families, int count);

/*
 * Helper: Convert string to threat type
 */
threat_type_t str_to_threat_type(const char *str);

/*
 * Helper: Convert threat type to string
 */
const char *threat_type_to_str(threat_type_t type);

/*
 * Helper: Convert string to IOC type
 */
ioc_type_t str_to_ioc_type(const char *str);

/*
 * Helper: Convert IOC type to string
 */
const char *ioc_type_to_str(ioc_type_t type);

/*
 * Helper: Get confidence level string
 */
const char *confidence_level_to_str(confidence_level_t level);

/*
 * Helper: Calculate confidence score from multiple indicators
 * Used for pattern matching where multiple weak indicators can increase confidence
 */
confidence_level_t calculate_confidence(int num_indicators, int num_matches);

#endif /* THREAT_INTEL_H */
