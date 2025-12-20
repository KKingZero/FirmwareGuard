/*
 * FirmwareGuard - CVE Correlation Database
 * Offline CVE tracking and version correlation for firmware components
 * OFFLINE-ONLY: No network connectivity, manual JSON imports only
 */

#ifndef CVE_DB_H
#define CVE_DB_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* Maximum string lengths */
#define CVE_ID_MAX              32    /* CVE-YYYY-NNNNN */
#define CVE_COMPONENT_MAX       256   /* Component name */
#define CVE_VENDOR_MAX          128   /* Vendor name */
#define CVE_DESCRIPTION_MAX     2048  /* CVE description */
#define CVE_REMEDIATION_MAX     2048  /* Remediation steps */
#define CVE_VERSION_MAX         64    /* Version string */
#define CVE_REFERENCES_MAX      10    /* Max references per CVE */
#define CVE_REFERENCE_LEN       512   /* Max reference URL length */

/* Firmware component types */
typedef enum {
    CVE_COMPONENT_INTEL_ME = 0,
    CVE_COMPONENT_INTEL_CSME,
    CVE_COMPONENT_INTEL_TXM,
    CVE_COMPONENT_AMD_PSP,
    CVE_COMPONENT_AMD_ASP,
    CVE_COMPONENT_UEFI_BIOS,
    CVE_COMPONENT_UEFI_SECUREBOOT,
    CVE_COMPONENT_UEFI_BOOTLOADER,
    CVE_COMPONENT_TPM,
    CVE_COMPONENT_BMC,
    CVE_COMPONENT_EC,
    CVE_COMPONENT_NIC_FIRMWARE,
    CVE_COMPONENT_UNKNOWN
} cve_component_type_t;

/* CVE severity based on CVSS */
typedef enum {
    CVE_SEVERITY_CRITICAL = 0,  /* CVSS 9.0-10.0 */
    CVE_SEVERITY_HIGH,          /* CVSS 7.0-8.9 */
    CVE_SEVERITY_MEDIUM,        /* CVSS 4.0-6.9 */
    CVE_SEVERITY_LOW,           /* CVSS 0.1-3.9 */
    CVE_SEVERITY_UNKNOWN
} cve_severity_t;

/* CVE entry structure */
typedef struct {
    int64_t id;                                     /* Database ID */
    char cve_id[CVE_ID_MAX];                       /* CVE identifier */
    char component[CVE_COMPONENT_MAX];             /* Component name */
    cve_component_type_t component_type;           /* Component type enum */
    char vendor[CVE_VENDOR_MAX];                   /* Vendor name */
    char description[CVE_DESCRIPTION_MAX];         /* CVE description */
    char remediation[CVE_REMEDIATION_MAX];         /* Remediation steps */

    /* Version information */
    char version_affected_start[CVE_VERSION_MAX];  /* First affected version */
    char version_affected_end[CVE_VERSION_MAX];    /* Last affected version */
    char version_fixed[CVE_VERSION_MAX];           /* Fixed in version */

    /* CVSS scoring */
    float cvss_score;                              /* CVSS base score */
    cve_severity_t severity;                       /* Derived severity */
    char cvss_vector[128];                         /* CVSS vector string */

    /* Metadata */
    time_t published_date;                         /* CVE publish date */
    time_t modified_date;                          /* Last modified date */
    char references[CVE_REFERENCES_MAX][CVE_REFERENCE_LEN]; /* URLs */
    int num_references;                            /* Reference count */

    /* Tracking */
    bool exploited_in_wild;                        /* Known exploitation */
    bool patch_available;                          /* Patch availability */
    time_t created_at;                             /* DB entry creation */
    time_t updated_at;                             /* DB entry update */
} cve_entry_t;

/* CVE search result */
typedef struct {
    cve_entry_t *cve;                              /* CVE entry */
    int confidence;                                /* Match confidence 0-100 */
    char match_reason[256];                        /* Why this CVE matched */
} cve_match_t;

/* CVE query options */
typedef struct {
    const char *cve_id;                            /* Specific CVE ID */
    const char *component;                         /* Component name */
    cve_component_type_t component_type;           /* Component type */
    const char *vendor;                            /* Vendor filter */
    const char *version;                           /* Version to check */
    cve_severity_t min_severity;                   /* Minimum severity */
    bool only_exploited;                           /* Only exploited CVEs */
    bool only_unpatched;                           /* Only unpatched CVEs */
    int limit;                                     /* Result limit */
    int offset;                                    /* Result offset */
} cve_query_opts_t;

/* Database statistics */
typedef struct {
    int64_t total_cves;
    int64_t critical_cves;
    int64_t high_cves;
    int64_t medium_cves;
    int64_t low_cves;
    int64_t exploited_cves;
    int64_t unpatched_cves;
    int64_t intel_me_cves;
    int64_t amd_psp_cves;
    int64_t uefi_cves;
    time_t oldest_cve;
    time_t newest_cve;
    char db_path[512];
    int64_t db_size_bytes;
} cve_db_stats_t;

/*
 * Initialize CVE database
 *
 * db_path: Path to SQLite database file (created if doesn't exist)
 *
 * Returns: 0 on success, -1 on error
 */
int cve_db_init(const char *db_path);

/*
 * Close CVE database
 */
void cve_db_close(void);

/*
 * Check if database is initialized
 */
bool cve_db_is_open(void);

/*
 * Search for CVEs matching criteria
 *
 * opts: Search options
 * results: Output array of matches (caller must free)
 * count: Output count of matches
 *
 * Returns: 0 on success, -1 on error
 */
int cve_db_search(const cve_query_opts_t *opts,
                  cve_match_t **results,
                  int *count);

/*
 * Get CVE by ID
 *
 * cve_id: CVE identifier (e.g., "CVE-2017-5689")
 * entry: Output CVE entry
 *
 * Returns: 0 on success, -1 on error/not found
 */
int cve_db_get_by_id(const char *cve_id, cve_entry_t *entry);

/*
 * Check if a specific version is vulnerable
 *
 * component: Component name (e.g., "Intel ME", "AMD PSP")
 * version: Version string to check
 * matches: Output array of matching CVEs (caller must free)
 * count: Output count of matches
 *
 * Returns: 0 on success, -1 on error
 */
int cve_db_check_version(const char *component,
                         const char *version,
                         cve_match_t **matches,
                         int *count);

/*
 * Get all CVEs for a component type
 *
 * component_type: Type of component
 * entries: Output array (caller must free)
 * count: Output count
 *
 * Returns: 0 on success, -1 on error
 */
int cve_db_get_by_component(cve_component_type_t component_type,
                            cve_entry_t **entries,
                            int *count);

/*
 * Import CVEs from JSON file (OFFLINE-ONLY)
 *
 * json_path: Path to JSON file with CVE entries
 * imported: Output count of imported entries
 * skipped: Output count of skipped/duplicate entries
 *
 * Returns: 0 on success, -1 on error
 */
int cve_db_import_json(const char *json_path, int *imported, int *skipped);

/*
 * Export CVEs to JSON file
 *
 * json_path: Output JSON file path
 * opts: Query options (NULL for all entries)
 *
 * Returns: Number of entries exported, -1 on error
 */
int cve_db_export_json(const char *json_path, const cve_query_opts_t *opts);

/*
 * Add a CVE entry to the database
 *
 * entry: CVE entry to add
 *
 * Returns: Entry ID on success, -1 on error
 */
int64_t cve_db_add(const cve_entry_t *entry);

/*
 * Update a CVE entry
 *
 * entry: CVE entry to update (must have valid id)
 *
 * Returns: 0 on success, -1 on error
 */
int cve_db_update(const cve_entry_t *entry);

/*
 * Delete a CVE entry
 *
 * cve_id: CVE identifier to delete
 *
 * Returns: 0 on success, -1 on error
 */
int cve_db_delete(const char *cve_id);

/*
 * Get database statistics
 *
 * stats: Output statistics structure
 *
 * Returns: 0 on success, -1 on error
 */
int cve_db_stats(cve_db_stats_t *stats);

/*
 * Mark CVE as exploited in the wild
 *
 * cve_id: CVE identifier
 * exploited: Exploitation status
 *
 * Returns: 0 on success, -1 on error
 */
int cve_db_mark_exploited(const char *cve_id, bool exploited);

/*
 * Mark CVE patch availability
 *
 * cve_id: CVE identifier
 * patched: Patch availability status
 *
 * Returns: 0 on success, -1 on error
 */
int cve_db_mark_patched(const char *cve_id, bool patched);

/*
 * Vacuum/optimize database
 *
 * Returns: 0 on success, -1 on error
 */
int cve_db_vacuum(void);

/*
 * Free CVE search results
 */
void cve_db_free_results(cve_match_t *results, int count);

/*
 * Free CVE entry array
 */
void cve_db_free_entries(cve_entry_t *entries, int count);

/*
 * Helper: Convert string to component type
 */
cve_component_type_t cve_str_to_component_type(const char *str);

/*
 * Helper: Convert component type to string
 */
const char *cve_component_type_to_str(cve_component_type_t type);

/*
 * Helper: Convert string to severity
 */
cve_severity_t cve_str_to_severity(const char *str);

/*
 * Helper: Convert severity to string
 */
const char *cve_severity_to_str(cve_severity_t severity);

/*
 * Helper: Derive severity from CVSS score
 */
cve_severity_t cve_cvss_to_severity(float cvss_score);

/*
 * Helper: Compare versions (for range checking)
 * Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
 */
int cve_version_compare(const char *v1, const char *v2);

/*
 * Helper: Check if version is in range
 * Returns: true if version is in [start, end] range
 */
bool cve_version_in_range(const char *version,
                          const char *range_start,
                          const char *range_end);

/*
 * Print CVE entry (for debugging/reporting)
 */
void cve_print_entry(const cve_entry_t *entry);

/*
 * Print database statistics
 */
void cve_print_stats(const cve_db_stats_t *stats);

#endif /* CVE_DB_H */
