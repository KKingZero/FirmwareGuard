#ifndef PATTERN_DB_H
#define PATTERN_DB_H

#include <stdint.h>
#include <stdbool.h>

/* Maximum limits */
#define MAX_PATTERNS 1000
#define MAX_PATTERN_ID_LEN 128
#define MAX_PATTERN_NAME_LEN 256
#define MAX_DESCRIPTION_LEN 2048
#define MAX_REMEDIATION_LEN 2048
#define MAX_REFERENCES 10
#define MAX_TAGS 20
#define MAX_PLATFORMS 10

/* Firmware types */
typedef enum {
    FIRMWARE_TYPE_INTEL_ME,
    FIRMWARE_TYPE_AMD_PSP,
    FIRMWARE_TYPE_ACPI,
    FIRMWARE_TYPE_NIC,
    FIRMWARE_TYPE_UEFI,
    FIRMWARE_TYPE_SMM,
    FIRMWARE_TYPE_BIOS,
    FIRMWARE_TYPE_GENERAL,
    FIRMWARE_TYPE_UNKNOWN
} firmware_type_t;

/* Risk levels */
typedef enum {
    RISK_LEVEL_CRITICAL,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_MEDIUM,
    RISK_LEVEL_LOW,
    RISK_LEVEL_INFO
} risk_level_t;

/* Detection methods */
typedef enum {
    DETECTION_METHOD_PCI_DEVICE,
    DETECTION_METHOD_MSR_REGISTER,
    DETECTION_METHOD_FILE_EXISTS,
    DETECTION_METHOD_FILE_CONTENT,
    DETECTION_METHOD_ACPI_TABLE,
    DETECTION_METHOD_SYSFS_VALUE,
    DETECTION_METHOD_MEMORY_PATTERN,
    DETECTION_METHOD_COMBINATION,
    DETECTION_METHOD_UNKNOWN
} detection_method_t;

/* PCI device criteria */
typedef struct {
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t subsystem_id;
    uint8_t bus;
    uint8_t device;
    uint8_t function;
    bool has_vendor;
    bool has_device;
    bool has_subsystem;
    bool has_bus;
    bool has_dev;
    bool has_func;
} pci_criteria_t;

/* MSR register criteria */
typedef struct {
    uint64_t register_addr;
    uint64_t mask;
    uint64_t expected_value;
    char description[256];
} msr_criteria_t;

/* File criteria */
typedef struct {
    char path[512];
    char regex[256];
    char contains[256];
} file_criteria_t;

/* ACPI table criteria */
typedef struct {
    char signature[5];  // 4 chars + null
    char path[512];
    char contains_bytes[256];
} acpi_criteria_t;

/* Sysfs criteria */
typedef struct {
    char path[512];
    char expected_value[256];
    char regex[256];
} sysfs_criteria_t;

/* Detection criteria union */
typedef struct {
    detection_method_t method;
    union {
        pci_criteria_t pci;
        msr_criteria_t msr;
        file_criteria_t file;
        acpi_criteria_t acpi;
        sysfs_criteria_t sysfs;
    } criteria;
} detection_t;

/* Pattern metadata */
typedef struct {
    char description[MAX_DESCRIPTION_LEN];
    char technical_details[MAX_DESCRIPTION_LEN];
    char remediation[MAX_REMEDIATION_LEN];
    char references[MAX_REFERENCES][512];
    int num_references;
    char platforms[MAX_PLATFORMS][256];
    int num_platforms;
    char discovered_by[256];
    char created_at[32];  // ISO 8601 date
    char updated_at[32];
    char tags[MAX_TAGS][64];
    int num_tags;
} pattern_metadata_t;

/* Complete pattern structure */
typedef struct {
    char id[MAX_PATTERN_ID_LEN];
    char name[MAX_PATTERN_NAME_LEN];
    char version[32];
    firmware_type_t firmware_type;
    detection_t detection;
    risk_level_t risk_level;
    int confidence;  // 0-100
    bool blockable;
    pattern_metadata_t metadata;
    bool enabled;  // Can be disabled without removing from DB
} pattern_t;

/* Pattern database */
typedef struct {
    pattern_t *patterns;
    int count;
    int capacity;
    char patterns_dir[512];
} pattern_db_t;

/* Pattern match result */
typedef struct {
    const pattern_t *pattern;
    bool matched;
    char match_details[512];
    int confidence_score;
} pattern_match_t;

/* Function declarations */

/**
 * Initialize pattern database
 */
pattern_db_t* pattern_db_init(const char *patterns_dir);

/**
 * Free pattern database
 */
void pattern_db_free(pattern_db_t *db);

/**
 * Load all patterns from directory
 * Returns number of patterns loaded, or -1 on error
 */
int pattern_db_load(pattern_db_t *db);

/**
 * Load a single pattern from JSON file
 * Returns 0 on success, -1 on error
 */
int pattern_db_load_file(pattern_db_t *db, const char *json_file);

/**
 * Find pattern by ID
 */
const pattern_t* pattern_db_find_by_id(pattern_db_t *db, const char *id);

/**
 * Get all patterns of a specific firmware type
 */
int pattern_db_get_by_type(pattern_db_t *db, firmware_type_t type,
                           const pattern_t **results, int max_results);

/**
 * Match pattern against system
 * Returns true if pattern matches, false otherwise
 */
bool pattern_match(const pattern_t *pattern, pattern_match_t *result);

/**
 * Match all patterns in database
 * Returns array of matches
 */
int pattern_match_all(pattern_db_t *db, pattern_match_t **results);

/**
 * Helper: Convert string to firmware type
 */
firmware_type_t str_to_firmware_type(const char *str);

/**
 * Helper: Convert string to risk level
 */
risk_level_t str_to_risk_level(const char *str);

/**
 * Helper: Convert string to detection method
 */
detection_method_t str_to_detection_method(const char *str);

/**
 * Helper: Convert firmware type to string
 */
const char* firmware_type_to_str(firmware_type_t type);

/**
 * Helper: Convert risk level to string
 */
const char* risk_level_to_str(risk_level_t level);

/**
 * Helper: Convert detection method to string
 */
const char* detection_method_to_str(detection_method_t method);

/**
 * Print pattern database statistics
 */
void pattern_db_print_stats(pattern_db_t *db);

#endif /* PATTERN_DB_H */
