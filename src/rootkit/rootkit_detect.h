/*
 * FirmwareGuard - Firmware Rootkit Detection
 * Signature-based and behavioral detection for firmware-level threats
 * OFFLINE-ONLY: No network connectivity
 *
 * Detects: LoJax, MosaicRegressor, MoonBounce, CosmicStrand, BlackLotus, ESPecter
 */

#ifndef ROOTKIT_DETECT_H
#define ROOTKIT_DETECT_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* Maximum values */
#define RK_MAX_SIGNATURES       256
#define RK_MAX_FINDINGS         128
#define RK_MAX_NAME_LEN         64
#define RK_MAX_DESC_LEN         512
#define RK_SIGNATURE_MAX_LEN    256

/* Rootkit families */
typedef enum {
    RK_FAMILY_UNKNOWN = 0,
    RK_FAMILY_LOJAX,           /* LoJax - Sednit/APT28 UEFI rootkit */
    RK_FAMILY_MOSAIC,          /* MosaicRegressor - Chinese APT */
    RK_FAMILY_MOONBOUNCE,      /* MoonBounce - APT41 */
    RK_FAMILY_COSMIC_STRAND,   /* CosmicStrand - Chinese APT */
    RK_FAMILY_BLACK_LOTUS,     /* BlackLotus - Bootkit */
    RK_FAMILY_ESPECTER,        /* ESPecter - Bootkit */
    RK_FAMILY_TRICKBOT,        /* TrickBot/TrickBoot module */
    RK_FAMILY_FINITE_STATE,    /* FiniteState research samples */
    RK_FAMILY_HACKING_TEAM,    /* Hacking Team UEFI implant */
    RK_FAMILY_EQUATION_GROUP,  /* Equation Group firmware mods */
    RK_FAMILY_GENERIC_SMM,     /* Generic SMM rootkit */
    RK_FAMILY_GENERIC_UEFI,    /* Generic UEFI bootkit */
    RK_FAMILY_MAX
} rk_family_t;

/* Detection method */
typedef enum {
    RK_METHOD_SIGNATURE = 0,   /* Byte pattern matching */
    RK_METHOD_BEHAVIORAL,      /* Behavioral anomaly */
    RK_METHOD_HEURISTIC,       /* Heuristic analysis */
    RK_METHOD_STRUCTURAL       /* Structural anomaly */
} rk_method_t;

/* Threat severity */
typedef enum {
    RK_SEVERITY_INFO = 0,
    RK_SEVERITY_LOW,
    RK_SEVERITY_MEDIUM,
    RK_SEVERITY_HIGH,
    RK_SEVERITY_CRITICAL
} rk_severity_t;

/* Signature definition */
typedef struct {
    char name[RK_MAX_NAME_LEN];
    char description[RK_MAX_DESC_LEN];
    rk_family_t family;
    rk_severity_t severity;

    /* Signature pattern */
    uint8_t pattern[RK_SIGNATURE_MAX_LEN];
    size_t pattern_len;
    uint8_t mask[RK_SIGNATURE_MAX_LEN];  /* 0xFF = match, 0x00 = wildcard */

    /* Offset constraints */
    bool any_offset;           /* Match at any offset */
    uint64_t min_offset;       /* Minimum file offset */
    uint64_t max_offset;       /* Maximum file offset (0 = no limit) */

    /* Context */
    char mitre_attack[64];     /* MITRE ATT&CK technique */
    char cve[32];              /* Associated CVE if any */
    bool enabled;
} rk_signature_t;

/* Detection finding */
typedef struct {
    rk_family_t family;
    rk_method_t method;
    rk_severity_t severity;
    char name[RK_MAX_NAME_LEN];
    char description[RK_MAX_DESC_LEN];
    uint64_t offset;           /* File offset where found */
    char matched_signature[RK_MAX_NAME_LEN];
    char mitre_attack[64];
    char evidence[256];        /* Hex dump of matched bytes */
    float confidence;          /* 0.0 - 1.0 */
} rk_finding_t;

/* Scan result */
typedef struct {
    /* Input file info */
    char filename[256];
    char filepath[512];
    uint64_t file_size;
    char sha256[65];
    time_t scan_time;

    /* Findings */
    int num_findings;
    rk_finding_t findings[RK_MAX_FINDINGS];

    /* Summary */
    rk_severity_t max_severity;
    int signature_matches;
    int behavioral_detections;
    int heuristic_detections;

    /* Risk assessment */
    int risk_score;            /* 0-100 */
    char risk_level[16];       /* "critical", "high", "medium", "low", "clean" */

    bool scan_complete;
    char error[256];
} rk_scan_result_t;

/* Scan options */
typedef struct {
    bool signature_scan;       /* Enable signature scanning */
    bool behavioral_scan;      /* Enable behavioral analysis */
    bool heuristic_scan;       /* Enable heuristic detection */
    bool deep_scan;            /* Full file scan (slower) */
    bool scan_boot_sector;     /* Include MBR/GPT analysis */
    int max_file_size_mb;      /* Skip files larger than this */
    const char *custom_sigs;   /* Path to custom signatures JSON */
} rk_scan_opts_t;

/* Default scan options */
#define RK_SCAN_OPTS_DEFAULT { \
    .signature_scan = true, \
    .behavioral_scan = true, \
    .heuristic_scan = true, \
    .deep_scan = false, \
    .scan_boot_sector = true, \
    .max_file_size_mb = 64, \
    .custom_sigs = NULL \
}

/*
 * Initialize rootkit detection engine
 * Loads built-in signatures
 *
 * Returns: 0 on success, -1 on error
 */
int rootkit_init(void);

/*
 * Load additional signatures from JSON file
 *
 * json_path: Path to signatures JSON file
 *
 * Returns: Number of signatures loaded, -1 on error
 */
int rootkit_load_signatures(const char *json_path);

/*
 * Get count of loaded signatures
 */
int rootkit_signature_count(void);

/*
 * Scan a firmware file for rootkits
 *
 * firmware_path: Path to firmware binary
 * opts: Scan options (NULL for defaults)
 * result: Output scan result
 *
 * Returns: 0 on success, -1 on error
 */
int rootkit_scan_file(const char *firmware_path,
                      const rk_scan_opts_t *opts,
                      rk_scan_result_t *result);

/*
 * Scan a memory buffer for rootkits
 *
 * data: Buffer containing firmware data
 * size: Size of buffer
 * name: Name for reporting
 * opts: Scan options (NULL for defaults)
 * result: Output scan result
 *
 * Returns: 0 on success, -1 on error
 */
int rootkit_scan_buffer(const uint8_t *data,
                        size_t size,
                        const char *name,
                        const rk_scan_opts_t *opts,
                        rk_scan_result_t *result);

/*
 * Quick scan for known bad signatures only
 * Faster but less thorough
 */
int rootkit_quick_scan(const char *firmware_path, rk_scan_result_t *result);

/*
 * Scan boot sector (MBR/GPT) for bootkits
 *
 * device: Block device path (e.g., /dev/sda)
 * result: Output scan result
 *
 * Returns: 0 on success, -1 on error (requires root)
 */
int rootkit_scan_boot_sector(const char *device, rk_scan_result_t *result);

/*
 * Scan SPI flash dump for firmware rootkits
 * Specialized scan for full SPI images
 */
int rootkit_scan_spi_dump(const char *dump_path, rk_scan_result_t *result);

/*
 * Perform behavioral analysis on running system
 * Checks for signs of active firmware compromise
 *
 * result: Output scan result
 *
 * Returns: 0 on success, -1 on error (requires root)
 */
int rootkit_behavioral_scan(rk_scan_result_t *result);

/*
 * Print scan results to stdout
 */
void rootkit_print_result(const rk_scan_result_t *result);

/*
 * Export results to JSON
 */
int rootkit_export_json(const rk_scan_result_t *result, const char *json_path);

/*
 * Get family name string
 */
const char *rootkit_family_name(rk_family_t family);

/*
 * Get severity string
 */
const char *rootkit_severity_string(rk_severity_t severity);

/*
 * Get method string
 */
const char *rootkit_method_string(rk_method_t method);

/*
 * Cleanup rootkit detection engine
 */
void rootkit_cleanup(void);

#endif /* ROOTKIT_DETECT_H */
