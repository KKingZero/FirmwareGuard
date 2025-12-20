#ifndef FG_UEFI_INTEGRITY_H
#define FG_UEFI_INTEGRITY_H

#include "../../include/firmwareguard.h"
#include <time.h>

/* UEFI Runtime Services paths */
#define UEFI_RUNTIME_PATH       "/sys/firmware/efi/runtime"
#define UEFI_RUNTIME_MAP_PATH   "/sys/firmware/efi/runtime-map"
#define UEFI_SYSTAB_PATH        "/sys/firmware/efi/systab"
#define UEFI_CONFIG_TABLE_PATH  "/sys/firmware/efi/config_table"

/* EFI Memory Type definitions from UEFI spec */
#define EFI_RESERVED_MEMORY_TYPE        0
#define EFI_LOADER_CODE                 1
#define EFI_LOADER_DATA                 2
#define EFI_BOOT_SERVICES_CODE          3
#define EFI_BOOT_SERVICES_DATA          4
#define EFI_RUNTIME_SERVICES_CODE       5
#define EFI_RUNTIME_SERVICES_DATA       6
#define EFI_CONVENTIONAL_MEMORY         7
#define EFI_UNUSABLE_MEMORY             8
#define EFI_ACPI_RECLAIM_MEMORY         9
#define EFI_ACPI_MEMORY_NVS            10
#define EFI_MEMORY_MAPPED_IO           11
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE 12
#define EFI_PAL_CODE                   13
#define EFI_PERSISTENT_MEMORY          14

/* EFI Memory Attributes */
#define EFI_MEMORY_UC           0x0000000000000001ULL
#define EFI_MEMORY_WC           0x0000000000000002ULL
#define EFI_MEMORY_WT           0x0000000000000004ULL
#define EFI_MEMORY_WB           0x0000000000000008ULL
#define EFI_MEMORY_UCE          0x0000000000000010ULL
#define EFI_MEMORY_WP           0x0000000000001000ULL
#define EFI_MEMORY_RP           0x0000000000002000ULL
#define EFI_MEMORY_XP           0x0000000000004000ULL
#define EFI_MEMORY_RO           0x0000000000020000ULL
#define EFI_MEMORY_RUNTIME      0x8000000000000000ULL

/* Maximum limits for security */
#define MAX_RUNTIME_REGIONS     64
#define MAX_SERVICE_POINTERS    128
#define MAX_HOOK_SIGNATURES     16
#define INTEGRITY_HASH_SIZE     32

/* Hook detection patterns */
typedef struct {
    uint8_t pattern[16];        /* x86-64 instruction pattern */
    uint8_t mask[16];            /* Mask for pattern matching */
    size_t pattern_len;          /* Pattern length in bytes */
    char description[128];       /* What this pattern detects */
} hook_signature_t;

/* EFI Runtime memory region */
typedef struct {
    uint32_t type;               /* EFI memory type */
    uint64_t phys_addr;          /* Physical address */
    uint64_t virt_addr;          /* Virtual address */
    uint64_t num_pages;          /* Number of 4KB pages */
    uint64_t attribute;          /* Memory attributes */
    uint64_t size;               /* Calculated size in bytes */
    bool writable;               /* Indicates if region is writable */
    bool executable;             /* Indicates if region is executable */
    bool runtime;                /* Marked as runtime region */
} uefi_runtime_region_t;

/* Service function pointer snapshot */
typedef struct {
    uint64_t address;            /* Function pointer value */
    uint64_t region_index;       /* Which runtime region it points to */
    char name[64];               /* Service name (for debugging) */
    uint8_t code_snapshot[64];   /* First 64 bytes of code */
    bool valid;                  /* Snapshot valid */
    bool analyzed;               /* Code analysis performed */
} service_pointer_t;

/* UEFI Runtime Services Table snapshot */
typedef struct {
    uint64_t table_address;      /* Virtual address of table */
    uint64_t signature;          /* Table signature */
    uint32_t revision;           /* UEFI revision */
    uint32_t header_size;        /* Header size */
    uint32_t crc32;              /* CRC32 checksum */

    /* Runtime Services function pointers */
    int num_services;
    service_pointer_t services[MAX_SERVICE_POINTERS];

    /* Snapshot integrity */
    uint8_t snapshot_hash[INTEGRITY_HASH_SIZE];
    time_t snapshot_time;
    bool snapshot_valid;
} uefi_runtime_table_snapshot_t;

/* Hook detection result */
typedef struct {
    bool hook_detected;
    char service_name[64];
    uint64_t hook_address;
    char hook_type[128];         /* e.g., "inline JMP hook", "trampoline" */
    uint8_t hook_bytes[32];
    size_t hook_size;
} uefi_hook_detection_t;

/* Integrity verification result */
typedef struct {
    bool tables_modified;
    bool pointers_changed;
    bool code_modified;
    int num_changes;
    char changes[16][256];
} uefi_integrity_verification_t;

/* Complete UEFI integrity scan result */
typedef struct {
    /* EFI system information */
    bool efi_supported;
    bool runtime_services_available;
    uint64_t runtime_table_ptr;

    /* Runtime memory regions */
    int num_regions;
    uefi_runtime_region_t regions[MAX_RUNTIME_REGIONS];
    uint64_t total_runtime_memory;

    /* Table snapshots */
    uefi_runtime_table_snapshot_t baseline_snapshot;
    uefi_runtime_table_snapshot_t current_snapshot;

    /* Hook detection */
    int num_hooks_detected;
    uefi_hook_detection_t hooks[MAX_SERVICE_POINTERS];

    /* Integrity verification */
    uefi_integrity_verification_t integrity;

    /* Security assessment */
    risk_level_t risk_level;
    char risk_reason[512];

    /* Detailed findings */
    int finding_count;
    char findings[32][256];

    /* Summary */
    char summary[1024];
    time_t scan_time;
} uefi_integrity_result_t;

/* Module state */
typedef struct {
    bool initialized;
    bool baseline_captured;
    uefi_runtime_table_snapshot_t baseline;
    char baseline_path[512];
    hook_signature_t signatures[MAX_HOOK_SIGNATURES];
    int num_signatures;
} uefi_integrity_state_t;

/* Initialize UEFI integrity checking subsystem */
int uefi_integrity_init(void);

/* Cleanup UEFI integrity subsystem */
void uefi_integrity_cleanup(void);

/* Snapshot UEFI Runtime Services tables and function pointers */
int uefi_snapshot_tables(uefi_runtime_table_snapshot_t *snapshot);

/* Verify UEFI tables against baseline */
int uefi_verify_tables(const uefi_runtime_table_snapshot_t *baseline,
                       const uefi_runtime_table_snapshot_t *current,
                       uefi_integrity_verification_t *result);

/* Detect hooks/patches in UEFI runtime services */
int uefi_detect_hooks(const uefi_runtime_table_snapshot_t *snapshot,
                      uefi_hook_detection_t *hooks, int max_hooks,
                      int *num_detected);

/* Generate integrity report */
int uefi_integrity_report(const uefi_integrity_result_t *result,
                          char *buffer, size_t buffer_size);

/* Perform full UEFI integrity scan */
int uefi_integrity_scan(uefi_integrity_result_t *result);

/* Quick integrity check (brief mode) */
int uefi_integrity_check_brief(uefi_integrity_result_t *result);

/* Read EFI runtime memory regions from sysfs */
int uefi_read_runtime_regions(uefi_runtime_region_t *regions,
                              int max_regions, int *num_regions);

/* Analyze runtime region for security properties */
int uefi_analyze_region_security(const uefi_runtime_region_t *region,
                                 char *analysis, size_t analysis_size);

/* Read service function pointer safely */
int uefi_read_service_pointer(uint64_t virt_addr, service_pointer_t *pointer);

/* Analyze code for hook patterns */
bool uefi_analyze_code_for_hooks(const uint8_t *code, size_t code_size,
                                 const hook_signature_t *signatures,
                                 int num_signatures,
                                 uefi_hook_detection_t *detection);

/* Calculate snapshot hash for integrity */
int uefi_calculate_snapshot_hash(const uefi_runtime_table_snapshot_t *snapshot,
                                 uint8_t *hash, size_t hash_size);

/* Save baseline snapshot to disk */
int uefi_save_baseline(const uefi_runtime_table_snapshot_t *snapshot,
                       const char *path);

/* Load baseline snapshot from disk */
int uefi_load_baseline(uefi_runtime_table_snapshot_t *snapshot,
                       const char *path);

/* Get memory type name string */
const char *uefi_get_memory_type_name(uint32_t type);

/* Get risk level string */
const char *uefi_integrity_risk_to_string(risk_level_t risk);

/* Print UEFI integrity results */
void uefi_integrity_print_result(const uefi_integrity_result_t *result,
                                 bool verbose);

/* Export results to JSON */
int uefi_integrity_to_json(const uefi_integrity_result_t *result,
                           char *buffer, size_t size);

/* Initialize hook detection signatures */
void uefi_init_hook_signatures(hook_signature_t *signatures, int *num_sigs);

/* Check if address is within runtime region */
bool uefi_is_address_in_runtime(uint64_t address,
                                const uefi_runtime_region_t *regions,
                                int num_regions, int *region_index);

/* Validate memory region security properties */
risk_level_t uefi_assess_region_risk(const uefi_runtime_region_t *region);

/* Assess overall UEFI integrity risk */
risk_level_t uefi_assess_integrity_risk(const uefi_integrity_result_t *result);

#endif /* FG_UEFI_INTEGRITY_H */
