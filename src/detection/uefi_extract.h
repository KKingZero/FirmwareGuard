#ifndef FG_UEFI_EXTRACT_H
#define FG_UEFI_EXTRACT_H

#include "../../include/firmwareguard.h"
#include <dirent.h>

/* UEFI GUID structure */
typedef struct {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t  data4[8];
} uefi_guid_t;

/* Common UEFI GUIDs */
#define UEFI_GLOBAL_VARIABLE_GUID \
    "8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define EFI_IMAGE_SECURITY_DATABASE_GUID \
    "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
#define EFI_SECURE_BOOT_GUID \
    "8be4df61-93ca-11d2-aa0d-00e098032b8c"

/* UEFI driver information */
typedef struct {
    char name[256];
    char guid[64];
    char full_path[512];
    uint32_t attributes;
    size_t data_size;
    bool is_boot_variable;
    bool is_secure_boot_related;
    bool is_driver_related;
    uint8_t sha256[32];
    char sha256_hex[65];
} uefi_var_info_t;

/* UEFI driver extraction result */
typedef struct {
    int var_count;
    int driver_count;
    int boot_var_count;
    int secure_boot_count;
    uefi_var_info_t *variables;
    int variables_capacity;

    /* Secure Boot status */
    bool secure_boot_enabled;
    bool setup_mode;
    bool audit_mode;
    bool deployed_mode;

    /* Summary */
    char summary[1024];
} uefi_enum_result_t;

/* Firmware region information (for SPI extraction) */
typedef struct {
    char name[32];
    uint64_t offset;
    uint64_t size;
    bool present;
    uint8_t sha256[32];
    char sha256_hex[65];
} firmware_region_t;

/* SPI flash extraction result */
typedef struct {
    bool flashrom_available;
    bool extraction_successful;
    char chip_name[128];
    uint64_t flash_size;

    /* Regions */
    firmware_region_t descriptor;
    firmware_region_t bios;
    firmware_region_t me;
    firmware_region_t gbe;
    firmware_region_t pdr;

    /* Extracted files */
    char output_dir[512];
    char full_dump_path[512];

    /* UEFI volume info */
    int uefi_volume_count;
    int uefi_driver_count;

    /* Summary */
    char summary[1024];
} spi_extract_result_t;

/* Combined UEFI analysis result */
typedef struct {
    uefi_enum_result_t runtime;
    spi_extract_result_t spi;
    bool runtime_scan_done;
    bool spi_scan_done;
    risk_level_t risk_level;
    char risk_reason[512];
    int finding_count;
    char findings[32][256];
} uefi_analysis_result_t;

/* Initialize UEFI extraction subsystem */
int uefi_extract_init(void);

/* Cleanup UEFI extraction subsystem */
void uefi_extract_cleanup(void);

/* Runtime EFI variable enumeration */
int uefi_enumerate_variables(uefi_enum_result_t *result);

/* Get specific EFI variable */
int uefi_get_variable(const char *name, const char *guid, uefi_var_info_t *var);

/* Check Secure Boot status */
int uefi_check_secure_boot(uefi_enum_result_t *result);

/* SPI flash extraction (requires flashrom) */
int spi_check_flashrom(void);
int spi_detect_chip(spi_extract_result_t *result);
int spi_dump_flash(const char *output_path, spi_extract_result_t *result);
int spi_dump_region(const char *region, const char *output_path, spi_extract_result_t *result);
int spi_extract_regions(const char *dump_path, const char *output_dir, spi_extract_result_t *result);

/* Combined analysis */
int uefi_full_analysis(uefi_analysis_result_t *result, bool include_spi);

/* Risk assessment */
risk_level_t uefi_assess_risk(const uefi_analysis_result_t *result);

/* Output functions */
void uefi_enum_print_result(const uefi_enum_result_t *result, bool verbose);
void spi_print_result(const spi_extract_result_t *result, bool verbose);
void uefi_analysis_print_result(const uefi_analysis_result_t *result, bool verbose);

/* JSON export */
int uefi_enum_to_json(const uefi_enum_result_t *result, char *buffer, size_t size);
int spi_result_to_json(const spi_extract_result_t *result, char *buffer, size_t size);
int uefi_analysis_to_json(const uefi_analysis_result_t *result, char *buffer, size_t size);

/* Free allocated memory */
void uefi_enum_free(uefi_enum_result_t *result);
void uefi_analysis_free(uefi_analysis_result_t *result);

#endif /* FG_UEFI_EXTRACT_H */
