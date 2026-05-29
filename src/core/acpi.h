#ifndef FG_ACPI_H
#define FG_ACPI_H

#include "../../include/firmwareguard.h"

#define FG_MAX_ACPI_FINDINGS 16

typedef struct {
    int table_count;
    bool fpdt_present;
    bool tpm2_present;
    bool dmar_present;
    bool ivrs_present;
    bool suspicious_oem_tables;
    int finding_count;
    char findings[FG_MAX_ACPI_FINDINGS][128];
} acpi_scan_result_t;

int acpi_scan_telemetry(acpi_scan_result_t *result);

/* Print scan result in human-readable text form */
void acpi_print_result(const acpi_scan_result_t *result, bool verbose);

/* Serialize scan result to JSON. Returns FG_SUCCESS on success. */
int acpi_result_to_json(const acpi_scan_result_t *result, char *buffer, size_t size);

#endif /* FG_ACPI_H */
