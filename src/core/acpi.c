#include "acpi.h"

#include <dirent.h>

static void add_finding(acpi_scan_result_t *result, const char *finding) {
    if (result->finding_count >= FG_MAX_ACPI_FINDINGS) {
        return;
    }
    snprintf(result->findings[result->finding_count],
             sizeof(result->findings[result->finding_count]), "%s", finding);
    result->finding_count++;
}

int acpi_scan_telemetry(acpi_scan_result_t *result) {
    DIR *dir;
    struct dirent *entry;

    if (!result) {
        return FG_ERROR;
    }

    memset(result, 0, sizeof(*result));

    dir = opendir("/sys/firmware/acpi/tables");
    if (!dir) {
        return FG_NOT_FOUND;
    }

    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;

        if (name[0] == '.') {
            continue;
        }

        result->table_count++;

        if (strcmp(name, "FPDT") == 0) {
            result->fpdt_present = true;
            add_finding(result, "FPDT firmware performance table present");
        } else if (strcmp(name, "TPM2") == 0) {
            result->tpm2_present = true;
            add_finding(result, "TPM2 table present");
        } else if (strcmp(name, "DMAR") == 0) {
            result->dmar_present = true;
            add_finding(result, "DMAR DMA-remapping table present");
        } else if (strcmp(name, "IVRS") == 0) {
            result->ivrs_present = true;
            add_finding(result, "IVRS AMD IOMMU table present");
        } else if (strncmp(name, "OEM", 3) == 0 || name[0] == '_') {
            result->suspicious_oem_tables = true;
        }
    }

    closedir(dir);

    if (result->suspicious_oem_tables) {
        add_finding(result, "Vendor/OEM-specific ACPI tables present");
    }

    return FG_SUCCESS;
}

void acpi_print_result(const acpi_scan_result_t *result, bool verbose) {
    if (!result) {
        return;
    }

    printf("\n=== ACPI Telemetry Scan ===\n");
    printf("ACPI tables found:    %d\n", result->table_count);
    printf("FPDT (perf table):    %s\n", result->fpdt_present ? "present" : "absent");
    printf("TPM2 table:           %s\n", result->tpm2_present ? "present" : "absent");
    printf("DMAR (Intel IOMMU):   %s\n", result->dmar_present ? "present" : "absent");
    printf("IVRS (AMD IOMMU):     %s\n", result->ivrs_present ? "present" : "absent");
    printf("OEM/vendor tables:    %s\n", result->suspicious_oem_tables ? "present" : "absent");

    if (result->finding_count > 0) {
        printf("\nFindings:\n");
        for (int i = 0; i < result->finding_count; i++) {
            printf("  - %s\n", result->findings[i]);
        }
    } else if (verbose) {
        printf("\nNo notable findings.\n");
    }
    printf("\n");
}

int acpi_result_to_json(const acpi_scan_result_t *result, char *buffer, size_t size) {
    if (!result || !buffer) {
        return FG_ERROR;
    }

    int written = snprintf(buffer, size,
        "{\n"
        "  \"table_count\": %d,\n"
        "  \"fpdt_present\": %s,\n"
        "  \"tpm2_present\": %s,\n"
        "  \"dmar_present\": %s,\n"
        "  \"ivrs_present\": %s,\n"
        "  \"suspicious_oem_tables\": %s,\n"
        "  \"findings\": [",
        result->table_count,
        result->fpdt_present ? "true" : "false",
        result->tpm2_present ? "true" : "false",
        result->dmar_present ? "true" : "false",
        result->ivrs_present ? "true" : "false",
        result->suspicious_oem_tables ? "true" : "false");

    if (written < 0 || (size_t)written >= size) {
        return FG_ERROR;
    }

    for (int i = 0; i < result->finding_count; i++) {
        int n = snprintf(buffer + written, size - written,
                         "%s\n    \"%s\"",
                         i == 0 ? "" : ",",
                         result->findings[i]);
        if (n < 0 || (size_t)(written + n) >= size) {
            return FG_ERROR;
        }
        written += n;
    }

    int n = snprintf(buffer + written, size - written,
                     "%s]\n}\n",
                     result->finding_count > 0 ? "\n  " : "");
    if (n < 0 || (size_t)(written + n) >= size) {
        return FG_ERROR;
    }

    return FG_SUCCESS;
}
