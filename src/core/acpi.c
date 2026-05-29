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
