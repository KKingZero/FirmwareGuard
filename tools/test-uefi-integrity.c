/*
 * FirmwareGuard - UEFI Integrity Test Tool
 *
 * This tool tests the UEFI runtime integrity checking module
 * to verify it can detect UEFI runtime services tables, memory
 * regions, and potential hooks/modifications.
 */

#include "../src/detection/uefi_integrity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_usage(const char *prog_name) {
    printf("FirmwareGuard UEFI Integrity Test Tool\n");
    printf("Usage: %s [options]\n", prog_name);
    printf("\nOptions:\n");
    printf("  -v, --verbose      Verbose output\n");
    printf("  -b, --brief        Brief scan (quick check)\n");
    printf("  -s, --save-baseline Save current state as baseline\n");
    printf("  -j, --json         Output in JSON format\n");
    printf("  -h, --help         Show this help message\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    bool verbose = false;
    bool brief = false;
    bool save_baseline = false;
    bool json_output = false;
    int ret;

    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--brief") == 0) {
            brief = true;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--save-baseline") == 0) {
            save_baseline = true;
        } else if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            json_output = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Check root privileges */
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: This tool requires root privileges\n");
        fprintf(stderr, "Please run with sudo: sudo %s\n", argv[0]);
        return 1;
    }

    /* Initialize UEFI integrity subsystem */
    printf("Initializing UEFI integrity checking subsystem...\n");
    ret = uefi_integrity_init();
    if (ret == FG_NOT_SUPPORTED) {
        printf("UEFI is not supported on this system (not UEFI-based or runtime not available)\n");
        return 0;
    } else if (ret != FG_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize UEFI integrity subsystem\n");
        return 1;
    }

    printf("UEFI integrity subsystem initialized successfully\n\n");

    /* Allocate result structure */
    uefi_integrity_result_t *result = calloc(1, sizeof(uefi_integrity_result_t));
    if (!result) {
        fprintf(stderr, "ERROR: Memory allocation failed\n");
        uefi_integrity_cleanup();
        return 1;
    }

    /* Perform scan */
    if (brief) {
        printf("Performing brief UEFI integrity check...\n");
        ret = uefi_integrity_check_brief(result);
    } else {
        printf("Performing full UEFI integrity scan...\n");
        ret = uefi_integrity_scan(result);
    }

    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        fprintf(stderr, "ERROR: UEFI integrity scan failed\n");
        free(result);
        uefi_integrity_cleanup();
        return 1;
    }

    /* Display results */
    if (json_output) {
        char json_buffer[8192];
        ret = uefi_integrity_to_json(result, json_buffer, sizeof(json_buffer));
        if (ret == FG_SUCCESS) {
            printf("%s\n", json_buffer);
        } else {
            fprintf(stderr, "ERROR: Failed to generate JSON output\n");
        }
    } else {
        uefi_integrity_print_result(result, verbose);
    }

    /* Save baseline if requested */
    if (save_baseline && result->current_snapshot.snapshot_valid) {
        const char *baseline_path = "/var/lib/firmwareguard/uefi_baseline.dat";
        printf("\nSaving baseline to %s...\n", baseline_path);

        /* Create directory if it doesn't exist */
        system("mkdir -p /var/lib/firmwareguard");

        ret = uefi_save_baseline(&result->current_snapshot, baseline_path);
        if (ret == FG_SUCCESS) {
            printf("Baseline saved successfully\n");
        } else {
            fprintf(stderr, "ERROR: Failed to save baseline\n");
        }
    }

    /* Display security recommendations */
    if (!json_output && result->risk_level >= RISK_HIGH) {
        printf("\n");
        printf("========================================\n");
        printf("  SECURITY RECOMMENDATIONS\n");
        printf("========================================\n");
        printf("\n");

        if (result->num_hooks_detected > 0) {
            printf("CRITICAL FINDINGS:\n");
            printf("  - Potential UEFI rootkit detected!\n");
            printf("  - %d suspicious hooks found in runtime services\n", result->num_hooks_detected);
            printf("\nImmediate Actions:\n");
            printf("  1. Disconnect from network immediately\n");
            printf("  2. Boot from trusted external media\n");
            printf("  3. Perform full system backup\n");
            printf("  4. Consider firmware re-flashing from known-good image\n");
            printf("  5. Contact security team or incident response\n");
            printf("\n");
        }

        if (result->integrity.tables_modified) {
            printf("WARNING: Runtime services tables modified\n");
            printf("  - This may indicate tampering or firmware corruption\n");
            printf("  - Compare with saved baseline\n");
            printf("  - Verify firmware integrity\n");
            printf("\n");
        }

        /* Check for W+X violations */
        for (int i = 0; i < result->num_regions; i++) {
            const uefi_runtime_region_t *region = &result->regions[i];
            if (region->type == EFI_RUNTIME_SERVICES_CODE &&
                region->writable && region->executable) {
                printf("CRITICAL: Writable+Executable runtime code detected\n");
                printf("  - Region %d has W+X permissions\n", i);
                printf("  - This violates memory protection best practices\n");
                printf("  - Consider firmware update if available\n");
                printf("\n");
                break;
            }
        }
    }

    /* Cleanup */
    free(result);
    uefi_integrity_cleanup();

    printf("\nTest complete.\n");
    return 0;
}
