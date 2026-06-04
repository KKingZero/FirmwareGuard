/*
 * FirmwareGuard CLI - scan / block / panic handlers
 */

#include <stdio.h>
#include <stdlib.h>

#include "cli.h"
#include "../core/probe.h"
#include "../block/blocker.h"
#include "../audit/reporter.h"
#include "../audit/sarif.h"

#ifndef FG_BUILD_ARM  /* scan/block drive the x86 hardware probe + blocker */

int cmd_scan(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    report_format_t fmt = o->report_fmt;
    bool sarif = o->sarif;
    const char *output_file = o->output_file;

    probe_result_t probe;
    audit_result_t audit;
    FILE *output = stdout;
    int ret;

    /* Check root */
    if (fg_require_root() != FG_SUCCESS) {
        return FG_NO_PERMISSION;
    }

    /* Initialize subsystems */
    probe_init();
    reporter_init();

    /* Perform hardware scan */
    FG_INFO("Starting hardware scan...");
    ret = probe_scan_hardware(&probe);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Hardware scan failed");
        probe_cleanup();
        return ret;
    }

    /* Convert to audit format */
    ret = probe_to_audit(&probe, &audit);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to convert probe results to audit format");
        probe_cleanup();
        return ret;
    }

    /* Open output file if specified */
    if (output_file) {
        output = fopen(output_file, "w");
        if (!output) {
            FG_LOG_ERROR("Failed to open output file: %s", output_file);
            probe_cleanup();
            return FG_ERROR;
        }
    }

    /* Generate report */
    if (sarif) {
        sarif_generate(&audit, output);
    } else {
        reporter_generate_audit_report(&audit, fmt, output);
    }

    if (output != stdout) {
        fclose(output);
        FG_INFO("Report written to: %s", output_file);
    }

    /* Cleanup */
    probe_cleanup();
    reporter_cleanup();

    return FG_SUCCESS;
}

int cmd_block(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    report_format_t fmt = o->report_fmt;
    bool sarif = o->sarif;
    const char *output_file = o->output_file;

    probe_result_t probe;
    audit_result_t audit;
    blocking_results_t blocking;
    FILE *output = stdout;
    int ret;

    /* Check root */
    if (fg_require_root() != FG_SUCCESS) {
        return FG_NO_PERMISSION;
    }

    /* Initialize subsystems */
    probe_init();
    blocker_init();
    reporter_init();

    /* Perform hardware scan */
    FG_INFO("Scanning hardware to identify blockable components...");
    ret = probe_scan_hardware(&probe);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Hardware scan failed");
        goto cleanup;
    }

    /* Convert to audit format */
    ret = probe_to_audit(&probe, &audit);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to convert probe results");
        goto cleanup;
    }

    /* Attempt blocking (non-destructive) */
    FG_INFO("Generating blocking recommendations...");
    ret = blocker_attempt_blocking(&audit, &blocking);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to generate blocking recommendations");
        goto cleanup;
    }

    /* Open output file if specified */
    if (output_file) {
        output = fopen(output_file, "w");
        if (!output) {
            FG_LOG_ERROR("Failed to open output file: %s", output_file);
            ret = FG_ERROR;
            goto cleanup;
        }
    }

    /* Generate combined report */
    if (sarif) {
        sarif_generate(&audit, output);
    } else {
        reporter_generate_combined_report(&audit, &blocking, fmt, output);
    }

    if (output != stdout) {
        fclose(output);
        FG_INFO("Report written to: %s", output_file);
    }

    ret = FG_SUCCESS;

cleanup:
    probe_cleanup();
    blocker_cleanup();
    reporter_cleanup();
    return ret;
}

#endif /* !FG_BUILD_ARM */

int cmd_panic(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv; (void)o;
    /* Panic mode: show all possible mitigations */
    printf("\n");
    printf("========================================\n");
    printf("  FIRMWAREGUARD PANIC MODE\n");
    printf("========================================\n");
    printf("\n");
    printf("This mode shows all possible firmware telemetry mitigation options.\n");
    printf("\n");
    printf("WARNING: Some of these actions may cause system instability.\n");
    printf("         Always have a backup and recovery plan.\n");
    printf("\n");

    printf("INTEL MANAGEMENT ENGINE (ME):\n");
    printf("-----------------------------\n");
    printf("1. BIOS/UEFI Settings:\n");
    printf("   - Look for 'Intel ME', 'AMT', or 'vPro' options\n");
    printf("   - Disable if available\n");
    printf("\n");
    printf("2. me_cleaner tool:\n");
    printf("   - https://github.com/corna/me_cleaner\n");
    printf("   - Can partially/fully disable ME\n");
    printf("   - Requires firmware modification (BACKUP FIRST)\n");
    printf("\n");
    printf("3. HAP/AltMeDisable bit:\n");
    printf("   - Some platforms support a 'High Assurance Platform' mode\n");
    printf("   - Check vendor documentation\n");
    printf("\n");

    printf("AMD PLATFORM SECURITY PROCESSOR (PSP):\n");
    printf("--------------------------------------\n");
    printf("1. BIOS Settings:\n");
    printf("   - Some ASUS boards have PSP/fTPM disable option\n");
    printf("   - Check under Security or Advanced settings\n");
    printf("\n");
    printf("2. Kernel Parameters:\n");
    printf("   - Add to GRUB: psp.psp_disabled=1\n");
    printf("   - Edit /etc/default/grub, run update-grub\n");
    printf("\n");

    printf("NETWORK INTERFACE TELEMETRY:\n");
    printf("---------------------------\n");
    printf("1. Disable Wake-on-LAN:\n");
    printf("   - sudo ethtool -s <interface> wol d\n");
    printf("   - Add to startup scripts for persistence\n");
    printf("\n");
    printf("2. Disable Intel AMT (if present):\n");
    printf("   - BIOS settings: disable AMT/vPro\n");
    printf("   - Or use MEBx setup (Ctrl+P during boot)\n");
    printf("\n");

    printf("UEFI/ACPI TELEMETRY:\n");
    printf("-------------------\n");
    printf("1. Disable Telemetry in BIOS:\n");
    printf("   - Look for 'Customer Experience', 'Telemetry', or 'Analytics'\n");
    printf("   - Disable all such options\n");
    printf("\n");
    printf("2. TPM:\n");
    printf("   - Can be disabled in BIOS if not needed\n");
    printf("   - May break BitLocker/fTPM features\n");
    printf("\n");

    printf("GENERAL RECOMMENDATIONS:\n");
    printf("-----------------------\n");
    printf("1. Keep firmware updated (security patches)\n");
    printf("2. Review BIOS settings after updates\n");
    printf("3. Monitor network traffic for unexpected connections\n");
    printf("4. Use hardware firewalls to block unexpected outbound traffic\n");
    printf("5. Consider Coreboot/Libreboot for maximum control (if supported)\n");
    printf("\n");

    printf("For a full audit, run: firmwareguard scan\n");
    printf("For specific recommendations: firmwareguard block\n");
    printf("\n");

    return FG_SUCCESS;
}
