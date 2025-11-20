#include "core/probe.h"
#include "block/blocker.h"
#include "audit/reporter.h"
#include <getopt.h>

static void print_usage(const char *prog_name) {
    printf("\n");
    printf("FirmwareGuard v%s - Firmware Integrity & Anomaly Detection Framework\n", FG_VERSION);
    printf("\n");
    printf("Usage: %s <command> [options]\n", prog_name);
    printf("\n");
    printf("Commands:\n");
    printf("  scan        Scan system for firmware telemetry components\n");
    printf("  block       Attempt to block detected telemetry (non-destructive)\n");
    printf("  report      Generate audit report from previous scan\n");
    printf("  panic       Show recommendations to disable all blockable components\n");
    printf("\n");
    printf("Options:\n");
    printf("  -j, --json       Output in JSON format\n");
    printf("  -o, --output     Output file (default: stdout)\n");
    printf("  -v, --verbose    Verbose output\n");
    printf("  -h, --help       Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s scan                    # Scan system\n", prog_name);
    printf("  %s scan --json -o report.json\n", prog_name);
    printf("  %s block                   # Generate blocking recommendations\n", prog_name);
    printf("  %s panic                   # Show all mitigation options\n", prog_name);
    printf("\n");
    printf("Note: Most operations require root privileges.\n");
    printf("\n");
}

static int cmd_scan(int argc, char **argv, bool json_output, const char *output_file) {
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
    reporter_generate_audit_report(&audit,
                                   json_output ? REPORT_FORMAT_JSON : REPORT_FORMAT_TEXT,
                                   output);

    if (output != stdout) {
        fclose(output);
        FG_INFO("Report written to: %s", output_file);
    }

    /* Cleanup */
    probe_cleanup();
    reporter_cleanup();

    return FG_SUCCESS;
}

static int cmd_block(int argc, char **argv, bool json_output, const char *output_file) {
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
    reporter_generate_combined_report(&audit, &blocking,
                                      json_output ? REPORT_FORMAT_JSON : REPORT_FORMAT_TEXT,
                                      output);

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

static int cmd_panic(int argc, char **argv) {
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

int main(int argc, char **argv) {
    int opt;
    bool json_output = false;
    bool verbose = false;
    const char *output_file = NULL;
    const char *command = NULL;

    static struct option long_options[] = {
        {"json",    no_argument,       0, 'j'},
        {"output",  required_argument, 0, 'o'},
        {"verbose", no_argument,       0, 'v'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    /* Parse command first */
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    command = argv[1];

    /* Parse options */
    optind = 2;  /* Start parsing after command */
    while ((opt = getopt_long(argc, argv, "jvo:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'j':
                json_output = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Execute command */
    if (strcmp(command, "scan") == 0) {
        return cmd_scan(argc, argv, json_output, output_file);
    } else if (strcmp(command, "block") == 0) {
        return cmd_block(argc, argv, json_output, output_file);
    } else if (strcmp(command, "report") == 0) {
        /* For now, report is same as scan */
        return cmd_scan(argc, argv, json_output, output_file);
    } else if (strcmp(command, "panic") == 0) {
        return cmd_panic(argc, argv);
    } else {
        FG_LOG_ERROR("Unknown command: %s", command);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
