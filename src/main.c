#include "probe.h"
#include "block/blocker.h"
#include "audit/reporter.h"
#include "detection/smm_detect.h"
#include "detection/uefi_extract.h"
#include "detection/bootguard_detect.h"
#include "detection/txt_sgx_detect.h"
#include "detection/baseline_capture.h"
#include "detection/implant_detect.h"
#include "compliance/compliance.h"
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
    printf("  smm-scan    Scan SMM (System Management Mode) security configuration\n");
    printf("  uefi-enum   Enumerate UEFI variables and check Secure Boot status\n");
    printf("  uefi-extract Extract firmware via SPI flash (requires flashrom)\n");
    printf("  bootguard-status  Quick Intel Boot Guard status check\n");
    printf("  bootguard-policy  Full Boot Guard policy analysis\n");
    printf("  secureboot-audit  Audit UEFI Secure Boot key configuration\n");
    printf("  txt-audit         Audit Intel TXT (Trusted Execution Technology) config\n");
    printf("  sgx-enum          Enumerate Intel SGX capabilities and EPC sections\n");
    printf("  tpm-measurements  Analyze TPM PCR values and event log\n");
    printf("  trusted-boot-full Full trusted boot analysis (TXT + SGX + TPM)\n");
    printf("  baseline-capture  Capture comprehensive system baseline snapshot\n");
    printf("  baseline-compare  Compare current state against saved baseline\n");
    printf("  implant-scan      Full hardware implant detection scan\n");
    printf("  compliance        Assess compliance against security frameworks\n");
    printf("\n");
    printf("Options:\n");
    printf("  -j, --json       Output in JSON format\n");
    printf("  -o, --output     Output file (default: stdout)\n");
    printf("  -v, --verbose    Verbose output\n");
    printf("  -b, --brief      Brief/quick output (for smm-scan)\n");
    printf("  -h, --help       Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s scan                    # Scan system\n", prog_name);
    printf("  %s scan --json -o report.json\n", prog_name);
    printf("  %s block                   # Generate blocking recommendations\n", prog_name);
    printf("  %s panic                   # Show all mitigation options\n", prog_name);
    printf("  %s smm-scan                # Scan SMM security\n", prog_name);
    printf("  %s smm-scan --brief        # Quick SMM status\n", prog_name);
    printf("  %s uefi-enum               # List UEFI variables\n", prog_name);
    printf("  %s uefi-extract -o dump.bin # Dump SPI flash\n", prog_name);
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

static int cmd_smm_scan(int argc, char **argv, bool json_output, bool brief, const char *output_file) {
    smm_scan_result_t result;
    FILE *output = stdout;
    int ret;

    /* Check root */
    if (fg_require_root() != FG_SUCCESS) {
        return FG_NO_PERMISSION;
    }

    /* Initialize SMM detection */
    ret = smm_detect_init();
    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        FG_LOG_ERROR("Failed to initialize SMM detection subsystem");
        return ret;
    }

    /* Perform SMM scan */
    if (brief) {
        FG_INFO("Performing quick SMM status check...");
        ret = smm_scan_brief(&result);
    } else {
        FG_INFO("Performing full SMM security scan...");
        ret = smm_scan(&result);
    }

    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("SMM scan failed");
        smm_detect_cleanup();
        return ret;
    }

    /* Open output file if specified */
    if (output_file) {
        output = fopen(output_file, "w");
        if (!output) {
            FG_LOG_ERROR("Failed to open output file: %s", output_file);
            smm_detect_cleanup();
            return FG_ERROR;
        }
    }

    /* Generate output */
    if (json_output) {
        char json_buffer[8192];
        if (smm_result_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            fprintf(output, "%s", json_buffer);
        }
    } else {
        /* Redirect stdout temporarily if output file specified */
        if (output != stdout) {
            /* For text output to file, we need to capture */
            fclose(output);
            /* Reopen for text output */
            output = fopen(output_file, "w");
            if (output) {
                FILE *old_stdout = stdout;
                stdout = output;
                smm_print_result(&result, !brief);
                stdout = old_stdout;
                fclose(output);
            }
        } else {
            smm_print_result(&result, !brief);
        }
    }

    if (output != stdout && output != NULL) {
        fclose(output);
        FG_INFO("Report written to: %s", output_file);
    }

    /* Cleanup */
    smm_detect_cleanup();

    return FG_SUCCESS;
}

static int cmd_uefi_enum(int argc, char **argv, bool json_output, bool verbose, const char *output_file) {
    uefi_enum_result_t result;
    FILE *output = stdout;
    int ret;

    /* Initialize */
    ret = uefi_extract_init();
    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        FG_LOG_ERROR("Failed to initialize UEFI subsystem");
        return ret;
    }

    /* Enumerate variables */
    FG_INFO("Enumerating UEFI variables...");
    ret = uefi_enumerate_variables(&result);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("UEFI enumeration failed");
        uefi_extract_cleanup();
        return ret;
    }

    /* Open output file if specified */
    if (output_file) {
        output = fopen(output_file, "w");
        if (!output) {
            FG_LOG_ERROR("Failed to open output file: %s", output_file);
            uefi_enum_free(&result);
            uefi_extract_cleanup();
            return FG_ERROR;
        }
    }

    /* Generate output */
    if (json_output) {
        char json_buffer[8192];
        if (uefi_enum_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            fprintf(output, "%s", json_buffer);
        }
    } else {
        if (output != stdout) {
            FILE *old_stdout = stdout;
            stdout = output;
            uefi_enum_print_result(&result, verbose);
            stdout = old_stdout;
        } else {
            uefi_enum_print_result(&result, verbose);
        }
    }

    if (output != stdout) {
        fclose(output);
        FG_INFO("Report written to: %s", output_file);
    }

    /* Cleanup */
    uefi_enum_free(&result);
    uefi_extract_cleanup();

    return FG_SUCCESS;
}

static int cmd_uefi_extract(int argc, char **argv, bool json_output, const char *output_file) {
    spi_extract_result_t result;
    int ret;

    /* Check root */
    if (fg_require_root() != FG_SUCCESS) {
        return FG_NO_PERMISSION;
    }

    /* Initialize */
    ret = uefi_extract_init();
    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        FG_LOG_ERROR("Failed to initialize UEFI subsystem");
        return ret;
    }

    /* Check flashrom */
    FG_INFO("Checking flashrom availability...");
    ret = spi_check_flashrom();
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("flashrom is required for SPI extraction");
        FG_LOG_ERROR("Install with: sudo apt install flashrom");
        uefi_extract_cleanup();
        return FG_NOT_FOUND;
    }

    /* Detect chip */
    FG_INFO("Detecting SPI flash chip...");
    ret = spi_detect_chip(&result);
    if (ret != FG_SUCCESS) {
        FG_WARN("Could not detect flash chip");
        FG_WARN("Try running with: sudo firmwareguard uefi-extract -o dump.bin");
    }

    /* If output file specified, dump flash */
    if (output_file) {
        FG_INFO("Dumping SPI flash...");
        ret = spi_dump_flash(output_file, &result);
        if (ret != FG_SUCCESS) {
            FG_LOG_ERROR("Flash dump failed");
            uefi_extract_cleanup();
            return ret;
        }
        FG_INFO("Flash dumped to: %s", output_file);
    }

    /* Print results */
    if (json_output) {
        char json_buffer[4096];
        if (spi_result_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s", json_buffer);
        }
    } else {
        spi_print_result(&result, true);
    }

    uefi_extract_cleanup();

    return FG_SUCCESS;
}

static int cmd_bootguard_status(int argc, char **argv, bool json_output) {
    bootguard_status_t result;
    int ret;

    /* Check root */
    if (fg_require_root() != FG_SUCCESS) {
        return FG_NO_PERMISSION;
    }

    /* Initialize */
    ret = bootguard_init();
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to initialize Boot Guard detection");
        return ret;
    }

    /* Scan status */
    ret = bootguard_scan_status(&result);

    /* Output */
    if (json_output) {
        char json_buffer[4096];
        if (bootguard_status_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s", json_buffer);
        }
    } else {
        bootguard_status_print(&result);
    }

    bootguard_cleanup();
    return ret == FG_NOT_SUPPORTED ? FG_SUCCESS : ret;
}

static int cmd_bootguard_policy(int argc, char **argv, bool json_output, bool verbose) {
    bootguard_policy_result_t result;
    int ret;

    /* Check root */
    if (fg_require_root() != FG_SUCCESS) {
        return FG_NO_PERMISSION;
    }

    /* Initialize */
    ret = bootguard_init();
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to initialize Boot Guard detection");
        return ret;
    }

    /* Scan policy */
    ret = bootguard_scan_policy(&result);

    /* Output */
    if (json_output) {
        char json_buffer[8192];
        if (bootguard_policy_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s", json_buffer);
        }
    } else {
        bootguard_policy_print(&result, verbose);
    }

    bootguard_cleanup();
    return ret == FG_NOT_SUPPORTED ? FG_SUCCESS : ret;
}

static int cmd_secureboot_audit(int argc, char **argv, bool json_output, bool verbose) {
    secureboot_audit_t result;
    int ret;

    /* Initialize */
    ret = bootguard_init();
    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        FG_LOG_ERROR("Failed to initialize Boot Guard detection");
        return ret;
    }

    /* Scan Secure Boot */
    ret = secureboot_audit_scan(&result);

    /* Output */
    if (json_output) {
        char json_buffer[4096];
        if (secureboot_audit_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s", json_buffer);
        }
    } else {
        secureboot_audit_print(&result, verbose);
    }

    bootguard_cleanup();
    return ret == FG_NOT_SUPPORTED ? FG_SUCCESS : ret;
}

static int cmd_txt_audit(int argc, char **argv, bool json_output, bool verbose) {
    txt_config_t result;
    int ret;

    /* Check root */
    if (fg_require_root() != FG_SUCCESS) {
        return FG_NO_PERMISSION;
    }

    /* Initialize */
    ret = txt_sgx_init();
    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        FG_LOG_ERROR("Failed to initialize TXT/SGX subsystem");
        return ret;
    }

    /* Scan TXT config */
    FG_INFO("Auditing Intel TXT configuration...");
    ret = txt_scan_config(&result);

    /* Output */
    if (json_output) {
        char json_buffer[8192];
        if (txt_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s\n", json_buffer);
        }
    } else {
        txt_print_result(&result, verbose);
    }

    txt_sgx_cleanup();
    return ret == FG_NOT_SUPPORTED ? FG_SUCCESS : ret;
}

static int cmd_sgx_enum(int argc, char **argv, bool json_output, bool verbose) {
    sgx_config_t result;
    int ret;

    /* Initialize */
    ret = txt_sgx_init();
    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        FG_LOG_ERROR("Failed to initialize TXT/SGX subsystem");
        return ret;
    }

    /* Enumerate SGX */
    FG_INFO("Enumerating Intel SGX capabilities...");
    ret = sgx_scan_config(&result);

    /* Output */
    if (json_output) {
        char json_buffer[8192];
        if (sgx_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s\n", json_buffer);
        }
    } else {
        sgx_print_result(&result, verbose);
    }

    txt_sgx_cleanup();
    return ret == FG_NOT_SUPPORTED ? FG_SUCCESS : ret;
}

static int cmd_tpm_measurements(int argc, char **argv, bool json_output, bool verbose) {
    tpm_measurement_t result;
    int ret;

    /* Initialize */
    ret = txt_sgx_init();
    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        FG_LOG_ERROR("Failed to initialize TXT/SGX subsystem");
        return ret;
    }

    /* Scan TPM */
    FG_INFO("Analyzing TPM measurements...");
    ret = tpm_scan_measurements(&result);

    /* Output */
    if (json_output) {
        char json_buffer[8192];
        if (tpm_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s\n", json_buffer);
        }
    } else {
        tpm_print_result(&result, verbose);
    }

    txt_sgx_cleanup();
    return ret == FG_NOT_SUPPORTED ? FG_SUCCESS : ret;
}

static int cmd_trusted_boot_full(int argc, char **argv, bool json_output, bool verbose) {
    trusted_boot_result_t result;
    int ret;

    /* Check root for TXT */
    if (fg_require_root() != FG_SUCCESS) {
        FG_WARN("Running without root - some TXT features may be limited");
    }

    /* Initialize */
    ret = txt_sgx_init();
    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        FG_LOG_ERROR("Failed to initialize TXT/SGX subsystem");
        return ret;
    }

    /* Full trusted boot scan */
    FG_INFO("Performing full trusted boot analysis...");
    ret = trusted_boot_full_scan(&result);

    /* Output */
    if (json_output) {
        char json_buffer[16384];
        if (trusted_boot_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s\n", json_buffer);
        }
    } else {
        trusted_boot_print_result(&result, verbose);
    }

    txt_sgx_cleanup();
    return ret == FG_NOT_SUPPORTED ? FG_SUCCESS : ret;
}

static int cmd_baseline_capture(int argc, char **argv, bool json_output, bool verbose, const char *output_file) {
    baseline_snapshot_t snapshot;
    int ret;

    /* Check root for full access */
    if (fg_require_root() != FG_SUCCESS) {
        FG_WARN("Running without root - some features may be limited");
    }

    /* Initialize */
    ret = baseline_init();
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to initialize baseline subsystem");
        return ret;
    }

    /* Capture baseline */
    FG_INFO("Capturing comprehensive system baseline...");
    ret = baseline_capture(&snapshot);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Baseline capture failed");
        baseline_cleanup();
        return ret;
    }

    /* Save to file if specified */
    if (output_file) {
        ret = baseline_save(&snapshot, output_file);
        if (ret == FG_SUCCESS) {
            FG_INFO("Baseline saved to: %s", output_file);
        }
    }

    /* Output */
    if (json_output) {
        char json_buffer[16384];
        if (baseline_to_json(&snapshot, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s\n", json_buffer);
        }
    } else {
        baseline_print_snapshot(&snapshot, verbose);
    }

    baseline_cleanup();
    return FG_SUCCESS;
}

static int cmd_baseline_compare(int argc, char **argv, bool json_output, bool verbose, const char *baseline_file) {
    baseline_comparison_t result;
    int ret;

    if (!baseline_file) {
        FG_LOG_ERROR("Baseline file required for comparison");
        FG_LOG_ERROR("Usage: firmwareguard baseline-compare -o <baseline_file>");
        return FG_ERROR;
    }

    /* Check root for full access */
    if (fg_require_root() != FG_SUCCESS) {
        FG_WARN("Running without root - some features may be limited");
    }

    /* Initialize */
    ret = baseline_init();
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to initialize baseline subsystem");
        return ret;
    }

    /* Compare against baseline */
    FG_INFO("Comparing current state against baseline: %s", baseline_file);
    ret = baseline_compare_file(baseline_file, &result);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Baseline comparison failed");
        baseline_cleanup();
        return ret;
    }

    /* Output */
    if (json_output) {
        char json_buffer[16384];
        if (baseline_comparison_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s\n", json_buffer);
        }
    } else {
        baseline_print_comparison(&result, verbose);
    }

    baseline_cleanup();
    return FG_SUCCESS;
}

static int cmd_implant_scan(int argc, char **argv, bool json_output, bool verbose) {
    implant_scan_result_t result;
    int ret;

    /* Initialize */
    ret = implant_detect_init();
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to initialize implant detection");
        return ret;
    }

    /* Perform scan */
    FG_INFO("Starting hardware implant detection scan...");
    ret = implant_full_scan(&result);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Implant scan failed");
        implant_detect_cleanup();
        return ret;
    }

    /* Output */
    if (json_output) {
        char json_buffer[16384];
        if (implant_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s\n", json_buffer);
        }
    } else {
        implant_print_result(&result, verbose);
    }

    implant_detect_cleanup();
    return FG_SUCCESS;
}

static int cmd_compliance(int argc, char **argv, bool json_output, const char *output_file) {
    compliance_result_t result;
    FILE *output = stdout;
    int ret;

    /* Initialize compliance subsystem */
    ret = compliance_init();
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to initialize compliance subsystem");
        return ret;
    }

    /* Perform compliance assessment (defaults to NIST 800-171) */
    FG_INFO("Assessing compliance against NIST 800-171...");
    ret = compliance_assess(FRAMEWORK_NIST_800_171, &result);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Compliance assessment failed");
        compliance_cleanup();
        return ret;
    }

    /* Open output file if specified */
    if (output_file) {
        output = fopen(output_file, "w");
        if (!output) {
            FG_LOG_ERROR("Failed to open output file: %s", output_file);
            compliance_cleanup();
            return FG_ERROR;
        }
    }

    /* Generate output */
    if (json_output) {
        /* 256KB buffer for worst-case JSON output */
        char *json_buffer = malloc(262144);
        if (!json_buffer) {
            FG_LOG_ERROR("Failed to allocate JSON buffer");
            if (output != stdout) fclose(output);
            compliance_cleanup();
            return FG_ERROR;
        }
        if (compliance_result_to_json(&result, json_buffer, 262144) == FG_SUCCESS) {
            fprintf(output, "%s\n", json_buffer);
        } else {
            FG_LOG_ERROR("Failed to generate JSON report");
        }
        free(json_buffer);
    } else {
        /*
         * Note: For file output, we redirect stdout temporarily.
         * This is not ideal for multi-threaded environments but
         * FirmwareGuard is single-threaded by design.
         */
        if (output != stdout) {
            FILE *old_stdout = stdout;
            stdout = output;
            compliance_print_result(&result, true);
            fflush(stdout);
            stdout = old_stdout;
        } else {
            compliance_print_result(&result, true);
        }
    }

    if (output != stdout) {
        fclose(output);
        FG_INFO("Report written to: %s", output_file);
    }

    /* Cleanup */
    compliance_cleanup();

    return FG_SUCCESS;
}

int main(int argc, char **argv) {
    int opt;
    bool json_output = false;
    bool verbose = false;
    bool brief = false;
    const char *output_file = NULL;
    const char *command = NULL;

    static struct option long_options[] = {
        {"json",    no_argument,       0, 'j'},
        {"output",  required_argument, 0, 'o'},
        {"verbose", no_argument,       0, 'v'},
        {"brief",   no_argument,       0, 'b'},
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
    while ((opt = getopt_long(argc, argv, "jvbo:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'j':
                json_output = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'b':
                brief = true;
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
    } else if (strcmp(command, "smm-scan") == 0) {
        return cmd_smm_scan(argc, argv, json_output, brief, output_file);
    } else if (strcmp(command, "uefi-enum") == 0) {
        return cmd_uefi_enum(argc, argv, json_output, verbose, output_file);
    } else if (strcmp(command, "uefi-extract") == 0) {
        return cmd_uefi_extract(argc, argv, json_output, output_file);
    } else if (strcmp(command, "bootguard-status") == 0) {
        return cmd_bootguard_status(argc, argv, json_output);
    } else if (strcmp(command, "bootguard-policy") == 0) {
        return cmd_bootguard_policy(argc, argv, json_output, verbose);
    } else if (strcmp(command, "secureboot-audit") == 0) {
        return cmd_secureboot_audit(argc, argv, json_output, verbose);
    } else if (strcmp(command, "txt-audit") == 0) {
        return cmd_txt_audit(argc, argv, json_output, verbose);
    } else if (strcmp(command, "sgx-enum") == 0) {
        return cmd_sgx_enum(argc, argv, json_output, verbose);
    } else if (strcmp(command, "tpm-measurements") == 0) {
        return cmd_tpm_measurements(argc, argv, json_output, verbose);
    } else if (strcmp(command, "trusted-boot-full") == 0) {
        return cmd_trusted_boot_full(argc, argv, json_output, verbose);
    } else if (strcmp(command, "baseline-capture") == 0) {
        return cmd_baseline_capture(argc, argv, json_output, verbose, output_file);
    } else if (strcmp(command, "baseline-compare") == 0) {
        return cmd_baseline_compare(argc, argv, json_output, verbose, output_file);
    } else if (strcmp(command, "implant-scan") == 0) {
        return cmd_implant_scan(argc, argv, json_output, verbose);
    } else if (strcmp(command, "compliance") == 0) {
        return cmd_compliance(argc, argv, json_output, output_file);
    } else {
        FG_LOG_ERROR("Unknown command: %s", command);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
