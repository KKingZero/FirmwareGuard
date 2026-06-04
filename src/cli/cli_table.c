/*
 * FirmwareGuard CLI - command registry + usage text
 */

#include <stdio.h>
#include <string.h>

#include "cli.h"

#ifdef FG_BUILD_ARM
/*
 * ARM build: only architecture-neutral commands run real handlers. x86-only
 * command names are kept (so scripts get a clear message) but resolve to the
 * not-applicable stub.
 */
const cli_command_t CLI_COMMANDS[] = {
    { "arm-detect",        cmd_arm_detect,        "Detect ARM firmware surfaces (UEFI/ACPI/DeviceTree/TEE)" },
    { "acpi-scan",         cmd_acpi_scan,         "Scan ACPI tables for firmware telemetry indicators" },
    { "nic-scan",          cmd_nic_scan,          "Profile network interfaces (WoL, firmware nodes)" },
    { "uefi-enum",         cmd_uefi_enum,         "Enumerate UEFI variables and check Secure Boot status" },
    { "cve-check",         cmd_cve_check,         "Check a component/version against the CVE database" },
    { "threat-scan",       cmd_threat_scan,       "Hash a file and check it against threat-intel IOCs" },
    { "rootkit-scan",      cmd_rootkit_scan,      "Scan a firmware image for known rootkit signatures" },
    { "integrity-verify",  cmd_integrity_verify,  "Verify a firmware file against known-good checksums" },
    { "panic",             cmd_panic,             "Show recommendations to disable blockable components" },
    /* x86-only command names — present but not applicable on ARM */
    { "scan",              cmd_not_applicable,    "(x86-only) hardware telemetry scan" },
    { "block",             cmd_not_applicable,    "(x86-only) telemetry blocking" },
    { "report",            cmd_not_applicable,    "(x86-only) audit report" },
    { "smm-scan",          cmd_not_applicable,    "(x86-only) SMM security scan" },
    { "uefi-extract",      cmd_not_applicable,    "(x86-only) SPI flash extraction" },
    { "bootguard-status",  cmd_not_applicable,    "(x86-only) Intel Boot Guard status" },
    { "bootguard-policy",  cmd_not_applicable,    "(x86-only) Intel Boot Guard policy" },
    { "secureboot-audit",  cmd_not_applicable,    "(x86-only) Secure Boot key audit" },
    { "txt-audit",         cmd_not_applicable,    "(x86-only) Intel TXT audit" },
    { "sgx-enum",          cmd_not_applicable,    "(x86-only) Intel SGX enumeration" },
    { "tpm-measurements",  cmd_not_applicable,    "(x86-only) TPM PCR analysis" },
    { "trusted-boot-full", cmd_not_applicable,    "(x86-only) full trusted boot analysis" },
    { "baseline-capture",  cmd_not_applicable,    "(x86-only) system baseline capture" },
    { "baseline-compare",  cmd_not_applicable,    "(x86-only) baseline comparison" },
    { "baseline-drift",    cmd_not_applicable,    "(x86-only) baseline drift history" },
    { "implant-scan",      cmd_not_applicable,    "(x86-only) hardware implant scan" },
    { "intel-me",          cmd_not_applicable,    "(x86-only) Intel ME detection" },
    { "amd-psp",           cmd_not_applicable,    "(x86-only) AMD PSP detection" },
    { "compliance",        cmd_not_applicable,    "(x86-only) compliance assessment" },
    { "heci-monitor",      cmd_not_applicable,    "(x86-only) Intel ME/HECI monitor" },
    { "spi-status",        cmd_not_applicable,    "(x86-only) SPI flash protection status" },
};
#else
const cli_command_t CLI_COMMANDS[] = {
    { "scan",              cmd_scan,              "Scan system for firmware telemetry components" },
    { "block",             cmd_block,             "Attempt to block detected telemetry (non-destructive)" },
    { "report",            cmd_scan,              "Generate audit report from previous scan" },
    { "panic",             cmd_panic,             "Show recommendations to disable all blockable components" },
    { "smm-scan",          cmd_smm_scan,          "Scan SMM security configuration" },
    { "uefi-enum",         cmd_uefi_enum,         "Enumerate UEFI variables and check Secure Boot status" },
    { "uefi-extract",      cmd_uefi_extract,      "Extract firmware via SPI flash (requires flashrom)" },
    { "bootguard-status",  cmd_bootguard_status,  "Quick Intel Boot Guard status check" },
    { "bootguard-policy",  cmd_bootguard_policy,  "Full Boot Guard policy analysis" },
    { "secureboot-audit",  cmd_secureboot_audit,  "Audit UEFI Secure Boot key configuration" },
    { "txt-audit",         cmd_txt_audit,         "Audit Intel TXT configuration" },
    { "sgx-enum",          cmd_sgx_enum,          "Enumerate Intel SGX capabilities and EPC sections" },
    { "tpm-measurements",  cmd_tpm_measurements,  "Analyze TPM PCR values and event log" },
    { "trusted-boot-full", cmd_trusted_boot_full, "Full trusted boot analysis (TXT + SGX + TPM)" },
    { "baseline-capture",  cmd_baseline_capture,  "Capture comprehensive system baseline snapshot" },
    { "baseline-compare",  cmd_baseline_compare,  "Compare current state against saved baseline" },
    { "baseline-drift",    cmd_baseline_drift,    "Show drift across the baseline history store" },
    { "implant-scan",      cmd_implant_scan,      "Full hardware implant detection scan" },
    { "acpi-scan",         cmd_acpi_scan,         "Scan ACPI tables for firmware telemetry indicators" },
    { "nic-scan",          cmd_nic_scan,          "Profile network interfaces (WoL, Intel AMT, firmware)" },
    { "intel-me",          cmd_intel_me,          "Detect Intel Management Engine / AMT status" },
    { "amd-psp",           cmd_amd_psp,           "Detect AMD Platform Security Processor / SEV status" },
    { "compliance",        cmd_compliance,        "Assess compliance against security frameworks" },
    /* Phase-4 modules */
    { "cve-check",         cmd_cve_check,         "Check a component/version against the CVE database" },
    { "threat-scan",       cmd_threat_scan,       "Hash a file and check it against the threat-intel IOCs" },
    { "rootkit-scan",      cmd_rootkit_scan,      "Scan a firmware image for known rootkit signatures" },
    { "integrity-verify",  cmd_integrity_verify,  "Verify a firmware file against known-good checksums" },
    { "heci-monitor",      cmd_heci_monitor,      "Monitor Intel ME/HECI traffic (requires /dev/mei0)" },
    { "spi-status",        cmd_spi_status,        "Show SPI flash write-protection status (requires kernel module)" },
};
#endif /* FG_BUILD_ARM */

const size_t CLI_COMMAND_COUNT = sizeof(CLI_COMMANDS) / sizeof(CLI_COMMANDS[0]);

const cli_command_t *cli_find_command(const char *name) {
    for (size_t i = 0; i < CLI_COMMAND_COUNT; i++) {
        if (strcmp(CLI_COMMANDS[i].name, name) == 0) {
            return &CLI_COMMANDS[i];
        }
    }
    return NULL;
}

void cli_print_usage(const char *prog_name) {
#ifdef FG_BUILD_ARM
    printf("\n");
    printf("FirmwareGuard v%s (ARM build) - Firmware Surface Auditor\n", FG_VERSION);
    printf("\n");
    printf("Usage: %s <command> [options]\n", prog_name);
    printf("\n");
    printf("Commands (architecture-neutral):\n");
    printf("  arm-detect        Detect ARM firmware surfaces (UEFI/ACPI/DeviceTree/TEE)\n");
    printf("  acpi-scan         Scan ACPI tables for firmware telemetry indicators\n");
    printf("  nic-scan          Profile network interfaces (WoL, firmware nodes)\n");
    printf("  uefi-enum         Enumerate UEFI variables and check Secure Boot status\n");
    printf("  cve-check         Check a component/version against the CVE database\n");
    printf("  threat-scan       Hash a file and check it against threat-intel IOCs\n");
    printf("  rootkit-scan      Scan a firmware image for known rootkit signatures\n");
    printf("  integrity-verify  Verify a firmware file against known-good checksums\n");
    printf("  panic             Show mitigation recommendations\n");
    printf("\n");
    printf("Options:\n");
    printf("  -j, --json       Output in JSON format\n");
    printf("  -v, --verbose    Verbose output\n");
    printf("  -h, --help       Show this help message\n");
    printf("\n");
    printf("Note: x86-only commands (scan, smm-scan, bootguard-*, txt-audit, intel-me,\n");
    printf("      baseline-*, compliance, ...) are not available in the ARM build.\n");
    printf("\n");
#else
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
    printf("  baseline-drift    Show drift across the baseline history store\n");
    printf("  implant-scan      Full hardware implant detection scan\n");
    printf("  acpi-scan         Scan ACPI tables for firmware telemetry indicators\n");
    printf("  nic-scan          Profile network interfaces (WoL, Intel AMT, firmware)\n");
    printf("  intel-me          Detect Intel Management Engine / AMT status\n");
    printf("  amd-psp           Detect AMD Platform Security Processor / SEV status\n");
    printf("  compliance        Assess compliance against security frameworks\n");
    printf("  cve-check         Check a component/version against the CVE database\n");
    printf("  threat-scan       Hash a file and check it against threat-intel IOCs\n");
    printf("  rootkit-scan      Scan a firmware image for known rootkit signatures\n");
    printf("  integrity-verify  Verify a firmware file against known-good checksums\n");
    printf("  heci-monitor      Monitor Intel ME/HECI traffic (requires /dev/mei0)\n");
    printf("  spi-status        Show SPI flash write-protection status\n");
    printf("\n");
    printf("Options:\n");
    printf("  -j, --json       Output in JSON format\n");
    printf("      --html       Output as a self-contained HTML report (scan/block)\n");
    printf("      --sarif      Output as SARIF 2.1.0 (scan/block)\n");
    printf("      --history    Save into the drift history store (baseline-capture)\n");
    printf("  -o, --output     Output file, or history dir for baseline-drift\n");
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
    printf("  %s cve-check \"Intel ME\" 11.8.50 # Check a component version for CVEs\n", prog_name);
    printf("  %s rootkit-scan dump.bin   # Scan a firmware image for rootkits\n", prog_name);
    printf("\n");
    printf("Note: Most operations require root privileges.\n");
    printf("\n");
#endif /* FG_BUILD_ARM */
}
