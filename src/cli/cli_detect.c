/*
 * FirmwareGuard CLI - implant / acpi / nic / intel-me / amd-psp / compliance handlers
 */

#include <stdio.h>
#include <stdlib.h>

#include "cli.h"
#include "../core/probe.h"
#include "../core/acpi.h"
#include "../core/me_psp.h"
#include "../core/nic.h"
#include "../detection/implant_detect.h"
#include "../compliance/compliance.h"

int cmd_implant_scan(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;

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
            printf("%s", json_buffer);
        }
    } else {
        implant_print_result(&result, verbose);
    }

    implant_detect_cleanup();
    return FG_SUCCESS;
}

int cmd_acpi_scan(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;

    acpi_scan_result_t result;
    int ret = acpi_scan_telemetry(&result);
    if (ret == FG_NOT_FOUND) {
        FG_WARN("ACPI tables not available (/sys/firmware/acpi/tables missing)");
        return ret;
    }
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("ACPI telemetry scan failed");
        return ret;
    }

    if (json_output) {
        char json_buffer[8192];
        if (acpi_result_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s", json_buffer);
        }
    } else {
        acpi_print_result(&result, verbose);
    }
    return FG_SUCCESS;
}

int cmd_nic_scan(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;

    nic_scan_result_t result;
    int ret = nic_scan(&result);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("NIC telemetry scan failed");
        return ret;
    }

    if (json_output) {
        char json_buffer[16384];
        if (nic_result_to_json(&result, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s", json_buffer);
        }
    } else {
        nic_print_result(&result, verbose);
    }
    return FG_SUCCESS;
}

int cmd_intel_me(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;

    intel_me_info_t info;
    int ret = probe_intel_me(&info);
    /* FG_NOT_FOUND simply means no ME surface detected; still report it */
    if (ret != FG_SUCCESS && ret != FG_NOT_FOUND) {
        FG_LOG_ERROR("Intel ME probe failed");
        return ret;
    }

    if (json_output) {
        char json_buffer[2048];
        if (intel_me_to_json(&info, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s", json_buffer);
        }
    } else {
        intel_me_print(&info, verbose);
    }
    return FG_SUCCESS;
}

int cmd_amd_psp(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;

    amd_psp_info_t info;
    int ret = probe_amd_psp(&info);
    if (ret != FG_SUCCESS && ret != FG_NOT_FOUND) {
        FG_LOG_ERROR("AMD PSP probe failed");
        return ret;
    }

    if (json_output) {
        char json_buffer[2048];
        if (amd_psp_to_json(&info, json_buffer, sizeof(json_buffer)) == FG_SUCCESS) {
            printf("%s", json_buffer);
        }
    } else {
        amd_psp_print(&info, verbose);
    }
    return FG_SUCCESS;
}

int cmd_compliance(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    const char *output_file = o->output_file;

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
