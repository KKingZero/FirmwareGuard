/*
 * FirmwareGuard CLI - smm-scan / uefi-enum / uefi-extract handlers
 */

#include <stdio.h>

#include "cli.h"
#include "../detection/smm_detect.h"
#include "../detection/uefi_extract.h"

#ifndef FG_BUILD_ARM  /* SMM scanning is x86-only */

int cmd_smm_scan(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool brief = o->brief;
    const char *output_file = o->output_file;

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

#endif /* !FG_BUILD_ARM */

int cmd_uefi_enum(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;
    const char *output_file = o->output_file;

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

#ifndef FG_BUILD_ARM  /* SPI flash extraction is x86-only */
int cmd_uefi_extract(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    const char *output_file = o->output_file;

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
#endif /* !FG_BUILD_ARM */
