/*
 * FirmwareGuard CLI - Boot Guard / Secure Boot / TXT / SGX / TPM handlers
 */

#include <stdio.h>

#include "cli.h"
#include "../detection/bootguard_detect.h"
#include "../detection/txt_sgx_detect.h"

#ifndef FG_BUILD_ARM  /* Boot Guard / Secure Boot / TXT / SGX / TPM are x86-only */

int cmd_bootguard_status(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;

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

int cmd_bootguard_policy(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;

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

int cmd_secureboot_audit(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;

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

int cmd_txt_audit(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;

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

int cmd_sgx_enum(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;

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

int cmd_tpm_measurements(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;

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

int cmd_trusted_boot_full(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;
    bool json_output = o->json;
    bool verbose = o->verbose;

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

#endif /* !FG_BUILD_ARM */
