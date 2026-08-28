/*
 * FirmwareGuard CLI - graduated advisory / analysis modules
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cli.h"
#include "../detection/uefi_integrity.h"
#include "../dump/live_dump.h"
#include "../ghidra/ghidra_wrapper.h"
#include "../migration/coreboot_migrate.h"

#define FG_DEFAULT_GHIDRA_OUT "ghidra_analysis"
#define FG_DEFAULT_DUMP_OUT "firmwareguard_dumps"

static const char *fg_data_dir(void) {
    const char *d = getenv("FG_DATA_DIR");
    return (d && *d) ? d : "data";
}

static void print_json_string(const char *s) {
    putchar('"');
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            switch (*p) {
                case '"': printf("\\\""); break;
                case '\\': printf("\\\\"); break;
                case '\n': printf("\\n"); break;
                case '\r': printf("\\r"); break;
                case '\t': printf("\\t"); break;
                default:
                    if (*p < 0x20) {
                        printf("\\u%04x", *p);
                    } else {
                        putchar(*p);
                    }
            }
        }
    }
    putchar('"');
}

static int write_output_file(const char *path, const char *data) {
    if (!path || !data) {
        return FG_SUCCESS;
    }

    FILE *fp = fopen(path, "w");
    if (!fp) {
        FG_LOG_ERROR("Cannot write output file %s: %s", path, strerror(errno));
        return FG_ERROR;
    }

    fputs(data, fp);
    fclose(fp);
    return FG_SUCCESS;
}

static int ensure_dir(const char *path) {
    struct stat st;

    if (!path || !*path || strstr(path, "..")) {
        FG_LOG_ERROR("Invalid output directory");
        return FG_ERROR;
    }

    if (stat(path, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            FG_LOG_ERROR("Output path is not a directory: %s", path);
            return FG_ERROR;
        }
        return FG_SUCCESS;
    }

    if (mkdir(path, 0755) != 0) {
        FG_LOG_ERROR("Cannot create output directory %s: %s", path, strerror(errno));
        return FG_ERROR;
    }

    return FG_SUCCESS;
}

static int validate_output_dir_path(const char *path) {
    struct stat st;

    if (!path || !*path || strstr(path, "..")) {
        FG_LOG_ERROR("Invalid output directory");
        return FG_ERROR;
    }

    if (stat(path, &st) == 0 && !S_ISDIR(st.st_mode)) {
        FG_LOG_ERROR("Output path is not a directory: %s", path);
        return FG_ERROR;
    }

    return FG_SUCCESS;
}

static bool confirm_dangerous(const char *label, const cli_opts_t *o) {
    if (o->yes) {
        return true;
    }

    if (!isatty(STDIN_FILENO)) {
        FG_LOG_ERROR("%s requires --yes when stdin is not interactive", label);
        return false;
    }

    printf("%s can touch privileged firmware interfaces. Type YES to continue: ", label);
    fflush(stdout);

    char answer[16] = {0};
    if (!fgets(answer, sizeof(answer), stdin)) {
        return false;
    }
    answer[strcspn(answer, "\r\n")] = '\0';
    return strcmp(answer, "YES") == 0;
}

int cmd_uefi_integrity(int argc, char **argv, const cli_opts_t *o) {
    (void)argv;
    if (argc != 0) {
        FG_LOG_ERROR("Usage: firmwareguard uefi-integrity [--brief] [--json] [-v] [-o path]");
        return FG_ERROR;
    }

    uefi_integrity_result_t result;
    int ret = o->brief ? uefi_integrity_check_brief(&result) : uefi_integrity_scan(&result);
    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        return FG_ERROR;
    }

    char buffer[16384];
    if (o->json) {
        if (uefi_integrity_to_json(&result, buffer, sizeof(buffer)) != FG_SUCCESS) {
            return FG_ERROR;
        }
        printf("%s", buffer);
        ret = write_output_file(o->output_file, buffer);
    } else if (o->output_file) {
        if (uefi_integrity_report(&result, buffer, sizeof(buffer)) != FG_SUCCESS) {
            return FG_ERROR;
        }
        uefi_integrity_print_result(&result, o->verbose);
        ret = write_output_file(o->output_file, buffer);
    } else {
        uefi_integrity_print_result(&result, o->verbose);
        ret = FG_SUCCESS;
    }

    return ret == FG_SUCCESS ? FG_SUCCESS : FG_ERROR;
}

int cmd_coreboot_check(int argc, char **argv, const cli_opts_t *o) {
    (void)argv;
    if (argc != 0) {
        FG_LOG_ERROR("Usage: firmwareguard coreboot-check [--json] [-v]");
        return FG_ERROR;
    }

    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/coreboot_boards.json", fg_data_dir());

    if (coreboot_migrate_init() != FG_SUCCESS) {
        return FG_ERROR;
    }

    int ret = coreboot_load_database(db_path);
    if (ret != FG_SUCCESS) {
        coreboot_migrate_cleanup();
        return ret == FG_NOT_FOUND ? FG_SUCCESS : FG_ERROR;
    }

    coreboot_compat_result_t result;
    ret = coreboot_check_compatibility(&result);
    if (ret != FG_SUCCESS) {
        coreboot_migrate_cleanup();
        return FG_ERROR;
    }

    if (o->json) {
        printf("{\n  \"board_found\": %s,\n  \"can_migrate\": %s,\n  \"compatibility\": ",
               result.board_found ? "true" : "false",
               result.can_migrate ? "true" : "false");
        print_json_string(coreboot_compat_to_str(result.compatibility));
        printf(",\n  \"risk\": ");
        print_json_string(coreboot_risk_to_str(result.overall_risk));
        printf(",\n  \"manufacturer\": ");
        print_json_string(result.detected_dmi.system_manufacturer);
        printf(",\n  \"product\": ");
        print_json_string(result.detected_dmi.system_product);
        printf(",\n  \"readiness_reason\": ");
        print_json_string(result.readiness_reason);
        printf(",\n  \"warnings\": [");
        for (int i = 0; i < result.warning_count; i++) {
            printf("%s", i ? ", " : "");
            print_json_string(result.warnings[i]);
        }
        printf("],\n  \"warning_count\": %d,\n  \"summary\": ", result.warning_count);
        print_json_string(result.summary);
        printf("\n}\n");
    } else {
        coreboot_print_compatibility(&result, o->verbose);
        printf("Read-only advisory only. Firmware backup/flashing is not exposed by this command.\n");
    }

    coreboot_migrate_cleanup();
    return FG_SUCCESS;
}

int cmd_ghidra_analyze(int argc, char **argv, const cli_opts_t *o) {
    if (argc != 1) {
        FG_LOG_ERROR("Usage: firmwareguard ghidra-analyze <firmware.bin> [--json] [-v] [-o dir]");
        return FG_ERROR;
    }

    const char *firmware = argv[0];
    if (access(firmware, R_OK) != 0) {
        FG_LOG_ERROR("Cannot read firmware file: %s", firmware);
        return FG_ERROR;
    }

    const char *out_dir = o->output_file ? o->output_file : FG_DEFAULT_GHIDRA_OUT;
    if (validate_output_dir_path(out_dir) != FG_SUCCESS) {
        return FG_ERROR;
    }

    ghidra_config_t config;
    memset(&config, 0, sizeof(config));
    strncpy(config.output_dir, out_dir, sizeof(config.output_dir) - 1);
    config.verbose = o->verbose;
    config.timeout_seconds = 300;
    const char *scripts_dir = getenv("FG_GHIDRA_SCRIPTS_DIR");
    if (scripts_dir && *scripts_dir) {
        if (validate_output_dir_path(scripts_dir) != FG_SUCCESS) {
            return FG_ERROR;
        }
        strncpy(config.scripts_dir, scripts_dir, sizeof(config.scripts_dir) - 1);
    } else if (access("tools/ghidra/ghidra_runner.sh", X_OK) == 0) {
        strncpy(config.scripts_dir, "tools/ghidra", sizeof(config.scripts_dir) - 1);
    } else {
        strncpy(config.scripts_dir, "/usr/share/firmwareguard/ghidra",
                sizeof(config.scripts_dir) - 1);
    }

    ghidra_result_t result;
    int ret = ghidra_init(&config);
    if (ret != FG_SUCCESS) {
        return FG_ERROR;
    }

    ret = ghidra_analyze(firmware, GHIDRA_ANALYSIS_AUTO, &result);
    if (ret == FG_NOT_FOUND) {
        if (o->json) {
            printf("{\"available\": false, \"error\": ");
            print_json_string(result.error_message);
            printf("}\n");
        } else {
            printf("Ghidra is not available. Set GHIDRA_HOME or install Ghidra in a common location.\n");
        }
        ghidra_cleanup();
        return FG_SUCCESS;
    }
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("%s", result.error_message[0] ? result.error_message : "Ghidra analysis failed");
        ghidra_cleanup();
        return FG_ERROR;
    }

    if (o->json) {
        printf("{\n  \"available\": true,\n  \"success\": %s,\n  \"filename\": ",
               result.success ? "true" : "false");
        print_json_string(result.filename);
        printf(",\n  \"firmware_type\": ");
        print_json_string(result.firmware_type);
        printf(",\n  \"risk_level\": ");
        print_json_string(result.risk_level);
        printf(",\n  \"risk_score\": %d,\n  \"indicators\": %d,\n  \"output_path\": ",
               result.risk_score, result.num_indicators);
        print_json_string(result.output_path);
        printf("\n}\n");
    } else {
        ghidra_print_summary(&result);
    }

    ghidra_free_result(&result);
    ghidra_cleanup();
    return FG_SUCCESS;
}

static void print_dump_capabilities_json(uint32_t caps) {
    printf("{\n  \"dry_run\": true,\n  \"capabilities\": [");
    for (int r = 0, printed = 0; r < DUMP_REGION_MAX; r++) {
        if (!(caps & (1u << r))) {
            continue;
        }
        printf("%s\n    {\"region\": ", printed ? "," : "");
        print_json_string(dump_region_name((dump_region_t)r));
        printf(", \"risk\": %d}", dump_region_risk_level((dump_region_t)r));
        printed++;
    }
    printf("\n  ]\n}\n");
}

static void print_dump_session_json(const dump_session_t *session) {
    printf("{\n  \"output_dir\": ");
    print_json_string(session->output_dir);
    printf(",\n  \"regions\": [");
    for (int i = 0; i < session->num_regions; i++) {
        const region_dump_t *r = &session->regions[i];
        printf("%s\n    {\"region\": ", i ? "," : "");
        print_json_string(dump_region_name(r->region));
        printf(", \"status\": ");
        print_json_string(dump_status_string(r->status));
        printf(", \"path\": ");
        print_json_string(r->output_path);
        printf(", \"size\": %llu, \"sha256\": ",
               (unsigned long long)r->size);
        print_json_string(r->sha256);
        printf(", \"error\": ");
        print_json_string(r->error);
        printf("}");
    }
    printf("\n  ]\n}\n");
}

int cmd_live_dump(int argc, char **argv, const cli_opts_t *o) {
    (void)argv;
    if (argc != 0) {
        FG_LOG_ERROR("Usage: firmwareguard live-dump [--json] [-o dir] [--acpi] [--optionrom] [--spi] [--smram] [--dangerous] [--yes]");
        return FG_ERROR;
    }

    if (dump_init() != FG_SUCCESS) {
        return FG_ERROR;
    }

    bool selected = o->acpi || o->optionrom || o->spi || o->smram;
    if (!selected) {
        uint32_t caps = 0;
        dump_check_capabilities(&caps);
        if (o->json) {
            print_dump_capabilities_json(caps);
        } else {
            printf("Live dump dry-run. Available capabilities:\n");
            for (int r = 0; r < DUMP_REGION_MAX; r++) {
                if (caps & (1u << r)) {
                    printf("  - %s (risk %d/10)\n",
                           dump_region_name((dump_region_t)r),
                           dump_region_risk_level((dump_region_t)r));
                }
            }
            printf("Select explicit targets to dump. SPI and SMRAM require --dangerous.\n");
        }
        dump_cleanup();
        return FG_SUCCESS;
    }

    if ((o->spi || o->smram) && !o->dangerous) {
        FG_LOG_ERROR("SPI and SMRAM dumps require --dangerous");
        dump_cleanup();
        return FG_ERROR;
    }

    if ((o->spi || o->smram) && geteuid() != 0) {
        FG_LOG_ERROR("SPI and SMRAM dumps require root");
        dump_cleanup();
        return FG_NO_PERMISSION;
    }

    if ((o->spi || o->smram) && !confirm_dangerous("live-dump", o)) {
        dump_cleanup();
        return FG_ERROR;
    }

    const char *out_dir = o->output_file ? o->output_file : FG_DEFAULT_DUMP_OUT;
    if (ensure_dir(out_dir) != FG_SUCCESS) {
        dump_cleanup();
        return FG_ERROR;
    }

    dump_options_t opts = {
        .safety_level = o->dangerous ? DUMP_AGGRESSIVE : DUMP_SAFE_ONLY,
        .output_dir = out_dir,
        .dump_me = false,
        .dump_psp = false,
        .dump_smram = o->smram,
        .dump_optionrom = o->optionrom,
        .dump_uefi_rt = false,
        .dump_acpi = o->acpi,
        .dump_spi = o->spi,
        .dry_run = false,
        .verbose = o->verbose
    };

    dump_session_t session;
    int ret = dump_session(&opts, &session);
    if (o->json) {
        print_dump_session_json(&session);
    } else {
        dump_print_session(&session);
    }

    dump_cleanup();
    return ret == FG_SUCCESS ? FG_SUCCESS : FG_ERROR;
}
