/*
 * FirmwareGuard - CLI dispatch layer
 *
 * Table-driven command dispatch. Each command is a cmd_fn that receives the
 * positional arguments remaining after global option parsing, plus a parsed
 * cli_opts_t carrying the global flags. main.c stays a thin parse+dispatch shell.
 */

#ifndef FG_CLI_H
#define FG_CLI_H

#include <stdbool.h>
#include <stddef.h>

#include "../../include/firmwareguard.h"
#include "../audit/reporter.h"   /* report_format_t */

/* Parsed global options, shared by every command handler. */
typedef struct {
    bool json;             /* -j/--json */
    bool html;             /* --html */
    bool sarif;            /* --sarif */
    bool verbose;          /* -v/--verbose */
    bool brief;            /* -b/--brief */
    bool history;          /* --history */
    const char *output_file; /* -o/--output (also baseline file / history dir) */
    report_format_t report_fmt; /* resolved scan/block report format */
} cli_opts_t;

/*
 * Command handler. argc/argv are the POSITIONAL arguments that follow the
 * command name and global options (i.e. argv[0] is the first positional arg,
 * not the program name). Most legacy handlers ignore them.
 */
typedef int (*cmd_fn)(int argc, char **argv, const cli_opts_t *o);

typedef struct {
    const char *name;
    cmd_fn fn;
    const char *summary;
} cli_command_t;

extern const cli_command_t CLI_COMMANDS[];
extern const size_t CLI_COMMAND_COUNT;

/* Look up a command by name, or NULL if unknown. */
const cli_command_t *cli_find_command(const char *name);

/* Print the full usage/help text. */
void cli_print_usage(const char *prog_name);

/* ---- Handlers: scan group (cli_scan.c) ---- */
int cmd_scan(int argc, char **argv, const cli_opts_t *o);
int cmd_block(int argc, char **argv, const cli_opts_t *o);
int cmd_panic(int argc, char **argv, const cli_opts_t *o);

/* ---- Handlers: firmware group (cli_firmware.c) ---- */
int cmd_smm_scan(int argc, char **argv, const cli_opts_t *o);
int cmd_uefi_enum(int argc, char **argv, const cli_opts_t *o);
int cmd_uefi_extract(int argc, char **argv, const cli_opts_t *o);

/* ---- Handlers: trusted-boot group (cli_trustedboot.c) ---- */
int cmd_bootguard_status(int argc, char **argv, const cli_opts_t *o);
int cmd_bootguard_policy(int argc, char **argv, const cli_opts_t *o);
int cmd_secureboot_audit(int argc, char **argv, const cli_opts_t *o);
int cmd_txt_audit(int argc, char **argv, const cli_opts_t *o);
int cmd_sgx_enum(int argc, char **argv, const cli_opts_t *o);
int cmd_tpm_measurements(int argc, char **argv, const cli_opts_t *o);
int cmd_trusted_boot_full(int argc, char **argv, const cli_opts_t *o);

/* ---- Handlers: baseline group (cli_baseline.c) ---- */
int cmd_baseline_capture(int argc, char **argv, const cli_opts_t *o);
int cmd_baseline_compare(int argc, char **argv, const cli_opts_t *o);
int cmd_baseline_drift(int argc, char **argv, const cli_opts_t *o);

/* ---- Handlers: detection group (cli_detect.c) ---- */
int cmd_implant_scan(int argc, char **argv, const cli_opts_t *o);
int cmd_acpi_scan(int argc, char **argv, const cli_opts_t *o);
int cmd_nic_scan(int argc, char **argv, const cli_opts_t *o);
int cmd_intel_me(int argc, char **argv, const cli_opts_t *o);
int cmd_amd_psp(int argc, char **argv, const cli_opts_t *o);
int cmd_compliance(int argc, char **argv, const cli_opts_t *o);

/* ---- Handlers: Phase-4 modules (cli_modules.c) ---- */
int cmd_cve_check(int argc, char **argv, const cli_opts_t *o);
int cmd_threat_scan(int argc, char **argv, const cli_opts_t *o);
int cmd_rootkit_scan(int argc, char **argv, const cli_opts_t *o);
int cmd_integrity_verify(int argc, char **argv, const cli_opts_t *o);
int cmd_heci_monitor(int argc, char **argv, const cli_opts_t *o);
int cmd_spi_status(int argc, char **argv, const cli_opts_t *o);

#endif /* FG_CLI_H */
