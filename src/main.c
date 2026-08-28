/*
 * FirmwareGuard - CLI entry point
 *
 * Thin shell: parse global options, then dispatch to a handler looked up in
 * the command table (src/cli/). All command logic lives in src/cli/cli_*.c.
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include "cli/cli.h"

int main(int argc, char **argv) {
    int opt;
    bool json_output = false;
    bool html_output = false;
    bool sarif_output = false;
    bool verbose = false;
    bool brief = false;
    bool history = false;
    bool apply = false;
    bool yes = false;
    bool dangerous = false;
    bool rollback = false;
    bool list_backups = false;
    bool iommu = false;
    bool wol = false;
    bool no_wol = false;
    bool amt = false;
    bool acpi = false;
    bool optionrom = false;
    bool spi = false;
    bool smram = false;
    const char *output_file = NULL;
    const char *command = NULL;

    enum {
        OPT_HTML = 1000,
        OPT_SARIF,
        OPT_HISTORY,
        OPT_APPLY,
        OPT_YES,
        OPT_DANGEROUS,
        OPT_ROLLBACK,
        OPT_LIST_BACKUPS,
        OPT_IOMMU,
        OPT_WOL,
        OPT_NO_WOL,
        OPT_AMT,
        OPT_ACPI,
        OPT_OPTIONROM,
        OPT_SPI,
        OPT_SMRAM
    };

    static struct option long_options[] = {
        {"json",    no_argument,       0, 'j'},
        {"html",    no_argument,       0, OPT_HTML},
        {"sarif",   no_argument,       0, OPT_SARIF},
        {"history", no_argument,       0, OPT_HISTORY},
        {"apply",   no_argument,       0, OPT_APPLY},
        {"yes",     no_argument,       0, OPT_YES},
        {"dangerous", no_argument,     0, OPT_DANGEROUS},
        {"rollback", no_argument,      0, OPT_ROLLBACK},
        {"list-backups", no_argument,  0, OPT_LIST_BACKUPS},
        {"iommu",   no_argument,       0, OPT_IOMMU},
        {"wol",     no_argument,       0, OPT_WOL},
        {"no-wol",  no_argument,       0, OPT_NO_WOL},
        {"amt",     no_argument,       0, OPT_AMT},
        {"acpi",    no_argument,       0, OPT_ACPI},
        {"optionrom", no_argument,     0, OPT_OPTIONROM},
        {"spi",     no_argument,       0, OPT_SPI},
        {"smram",   no_argument,       0, OPT_SMRAM},
        {"output",  required_argument, 0, 'o'},
        {"verbose", no_argument,       0, 'v'},
        {"brief",   no_argument,       0, 'b'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    /* Parse command first */
    if (argc < 2) {
        cli_print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        cli_print_usage(argv[0]);
        return 0;
    }

    command = argv[1];

    /* Parse options */
    optind = 2;  /* Start parsing after command */
    while ((opt = getopt_long(argc, argv, "jvbo:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'j':
                json_output = true;
                break;
            case OPT_HTML:
                html_output = true;
                break;
            case OPT_SARIF:
                sarif_output = true;
                break;
            case OPT_HISTORY:
                history = true;
                break;
            case OPT_APPLY:
                apply = true;
                break;
            case OPT_YES:
                yes = true;
                break;
            case OPT_DANGEROUS:
                dangerous = true;
                break;
            case OPT_ROLLBACK:
                rollback = true;
                break;
            case OPT_LIST_BACKUPS:
                list_backups = true;
                break;
            case OPT_IOMMU:
                iommu = true;
                break;
            case OPT_WOL:
                wol = true;
                break;
            case OPT_NO_WOL:
                no_wol = true;
                break;
            case OPT_AMT:
                amt = true;
                break;
            case OPT_ACPI:
                acpi = true;
                break;
            case OPT_OPTIONROM:
                optionrom = true;
                break;
            case OPT_SPI:
                spi = true;
                break;
            case OPT_SMRAM:
                smram = true;
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
                cli_print_usage(argv[0]);
                return 0;
            default:
                cli_print_usage(argv[0]);
                return 1;
        }
    }

    /* Resolve report format for reporter-based commands (scan/block/report).
     * Precedence: HTML > JSON > text. SARIF is handled out-of-band. */
    report_format_t report_fmt = html_output ? REPORT_FORMAT_HTML :
                                 json_output ? REPORT_FORMAT_JSON : REPORT_FORMAT_TEXT;

    cli_opts_t opts = {
        .json = json_output,
        .html = html_output,
        .sarif = sarif_output,
        .verbose = verbose,
        .brief = brief,
        .history = history,
        .apply = apply,
        .yes = yes,
        .dangerous = dangerous,
        .rollback = rollback,
        .list_backups = list_backups,
        .iommu = iommu,
        .wol = wol,
        .no_wol = no_wol,
        .amt = amt,
        .acpi = acpi,
        .optionrom = optionrom,
        .spi = spi,
        .smram = smram,
        .output_file = output_file,
        .report_fmt = report_fmt,
    };

    const cli_command_t *cmd = cli_find_command(command);
    if (!cmd) {
        FG_LOG_ERROR("Unknown command: %s", command);
        cli_print_usage(argv[0]);
        return 1;
    }

    /* Pass the positional arguments that follow the command + options. */
    return cmd->fn(argc - optind, argv + optind, &opts);
}
