/*
 * FirmwareGuard CLI - ARM build helpers
 *
 * cmd_not_applicable backs every x86-only command name in the ARM build so
 * invoking one prints a clean message instead of "unknown command".
 * cmd_arm_detect exposes the ARM firmware-surface detector as a CLI command
 * (only compiled into the ARM build).
 */

#include <stdio.h>

#include "cli.h"

#ifdef FG_BUILD_ARM
#include "../arm/arm_detect.h"
#endif

int cmd_not_applicable(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv; (void)o;
    fprintf(stderr,
            "[ERROR] This command requires an x86/x86_64 platform and is not "
            "available in the ARM build of FirmwareGuard.\n");
    return FG_NOT_SUPPORTED;
}

#ifdef FG_BUILD_ARM
int cmd_arm_detect(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;

    arm_detect_result_t r;
    if (arm_detect_run(&r) != FG_SUCCESS) {
        FG_LOG_ERROR("ARM firmware-surface detection failed");
        return FG_ERROR;
    }

    if (o->json) {
        char buf[4096];
        if (arm_detect_to_json(&r, buf, sizeof(buf)) == FG_SUCCESS) {
            printf("%s\n", buf);
        }
    } else {
        arm_detect_print(&r, o->verbose);
    }
    return FG_SUCCESS;
}
#endif /* FG_BUILD_ARM */
