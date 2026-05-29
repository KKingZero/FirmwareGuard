#include "firmwareguard.h"
#include "arm_detect.h"
#include "arm_probe.h"

static void print_usage(const char *prog) {
    printf("FirmwareGuard ARM build %s\n", FG_VERSION);
    printf("Usage: %s <command> [options]\n", prog);
    printf("\n");
    printf("Commands:\n");
    printf("  scan             Run ARM firmware surface detection\n");
    printf("  scan --json      Emit detection result as JSON\n");
    printf("  arch             Print detected host architecture\n");
    printf("  --help, -h       Show this help\n");
}

static void print_banner(void) {
    fg_arch_t a = fg_detect_arch();
    printf("FirmwareGuard-ARM %s  [host arch: %s]\n",
           FG_VERSION, fg_arch_name(a));
    if (!fg_arch_is_x86_family(a) && a != FG_ARCH_ARM && a != FG_ARCH_AARCH64) {
        printf("  note: running on unrecognized arch; ARM detectors still execute.\n");
    }
}

static int cmd_scan(int argc, char **argv) {
    bool json = false;
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--json") == 0) json = true;
    }

    arm_detect_result_t r;
    int rc = arm_detect_run(&r);
    if (rc != FG_SUCCESS) {
        FG_LOG_ERROR("arm_detect_run failed: %d", rc);
        return 1;
    }

    if (json) {
        char buf[2048];
        if (arm_detect_to_json(&r, buf, sizeof(buf)) != FG_SUCCESS) {
            FG_LOG_ERROR("JSON serialization failed");
            return 1;
        }
        printf("%s\n", buf);
    } else {
        arm_detect_print(&r, false);
    }
    return 0;
}

static int cmd_arch(void) {
    printf("%s\n", fg_arch_name(fg_detect_arch()));
    return 0;
}

int main(int argc, char **argv) {
    /* POSIX allows exec*() with argc==0 or argv[0]==NULL; avoid UB in printf. */
    const char *prog = (argc >= 1 && argv[0] && argv[0][0]) ? argv[0] : "firmwareguard-arm";

    if (argc < 2) {
        print_banner();
        print_usage(prog);
        return 0;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_banner();
        print_usage(prog);
        return 0;
    }

    if (strcmp(argv[1], "arch") == 0) {
        return cmd_arch();
    }

    if (strcmp(argv[1], "scan") == 0) {
        print_banner();
        return cmd_scan(argc, argv);
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    print_usage(prog);
    return 2;
}
