#include "firmwareguard.h"
#include "arm/arm_detect.h"
#include <assert.h>

static int test_x86_only(void) {
    FG_REQUIRE_X86();
    return FG_SUCCESS;
}

static void test_detect_arch(void) {
    fg_arch_t a = fg_detect_arch();
    assert(a != FG_ARCH_UNKNOWN);
    printf("[ok] fg_detect_arch -> %s\n", fg_arch_name(a));
}

static void test_arch_names(void) {
    const fg_arch_t all[] = {
        FG_ARCH_UNKNOWN, FG_ARCH_X86, FG_ARCH_X86_64,
        FG_ARCH_ARM, FG_ARCH_AARCH64
    };
    for (size_t i = 0; i < sizeof(all)/sizeof(all[0]); ++i) {
        const char *n = fg_arch_name(all[i]);
        assert(n != NULL);
        assert(n[0] != '\0');
    }
    printf("[ok] fg_arch_name non-null for all enum values\n");
}

static void test_is_x86_family(void) {
    fg_arch_t a = fg_detect_arch();
    bool is_x86 = fg_arch_is_x86_family(a);
#if defined(__x86_64__) || defined(__i386__)
    assert(is_x86);
#else
    assert(!is_x86);
#endif
    printf("[ok] fg_arch_is_x86_family matches host (%s)\n",
           is_x86 ? "x86" : "non-x86");
}

static void test_require_x86_gate(void) {
    int rc = test_x86_only();
#if defined(__x86_64__) || defined(__i386__)
    /* Host-run limitation: on x86 the gate passes through. The off-x86 branch
     * is the real negative assertion and fires when cross-built on aarch64. */
    assert(rc == FG_SUCCESS);
    printf("[ok] FG_REQUIRE_X86 passes on x86 host (rc=%d)\n", rc);
#else
    assert(rc == FG_NOT_SUPPORTED);
    printf("[ok] FG_REQUIRE_X86 returns FG_NOT_SUPPORTED off-x86\n");
#endif
}

static void test_arm_detect_run(void) {
    arm_detect_result_t r;
    int rc = arm_detect_run(&r);
    assert(rc == FG_SUCCESS);
    assert(r.kernel_release[0] != '\0');
#if defined(__x86_64__) || defined(__i386__)
    /* On an x86 host the ARM-only surfaces must all report absent; any true
     * here means the detector is producing bogus positives. */
    assert(!r.devicetree_present);
    assert(!r.tee_present);
    assert(!r.optee_present);
    assert(!r.secure_monitor_hint);
#endif
    printf("[ok] arm_detect_run success, kernel=%s\n", r.kernel_release);
}

static void test_arm_detect_json(void) {
    arm_detect_result_t r;
    memset(&r, 0, sizeof(r));
    /* Inject a hostile firmware string to confirm the JSON encoder escapes it. */
    snprintf(r.kernel_release, sizeof(r.kernel_release), "k\"ernel");
    snprintf(r.machine_model,  sizeof(r.machine_model),  "evil\\\"model\nline2");
    char buf[1024];
    int rc = arm_detect_to_json(&r, buf, sizeof(buf));
    assert(rc == FG_SUCCESS);
    /* No raw unescaped quote may appear inside the value payload. */
    assert(strstr(buf, "k\"ernel") == NULL);
    assert(strstr(buf, "evil\\\"model\nline2") == NULL);
    /* Escaped forms must be present. */
    assert(strstr(buf, "k\\\"ernel") != NULL);
    printf("[ok] arm_detect_to_json escapes firmware-controlled strings\n");
}

int main(void) {
    printf("test_arch: host=%s\n", fg_arch_name(fg_detect_arch()));
    test_detect_arch();
    test_arch_names();
    test_is_x86_family();
    test_require_x86_gate();
    test_arm_detect_run();
    test_arm_detect_json();
    printf("All arch tests passed.\n");
    return 0;
}
