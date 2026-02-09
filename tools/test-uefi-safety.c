/*
 * FirmwareGuard - UEFI Safety Tests
 * Tests HAP platform validation and Secure Boot detection
 *
 * Designed to run in a podman container or VM where /sys/firmware/efi
 * may not exist. Tests gracefully handle missing UEFI subsystem.
 *
 * Build:
 *   gcc -Wall -Wextra -O2 -std=gnu11 -Iinclude -D_GNU_SOURCE \
 *       -o build/test-uefi-safety tools/test-uefi-safety.c \
 *       src/uefi/uefi_vars.c src/safety/safety.c -lcrypto -lm
 *
 * Run:
 *   ./build/test-uefi-safety
 */

#include "../src/uefi/uefi_vars.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* ANSI color codes */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"

static int tests_passed = 0;
static int tests_failed = 0;

static void test_result(const char *test_name, int passed)
{
    if (passed) {
        printf("%s[PASS]%s %s\n", COLOR_GREEN, COLOR_RESET, test_name);
        tests_passed++;
    } else {
        printf("%s[FAIL]%s %s\n", COLOR_RED, COLOR_RESET, test_name);
        tests_failed++;
    }
}

static void test_info(const char *test_name, const char *info)
{
    printf("%s[INFO]%s %s: %s\n", COLOR_YELLOW, COLOR_RESET, test_name, info);
}

/* ============================================================
 * Helper: Parse cpuinfo from a file path (test-only)
 *
 * Mirrors the logic in uefi_check_hap_platform_support() so we
 * can test parsing with mock files without touching /proc/cpuinfo.
 * ============================================================ */
typedef struct {
    char vendor[64];
    int cpu_family;
    int cpu_model;
    bool parsed;
} cpuinfo_result_t;

static cpuinfo_result_t parse_cpuinfo_file(const char *path)
{
    cpuinfo_result_t result = { .vendor = {0}, .cpu_family = -1,
                                .cpu_model = -1, .parsed = false };
    FILE *fp;
    char line[256];

    fp = fopen(path, "r");
    if (!fp) return result;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "vendor_id", 9) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                colon++;
                while (*colon == ' ' || *colon == '\t') colon++;
                char *nl = strchr(colon, '\n');
                if (nl) *nl = '\0';
                strncpy(result.vendor, colon, sizeof(result.vendor) - 1);
            }
        } else if (strncmp(line, "cpu family", 10) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                result.cpu_family = atoi(colon + 1);
            }
        } else if (strncmp(line, "model\t", 6) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                result.cpu_model = atoi(colon + 1);
            }
        }

        if (result.vendor[0] && result.cpu_family >= 0 && result.cpu_model >= 0)
            break;
    }

    fclose(fp);

    result.parsed = (result.vendor[0] && result.cpu_family >= 0 &&
                     result.cpu_model >= 0);
    return result;
}

/* Check if parsed cpuinfo would pass HAP validation */
static bool would_pass_hap_check(const cpuinfo_result_t *info)
{
    if (!info->parsed) return false;
    if (strcmp(info->vendor, "GenuineIntel") != 0) return false;
    if (info->cpu_family != 6) return false;
    if (info->cpu_model < 0x4E) return false;
    return true;
}

/* Helper: Write a mock cpuinfo file */
static int write_mock_cpuinfo(const char *path, const char *vendor,
                               int family, int model,
                               const char *model_name)
{
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;

    fprintf(fp, "processor\t: 0\n");
    fprintf(fp, "vendor_id\t: %s\n", vendor);
    fprintf(fp, "cpu family\t: %d\n", family);
    fprintf(fp, "model\t\t: %d\n", model);
    fprintf(fp, "model name\t: %s\n", model_name);
    fprintf(fp, "stepping\t: 2\n");
    fprintf(fp, "cpu MHz\t\t: 2400.000\n");
    fprintf(fp, "cache size\t: 12288 KB\n");
    fprintf(fp, "bogomips\t: 4800.00\n");
    fprintf(fp, "\n");

    fclose(fp);
    return 0;
}

/* ============================================================
 * Test: Mock cpuinfo - Intel Skylake (model 0x4E = 78)
 * ============================================================ */
static void test_mock_skylake(void)
{
    printf("\n%s=== Test: Mock cpuinfo - Intel Skylake ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    const char *path = "/tmp/fg_test_cpuinfo_skylake";
    write_mock_cpuinfo(path, "GenuineIntel", 6, 0x4E,
                       "Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz");

    cpuinfo_result_t info = parse_cpuinfo_file(path);
    test_result("Skylake cpuinfo parsed successfully", info.parsed);
    test_result("Vendor is GenuineIntel",
                strcmp(info.vendor, "GenuineIntel") == 0);
    test_result("Family is 6", info.cpu_family == 6);
    test_result("Model is 0x4E (78)", info.cpu_model == 0x4E);
    test_result("Skylake passes HAP check", would_pass_hap_check(&info));

    unlink(path);
}

/* ============================================================
 * Test: Mock cpuinfo - Intel Alder Lake (model 0x97 = 151)
 * ============================================================ */
static void test_mock_alderlake(void)
{
    printf("\n%s=== Test: Mock cpuinfo - Intel Alder Lake ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    const char *path = "/tmp/fg_test_cpuinfo_alderlake";
    write_mock_cpuinfo(path, "GenuineIntel", 6, 0x97,
                       "12th Gen Intel(R) Core(TM) i7-12700K");

    cpuinfo_result_t info = parse_cpuinfo_file(path);
    test_result("Alder Lake cpuinfo parsed", info.parsed);
    test_result("Model is 0x97 (151)", info.cpu_model == 0x97);
    test_result("Alder Lake passes HAP check", would_pass_hap_check(&info));

    unlink(path);
}

/* ============================================================
 * Test: Mock cpuinfo - Intel Raptor Lake (model 0xB7 = 183)
 * ============================================================ */
static void test_mock_raptorlake(void)
{
    printf("\n%s=== Test: Mock cpuinfo - Intel Raptor Lake ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    const char *path = "/tmp/fg_test_cpuinfo_raptorlake";
    write_mock_cpuinfo(path, "GenuineIntel", 6, 0xB7,
                       "13th Gen Intel(R) Core(TM) i7-13700K");

    cpuinfo_result_t info = parse_cpuinfo_file(path);
    test_result("Raptor Lake cpuinfo parsed", info.parsed);
    test_result("Model is 0xB7 (183)", info.cpu_model == 0xB7);
    test_result("Raptor Lake passes HAP check", would_pass_hap_check(&info));

    unlink(path);
}

/* ============================================================
 * Test: Mock cpuinfo - Intel Haswell (model 0x3C = 60) - TOO OLD
 * ============================================================ */
static void test_mock_haswell(void)
{
    printf("\n%s=== Test: Mock cpuinfo - Intel Haswell (Pre-Skylake) ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    const char *path = "/tmp/fg_test_cpuinfo_haswell";
    write_mock_cpuinfo(path, "GenuineIntel", 6, 0x3C,
                       "Intel(R) Core(TM) i7-4770 CPU @ 3.40GHz");

    cpuinfo_result_t info = parse_cpuinfo_file(path);
    test_result("Haswell cpuinfo parsed", info.parsed);
    test_result("Model is 0x3C (60)", info.cpu_model == 0x3C);
    test_result("Haswell REJECTED by HAP check (pre-Skylake)",
                !would_pass_hap_check(&info));

    unlink(path);
}

/* ============================================================
 * Test: Mock cpuinfo - Intel Broadwell (model 0x3D = 61) - TOO OLD
 * ============================================================ */
static void test_mock_broadwell(void)
{
    printf("\n%s=== Test: Mock cpuinfo - Intel Broadwell (Pre-Skylake) ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    const char *path = "/tmp/fg_test_cpuinfo_broadwell";
    write_mock_cpuinfo(path, "GenuineIntel", 6, 0x3D,
                       "Intel(R) Core(TM) i7-5775C CPU @ 3.30GHz");

    cpuinfo_result_t info = parse_cpuinfo_file(path);
    test_result("Broadwell cpuinfo parsed", info.parsed);
    test_result("Broadwell REJECTED by HAP check (model 0x3D < 0x4E)",
                !would_pass_hap_check(&info));

    unlink(path);
}

/* ============================================================
 * Test: Mock cpuinfo - AMD Ryzen (wrong vendor)
 * ============================================================ */
static void test_mock_amd(void)
{
    printf("\n%s=== Test: Mock cpuinfo - AMD Ryzen (Non-Intel) ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    const char *path = "/tmp/fg_test_cpuinfo_amd";
    write_mock_cpuinfo(path, "AuthenticAMD", 25, 33,
                       "AMD Ryzen 7 5800X 8-Core Processor");

    cpuinfo_result_t info = parse_cpuinfo_file(path);
    test_result("AMD cpuinfo parsed", info.parsed);
    test_result("Vendor is AuthenticAMD",
                strcmp(info.vendor, "AuthenticAMD") == 0);
    test_result("AMD REJECTED by HAP check (Intel-only)",
                !would_pass_hap_check(&info));

    unlink(path);
}

/* ============================================================
 * Test: Mock cpuinfo - Intel but wrong family
 * ============================================================ */
static void test_mock_wrong_family(void)
{
    printf("\n%s=== Test: Mock cpuinfo - Intel Family 15 (Netburst) ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    const char *path = "/tmp/fg_test_cpuinfo_netburst";
    write_mock_cpuinfo(path, "GenuineIntel", 15, 4,
                       "Intel(R) Pentium(R) 4 CPU 3.00GHz");

    cpuinfo_result_t info = parse_cpuinfo_file(path);
    test_result("Netburst cpuinfo parsed", info.parsed);
    test_result("Family is 15", info.cpu_family == 15);
    test_result("Netburst REJECTED by HAP check (family != 6)",
                !would_pass_hap_check(&info));

    unlink(path);
}

/* ============================================================
 * Test: Edge case - empty cpuinfo file
 * ============================================================ */
static void test_mock_empty(void)
{
    printf("\n%s=== Test: Edge Case - Empty cpuinfo ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    const char *path = "/tmp/fg_test_cpuinfo_empty";
    FILE *fp = fopen(path, "w");
    if (fp) fclose(fp);

    cpuinfo_result_t info = parse_cpuinfo_file(path);
    test_result("Empty cpuinfo fails to parse", !info.parsed);
    test_result("Empty cpuinfo REJECTED by HAP check",
                !would_pass_hap_check(&info));

    unlink(path);
}

/* ============================================================
 * Test: Edge case - missing model field
 * ============================================================ */
static void test_mock_missing_model(void)
{
    printf("\n%s=== Test: Edge Case - Missing model field ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    const char *path = "/tmp/fg_test_cpuinfo_nomodel";
    FILE *fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "processor\t: 0\n");
        fprintf(fp, "vendor_id\t: GenuineIntel\n");
        fprintf(fp, "cpu family\t: 6\n");
        /* model line intentionally omitted */
        fprintf(fp, "model name\t: Intel Something\n");
        fprintf(fp, "\n");
        fclose(fp);
    }

    cpuinfo_result_t info = parse_cpuinfo_file(path);
    test_result("Missing model field fails to parse fully", !info.parsed);
    test_result("Missing model REJECTED by HAP check",
                !would_pass_hap_check(&info));

    unlink(path);
}

/* ============================================================
 * Test: Edge case - non-existent cpuinfo file
 * ============================================================ */
static void test_mock_nonexistent(void)
{
    printf("\n%s=== Test: Edge Case - Non-existent file ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    cpuinfo_result_t info = parse_cpuinfo_file("/tmp/fg_this_file_does_not_exist");
    test_result("Non-existent file fails to parse", !info.parsed);
    test_result("Non-existent file REJECTED by HAP check",
                !would_pass_hap_check(&info));
}

/* ============================================================
 * Test: Edge case - model boundary (0x4D = 77, just below threshold)
 * ============================================================ */
static void test_mock_boundary_below(void)
{
    printf("\n%s=== Test: Edge Case - Model 0x4D (One Below Threshold) ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    const char *path = "/tmp/fg_test_cpuinfo_boundary";
    write_mock_cpuinfo(path, "GenuineIntel", 6, 0x4D,
                       "Intel Boundary Test CPU");

    cpuinfo_result_t info = parse_cpuinfo_file(path);
    test_result("Model 0x4D parsed", info.parsed);
    test_result("Model 0x4D REJECTED (just below 0x4E threshold)",
                !would_pass_hap_check(&info));

    unlink(path);
}

/* ============================================================
 * Test: Edge case - model boundary (0x4E = 78, exactly at threshold)
 * ============================================================ */
static void test_mock_boundary_exact(void)
{
    printf("\n%s=== Test: Edge Case - Model 0x4E (Exact Threshold) ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    const char *path = "/tmp/fg_test_cpuinfo_exact";
    write_mock_cpuinfo(path, "GenuineIntel", 6, 0x4E,
                       "Intel Skylake-U");

    cpuinfo_result_t info = parse_cpuinfo_file(path);
    test_result("Model 0x4E parsed", info.parsed);
    test_result("Model 0x4E ACCEPTED (exact Skylake threshold)",
                would_pass_hap_check(&info));

    unlink(path);
}

/* ============================================================
 * Test: Real /proc/cpuinfo on this system
 * ============================================================ */
static void test_real_cpuinfo(void)
{
    printf("\n%s=== Test: Real /proc/cpuinfo (Informational) ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    struct stat st;
    if (stat("/proc/cpuinfo", &st) != 0) {
        test_info("Real cpuinfo", "/proc/cpuinfo not available (expected in some containers)");
        return;
    }

    cpuinfo_result_t info = parse_cpuinfo_file("/proc/cpuinfo");
    test_result("Real /proc/cpuinfo parsed", info.parsed);

    if (info.parsed) {
        char detail[128];
        snprintf(detail, sizeof(detail), "vendor=%s family=%d model=0x%02X (%d)",
                 info.vendor, info.cpu_family, info.cpu_model, info.cpu_model);
        test_info("Detected CPU", detail);

        bool hap_ok = would_pass_hap_check(&info);
        test_info("HAP support", hap_ok ? "YES (Skylake or newer Intel)" : "NO");
    }

    /* Also call the real function to verify it doesn't crash */
    bool real_result = uefi_check_hap_platform_support();
    test_result("uefi_check_hap_platform_support() runs without crash", 1);
    test_info("Real HAP check result", real_result ? "supported" : "not supported");
}

/* ============================================================
 * Test: Secure Boot detection in container
 * ============================================================ */
static void test_secureboot_container(void)
{
    printf("\n%s=== Test: Secure Boot Detection (Container/VM) ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    struct stat st;
    bool has_efi = (stat("/sys/firmware/efi", &st) == 0);

    if (!has_efi) {
        test_info("UEFI subsystem", "Not available (/sys/firmware/efi missing)");
        test_info("Expected", "Normal for containers without UEFI passthrough");

        /* These should return safe defaults (false) when UEFI not present */
        bool sb = uefi_is_secure_boot_enabled();
        test_result("Secure Boot returns false when UEFI unavailable", !sb);

        bool can_modify = uefi_can_modify_vars_with_secureboot();
        test_result("can_modify_vars returns false when UEFI unavailable", !can_modify);

        bool hap = uefi_is_me_hap_available();
        test_result("HAP available returns false when UEFI unavailable", !hap);
    } else {
        test_info("UEFI subsystem", "Available");

        /* Read actual state */
        bool sb = uefi_is_secure_boot_enabled();
        test_info("Secure Boot", sb ? "ENABLED" : "disabled or not found");
        test_result("uefi_is_secure_boot_enabled() runs without crash", 1);

        bool enabled, setup_mode;
        int ret = uefi_get_secure_boot_state(&enabled, &setup_mode);
        if (ret == FG_SUCCESS) {
            char buf[64];
            snprintf(buf, sizeof(buf), "enabled=%d setup_mode=%d", enabled, setup_mode);
            test_info("Secure Boot state", buf);
        } else {
            test_info("Secure Boot state", "not found (may be legacy BIOS)");
        }

        bool can_modify = uefi_can_modify_vars_with_secureboot();
        test_info("Can modify vars", can_modify ? "yes" : "no (SB blocking)");
        test_result("uefi_can_modify_vars_with_secureboot() runs without crash", 1);
    }
}

/* ============================================================
 * Test: HAP set function rejects when safety context is NULL
 * ============================================================ */
static void test_hap_set_null_safety(void)
{
    printf("\n%s=== Test: HAP Set Rejects NULL Safety Context ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    int ret = uefi_set_me_hap_bit(NULL, true);
    test_result("uefi_set_me_hap_bit(NULL, true) returns FG_ERROR",
                ret == FG_ERROR);

    ret = uefi_set_me_hap_bit(NULL, false);
    test_result("uefi_set_me_hap_bit(NULL, false) returns FG_ERROR",
                ret == FG_ERROR);
}

/* ============================================================
 * Test: Secure Boot state function rejects NULL params
 * ============================================================ */
static void test_secureboot_null_params(void)
{
    printf("\n%s=== Test: Secure Boot State NULL Params ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    bool dummy;
    int ret;

    ret = uefi_get_secure_boot_state(NULL, &dummy);
    test_result("NULL enabled param returns FG_ERROR", ret == FG_ERROR);

    ret = uefi_get_secure_boot_state(&dummy, NULL);
    test_result("NULL setup_mode param returns FG_ERROR", ret == FG_ERROR);

    ret = uefi_get_secure_boot_state(NULL, NULL);
    test_result("Both NULL params returns FG_ERROR", ret == FG_ERROR);
}

/* ============================================================
 * Test: Delete variable rejects invalid names
 * ============================================================ */
static void test_delete_var_validation(void)
{
    printf("\n%s=== Test: Delete Variable Input Validation ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    safety_context_t ctx;
    safety_init(&ctx, SAFETY_MODE_DRY_RUN);
    int ret;

    /* NULL name */
    ret = uefi_delete_variable(&ctx, NULL, EFI_GLOBAL_VARIABLE_GUID);
    test_result("NULL name rejected", ret == FG_ERROR);

    /* NULL guid */
    ret = uefi_delete_variable(&ctx, "TestVar", NULL);
    test_result("NULL guid rejected", ret == FG_ERROR);

    /* Path traversal in name */
    ret = uefi_delete_variable(&ctx, "../../../etc/shadow", EFI_GLOBAL_VARIABLE_GUID);
    test_result("Path traversal in name rejected", ret == FG_ERROR);

    /* Path traversal in GUID */
    ret = uefi_delete_variable(&ctx, "TestVar", "../../etc/shadow");
    test_result("Path traversal in GUID rejected", ret == FG_ERROR);

    /* Backslash in name */
    ret = uefi_delete_variable(&ctx, "Test\\Var", EFI_GLOBAL_VARIABLE_GUID);
    test_result("Backslash in name rejected", ret == FG_ERROR);

    safety_cleanup(&ctx);
}

/* ============================================================
 * Test: Write variable rejects invalid names
 * ============================================================ */
static void test_write_var_validation(void)
{
    printf("\n%s=== Test: Write Variable Input Validation ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    uint8_t data = 0x42;

    /* NULL params */
    int ret = uefi_write_variable(NULL, NULL, NULL, 0, &data, 1);
    test_result("All NULL params rejected", ret == FG_ERROR);

    ret = uefi_write_variable(NULL, "Test", EFI_GLOBAL_VARIABLE_GUID, 0, NULL, 1);
    test_result("NULL data rejected", ret == FG_ERROR);

    ret = uefi_write_variable(NULL, "Test", EFI_GLOBAL_VARIABLE_GUID, 0, &data, 0);
    test_result("Zero size rejected", ret == FG_ERROR);

    /* Path traversal */
    ret = uefi_write_variable(NULL, "../etc/shadow", EFI_GLOBAL_VARIABLE_GUID, 0, &data, 1);
    test_result("Path traversal rejected", ret == FG_ERROR);
}

/* ============================================================
 * Test: Delete blocked by Secure Boot check (new code path)
 *
 * In a container without UEFI, uefi_can_modify_vars_with_secureboot()
 * returns false (can't determine SB state → fail-safe).
 * On a host with UEFI but SB unknown, same result.
 * This verifies the NEW Secure Boot gate in uefi_delete_variable().
 * ============================================================ */
static void test_delete_blocked_by_secureboot(void)
{
    printf("\n%s=== Test: Delete Blocked by Secure Boot Gate ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    safety_context_t ctx;
    safety_init(&ctx, SAFETY_MODE_CONFIRM);

    bool can_modify = uefi_can_modify_vars_with_secureboot();

    if (!can_modify) {
        /* SB state unknown or enabled — delete should be blocked with FG_NO_PERMISSION */
        int ret = uefi_delete_variable(&ctx, "TestVar",
                                        EFI_GLOBAL_VARIABLE_GUID);
        test_result("Delete blocked by Secure Boot gate (FG_NO_PERMISSION)",
                    ret == FG_NO_PERMISSION);
        test_info("Why blocked", "Secure Boot state unknown or enabled");
    } else {
        /* SB disabled or in setup mode — delete would proceed past SB check
         * but fail later (variable doesn't exist). That's fine. */
        test_info("Secure Boot", "disabled — delete would pass SB gate (skipping)");
        test_result("can_modify_vars is true (SB disabled)", can_modify);
    }

    safety_cleanup(&ctx);
}

/* ============================================================
 * Test: HAP set with valid safety context — platform/SB gates
 *
 * Tests the full uefi_set_me_hap_bit() code path with a real
 * safety context. Expected outcomes:
 *   - Non-Intel / pre-Skylake: FG_NOT_SUPPORTED (platform check)
 *   - Intel Skylake+ w/ SB enabled: FG_NO_PERMISSION (SB check)
 *   - Intel Skylake+ w/o SB: FG_NOT_SUPPORTED (ME var missing)
 * ============================================================ */
static void test_hap_set_with_safety_context(void)
{
    printf("\n%s=== Test: HAP Set with Valid Safety Context ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    safety_context_t ctx;
    /* Use AUTO mode to skip interactive confirmation prompt */
    safety_init(&ctx, SAFETY_MODE_AUTO);

    bool platform_ok = uefi_check_hap_platform_support();

    int ret = uefi_set_me_hap_bit(&ctx, true);

    if (!platform_ok) {
        test_result("HAP set returns FG_NOT_SUPPORTED on unsupported platform",
                    ret == FG_NOT_SUPPORTED);
    } else {
        /* Platform passes — next gate is Secure Boot */
        bool sb = uefi_is_secure_boot_enabled();
        if (sb) {
            test_result("HAP set returns FG_NO_PERMISSION (Secure Boot on)",
                        ret == FG_NO_PERMISSION);
        } else {
            /* Platform OK, SB off — will try to read ME variable and fail */
            test_result("HAP set returns FG_NOT_SUPPORTED (ME var missing)",
                        ret == FG_NOT_SUPPORTED);
            test_info("Why", "Platform supported but MeSetup UEFI var not found");
        }
    }

    safety_cleanup(&ctx);
}

/* ============================================================
 * Test: uefi_is_me_hap_available() with platform gate
 *
 * The function now checks platform support first, before
 * trying to read ME variables. This test verifies that gate.
 * ============================================================ */
static void test_hap_available_platform_gate(void)
{
    printf("\n%s=== Test: HAP Available Platform Gate ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    bool platform_ok = uefi_check_hap_platform_support();
    bool hap_avail = uefi_is_me_hap_available();

    if (!platform_ok) {
        test_result("HAP not available on unsupported platform", !hap_avail);
    } else {
        /* Platform supported — result depends on whether ME var exists */
        test_result("uefi_is_me_hap_available() runs without crash", 1);
        test_info("HAP available", hap_avail ? "yes (ME var found)" :
                  "no (ME var not found, but platform OK)");
    }
}

/* ============================================================
 * Test: Write variable blocked by Secure Boot gate
 * ============================================================ */
static void test_write_blocked_by_secureboot(void)
{
    printf("\n%s=== Test: Write Blocked by Secure Boot Gate ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    safety_context_t ctx;
    safety_init(&ctx, SAFETY_MODE_CONFIRM);

    bool can_modify = uefi_can_modify_vars_with_secureboot();
    uint8_t data = 0x42;

    if (!can_modify) {
        int ret = uefi_write_variable(&ctx, "TestVar",
                                       EFI_GLOBAL_VARIABLE_GUID,
                                       EFI_VARIABLE_NON_VOLATILE, &data, 1);
        test_result("Write blocked by Secure Boot gate (FG_NO_PERMISSION)",
                    ret == FG_NO_PERMISSION);
    } else {
        test_info("Secure Boot", "disabled — write would pass SB gate (skipping)");
        test_result("can_modify_vars is true (SB disabled)", can_modify);
    }

    safety_cleanup(&ctx);
}

/* ============================================================
 * Main test runner
 * ============================================================ */
int main(void)
{
    printf("\n");
    printf("========================================\n");
    printf("  FirmwareGuard UEFI Safety Tests\n");
    printf("  (HAP Platform + Secure Boot)\n");
    printf("========================================\n");

    /* Mock cpuinfo parsing tests (portable, no real hardware needed) */
    test_mock_skylake();
    test_mock_alderlake();
    test_mock_raptorlake();
    test_mock_haswell();
    test_mock_broadwell();
    test_mock_amd();
    test_mock_wrong_family();
    test_mock_empty();
    test_mock_missing_model();
    test_mock_nonexistent();
    test_mock_boundary_below();
    test_mock_boundary_exact();

    /* Real system tests (informational in container) */
    test_real_cpuinfo();
    test_secureboot_container();

    /* New code path tests (Secure Boot gates + HAP platform gates) */
    test_delete_blocked_by_secureboot();
    test_write_blocked_by_secureboot();
    test_hap_set_with_safety_context();
    test_hap_available_platform_gate();

    /* Function-level edge cases */
    test_hap_set_null_safety();
    test_secureboot_null_params();
    test_delete_var_validation();
    test_write_var_validation();

    printf("\n");
    printf("========================================\n");
    printf("  Test Summary\n");
    printf("========================================\n");
    printf("  Tests Passed: %s%d%s\n", COLOR_GREEN, tests_passed, COLOR_RESET);
    printf("  Tests Failed: %s%d%s\n",
           tests_failed > 0 ? COLOR_RED : COLOR_GREEN,
           tests_failed, COLOR_RESET);
    printf("  Total Tests:  %d\n", tests_passed + tests_failed);
    printf("========================================\n\n");

    return (tests_failed == 0) ? 0 : 1;
}
