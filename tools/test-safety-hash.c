/*
 * FirmwareGuard - Safety Hash Test Tool
 * Tests SHA-256 backup integrity (replaces old CRC32-like checksum)
 *
 * Build:
 *   gcc -Wall -Wextra -O2 -std=gnu11 -Iinclude -D_GNU_SOURCE \
 *       -o build/test-safety-hash tools/test-safety-hash.c src/safety/safety.c \
 *       -lcrypto -lm
 *
 * Run:
 *   ./build/test-safety-hash
 */

#include "../src/safety/safety.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ANSI color codes for output */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_CYAN    "\033[36m"

/* Test result tracking */
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

/* Helper: format hash as hex string */
static void hash_to_hex(const uint8_t hash[32], char hex[65])
{
    for (int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", hash[i]);
    hex[64] = '\0';
}

/* ============================================================
 * Test: Known SHA-256 test vectors (NIST FIPS 180-4)
 * ============================================================ */
static void test_known_vectors(void)
{
    printf("\n%s=== Test: Known SHA-256 Vectors ===%s\n", COLOR_CYAN, COLOR_RESET);

    uint8_t hash[32];
    char hex[65];
    int ret;

    /* SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223
     *                  b00361a3 96177a9c b410ff61 f20015ad */
    const char *input1 = "abc";
    const char *expected1 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    ret = safety_calculate_hash(input1, 3, hash);
    hash_to_hex(hash, hex);

    test_result("SHA-256(\"abc\") returns FG_SUCCESS", ret == FG_SUCCESS);
    test_result("SHA-256(\"abc\") matches NIST vector", strcmp(hex, expected1) == 0);

    if (strcmp(hex, expected1) != 0) {
        printf("  expected: %s\n", expected1);
        printf("  got:      %s\n", hex);
    }

    /* SHA-256("") - but our function rejects size==0, so test with 1 byte */
    /* SHA-256("a") = ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb */
    const char *input2 = "a";
    const char *expected2 = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";

    ret = safety_calculate_hash(input2, 1, hash);
    hash_to_hex(hash, hex);

    test_result("SHA-256(\"a\") returns FG_SUCCESS", ret == FG_SUCCESS);
    test_result("SHA-256(\"a\") matches NIST vector", strcmp(hex, expected2) == 0);

    /* SHA-256 of 1 million 'a' characters
     * = cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0 */
    char *million_a = malloc(1000000);
    if (million_a) {
        memset(million_a, 'a', 1000000);
        const char *expected3 = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

        ret = safety_calculate_hash(million_a, 1000000, hash);
        hash_to_hex(hash, hex);

        test_result("SHA-256(1M x 'a') returns FG_SUCCESS", ret == FG_SUCCESS);
        test_result("SHA-256(1M x 'a') matches NIST vector", strcmp(hex, expected3) == 0);

        free(million_a);
    } else {
        test_result("SHA-256(1M x 'a') malloc failed (skipped)", 0);
    }
}

/* ============================================================
 * Test: NULL and invalid inputs
 * ============================================================ */
static void test_null_inputs(void)
{
    printf("\n%s=== Test: NULL / Invalid Inputs ===%s\n", COLOR_CYAN, COLOR_RESET);

    uint8_t hash[32];
    int ret;

    /* NULL data */
    ret = safety_calculate_hash(NULL, 100, hash);
    test_result("NULL data returns FG_ERROR", ret == FG_ERROR);

    /* Zero size */
    ret = safety_calculate_hash("data", 0, hash);
    test_result("Zero size returns FG_ERROR", ret == FG_ERROR);

    /* NULL hash_out */
    ret = safety_calculate_hash("data", 4, NULL);
    test_result("NULL hash_out returns FG_ERROR", ret == FG_ERROR);

    /* All NULL */
    ret = safety_calculate_hash(NULL, 0, NULL);
    test_result("All NULL returns FG_ERROR", ret == FG_ERROR);
}

/* ============================================================
 * Test: Hash consistency (same input = same output)
 * ============================================================ */
static void test_consistency(void)
{
    printf("\n%s=== Test: Hash Consistency ===%s\n", COLOR_CYAN, COLOR_RESET);

    uint8_t hash1[32], hash2[32];
    const char *data = "FirmwareGuard backup data test payload";
    size_t len = strlen(data);

    safety_calculate_hash(data, len, hash1);
    safety_calculate_hash(data, len, hash2);

    test_result("Same input produces same hash", memcmp(hash1, hash2, 32) == 0);

    /* Different input produces different hash */
    uint8_t hash3[32];
    const char *data2 = "FirmwareGuard backup data test payloa!"; /* last char changed */
    safety_calculate_hash(data2, strlen(data2), hash3);

    test_result("Different input produces different hash", memcmp(hash1, hash3, 32) != 0);

    /* Single bit difference */
    char buf1[4] = {0x00, 0x00, 0x00, 0x00};
    char buf2[4] = {0x00, 0x00, 0x00, 0x01}; /* one bit changed */
    uint8_t h1[32], h2[32];

    safety_calculate_hash(buf1, 4, h1);
    safety_calculate_hash(buf2, 4, h2);

    test_result("Single bit change produces different hash", memcmp(h1, h2, 32) != 0);
}

/* ============================================================
 * Test: backup_entry_t struct layout
 * ============================================================ */
static void test_struct_layout(void)
{
    printf("\n%s=== Test: Struct Layout ===%s\n", COLOR_CYAN, COLOR_RESET);

    backup_entry_t entry;
    memset(&entry, 0, sizeof(entry));

    /* Verify checksum field is 32 bytes */
    test_result("backup_entry_t.checksum is 32 bytes",
                sizeof(entry.checksum) == 32);

    /* Verify checksum_version field exists and is 1 byte */
    test_result("backup_entry_t.checksum_version is 1 byte",
                sizeof(entry.checksum_version) == 1);

    /* Verify full struct compiles and is reasonable size */
    test_result("backup_entry_t size > 0", sizeof(backup_entry_t) > 0);

    printf("  sizeof(backup_entry_t) = %zu bytes\n", sizeof(backup_entry_t));
    printf("  sizeof(backup_registry_t) = %zu bytes\n", sizeof(backup_registry_t));
}

/* ============================================================
 * Test: Backup create/verify cycle (dry-run mode)
 * ============================================================ */
static void test_backup_cycle_dryrun(void)
{
    printf("\n%s=== Test: Backup Create/Verify Cycle (Dry-Run) ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    safety_context_t ctx;
    int ret;

    /* Initialize in dry-run mode (no filesystem writes) */
    ret = safety_init(&ctx, SAFETY_MODE_DRY_RUN);
    test_result("safety_init (dry-run) succeeds", ret == FG_SUCCESS);
    test_result("Dry-run mode is set", ctx.dry_run == true);

    /* Create backup with known data */
    const char *test_data = "UEFI variable backup test data for SHA-256 verification";
    size_t test_size = strlen(test_data);

    ret = safety_create_backup(&ctx, BACKUP_TYPE_UEFI_VAR,
                                "test-backup-sha256", test_data, test_size);
    test_result("Dry-run backup creation succeeds", ret == FG_SUCCESS);

    /* Verify the entry was created */
    test_result("Registry has 1 backup", ctx.registry.num_backups == 1);

    if (ctx.registry.num_backups == 1) {
        backup_entry_t *entry = &ctx.registry.backups[0];

        /* Verify checksum is non-zero (SHA-256 of non-empty data) */
        uint8_t zero_hash[32] = {0};
        test_result("Checksum is non-zero", memcmp(entry->checksum, zero_hash, 32) != 0);

        /* Compute expected hash independently and compare */
        uint8_t expected_hash[32];
        safety_calculate_hash(test_data, test_size, expected_hash);
        test_result("Entry checksum matches independent computation",
                    memcmp(entry->checksum, expected_hash, 32) == 0);

        /* Print the hash */
        char hex[65];
        hash_to_hex(entry->checksum, hex);
        printf("  SHA-256: %s\n", hex);
    }

    safety_cleanup(&ctx);
}

/* ============================================================
 * Test: Rollback point preserves hashes
 * ============================================================ */
static void test_rollback_point_hashes(void)
{
    printf("\n%s=== Test: Rollback Point Preserves Hashes ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    safety_context_t ctx;
    safety_init(&ctx, SAFETY_MODE_DRY_RUN);

    /* Create two backups with different data */
    safety_create_backup(&ctx, BACKUP_TYPE_UEFI_VAR,
                          "rollback-test-1", "data-one", 8);
    safety_create_backup(&ctx, BACKUP_TYPE_GRUB_CONFIG,
                          "rollback-test-2", "data-two", 8);

    test_result("Two backups created", ctx.registry.num_backups == 2);

    /* Save hashes before rollback point */
    uint8_t hash1[32], hash2[32];
    memcpy(hash1, ctx.registry.backups[0].checksum, 32);
    memcpy(hash2, ctx.registry.backups[1].checksum, 32);

    /* Create rollback point */
    int ret = safety_create_rollback_point(&ctx, "Test rollback");
    test_result("Rollback point created", ret == FG_SUCCESS);

    /* Verify rollback point preserved the hashes */
    test_result("Rollback backup 1 hash preserved",
                memcmp(ctx.rollback_point.backups[0].checksum, hash1, 32) == 0);
    test_result("Rollback backup 2 hash preserved",
                memcmp(ctx.rollback_point.backups[1].checksum, hash2, 32) == 0);

    /* Verify the two different backups have different hashes */
    test_result("Different data produces different backup hashes",
                memcmp(hash1, hash2, 32) != 0);

    safety_cleanup(&ctx);
}

/* ============================================================
 * Test: List backups formats SHA-256 correctly
 * ============================================================ */
static void test_list_backups_format(void)
{
    printf("\n%s=== Test: List Backups SHA-256 Format ===%s\n",
           COLOR_CYAN, COLOR_RESET);

    safety_context_t ctx;
    safety_init(&ctx, SAFETY_MODE_DRY_RUN);

    safety_create_backup(&ctx, BACKUP_TYPE_UEFI_VAR,
                          "format-test", "test", 4);

    /* Capture list output to a temp file */
    FILE *tmp = tmpfile();
    if (!tmp) {
        test_result("tmpfile() creation", 0);
        safety_cleanup(&ctx);
        return;
    }

    safety_list_backups(&ctx, tmp);
    fflush(tmp);

    /* Read back and check for SHA-256 label */
    fseek(tmp, 0, SEEK_SET);
    char line[512];
    int found_sha256 = 0;
    int found_old_checksum = 0;

    while (fgets(line, sizeof(line), tmp)) {
        if (strstr(line, "SHA-256:"))
            found_sha256 = 1;
        if (strstr(line, "Checksum: 0x"))
            found_old_checksum = 1;
    }

    fclose(tmp);

    test_result("List output contains 'SHA-256:' label", found_sha256);
    test_result("List output does NOT contain old '0x' format", !found_old_checksum);

    safety_cleanup(&ctx);
}

/* ============================================================
 * Test: Invalid backup name characters rejected
 * ============================================================ */
static void test_backup_name_validation(void)
{
    printf("\n%s=== Test: Backup Name Validation ===%s\n", COLOR_CYAN, COLOR_RESET);

    safety_context_t ctx;
    safety_init(&ctx, SAFETY_MODE_DRY_RUN);

    /* Valid names */
    int ret = safety_create_backup(&ctx, BACKUP_TYPE_UEFI_VAR,
                                    "valid-name_123", "data", 4);
    test_result("Alphanumeric-dash-underscore name accepted", ret == FG_SUCCESS);

    /* Path traversal attempt */
    ret = safety_create_backup(&ctx, BACKUP_TYPE_UEFI_VAR,
                                "../../../etc/passwd", "data", 4);
    test_result("Path traversal '../' name rejected", ret == FG_ERROR);

    /* Spaces */
    ret = safety_create_backup(&ctx, BACKUP_TYPE_UEFI_VAR,
                                "name with spaces", "data", 4);
    test_result("Name with spaces rejected", ret == FG_ERROR);

    /* Empty name */
    ret = safety_create_backup(&ctx, BACKUP_TYPE_UEFI_VAR,
                                "", "data", 4);
    test_result("Empty name rejected", ret == FG_ERROR);

    /* NULL data */
    ret = safety_create_backup(&ctx, BACKUP_TYPE_UEFI_VAR,
                                "null-data", NULL, 4);
    test_result("NULL data rejected", ret == FG_ERROR);

    safety_cleanup(&ctx);
}

/* ============================================================
 * Main test runner
 * ============================================================ */
int main(void)
{
    printf("\n");
    printf("========================================\n");
    printf("  FirmwareGuard Safety Hash Tests\n");
    printf("  (SHA-256 Backup Integrity)\n");
    printf("========================================\n");

    test_known_vectors();
    test_null_inputs();
    test_consistency();
    test_struct_layout();
    test_backup_cycle_dryrun();
    test_rollback_point_hashes();
    test_list_backups_format();
    test_backup_name_validation();

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
