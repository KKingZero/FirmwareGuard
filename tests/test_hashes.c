/*
 * FirmwareGuard - unit tests for the shared FNV-1a fingerprint hashes.
 *
 * Links directly against src/detection/fg_hash.c (no other deps), so the
 * shipped code is exercised, not a copy. Build/run via tools/run-tests.sh.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../src/detection/fg_hash.h"

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, int ok) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) g_pass++; else g_fail++;
}

int main(void) {
    printf("\n=== fg_hash unit tests ===\n");

    /* Known-answer: empty input => seed lanes rendered as hex. Any change to
     * the algorithm or seeds breaks this, guarding baseline-hash stability. */
    char hex[65];
    compute_hash((const uint8_t *)"", 0, hex);
    check("compute_hash(empty) == seed concat",
          strcmp(hex, "cbf29ce48422232584222325cbf29ce4f29ce484222325cb222325cbf29ce484") == 0);

    /* Determinism + length */
    char a[65], b[65];
    compute_hash((const uint8_t *)"firmwareguard", 13, a);
    compute_hash((const uint8_t *)"firmwareguard", 13, b);
    check("compute_hash deterministic", strcmp(a, b) == 0);
    check("compute_hash length == 64", strlen(a) == 64);

    /* Sensitivity: one byte change must alter the digest */
    char c[65];
    compute_hash((const uint8_t *)"firmwareguarE", 13, c);
    check("compute_hash one-byte change differs", strcmp(a, c) != 0);

    /* compute_simple_hash known-answer for empty input */
    uint8_t raw[32];
    char shex[65];
    compute_simple_hash((const uint8_t *)"", 0, raw, shex);
    check("compute_simple_hash(empty) hex",
          strcmp(shex, "25232284e49cf2cb25232284e49cf2cb25232284e49cf2cb25232284e49cf2cb") == 0);

    /* Raw bytes and hex must be consistent */
    uint8_t raw2[32];
    char shex2[65];
    compute_simple_hash((const uint8_t *)"abc", 3, raw2, shex2);
    char rebuilt[65];
    for (int i = 0; i < 32; i++) {
        snprintf(rebuilt + (i * 2), 3, "%02x", raw2[i]);
    }
    rebuilt[64] = '\0';
    check("compute_simple_hash hex matches raw bytes", strcmp(rebuilt, shex2) == 0);

    /* NULL hex_out must be tolerated */
    compute_simple_hash((const uint8_t *)"abc", 3, raw2, NULL);
    check("compute_simple_hash NULL hex_out tolerated", 1);

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
