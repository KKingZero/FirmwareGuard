/*
 * FirmwareGuard - shared non-cryptographic fingerprint hashes (FNV-1a 256-bit)
 *
 * Moved verbatim from baseline_capture.c (compute_hash) and uefi_extract.c
 * (compute_simple_hash) so the two parsers can be unit-tested and fuzzed.
 * The byte output is identical to the previous in-module definitions.
 */

#include "fg_hash.h"
#include <stdio.h>

/* Helper to compute simple hash (FNV-1a based) */
void compute_hash(const uint8_t *data, size_t len, char *hex_out) {
    uint64_t h[4] = {0xcbf29ce484222325ULL, 0x84222325cbf29ce4ULL,
                     0xf29ce484222325cbULL, 0x222325cbf29ce484ULL};
    const uint64_t prime = 0x100000001b3ULL;

    for (size_t i = 0; i < len; i++) {
        int idx = i % 4;
        h[idx] ^= data[i];
        h[idx] *= prime;
    }

    snprintf(hex_out, 65, "%016llx%016llx%016llx%016llx",
             (unsigned long long)h[0], (unsigned long long)h[1],
             (unsigned long long)h[2], (unsigned long long)h[3]);
}

/* Simple FNV-1a based hash (not cryptographic, just for fingerprinting) */
void compute_simple_hash(const uint8_t *data, size_t len, uint8_t *hash, char *hex_out) {
    /* FNV-1a 256-bit hash approximation using multiple 64-bit hashes */
    uint64_t h[4] = {0xcbf29ce484222325ULL, 0xcbf29ce484222325ULL,
                     0xcbf29ce484222325ULL, 0xcbf29ce484222325ULL};
    const uint64_t prime = 0x100000001b3ULL;

    for (size_t i = 0; i < len; i++) {
        int idx = i % 4;
        h[idx] ^= data[i];
        h[idx] *= prime;
    }

    /* Store as 32 bytes */
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            hash[i * 8 + j] = (h[i] >> (j * 8)) & 0xFF;
        }
    }

    if (hex_out) {
        for (int i = 0; i < 32; i++) {
            sprintf(hex_out + (i * 2), "%02x", hash[i]);
        }
        hex_out[64] = '\0';
    }
}
