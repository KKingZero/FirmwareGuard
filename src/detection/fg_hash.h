/*
 * FirmwareGuard - shared non-cryptographic fingerprint hashes (FNV-1a 256-bit)
 *
 * These are used to fingerprint firmware/baseline blobs for change detection.
 * They are NOT cryptographic and must not be used for integrity guarantees.
 * Extracted into one TU so they can be unit-tested and fuzzed in isolation.
 */

#ifndef FG_HASH_H
#define FG_HASH_H

#include <stdint.h>
#include <stddef.h>

/*
 * Baseline fingerprint: 4-lane FNV-1a with rotated seeds.
 * hex_out must point to at least 65 bytes; it receives 64 hex chars + NUL.
 */
void compute_hash(const uint8_t *data, size_t len, char *hex_out);

/*
 * UEFI-variable fingerprint: 4-lane FNV-1a with identical seeds.
 * hash receives 32 raw bytes. hex_out (optional) must be >= 65 bytes when
 * non-NULL; it receives 64 hex chars + NUL.
 */
void compute_simple_hash(const uint8_t *data, size_t len, uint8_t *hash, char *hex_out);

#endif /* FG_HASH_H */
