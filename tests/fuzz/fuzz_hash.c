/*
 * libFuzzer harness for the FNV-1a fingerprint parsers.
 *
 * Both hashers consume an untrusted (buffer, length) pair — exactly the shape
 * firmware/baseline blobs arrive in. Run under ASan/UBSan to catch OOB reads
 * or UB on adversarial lengths/contents.
 *
 * Build:  make fuzz   (clang + libFuzzer)
 * Run:    ./build/fuzz_hash -max_total_time=30
 */

#include <stdint.h>
#include <stddef.h>

#include "../../src/detection/fg_hash.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char hex[65];
    compute_hash(data, size, hex);

    uint8_t raw[32];
    char shex[65];
    compute_simple_hash(data, size, raw, shex);
    compute_simple_hash(data, size, raw, NULL);

    return 0;
}
