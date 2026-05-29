#ifndef FG_SARIF_H
#define FG_SARIF_H

#include <stdio.h>
#include "firmwareguard.h"

/*
 * Generate a SARIF 2.1.0 report from an audit result and write it to `output`.
 * Each detected component becomes a SARIF result; risk levels map to SARIF
 * levels (CRITICAL/HIGH -> error, MEDIUM -> warning, LOW/NONE -> note).
 * Returns FG_SUCCESS on success.
 */
int sarif_generate(const audit_result_t *audit, FILE *output);

#endif /* FG_SARIF_H */
