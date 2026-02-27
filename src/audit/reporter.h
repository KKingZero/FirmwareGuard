#ifndef FG_REPORTER_H
#define FG_REPORTER_H

#include <stdbool.h>
#include <stdio.h>
#include "probe.h"
#include "../block/blocker.h"
#include "firmwareguard.h"

/* Report format types */
typedef enum {
    REPORT_FORMAT_TEXT = 0,
    REPORT_FORMAT_JSON,
    REPORT_FORMAT_DETAILED
} report_format_t;

/* Initialize reporter subsystem */
int reporter_init(void);

/* Cleanup reporter subsystem */
void reporter_cleanup(void);

/* Generate audit report */
int reporter_generate_audit_report(const audit_result_t *audit,
                                   report_format_t format,
                                   FILE *output);

/* Generate blocking report */
int reporter_generate_blocking_report(const blocking_results_t *results,
                                      report_format_t format,
                                      FILE *output);

/* Generate combined report (audit + blocking) */
int reporter_generate_combined_report(const audit_result_t *audit,
                                      const blocking_results_t *blocking,
                                      report_format_t format,
                                      FILE *output);

/* Get risk level string */
const char* reporter_risk_to_string(risk_level_t risk);

/* Get component type string */
const char* reporter_component_type_to_string(component_type_t type);

#endif /* FG_REPORTER_H */
