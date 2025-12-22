#ifndef FG_COMPLIANCE_H
#define FG_COMPLIANCE_H

#include "../../include/firmwareguard.h"
#include "../detection/smm_detect.h"
#include "../detection/bootguard_detect.h"
#include "../detection/txt_sgx_detect.h"
#include "../detection/implant_detect.h"

/* Maximum limits */
#define COMPLIANCE_MAX_CONTROLS      64
#define COMPLIANCE_MAX_FINDINGS      8   /* Max findings per control */
#define COMPLIANCE_MAX_FAMILIES      16

/* Compliance frameworks */
typedef enum {
    FRAMEWORK_NIST_800_171 = 0,
    FRAMEWORK_GDPR_ART32,
    FRAMEWORK_CIS_BENCHMARK,
    FRAMEWORK_MAX
} compliance_framework_t;

/* Control status */
typedef enum {
    CONTROL_NOT_ASSESSED = 0,
    CONTROL_PASS,
    CONTROL_PARTIAL,
    CONTROL_FAIL,
    CONTROL_NOT_APPLICABLE
} control_status_t;

/* Individual control result */
typedef struct {
    char control_id[32];           /* e.g., "3.4.1", "3.13.1" */
    char control_name[128];        /* Short name */
    char control_desc[512];        /* Full description */
    char family_id[16];            /* e.g., "3.4" for Config Mgmt */
    char family_name[64];          /* e.g., "Configuration Management" */

    control_status_t status;
    risk_level_t risk_impact;      /* Risk if control fails */

    char evidence[512];            /* What was found */
    int finding_count;
    char findings[COMPLIANCE_MAX_FINDINGS][256];  /* Detailed findings */
} compliance_control_t;

/* Control family summary */
typedef struct {
    char family_id[16];
    char family_name[64];

    int total_controls;
    int passed;
    int partial;
    int failed;
    int not_applicable;

    float compliance_pct;          /* 0.0 - 100.0 */
} compliance_family_t;

/* Full framework assessment result */
typedef struct {
    compliance_framework_t framework;
    char framework_name[64];
    char framework_version[32];

    /* Control-level results */
    int num_controls;
    compliance_control_t controls[COMPLIANCE_MAX_CONTROLS];

    /* Family-level summaries */
    int num_families;
    compliance_family_t families[COMPLIANCE_MAX_FAMILIES];

    /* Overall scores */
    int total_controls;
    int passed_controls;
    int partial_controls;
    int failed_controls;
    int na_controls;

    float overall_compliance_pct;
    risk_level_t overall_risk;

    /* Metadata */
    time_t assessment_time;
    char summary[1024];
} compliance_result_t;

/* Initialize compliance subsystem */
int compliance_init(void);

/* Cleanup compliance subsystem */
void compliance_cleanup(void);

/* Run full compliance assessment */
int compliance_assess(compliance_framework_t framework,
                      compliance_result_t *result);

/* Run NIST 800-171 assessment specifically */
int compliance_assess_nist_800_171(compliance_result_t *result);

/* Map scan findings to compliance controls */
int compliance_map_smm_findings(const smm_scan_result_t *smm,
                                compliance_result_t *result);
int compliance_map_bootguard_findings(const bootguard_status_t *bg,
                                      compliance_result_t *result);
int compliance_map_secureboot_findings(const secureboot_audit_t *sb,
                                       compliance_result_t *result);
int compliance_map_implant_findings(const implant_scan_result_t *implant,
                                    compliance_result_t *result);

/* Calculate compliance scores */
void compliance_calculate_scores(compliance_result_t *result);

/* Output functions */
void compliance_print_result(const compliance_result_t *result,
                             bool show_details);
int compliance_result_to_json(const compliance_result_t *result,
                              char *buffer, size_t size);

/* Helper functions */
const char *compliance_framework_to_string(compliance_framework_t framework);
const char *compliance_status_to_string(control_status_t status);
const char *compliance_status_to_color(control_status_t status);

#endif /* FG_COMPLIANCE_H */
