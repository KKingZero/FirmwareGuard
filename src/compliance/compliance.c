/*
 * FirmwareGuard - Compliance Assessment Implementation
 *
 * This module provides framework-based compliance assessment by mapping
 * firmware security findings to compliance control requirements.
 *
 * Security considerations:
 * - All input pointers are validated before dereferencing
 * - Buffer sizes are enforced using sizeof() to prevent overflows
 * - String operations use bounded functions (snprintf, strncpy)
 * - Array bounds are checked before indexing
 * - No dynamic memory allocation during assessment to prevent leaks
 */

#include "compliance.h"
#include "../../include/cJSON.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* External NIST 800-171 mapping functions */
extern int nist_init_controls(compliance_result_t *result);
extern int nist_map_smm_findings(const smm_scan_result_t *smm,
                                 compliance_result_t *result);
extern int nist_map_bootguard_findings(const bootguard_status_t *bg,
                                       compliance_result_t *result);
extern int nist_map_secureboot_findings(const secureboot_audit_t *sb,
                                        compliance_result_t *result);
extern int nist_map_implant_findings(const implant_scan_result_t *implant,
                                     compliance_result_t *result);

/* ANSI color codes for terminal output */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_DIM     "\033[2m"

/* Module state */
static bool g_compliance_initialized = false;

/*
 * Initialize compliance subsystem
 *
 * Returns: FG_SUCCESS on success, FG_ERROR on failure
 */
int compliance_init(void) {
    if (g_compliance_initialized) {
        FG_WARN("Compliance subsystem already initialized");
        return FG_SUCCESS;
    }

    FG_INFO("Initializing compliance assessment subsystem...");

    /* No additional initialization needed - mappings are statically defined */
    g_compliance_initialized = true;

    FG_INFO("Compliance subsystem initialized");
    return FG_SUCCESS;
}

/*
 * Cleanup compliance subsystem
 */
void compliance_cleanup(void) {
    if (!g_compliance_initialized) {
        return;
    }

    FG_INFO("Cleaning up compliance subsystem");
    g_compliance_initialized = false;
}

/*
 * Run full compliance assessment for specified framework
 *
 * This is the main entry point that orchestrates the complete assessment:
 * 1. Initializes control structures for the framework
 * 2. Runs all relevant security scans
 * 3. Maps findings to compliance controls
 * 4. Calculates compliance scores
 *
 * Input validation:
 * - Validates result pointer before use
 * - Validates framework enum is in valid range
 * - Zeroes result structure to prevent uninitialized data
 *
 * Returns: FG_SUCCESS on success, FG_ERROR on failure
 */
int compliance_assess(compliance_framework_t framework,
                      compliance_result_t *result) {
    if (!result) {
        FG_LOG_ERROR("compliance_assess: NULL result pointer");
        return FG_ERROR;
    }

    /* Validate framework enum to prevent out-of-bounds access */
    if (framework >= FRAMEWORK_MAX) {
        FG_LOG_ERROR("compliance_assess: Invalid framework %d", framework);
        return FG_ERROR;
    }

    /* Zero result structure to prevent information leakage */
    memset(result, 0, sizeof(compliance_result_t));

    FG_INFO("Starting compliance assessment for framework: %s",
            compliance_framework_to_string(framework));

    /* Dispatch to framework-specific assessment */
    switch (framework) {
        case FRAMEWORK_NIST_800_171:
            return compliance_assess_nist_800_171(result);

        case FRAMEWORK_GDPR_ART32:
        case FRAMEWORK_CIS_BENCHMARK:
            FG_LOG_ERROR("Framework %s not yet implemented",
                        compliance_framework_to_string(framework));
            return FG_NOT_SUPPORTED;

        default:
            FG_LOG_ERROR("Unknown framework: %d", framework);
            return FG_ERROR;
    }
}

/*
 * Run NIST 800-171 Rev 2 compliance assessment
 *
 * Execution flow:
 * 1. Initialize NIST 800-171 control structure
 * 2. Run SMM security scan and map to controls
 * 3. Run Boot Guard scan and map to controls
 * 4. Run Secure Boot audit and map to controls
 * 5. Run implant/DMA scan and map to controls
 * 6. Calculate family and overall compliance scores
 * 7. Generate summary
 *
 * Security notes:
 * - Each scan is isolated - failure of one doesn't prevent others
 * - All scan result structures are stack-allocated
 * - Memory is not leaked even if scans fail
 *
 * Returns: FG_SUCCESS on success (even if some scans fail)
 */
int compliance_assess_nist_800_171(compliance_result_t *result) {
    int ret;

    if (!result) {
        return FG_ERROR;
    }

    FG_INFO("Running NIST 800-171 Rev 2 assessment...");

    /* Initialize NIST 800-171 control definitions */
    ret = nist_init_controls(result);
    if (ret != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to initialize NIST controls");
        return ret;
    }

    /* Record assessment timestamp */
    result->assessment_time = time(NULL);

    /*
     * Run security scans and map to compliance controls
     * Each scan is independent - continue even if some fail
     */

    /* 1. SMM Security Assessment */
    FG_INFO("Scanning SMM security configuration...");
    smm_scan_result_t smm_result;
    memset(&smm_result, 0, sizeof(smm_result));

    ret = smm_scan(&smm_result);
    if (ret == FG_SUCCESS) {
        nist_map_smm_findings(&smm_result, result);
    } else if (ret == FG_NOT_SUPPORTED) {
        FG_WARN("SMM scanning not supported on this platform");
    } else {
        FG_WARN("SMM scan failed: %d", ret);
    }

    /* 2. Boot Guard Status Assessment */
    FG_INFO("Scanning Boot Guard configuration...");
    bootguard_status_t bg_result;
    memset(&bg_result, 0, sizeof(bg_result));

    ret = bootguard_scan_status(&bg_result);
    if (ret == FG_SUCCESS) {
        nist_map_bootguard_findings(&bg_result, result);
    } else if (ret == FG_NOT_SUPPORTED) {
        FG_WARN("Boot Guard not supported on this platform");
    } else {
        FG_WARN("Boot Guard scan failed: %d", ret);
    }

    /* 3. Secure Boot Audit */
    FG_INFO("Auditing UEFI Secure Boot configuration...");
    secureboot_audit_t sb_result;
    memset(&sb_result, 0, sizeof(sb_result));

    ret = secureboot_audit_scan(&sb_result);
    if (ret == FG_SUCCESS) {
        nist_map_secureboot_findings(&sb_result, result);
    } else if (ret == FG_NOT_SUPPORTED) {
        FG_WARN("Secure Boot audit not supported");
    } else {
        FG_WARN("Secure Boot audit failed: %d", ret);
    }

    /* 4. Implant/DMA Security Assessment */
    FG_INFO("Scanning for implant indicators and DMA vulnerabilities...");
    implant_scan_result_t implant_result;
    memset(&implant_result, 0, sizeof(implant_result));

    ret = implant_full_scan(&implant_result);
    if (ret == FG_SUCCESS) {
        nist_map_implant_findings(&implant_result, result);
    } else if (ret == FG_NOT_SUPPORTED) {
        FG_WARN("Implant scanning not fully supported");
    } else {
        FG_WARN("Implant scan failed: %d", ret);
    }

    /* Calculate compliance scores and generate summary */
    compliance_calculate_scores(result);

    FG_INFO("NIST 800-171 assessment complete: %.1f%% compliant",
            result->overall_compliance_pct);

    return FG_SUCCESS;
}

/*
 * Calculate compliance scores at all levels
 *
 * This function implements a three-level scoring hierarchy:
 * 1. Control-level: Individual pass/fail/partial status
 * 2. Family-level: Aggregated scores per control family
 * 3. Overall: System-wide compliance percentage
 *
 * Scoring algorithm:
 * - PASS = 100% weight
 * - PARTIAL = 50% weight
 * - FAIL/NOT_ASSESSED = 0% weight
 * - NOT_APPLICABLE = excluded from calculation
 *
 * Risk assessment:
 * - CRITICAL: < 50% compliance OR any critical control failed
 * - HIGH: 50-70% compliance OR high control failed
 * - MEDIUM: 70-85% compliance
 * - LOW: 85-95% compliance
 * - NONE: > 95% compliance
 *
 * Memory safety:
 * - All array accesses are bounds-checked
 * - String operations use bounded functions
 */
void compliance_calculate_scores(compliance_result_t *result) {
    if (!result) {
        return;
    }

    /* Initialize counters */
    result->total_controls = 0;
    result->passed_controls = 0;
    result->partial_controls = 0;
    result->failed_controls = 0;
    result->na_controls = 0;
    result->num_families = 0;

    /* First pass: Count control statuses and identify families */
    for (int i = 0; i < result->num_controls; i++) {
        compliance_control_t *ctrl = &result->controls[i];

        /* Count by status */
        switch (ctrl->status) {
            case CONTROL_PASS:
                result->passed_controls++;
                result->total_controls++;
                break;
            case CONTROL_PARTIAL:
                result->partial_controls++;
                result->total_controls++;
                break;
            case CONTROL_FAIL:
                result->failed_controls++;
                result->total_controls++;
                break;
            case CONTROL_NOT_APPLICABLE:
                result->na_controls++;
                /* N/A controls don't count toward total */
                break;
            case CONTROL_NOT_ASSESSED:
                /* Not assessed controls are treated as fails for scoring */
                result->failed_controls++;
                result->total_controls++;
                break;
        }

        /* Build family list (deduplicated) */
        bool family_exists = false;
        for (int j = 0; j < result->num_families; j++) {
            if (strcmp(result->families[j].family_id, ctrl->family_id) == 0) {
                family_exists = true;
                break;
            }
        }

        if (!family_exists && result->num_families < COMPLIANCE_MAX_FAMILIES) {
            compliance_family_t *family = &result->families[result->num_families];

            /* Bounds-checked string copy */
            snprintf(family->family_id, sizeof(family->family_id),
                    "%s", ctrl->family_id);
            snprintf(family->family_name, sizeof(family->family_name),
                    "%s", ctrl->family_name);

            family->total_controls = 0;
            family->passed = 0;
            family->partial = 0;
            family->failed = 0;
            family->not_applicable = 0;
            family->compliance_pct = 0.0f;

            result->num_families++;
        }
    }

    /* Second pass: Calculate family-level scores */
    for (int i = 0; i < result->num_families; i++) {
        compliance_family_t *family = &result->families[i];

        /* Count controls in this family */
        for (int j = 0; j < result->num_controls; j++) {
            compliance_control_t *ctrl = &result->controls[j];

            if (strcmp(ctrl->family_id, family->family_id) != 0) {
                continue;
            }

            switch (ctrl->status) {
                case CONTROL_PASS:
                    family->passed++;
                    family->total_controls++;
                    break;
                case CONTROL_PARTIAL:
                    family->partial++;
                    family->total_controls++;
                    break;
                case CONTROL_FAIL:
                case CONTROL_NOT_ASSESSED:
                    family->failed++;
                    family->total_controls++;
                    break;
                case CONTROL_NOT_APPLICABLE:
                    family->not_applicable++;
                    /* N/A doesn't count toward total */
                    break;
            }
        }

        /* Calculate family compliance percentage */
        if (family->total_controls > 0) {
            /* PASS = 100%, PARTIAL = 50%, FAIL = 0% */
            float score = (float)family->passed + (0.5f * (float)family->partial);
            family->compliance_pct = (score / (float)family->total_controls) * 100.0f;
        } else {
            family->compliance_pct = 0.0f;
        }
    }

    /* Calculate overall compliance percentage */
    if (result->total_controls > 0) {
        float score = (float)result->passed_controls +
                     (0.5f * (float)result->partial_controls);
        result->overall_compliance_pct = (score / (float)result->total_controls) * 100.0f;
    } else {
        result->overall_compliance_pct = 0.0f;
    }

    /* Determine overall risk level based on compliance and control failures */
    bool has_critical_fail = false;
    bool has_high_fail = false;

    /* Check for critical/high control failures */
    for (int i = 0; i < result->num_controls; i++) {
        compliance_control_t *ctrl = &result->controls[i];

        if (ctrl->status == CONTROL_FAIL || ctrl->status == CONTROL_NOT_ASSESSED) {
            if (ctrl->risk_impact == RISK_CRITICAL) {
                has_critical_fail = true;
            } else if (ctrl->risk_impact == RISK_HIGH) {
                has_high_fail = true;
            }
        }
    }

    /* Risk determination with defense-in-depth approach */
    if (has_critical_fail || result->overall_compliance_pct < 50.0f) {
        result->overall_risk = RISK_CRITICAL;
    } else if (has_high_fail || result->overall_compliance_pct < 70.0f) {
        result->overall_risk = RISK_HIGH;
    } else if (result->overall_compliance_pct < 85.0f) {
        result->overall_risk = RISK_MEDIUM;
    } else if (result->overall_compliance_pct < 95.0f) {
        result->overall_risk = RISK_LOW;
    } else {
        result->overall_risk = RISK_NONE;
    }

    /* Generate summary text */
    snprintf(result->summary, sizeof(result->summary),
            "%s assessment: %.1f%% compliant. "
            "%d controls assessed: %d passed, %d partial, %d failed, %d N/A. "
            "Overall risk: %s.",
            result->framework_name,
            result->overall_compliance_pct,
            result->total_controls,
            result->passed_controls,
            result->partial_controls,
            result->failed_controls,
            result->na_controls,
            (result->overall_risk == RISK_CRITICAL) ? "CRITICAL" :
            (result->overall_risk == RISK_HIGH) ? "HIGH" :
            (result->overall_risk == RISK_MEDIUM) ? "MEDIUM" :
            (result->overall_risk == RISK_LOW) ? "LOW" : "MINIMAL");
}

/*
 * Print compliance assessment results with colored terminal output
 *
 * Output format:
 * 1. Overall summary with risk-based coloring
 * 2. Family-level summary table
 * 3. Individual control details (if show_details is true)
 *
 * Terminal colors:
 * - Green: PASS status
 * - Yellow: PARTIAL status
 * - Red: FAIL status
 * - Cyan: Informational headers
 * - Dim: N/A or metadata
 *
 * Security: All array accesses are bounds-checked
 */
void compliance_print_result(const compliance_result_t *result,
                             bool show_details) {
    if (!result) {
        return;
    }

    /* Print header */
    printf("\n");
    printf("%s╔══════════════════════════════════════════════════════════════════════╗%s\n",
           COLOR_BOLD COLOR_CYAN, COLOR_RESET);
    printf("%s║           COMPLIANCE ASSESSMENT REPORT                                ║%s\n",
           COLOR_BOLD COLOR_CYAN, COLOR_RESET);
    printf("%s╚══════════════════════════════════════════════════════════════════════╝%s\n",
           COLOR_BOLD COLOR_CYAN, COLOR_RESET);
    printf("\n");

    /* Framework information */
    printf("%sFramework:%s %s %s\n", COLOR_BOLD, COLOR_RESET,
           result->framework_name, result->framework_version);

    char time_str[64];
    struct tm *tm_info = localtime(&result->assessment_time);
    if (tm_info) {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(time_str, sizeof(time_str), "Invalid timestamp");
    }
    printf("%sAssessed:%s  %s\n", COLOR_BOLD, COLOR_RESET, time_str);
    printf("\n");

    /* Overall compliance score with color-coded risk */
    const char *risk_color;
    switch (result->overall_risk) {
        case RISK_CRITICAL:
            risk_color = COLOR_RED COLOR_BOLD;
            break;
        case RISK_HIGH:
            risk_color = COLOR_RED;
            break;
        case RISK_MEDIUM:
            risk_color = COLOR_YELLOW;
            break;
        case RISK_LOW:
            risk_color = COLOR_GREEN;
            break;
        default:
            risk_color = COLOR_GREEN COLOR_BOLD;
            break;
    }

    printf("%s┌─ Overall Compliance ─────────────────────────────────────────────┐%s\n",
           COLOR_BOLD, COLOR_RESET);
    printf("%s│%s Compliance Score: %s%.1f%%%s                                          %s│%s\n",
           COLOR_BOLD, COLOR_RESET, risk_color, result->overall_compliance_pct,
           COLOR_RESET, COLOR_BOLD, COLOR_RESET);
    printf("%s│%s Risk Level:        %s%-10s%s                                   %s│%s\n",
           COLOR_BOLD, COLOR_RESET, risk_color,
           (result->overall_risk == RISK_CRITICAL) ? "CRITICAL" :
           (result->overall_risk == RISK_HIGH) ? "HIGH" :
           (result->overall_risk == RISK_MEDIUM) ? "MEDIUM" :
           (result->overall_risk == RISK_LOW) ? "LOW" : "MINIMAL",
           COLOR_RESET, COLOR_BOLD, COLOR_RESET);
    printf("%s└──────────────────────────────────────────────────────────────────┘%s\n",
           COLOR_BOLD, COLOR_RESET);
    printf("\n");

    /* Control summary statistics */
    printf("%s┌─ Control Summary ────────────────────────────────────────────────┐%s\n",
           COLOR_BOLD, COLOR_RESET);
    printf("%s│%s Total Controls:    %-3d                                           %s│%s\n",
           COLOR_BOLD, COLOR_RESET, result->total_controls, COLOR_BOLD, COLOR_RESET);
    printf("%s│%s   %sPassed:%s          %-3d (%.0f%%)                                   %s│%s\n",
           COLOR_BOLD, COLOR_RESET, COLOR_GREEN, COLOR_RESET,
           result->passed_controls,
           result->total_controls > 0 ?
               (100.0f * result->passed_controls / result->total_controls) : 0.0f,
           COLOR_BOLD, COLOR_RESET);
    printf("%s│%s   %sPartial:%s         %-3d (%.0f%%)                                   %s│%s\n",
           COLOR_BOLD, COLOR_RESET, COLOR_YELLOW, COLOR_RESET,
           result->partial_controls,
           result->total_controls > 0 ?
               (100.0f * result->partial_controls / result->total_controls) : 0.0f,
           COLOR_BOLD, COLOR_RESET);
    printf("%s│%s   %sFailed:%s          %-3d (%.0f%%)                                   %s│%s\n",
           COLOR_BOLD, COLOR_RESET, COLOR_RED, COLOR_RESET,
           result->failed_controls,
           result->total_controls > 0 ?
               (100.0f * result->failed_controls / result->total_controls) : 0.0f,
           COLOR_BOLD, COLOR_RESET);
    printf("%s│%s   %sN/A:%s             %-3d                                         %s│%s\n",
           COLOR_BOLD, COLOR_RESET, COLOR_DIM, COLOR_RESET,
           result->na_controls, COLOR_BOLD, COLOR_RESET);
    printf("%s└──────────────────────────────────────────────────────────────────┘%s\n",
           COLOR_BOLD, COLOR_RESET);
    printf("\n");

    /* Family-level summary table */
    if (result->num_families > 0) {
        printf("%s╔═══════════════════════════ FAMILY SUMMARY ═══════════════════════════╗%s\n",
               COLOR_BOLD COLOR_CYAN, COLOR_RESET);
        printf("%s║ %-8s %-32s %4s %4s %4s %4s %7s ║%s\n",
               COLOR_BOLD, "ID", "Family Name", "Pass", "Part", "Fail", "N/A", "Score", COLOR_RESET);
        printf("%s╠══════════════════════════════════════════════════════════════════════╣%s\n",
               COLOR_BOLD COLOR_CYAN, COLOR_RESET);

        for (int i = 0; i < result->num_families && i < COMPLIANCE_MAX_FAMILIES; i++) {
            const compliance_family_t *fam = &result->families[i];

            /* Choose color based on family compliance score */
            const char *fam_color;
            if (fam->compliance_pct >= 90.0f) {
                fam_color = COLOR_GREEN;
            } else if (fam->compliance_pct >= 70.0f) {
                fam_color = COLOR_YELLOW;
            } else {
                fam_color = COLOR_RED;
            }

            printf("%s║%s %s%-8s%s %-32s %s%4d%s %s%4d%s %s%4d%s %s%4d%s %s%6.1f%%%s %s║%s\n",
                   COLOR_BOLD, COLOR_RESET,
                   COLOR_CYAN, fam->family_id, COLOR_RESET,
                   fam->family_name,
                   COLOR_GREEN, fam->passed, COLOR_RESET,
                   COLOR_YELLOW, fam->partial, COLOR_RESET,
                   COLOR_RED, fam->failed, COLOR_RESET,
                   COLOR_DIM, fam->not_applicable, COLOR_RESET,
                   fam_color, fam->compliance_pct, COLOR_RESET,
                   COLOR_BOLD, COLOR_RESET);
        }

        printf("%s╚══════════════════════════════════════════════════════════════════════╝%s\n",
               COLOR_BOLD COLOR_CYAN, COLOR_RESET);
        printf("\n");
    }

    /* Detailed control results */
    if (show_details && result->num_controls > 0) {
        printf("%s╔═════════════════════ DETAILED CONTROL RESULTS ═══════════════════════╗%s\n",
               COLOR_BOLD COLOR_CYAN, COLOR_RESET);
        printf("\n");

        for (int i = 0; i < result->num_controls && i < COMPLIANCE_MAX_CONTROLS; i++) {
            const compliance_control_t *ctrl = &result->controls[i];

            /* Skip N/A controls in detailed view */
            if (ctrl->status == CONTROL_NOT_APPLICABLE) {
                continue;
            }

            const char *status_color = compliance_status_to_color(ctrl->status);
            const char *status_str = compliance_status_to_string(ctrl->status);

            printf("%s[%s]%s %s%s%s - %s\n",
                   COLOR_BOLD COLOR_CYAN, ctrl->control_id, COLOR_RESET,
                   status_color, status_str, COLOR_RESET,
                   ctrl->control_name);

            printf("  %sDescription:%s %s\n", COLOR_DIM, COLOR_RESET, ctrl->control_desc);

            if (ctrl->evidence[0] != '\0') {
                printf("  %sEvidence:%s    %s\n", COLOR_DIM, COLOR_RESET, ctrl->evidence);
            }

            /* Print findings if present */
            if (ctrl->finding_count > 0) {
                printf("  %sFindings:%s\n", COLOR_DIM, COLOR_RESET);
                for (int j = 0; j < ctrl->finding_count && j < 8; j++) {
                    printf("    %s•%s %s\n", COLOR_RED, COLOR_RESET, ctrl->findings[j]);
                }
            }

            printf("\n");
        }

        printf("%s╚══════════════════════════════════════════════════════════════════════╝%s\n",
               COLOR_BOLD COLOR_CYAN, COLOR_RESET);
    }

    /* Summary */
    printf("\n%sSummary:%s %s\n\n", COLOR_BOLD, COLOR_RESET, result->summary);
}

/*
 * Export compliance results to JSON format
 *
 * JSON structure:
 * {
 *   "framework": {...},
 *   "overall_scores": {...},
 *   "families": [...],
 *   "controls": [...],
 *   "metadata": {...}
 * }
 *
 * Security considerations:
 * - Uses cJSON library which handles memory safely
 * - All string operations are bounds-checked
 * - Buffer size is validated before writing
 * - JSON object is properly freed to prevent leaks
 *
 * Returns: FG_SUCCESS on success, FG_ERROR on failure
 */
int compliance_result_to_json(const compliance_result_t *result,
                              char *buffer, size_t size) {
    if (!result || !buffer || size == 0) {
        return FG_ERROR;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return FG_ERROR;
    }

    /* Validate array bounds to prevent OOB access */
    if (result->num_families > COMPLIANCE_MAX_FAMILIES ||
        result->num_controls > COMPLIANCE_MAX_CONTROLS) {
        cJSON_Delete(root);
        return FG_ERROR;
    }

    /* Framework information */
    cJSON *framework_obj = cJSON_CreateObject();
    if (!framework_obj) {
        cJSON_Delete(root);
        return FG_ERROR;
    }
    cJSON_AddStringToObject(framework_obj, "name", result->framework_name);
    cJSON_AddStringToObject(framework_obj, "version", result->framework_version);
    cJSON_AddStringToObject(framework_obj, "framework_type",
                           compliance_framework_to_string(result->framework));
    cJSON_AddItemToObject(root, "framework", framework_obj);

    /* Overall scores */
    cJSON *scores_obj = cJSON_CreateObject();
    if (!scores_obj) {
        cJSON_Delete(root);
        return FG_ERROR;
    }
    cJSON_AddNumberToObject(scores_obj, "compliance_percentage", result->overall_compliance_pct);
    cJSON_AddNumberToObject(scores_obj, "total_controls", result->total_controls);
    cJSON_AddNumberToObject(scores_obj, "passed", result->passed_controls);
    cJSON_AddNumberToObject(scores_obj, "partial", result->partial_controls);
    cJSON_AddNumberToObject(scores_obj, "failed", result->failed_controls);
    cJSON_AddNumberToObject(scores_obj, "not_applicable", result->na_controls);

    const char *risk_str = (result->overall_risk == RISK_CRITICAL) ? "CRITICAL" :
                          (result->overall_risk == RISK_HIGH) ? "HIGH" :
                          (result->overall_risk == RISK_MEDIUM) ? "MEDIUM" :
                          (result->overall_risk == RISK_LOW) ? "LOW" : "MINIMAL";
    cJSON_AddStringToObject(scores_obj, "risk_level", risk_str);
    cJSON_AddItemToObject(root, "overall_scores", scores_obj);

    /* Family summaries */
    cJSON *families_array = cJSON_CreateArray();
    if (!families_array) {
        cJSON_Delete(root);
        return FG_ERROR;
    }
    for (int i = 0; i < result->num_families && i < COMPLIANCE_MAX_FAMILIES; i++) {
        const compliance_family_t *fam = &result->families[i];

        cJSON *fam_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(fam_obj, "family_id", fam->family_id);
        cJSON_AddStringToObject(fam_obj, "family_name", fam->family_name);
        cJSON_AddNumberToObject(fam_obj, "total_controls", fam->total_controls);
        cJSON_AddNumberToObject(fam_obj, "passed", fam->passed);
        cJSON_AddNumberToObject(fam_obj, "partial", fam->partial);
        cJSON_AddNumberToObject(fam_obj, "failed", fam->failed);
        cJSON_AddNumberToObject(fam_obj, "not_applicable", fam->not_applicable);
        cJSON_AddNumberToObject(fam_obj, "compliance_percentage", fam->compliance_pct);

        cJSON_AddItemToArray(families_array, fam_obj);
    }
    cJSON_AddItemToObject(root, "families", families_array);

    /* Control details */
    cJSON *controls_array = cJSON_CreateArray();
    if (!controls_array) {
        cJSON_Delete(root);
        return FG_ERROR;
    }
    for (int i = 0; i < result->num_controls && i < COMPLIANCE_MAX_CONTROLS; i++) {
        const compliance_control_t *ctrl = &result->controls[i];

        cJSON *ctrl_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(ctrl_obj, "control_id", ctrl->control_id);
        cJSON_AddStringToObject(ctrl_obj, "control_name", ctrl->control_name);
        cJSON_AddStringToObject(ctrl_obj, "control_description", ctrl->control_desc);
        cJSON_AddStringToObject(ctrl_obj, "family_id", ctrl->family_id);
        cJSON_AddStringToObject(ctrl_obj, "family_name", ctrl->family_name);
        cJSON_AddStringToObject(ctrl_obj, "status", compliance_status_to_string(ctrl->status));

        const char *risk_impact = (ctrl->risk_impact == RISK_CRITICAL) ? "CRITICAL" :
                                 (ctrl->risk_impact == RISK_HIGH) ? "HIGH" :
                                 (ctrl->risk_impact == RISK_MEDIUM) ? "MEDIUM" :
                                 (ctrl->risk_impact == RISK_LOW) ? "LOW" : "NONE";
        cJSON_AddStringToObject(ctrl_obj, "risk_impact", risk_impact);

        if (ctrl->evidence[0] != '\0') {
            cJSON_AddStringToObject(ctrl_obj, "evidence", ctrl->evidence);
        }

        if (ctrl->finding_count > 0) {
            cJSON *findings_array = cJSON_CreateArray();
            if (findings_array) {
                int max_findings = (ctrl->finding_count > 8) ? 8 : ctrl->finding_count;
                for (int j = 0; j < max_findings; j++) {
                    cJSON_AddItemToArray(findings_array, cJSON_CreateString(ctrl->findings[j]));
                }
                cJSON_AddItemToObject(ctrl_obj, "findings", findings_array);
            }
        }

        cJSON_AddItemToArray(controls_array, ctrl_obj);
    }
    cJSON_AddItemToObject(root, "controls", controls_array);

    /* Metadata */
    cJSON *meta_obj = cJSON_CreateObject();
    if (!meta_obj) {
        cJSON_Delete(root);
        return FG_ERROR;
    }
    cJSON_AddNumberToObject(meta_obj, "assessment_timestamp", (double)result->assessment_time);
    cJSON_AddStringToObject(meta_obj, "summary", result->summary);
    cJSON_AddItemToObject(root, "metadata", meta_obj);

    /* Render to string with bounds checking */
    char *json_str = cJSON_Print(root);
    if (!json_str) {
        cJSON_Delete(root);
        return FG_ERROR;
    }

    /* Copy to output buffer with size validation */
    size_t json_len = strlen(json_str);
    if (json_len >= size) {
        /* Buffer too small */
        free(json_str);
        cJSON_Delete(root);
        return FG_ERROR;
    }

    /* Safe string copy */
    strncpy(buffer, json_str, size - 1);
    buffer[size - 1] = '\0';

    /* Clean up */
    free(json_str);
    cJSON_Delete(root);

    return FG_SUCCESS;
}

/*
 * Convert framework enum to string representation
 *
 * Returns: Static string (never NULL)
 */
const char *compliance_framework_to_string(compliance_framework_t framework) {
    switch (framework) {
        case FRAMEWORK_NIST_800_171:
            return "NIST_800_171";
        case FRAMEWORK_GDPR_ART32:
            return "GDPR_ARTICLE_32";
        case FRAMEWORK_CIS_BENCHMARK:
            return "CIS_BENCHMARK";
        default:
            return "UNKNOWN";
    }
}

/*
 * Convert control status enum to string representation
 *
 * Returns: Static string (never NULL)
 */
const char *compliance_status_to_string(control_status_t status) {
    switch (status) {
        case CONTROL_NOT_ASSESSED:
            return "NOT_ASSESSED";
        case CONTROL_PASS:
            return "PASS";
        case CONTROL_PARTIAL:
            return "PARTIAL";
        case CONTROL_FAIL:
            return "FAIL";
        case CONTROL_NOT_APPLICABLE:
            return "N/A";
        default:
            return "UNKNOWN";
    }
}

/*
 * Get ANSI color code for control status
 *
 * Returns: Static ANSI color string (never NULL)
 */
const char *compliance_status_to_color(control_status_t status) {
    switch (status) {
        case CONTROL_PASS:
            return COLOR_GREEN COLOR_BOLD;
        case CONTROL_PARTIAL:
            return COLOR_YELLOW;
        case CONTROL_FAIL:
        case CONTROL_NOT_ASSESSED:
            return COLOR_RED COLOR_BOLD;
        case CONTROL_NOT_APPLICABLE:
            return COLOR_DIM;
        default:
            return COLOR_RESET;
    }
}
