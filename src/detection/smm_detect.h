#ifndef FG_SMM_DETECT_H
#define FG_SMM_DETECT_H

#include "../../include/firmwareguard.h"
#include "../core/msr.h"

/* SMM-related MSR addresses */
#define MSR_SMBASE                  0x0000009E  /* SMM Base Address */
#define MSR_SMM_MASK                0xC0010113  /* AMD SMM TSEG Mask */
#define MSR_SMM_ADDR                0xC0010112  /* AMD SMM TSEG Base */
#define MSR_IA32_SMRR_PHYSBASE      0x000001F2  /* Intel SMRR Base */
#define MSR_IA32_SMRR_PHYSMASK      0x000001F3  /* Intel SMRR Mask */
#define MSR_SMI_COUNT               0x00000034  /* SMI Counter */
#define MSR_IA32_FEATURE_CONTROL    0x0000003A  /* Feature Control */
#define MSR_IA32_VMX_BASIC          0x00000480  /* VMX Basic Info */
#define MSR_IA32_SMM_MONITOR_CTL    0x0000009B  /* SMM Monitor Control */

/* SMM Feature Control bits */
#define FEATURE_CONTROL_LOCK        (1 << 0)
#define FEATURE_CONTROL_VMX_SMX     (1 << 1)
#define FEATURE_CONTROL_VMX_OUTSIDE (1 << 2)
#define FEATURE_CONTROL_SENTER_EN   (0x7F << 8)  /* SENTER local enables */
#define FEATURE_CONTROL_SENTER_GE   (1 << 15)    /* SENTER global enable */
#define FEATURE_CONTROL_SGX_LE      (1 << 17)    /* SGX Launch Control enable */
#define FEATURE_CONTROL_SGX_GE      (1 << 18)    /* SGX global enable */
#define FEATURE_CONTROL_LMCE        (1 << 20)    /* LMCE enable */

/* SMM risk levels */
typedef enum {
    SMM_RISK_NONE = 0,
    SMM_RISK_LOW,
    SMM_RISK_MEDIUM,
    SMM_RISK_HIGH,
    SMM_RISK_CRITICAL
} smm_risk_t;

/* SMM handler information */
typedef struct {
    uint64_t smbase;            /* SMM Base Address */
    uint64_t smrr_base;         /* SMRR Physical Base (Intel) or TSEG Base (AMD) */
    uint64_t smrr_mask;         /* SMRR Physical Mask (Intel) or TSEG Mask (AMD) */
    uint64_t smram_size;        /* Calculated SMRAM size */
    bool smrr_valid;            /* SMRR/TSEG configuration valid */
    bool smrr_locked;           /* SMRR/TSEG locked */
} smm_region_info_t;

/* SMI statistics */
typedef struct {
    uint64_t smi_count;         /* Total SMI count from MSR */
    uint64_t smi_rate_estimate; /* Estimated SMIs per second */
    bool smi_count_supported;   /* SMI count MSR available */
} smm_smi_stats_t;

/* SMM security configuration */
typedef struct {
    bool feature_control_locked;    /* IA32_FEATURE_CONTROL locked */
    bool vmx_in_smx_enabled;        /* VMX in SMX mode enabled */
    bool vmx_outside_smx_enabled;   /* VMX outside SMX enabled */
    bool senter_enabled;            /* SENTER (TXT) enabled */
    bool sgx_enabled;               /* SGX enabled */
    bool smm_monitor_valid;         /* SMM Monitor Control valid */
    uint64_t feature_control_raw;   /* Raw feature control value */
} smm_security_config_t;

/* Complete SMM scan result */
typedef struct {
    /* Basic detection */
    bool smm_present;
    bool is_intel;
    bool is_amd;
    int cpu_count;

    /* Per-CPU SMM region info (first CPU) */
    smm_region_info_t region;

    /* SMI statistics */
    smm_smi_stats_t smi_stats;

    /* Security configuration */
    smm_security_config_t security;

    /* Risk assessment */
    smm_risk_t risk_level;
    char risk_reason[512];

    /* Detailed findings */
    int finding_count;
    char findings[16][256];

    /* Summary */
    char summary[1024];
} smm_scan_result_t;

/* Initialize SMM detection subsystem */
int smm_detect_init(void);

/* Cleanup SMM detection subsystem */
void smm_detect_cleanup(void);

/* Perform full SMM scan */
int smm_scan(smm_scan_result_t *result);

/* Quick SMM status check (brief mode) */
int smm_scan_brief(smm_scan_result_t *result);

/* Read SMM region information */
int smm_read_region_info(smm_region_info_t *info, bool is_amd);

/* Read SMI statistics */
int smm_read_smi_stats(smm_smi_stats_t *stats);

/* Read SMM security configuration */
int smm_read_security_config(smm_security_config_t *config);

/* Assess SMM risk level */
smm_risk_t smm_assess_risk(const smm_scan_result_t *result);

/* Get risk level string */
const char *smm_risk_to_string(smm_risk_t risk);

/* Print SMM scan results */
void smm_print_result(const smm_scan_result_t *result, bool verbose);

/* Export SMM results to JSON */
int smm_result_to_json(const smm_scan_result_t *result, char *buffer, size_t size);

#endif /* FG_SMM_DETECT_H */
