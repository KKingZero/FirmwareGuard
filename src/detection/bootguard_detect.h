#ifndef FG_BOOTGUARD_DETECT_H
#define FG_BOOTGUARD_DETECT_H

#include "../../include/firmwareguard.h"
#include "msr.h"

/* Boot Guard MSR addresses */
#define MSR_BOOT_GUARD_SACM_INFO    0x0000013A  /* SACM INFO MSR */
#define MSR_IA32_FEATURE_CONTROL    0x0000003A

/* Boot Guard SACM INFO bit definitions */
#define BG_SACM_INFO_NEM_ENABLED        (1ULL << 0)
#define BG_SACM_INFO_TPM_SUCCESS        (1ULL << 3)
#define BG_SACM_INFO_TPM_DEACTIVATED    (1ULL << 4)
#define BG_SACM_INFO_MEASURED_BOOT      (1ULL << 5)
#define BG_SACM_INFO_VERIFIED_BOOT      (1ULL << 6)
#define BG_SACM_INFO_REVOKED            (1ULL << 7)
#define BG_SACM_INFO_BTG_CAPABLE        (1ULL << 32)
#define BG_SACM_INFO_BTG_ACM_ACTIVE     (1ULL << 33)
#define BG_SACM_INFO_FORCE_ANCHOR       (1ULL << 34)
#define BG_SACM_INFO_FPF_SOC_CONFIG_LOCK (1ULL << 35)

/* Boot Guard enforcement policies */
typedef enum {
    BG_POLICY_DISABLED = 0,
    BG_POLICY_MEASURED_BOOT,        /* Measure only */
    BG_POLICY_VERIFIED_BOOT,        /* Verify only */
    BG_POLICY_MEASURED_AND_VERIFIED /* Both */
} bootguard_policy_t;

/* Boot Guard status result */
typedef struct {
    /* Basic detection */
    bool bootguard_capable;
    bool bootguard_enabled;
    bool acm_active;

    /* Policy */
    bootguard_policy_t policy;
    bool measured_boot;
    bool verified_boot;

    /* Security state */
    bool nem_enabled;
    bool tpm_success;
    bool tpm_deactivated;
    bool key_revoked;
    bool force_anchor;
    bool fpf_locked;

    /* Raw MSR value */
    uint64_t sacm_info_raw;

    /* Risk assessment */
    risk_level_t risk_level;
    char risk_reason[256];

    /* Summary */
    char summary[512];
} bootguard_status_t;

/* Boot Guard Key Manifest structure */
typedef struct {
    uint8_t km_id[32];
    uint8_t km_hash[32];
    char km_hash_hex[65];
    uint32_t km_svn;
    bool km_present;
} key_manifest_t;

/* Boot Policy Manifest structure */
typedef struct {
    uint8_t bpm_hash[32];
    char bpm_hash_hex[65];
    uint32_t bpm_svn;
    bool bpm_present;
    bool ibb_verified;
} boot_policy_manifest_t;

/* Full Boot Guard policy analysis */
typedef struct {
    bootguard_status_t status;

    /* Key Manifest */
    key_manifest_t key_manifest;

    /* Boot Policy Manifest */
    boot_policy_manifest_t boot_policy;

    /* ACM info */
    char acm_version[32];
    uint32_t acm_svn;
    bool acm_production;
    bool acm_debug;

    /* Detailed findings */
    int finding_count;
    char findings[16][256];

    /* Summary */
    char summary[1024];
} bootguard_policy_result_t;

/* Secure Boot key information */
typedef struct {
    char name[64];          /* Key name (PK, KEK, db, dbx, etc.) */
    int cert_count;         /* Number of certificates/hashes */
    bool present;
    size_t data_size;
    char owner_guid[64];
} secureboot_key_t;

/* Secure Boot audit result */
typedef struct {
    /* Secure Boot status */
    bool secure_boot_enabled;
    bool setup_mode;
    bool audit_mode;
    bool deployed_mode;

    /* Keys */
    secureboot_key_t pk;    /* Platform Key */
    secureboot_key_t kek;   /* Key Exchange Key */
    secureboot_key_t db;    /* Signature Database */
    secureboot_key_t dbx;   /* Revocation Database */
    secureboot_key_t dbt;   /* Timestamp Database */
    secureboot_key_t dbr;   /* Recovery Database */

    /* Custom keys detected */
    bool custom_pk;
    bool custom_kek;
    bool microsoft_ca_present;
    bool microsoft_uefi_present;

    /* Risk assessment */
    risk_level_t risk_level;
    char risk_reason[256];

    /* Findings */
    int finding_count;
    char findings[16][256];

    /* Summary */
    char summary[1024];
} secureboot_audit_t;

/* Initialize Boot Guard detection */
int bootguard_init(void);
void bootguard_cleanup(void);

/* Command 1: Boot Guard Status Detection */
int bootguard_scan_status(bootguard_status_t *result);
void bootguard_status_print(const bootguard_status_t *result);
int bootguard_status_to_json(const bootguard_status_t *result, char *buffer, size_t size);

/* Command 2: Boot Guard Policy Analysis */
int bootguard_scan_policy(bootguard_policy_result_t *result);
void bootguard_policy_print(const bootguard_policy_result_t *result, bool verbose);
int bootguard_policy_to_json(const bootguard_policy_result_t *result, char *buffer, size_t size);

/* Command 3: Secure Boot Audit */
int secureboot_audit_scan(secureboot_audit_t *result);
void secureboot_audit_print(const secureboot_audit_t *result, bool verbose);
int secureboot_audit_to_json(const secureboot_audit_t *result, char *buffer, size_t size);

/* Helper functions */
const char *bootguard_policy_to_string(bootguard_policy_t policy);
risk_level_t bootguard_assess_risk(const bootguard_status_t *status);

#endif /* FG_BOOTGUARD_DETECT_H */
