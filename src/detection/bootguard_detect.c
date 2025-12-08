#include "bootguard_detect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define EFIVARS_PATH "/sys/firmware/efi/efivars"
#define UEFI_GLOBAL_GUID "8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define EFI_IMAGE_SECURITY_DB_GUID "d719b2cb-3d3a-4596-a3bc-dad00e67656f"

/* Forward declarations */
static void add_status_finding(bootguard_policy_result_t *result, const char *finding);
static void add_sb_finding(secureboot_audit_t *result, const char *finding);
static int read_efi_variable_size(const char *name, const char *guid, size_t *size);
static int read_efi_variable_byte(const char *name, const char *guid, uint8_t *value);

int bootguard_init(void) {
    FG_INFO("Initializing Boot Guard detection subsystem...");

    int ret = msr_init();
    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        FG_WARN("MSR initialization failed - Boot Guard detection limited");
    }

    FG_INFO("Boot Guard detection subsystem initialized");
    return FG_SUCCESS;
}

void bootguard_cleanup(void) {
    msr_cleanup();
    FG_INFO("Boot Guard detection subsystem cleaned up");
}

static void add_status_finding(bootguard_policy_result_t *result, const char *finding) {
    if (result && result->finding_count < 16) {
        strncpy(result->findings[result->finding_count], finding,
                sizeof(result->findings[0]) - 1);
        result->finding_count++;
    }
}

static void add_sb_finding(secureboot_audit_t *result, const char *finding) {
    if (result && result->finding_count < 16) {
        strncpy(result->findings[result->finding_count], finding,
                sizeof(result->findings[0]) - 1);
        result->finding_count++;
    }
}

static int read_efi_variable_size(const char *name, const char *guid, size_t *size) {
    char path[768];
    struct stat st;

    snprintf(path, sizeof(path), "%s/%s-%s", EFIVARS_PATH, name, guid);

    if (stat(path, &st) != 0) {
        return FG_NOT_FOUND;
    }

    /* Subtract 4 bytes for attributes */
    *size = st.st_size > 4 ? st.st_size - 4 : 0;
    return FG_SUCCESS;
}

static int read_efi_variable_byte(const char *name, const char *guid, uint8_t *value) {
    char path[768];
    FILE *fp;
    uint32_t attrs;
    int ret = FG_ERROR;

    snprintf(path, sizeof(path), "%s/%s-%s", EFIVARS_PATH, name, guid);

    fp = fopen(path, "rb");
    if (!fp) {
        return FG_NOT_FOUND;
    }

    if (fread(&attrs, sizeof(uint32_t), 1, fp) == 1 &&
        fread(value, sizeof(uint8_t), 1, fp) == 1) {
        ret = FG_SUCCESS;
    }

    fclose(fp);
    return ret;
}

const char *bootguard_policy_to_string(bootguard_policy_t policy) {
    switch (policy) {
        case BG_POLICY_DISABLED:            return "Disabled";
        case BG_POLICY_MEASURED_BOOT:       return "Measured Boot";
        case BG_POLICY_VERIFIED_BOOT:       return "Verified Boot";
        case BG_POLICY_MEASURED_AND_VERIFIED: return "Measured + Verified Boot";
        default:                            return "Unknown";
    }
}

risk_level_t bootguard_assess_risk(const bootguard_status_t *status) {
    int risk_score = 0;

    if (!status) return RISK_NONE;

    /* Boot Guard not capable: MEDIUM (older platform) */
    if (!status->bootguard_capable) {
        return RISK_MEDIUM;
    }

    /* Boot Guard capable but disabled: HIGH */
    if (status->bootguard_capable && !status->bootguard_enabled) {
        risk_score += 4;
    }

    /* No verified boot: HIGH */
    if (status->bootguard_enabled && !status->verified_boot) {
        risk_score += 3;
    }

    /* Key revoked: CRITICAL */
    if (status->key_revoked) {
        risk_score += 5;
    }

    /* TPM issues */
    if (status->bootguard_enabled && status->tpm_deactivated) {
        risk_score += 2;
    }

    /* FPF not locked: MEDIUM */
    if (status->bootguard_enabled && !status->fpf_locked) {
        risk_score += 2;
    }

    if (risk_score >= 5) return RISK_CRITICAL;
    if (risk_score >= 4) return RISK_HIGH;
    if (risk_score >= 2) return RISK_MEDIUM;
    if (risk_score >= 1) return RISK_LOW;

    return RISK_NONE;
}

int bootguard_scan_status(bootguard_status_t *result) {
    uint64_t sacm_info;
    int ret;

    if (!result) return FG_ERROR;

    memset(result, 0, sizeof(bootguard_status_t));

    FG_INFO("Scanning Boot Guard status...");

    /* Read SACM INFO MSR */
    ret = msr_read(0, MSR_BOOT_GUARD_SACM_INFO, &sacm_info);
    if (ret != FG_SUCCESS) {
        /* Try alternative approach - check CPU support */
        FG_WARN("Cannot read Boot Guard SACM INFO MSR");
        FG_WARN("Boot Guard status detection may be incomplete");

        /* Assume not capable if we can't read the MSR */
        result->bootguard_capable = false;
        snprintf(result->summary, sizeof(result->summary),
                "Boot Guard: Unable to detect (MSR not accessible)");
        result->risk_level = RISK_MEDIUM;
        strncpy(result->risk_reason, "Cannot determine Boot Guard status",
                sizeof(result->risk_reason) - 1);
        return FG_NOT_SUPPORTED;
    }

    result->sacm_info_raw = sacm_info;

    /* Parse SACM INFO bits */
    result->nem_enabled = (sacm_info & BG_SACM_INFO_NEM_ENABLED) != 0;
    result->tpm_success = (sacm_info & BG_SACM_INFO_TPM_SUCCESS) != 0;
    result->tpm_deactivated = (sacm_info & BG_SACM_INFO_TPM_DEACTIVATED) != 0;
    result->measured_boot = (sacm_info & BG_SACM_INFO_MEASURED_BOOT) != 0;
    result->verified_boot = (sacm_info & BG_SACM_INFO_VERIFIED_BOOT) != 0;
    result->key_revoked = (sacm_info & BG_SACM_INFO_REVOKED) != 0;
    result->bootguard_capable = (sacm_info & BG_SACM_INFO_BTG_CAPABLE) != 0;
    result->acm_active = (sacm_info & BG_SACM_INFO_BTG_ACM_ACTIVE) != 0;
    result->force_anchor = (sacm_info & BG_SACM_INFO_FORCE_ANCHOR) != 0;
    result->fpf_locked = (sacm_info & BG_SACM_INFO_FPF_SOC_CONFIG_LOCK) != 0;

    /* Determine if Boot Guard is enabled */
    result->bootguard_enabled = result->bootguard_capable &&
                                 (result->measured_boot || result->verified_boot);

    /* Determine policy */
    if (!result->bootguard_enabled) {
        result->policy = BG_POLICY_DISABLED;
    } else if (result->measured_boot && result->verified_boot) {
        result->policy = BG_POLICY_MEASURED_AND_VERIFIED;
    } else if (result->verified_boot) {
        result->policy = BG_POLICY_VERIFIED_BOOT;
    } else if (result->measured_boot) {
        result->policy = BG_POLICY_MEASURED_BOOT;
    } else {
        result->policy = BG_POLICY_DISABLED;
    }

    /* Assess risk */
    result->risk_level = bootguard_assess_risk(result);

    /* Generate risk reason */
    if (result->key_revoked) {
        strncpy(result->risk_reason, "Boot Guard key has been revoked!",
                sizeof(result->risk_reason) - 1);
    } else if (!result->bootguard_capable) {
        strncpy(result->risk_reason, "Platform does not support Boot Guard",
                sizeof(result->risk_reason) - 1);
    } else if (!result->bootguard_enabled) {
        strncpy(result->risk_reason, "Boot Guard is disabled",
                sizeof(result->risk_reason) - 1);
    } else if (!result->verified_boot) {
        strncpy(result->risk_reason, "Verified Boot not enabled",
                sizeof(result->risk_reason) - 1);
    } else {
        strncpy(result->risk_reason, "Boot Guard properly configured",
                sizeof(result->risk_reason) - 1);
    }

    /* Generate summary */
    snprintf(result->summary, sizeof(result->summary),
            "Boot Guard: %s, Policy: %s, ACM: %s, Risk: %s",
            result->bootguard_capable ? (result->bootguard_enabled ? "Enabled" : "Disabled") : "Not Supported",
            bootguard_policy_to_string(result->policy),
            result->acm_active ? "Active" : "Inactive",
            result->risk_level == RISK_CRITICAL ? "CRITICAL" :
            result->risk_level == RISK_HIGH ? "HIGH" :
            result->risk_level == RISK_MEDIUM ? "MEDIUM" :
            result->risk_level == RISK_LOW ? "LOW" : "NONE");

    FG_INFO("%s", result->summary);

    return FG_SUCCESS;
}

int bootguard_scan_policy(bootguard_policy_result_t *result) {
    if (!result) return FG_ERROR;

    memset(result, 0, sizeof(bootguard_policy_result_t));

    FG_INFO("Scanning Boot Guard policy configuration...");

    /* First get basic status */
    int ret = bootguard_scan_status(&result->status);
    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        return ret;
    }

    /* Add findings based on status */
    if (result->status.bootguard_capable) {
        add_status_finding(result, "Platform supports Intel Boot Guard");
    } else {
        add_status_finding(result, "Platform does NOT support Intel Boot Guard");
        snprintf(result->summary, sizeof(result->summary),
                "Boot Guard not supported on this platform");
        return FG_SUCCESS;
    }

    if (result->status.bootguard_enabled) {
        add_status_finding(result, "Boot Guard is ENABLED");
    } else {
        add_status_finding(result, "WARNING: Boot Guard is DISABLED");
    }

    if (result->status.acm_active) {
        add_status_finding(result, "ACM (Authenticated Code Module) is active");
    }

    if (result->status.measured_boot) {
        add_status_finding(result, "Measured Boot is enabled");
    }

    if (result->status.verified_boot) {
        add_status_finding(result, "Verified Boot is enabled");
    }

    if (result->status.key_revoked) {
        add_status_finding(result, "CRITICAL: Boot Guard key has been REVOKED");
    }

    if (result->status.fpf_locked) {
        add_status_finding(result, "Field Programmable Fuses (FPF) are locked (good)");
    } else {
        add_status_finding(result, "WARNING: FPF not locked - configuration may be modifiable");
    }

    if (result->status.tpm_success) {
        add_status_finding(result, "TPM initialization successful");
    }

    if (result->status.tpm_deactivated) {
        add_status_finding(result, "WARNING: TPM is deactivated");
    }

    /* Note: Full Key Manifest and Boot Policy Manifest extraction
     * requires parsing firmware image - mark as not extracted */
    result->key_manifest.km_present = false;
    result->boot_policy.bpm_present = false;

    add_status_finding(result, "Note: KM/BPM extraction requires firmware image analysis");

    /* Generate summary */
    snprintf(result->summary, sizeof(result->summary),
            "Boot Guard Policy: %s, Measured: %s, Verified: %s, FPF Locked: %s",
            bootguard_policy_to_string(result->status.policy),
            result->status.measured_boot ? "Yes" : "No",
            result->status.verified_boot ? "Yes" : "No",
            result->status.fpf_locked ? "Yes" : "No");

    return FG_SUCCESS;
}

int secureboot_audit_scan(secureboot_audit_t *result) {
    uint8_t value;
    size_t size;

    if (!result) return FG_ERROR;

    memset(result, 0, sizeof(secureboot_audit_t));

    FG_INFO("Auditing Secure Boot configuration...");

    /* Check if EFI variables are accessible */
    struct stat st;
    if (stat(EFIVARS_PATH, &st) != 0) {
        FG_WARN("EFI variables not accessible - system may not be UEFI boot");
        add_sb_finding(result, "EFI variables not accessible");
        result->risk_level = RISK_MEDIUM;
        strncpy(result->risk_reason, "Cannot access UEFI variables",
                sizeof(result->risk_reason) - 1);
        return FG_NOT_SUPPORTED;
    }

    /* Read Secure Boot status */
    if (read_efi_variable_byte("SecureBoot", UEFI_GLOBAL_GUID, &value) == FG_SUCCESS) {
        result->secure_boot_enabled = (value == 1);
        if (result->secure_boot_enabled) {
            add_sb_finding(result, "Secure Boot is ENABLED");
        } else {
            add_sb_finding(result, "WARNING: Secure Boot is DISABLED");
        }
    } else {
        add_sb_finding(result, "SecureBoot variable not found");
    }

    /* Read Setup Mode */
    if (read_efi_variable_byte("SetupMode", UEFI_GLOBAL_GUID, &value) == FG_SUCCESS) {
        result->setup_mode = (value == 1);
        if (result->setup_mode) {
            add_sb_finding(result, "WARNING: System is in Setup Mode - keys can be modified!");
        } else {
            add_sb_finding(result, "System is NOT in Setup Mode (good)");
        }
    }

    /* Read Audit Mode */
    if (read_efi_variable_byte("AuditMode", UEFI_GLOBAL_GUID, &value) == FG_SUCCESS) {
        result->audit_mode = (value == 1);
        if (result->audit_mode) {
            add_sb_finding(result, "Audit Mode is enabled");
        }
    }

    /* Read Deployed Mode */
    if (read_efi_variable_byte("DeployedMode", UEFI_GLOBAL_GUID, &value) == FG_SUCCESS) {
        result->deployed_mode = (value == 1);
        if (result->deployed_mode) {
            add_sb_finding(result, "Deployed Mode is enabled (most secure)");
        }
    }

    /* Check Platform Key (PK) */
    if (read_efi_variable_size("PK", UEFI_GLOBAL_GUID, &size) == FG_SUCCESS) {
        strncpy(result->pk.name, "Platform Key (PK)", sizeof(result->pk.name) - 1);
        result->pk.present = true;
        result->pk.data_size = size;
        add_sb_finding(result, "Platform Key (PK) is enrolled");
    } else {
        add_sb_finding(result, "WARNING: Platform Key (PK) not enrolled");
    }

    /* Check KEK */
    if (read_efi_variable_size("KEK", UEFI_GLOBAL_GUID, &size) == FG_SUCCESS) {
        strncpy(result->kek.name, "Key Exchange Key (KEK)", sizeof(result->kek.name) - 1);
        result->kek.present = true;
        result->kek.data_size = size;
        add_sb_finding(result, "Key Exchange Key (KEK) is enrolled");
    } else {
        add_sb_finding(result, "WARNING: KEK not enrolled");
    }

    /* Check db (Signature Database) */
    if (read_efi_variable_size("db", EFI_IMAGE_SECURITY_DB_GUID, &size) == FG_SUCCESS) {
        strncpy(result->db.name, "Signature Database (db)", sizeof(result->db.name) - 1);
        result->db.present = true;
        result->db.data_size = size;
        char finding[256];
        snprintf(finding, sizeof(finding), "Signature Database (db): %zu bytes", size);
        add_sb_finding(result, finding);
    }

    /* Check dbx (Revocation Database) */
    if (read_efi_variable_size("dbx", EFI_IMAGE_SECURITY_DB_GUID, &size) == FG_SUCCESS) {
        strncpy(result->dbx.name, "Revocation Database (dbx)", sizeof(result->dbx.name) - 1);
        result->dbx.present = true;
        result->dbx.data_size = size;
        char finding[256];
        snprintf(finding, sizeof(finding), "Revocation Database (dbx): %zu bytes", size);
        add_sb_finding(result, finding);
    } else {
        add_sb_finding(result, "WARNING: Revocation Database (dbx) not present");
    }

    /* Risk assessment */
    int risk_score = 0;

    if (!result->secure_boot_enabled) {
        risk_score += 4;
    }

    if (result->setup_mode) {
        risk_score += 4;
    }

    if (!result->pk.present) {
        risk_score += 3;
    }

    if (!result->dbx.present) {
        risk_score += 1;
    }

    if (risk_score >= 5) {
        result->risk_level = RISK_CRITICAL;
    } else if (risk_score >= 4) {
        result->risk_level = RISK_HIGH;
    } else if (risk_score >= 2) {
        result->risk_level = RISK_MEDIUM;
    } else if (risk_score >= 1) {
        result->risk_level = RISK_LOW;
    } else {
        result->risk_level = RISK_NONE;
    }

    /* Generate risk reason */
    if (!result->secure_boot_enabled) {
        strncpy(result->risk_reason, "Secure Boot is disabled",
                sizeof(result->risk_reason) - 1);
    } else if (result->setup_mode) {
        strncpy(result->risk_reason, "System in Setup Mode - keys can be modified",
                sizeof(result->risk_reason) - 1);
    } else if (!result->pk.present) {
        strncpy(result->risk_reason, "Platform Key not enrolled",
                sizeof(result->risk_reason) - 1);
    } else {
        strncpy(result->risk_reason, "Secure Boot properly configured",
                sizeof(result->risk_reason) - 1);
    }

    /* Generate summary */
    snprintf(result->summary, sizeof(result->summary),
            "Secure Boot: %s, Setup Mode: %s, PK: %s, KEK: %s, db: %s, dbx: %s, Risk: %s",
            result->secure_boot_enabled ? "Enabled" : "DISABLED",
            result->setup_mode ? "YES" : "No",
            result->pk.present ? "Yes" : "No",
            result->kek.present ? "Yes" : "No",
            result->db.present ? "Yes" : "No",
            result->dbx.present ? "Yes" : "No",
            result->risk_level == RISK_CRITICAL ? "CRITICAL" :
            result->risk_level == RISK_HIGH ? "HIGH" :
            result->risk_level == RISK_MEDIUM ? "MEDIUM" :
            result->risk_level == RISK_LOW ? "LOW" : "NONE");

    FG_INFO("%s", result->summary);

    return FG_SUCCESS;
}

void bootguard_status_print(const bootguard_status_t *result) {
    if (!result) return;

    printf("\n");
    printf("==========================================\n");
    printf("  Intel Boot Guard Status\n");
    printf("==========================================\n");
    printf("\n");

    printf("Boot Guard Capable: %s\n", result->bootguard_capable ? "Yes" : "No");
    printf("Boot Guard Enabled: %s\n", result->bootguard_enabled ? "Yes" : "No");
    printf("ACM Active: %s\n", result->acm_active ? "Yes" : "No");
    printf("\n");

    printf("Policy: %s\n", bootguard_policy_to_string(result->policy));
    printf("  Measured Boot: %s\n", result->measured_boot ? "Enabled" : "Disabled");
    printf("  Verified Boot: %s\n", result->verified_boot ? "Enabled" : "Disabled");
    printf("\n");

    printf("Security State:\n");
    printf("  NEM Enabled: %s\n", result->nem_enabled ? "Yes" : "No");
    printf("  TPM Success: %s\n", result->tpm_success ? "Yes" : "No");
    printf("  TPM Deactivated: %s\n", result->tpm_deactivated ? "Yes" : "No");
    printf("  Key Revoked: %s\n", result->key_revoked ? "YES (WARNING!)" : "No");
    printf("  Force Anchor: %s\n", result->force_anchor ? "Yes" : "No");
    printf("  FPF Locked: %s\n", result->fpf_locked ? "Yes" : "No");
    printf("\n");

    printf("Raw SACM INFO MSR: 0x%016lX\n", result->sacm_info_raw);
    printf("\n");

    printf("Risk Assessment:\n");
    printf("  Level: %s\n",
           result->risk_level == RISK_CRITICAL ? "CRITICAL" :
           result->risk_level == RISK_HIGH ? "HIGH" :
           result->risk_level == RISK_MEDIUM ? "MEDIUM" :
           result->risk_level == RISK_LOW ? "LOW" : "NONE");
    printf("  Reason: %s\n", result->risk_reason);
    printf("\n");

    printf("Summary: %s\n", result->summary);
    printf("\n");
}

void bootguard_policy_print(const bootguard_policy_result_t *result, bool verbose) {
    if (!result) return;

    printf("\n");
    printf("==========================================\n");
    printf("  Intel Boot Guard Policy Analysis\n");
    printf("==========================================\n");
    printf("\n");

    /* Print status first */
    bootguard_status_print(&result->status);

    if (result->finding_count > 0) {
        printf("Policy Findings:\n");
        for (int i = 0; i < result->finding_count; i++) {
            printf("  [%d] %s\n", i + 1, result->findings[i]);
        }
        printf("\n");
    }

    if (verbose) {
        printf("Key Manifest: %s\n", result->key_manifest.km_present ? "Found" : "Not extracted");
        printf("Boot Policy Manifest: %s\n", result->boot_policy.bpm_present ? "Found" : "Not extracted");
        printf("\n");
    }

    printf("Summary: %s\n", result->summary);
    printf("\n");
}

void secureboot_audit_print(const secureboot_audit_t *result, bool verbose) {
    if (!result) return;

    printf("\n");
    printf("==========================================\n");
    printf("  UEFI Secure Boot Audit\n");
    printf("==========================================\n");
    printf("\n");

    printf("Secure Boot Status:\n");
    printf("  Secure Boot: %s\n", result->secure_boot_enabled ? "ENABLED" : "DISABLED");
    printf("  Setup Mode: %s\n", result->setup_mode ? "YES (keys can be modified!)" : "No");
    printf("  Audit Mode: %s\n", result->audit_mode ? "Yes" : "No");
    printf("  Deployed Mode: %s\n", result->deployed_mode ? "Yes (most secure)" : "No");
    printf("\n");

    printf("Secure Boot Keys:\n");
    printf("  Platform Key (PK): %s", result->pk.present ? "Enrolled" : "NOT ENROLLED");
    if (result->pk.present) printf(" (%zu bytes)", result->pk.data_size);
    printf("\n");

    printf("  Key Exchange Key (KEK): %s", result->kek.present ? "Enrolled" : "NOT ENROLLED");
    if (result->kek.present) printf(" (%zu bytes)", result->kek.data_size);
    printf("\n");

    printf("  Signature Database (db): %s", result->db.present ? "Present" : "NOT PRESENT");
    if (result->db.present) printf(" (%zu bytes)", result->db.data_size);
    printf("\n");

    printf("  Revocation Database (dbx): %s", result->dbx.present ? "Present" : "NOT PRESENT");
    if (result->dbx.present) printf(" (%zu bytes)", result->dbx.data_size);
    printf("\n\n");

    printf("Risk Assessment:\n");
    printf("  Level: %s\n",
           result->risk_level == RISK_CRITICAL ? "CRITICAL" :
           result->risk_level == RISK_HIGH ? "HIGH" :
           result->risk_level == RISK_MEDIUM ? "MEDIUM" :
           result->risk_level == RISK_LOW ? "LOW" : "NONE");
    printf("  Reason: %s\n", result->risk_reason);
    printf("\n");

    if (result->finding_count > 0) {
        printf("Audit Findings:\n");
        for (int i = 0; i < result->finding_count; i++) {
            printf("  [%d] %s\n", i + 1, result->findings[i]);
        }
        printf("\n");
    }

    /* Recommendations */
    if (result->risk_level >= RISK_HIGH) {
        printf("Recommendations:\n");
        if (!result->secure_boot_enabled) {
            printf("  - Enable Secure Boot in BIOS/UEFI settings\n");
        }
        if (result->setup_mode) {
            printf("  - Exit Setup Mode by enrolling Secure Boot keys\n");
            printf("  - Use mokutil or sbsigntools to manage keys\n");
        }
        if (!result->pk.present) {
            printf("  - Enroll a Platform Key (PK)\n");
        }
        if (!result->dbx.present) {
            printf("  - Update dbx with latest revocation list from UEFI.org\n");
        }
        printf("\n");
    }

    printf("Summary: %s\n", result->summary);
    printf("\n");
}

int bootguard_status_to_json(const bootguard_status_t *result, char *buffer, size_t size) {
    if (!result || !buffer || size == 0) return FG_ERROR;

    int written = snprintf(buffer, size,
        "{\n"
        "  \"bootguard_capable\": %s,\n"
        "  \"bootguard_enabled\": %s,\n"
        "  \"acm_active\": %s,\n"
        "  \"policy\": \"%s\",\n"
        "  \"measured_boot\": %s,\n"
        "  \"verified_boot\": %s,\n"
        "  \"nem_enabled\": %s,\n"
        "  \"tpm_success\": %s,\n"
        "  \"tpm_deactivated\": %s,\n"
        "  \"key_revoked\": %s,\n"
        "  \"fpf_locked\": %s,\n"
        "  \"sacm_info_raw\": \"0x%016lX\",\n"
        "  \"risk\": {\n"
        "    \"level\": \"%s\",\n"
        "    \"reason\": \"%s\"\n"
        "  },\n"
        "  \"summary\": \"%s\"\n"
        "}\n",
        result->bootguard_capable ? "true" : "false",
        result->bootguard_enabled ? "true" : "false",
        result->acm_active ? "true" : "false",
        bootguard_policy_to_string(result->policy),
        result->measured_boot ? "true" : "false",
        result->verified_boot ? "true" : "false",
        result->nem_enabled ? "true" : "false",
        result->tpm_success ? "true" : "false",
        result->tpm_deactivated ? "true" : "false",
        result->key_revoked ? "true" : "false",
        result->fpf_locked ? "true" : "false",
        result->sacm_info_raw,
        result->risk_level == RISK_CRITICAL ? "CRITICAL" :
        result->risk_level == RISK_HIGH ? "HIGH" :
        result->risk_level == RISK_MEDIUM ? "MEDIUM" :
        result->risk_level == RISK_LOW ? "LOW" : "NONE",
        result->risk_reason,
        result->summary
    );

    return (written > 0 && (size_t)written < size) ? FG_SUCCESS : FG_ERROR;
}

int bootguard_policy_to_json(const bootguard_policy_result_t *result, char *buffer, size_t size) {
    if (!result || !buffer || size == 0) return FG_ERROR;

    /* Just wrap the status JSON for now */
    return bootguard_status_to_json(&result->status, buffer, size);
}

int secureboot_audit_to_json(const secureboot_audit_t *result, char *buffer, size_t size) {
    if (!result || !buffer || size == 0) return FG_ERROR;

    int written = snprintf(buffer, size,
        "{\n"
        "  \"secure_boot_enabled\": %s,\n"
        "  \"setup_mode\": %s,\n"
        "  \"audit_mode\": %s,\n"
        "  \"deployed_mode\": %s,\n"
        "  \"keys\": {\n"
        "    \"pk\": { \"present\": %s, \"size\": %zu },\n"
        "    \"kek\": { \"present\": %s, \"size\": %zu },\n"
        "    \"db\": { \"present\": %s, \"size\": %zu },\n"
        "    \"dbx\": { \"present\": %s, \"size\": %zu }\n"
        "  },\n"
        "  \"risk\": {\n"
        "    \"level\": \"%s\",\n"
        "    \"reason\": \"%s\"\n"
        "  },\n"
        "  \"summary\": \"%s\"\n"
        "}\n",
        result->secure_boot_enabled ? "true" : "false",
        result->setup_mode ? "true" : "false",
        result->audit_mode ? "true" : "false",
        result->deployed_mode ? "true" : "false",
        result->pk.present ? "true" : "false", result->pk.data_size,
        result->kek.present ? "true" : "false", result->kek.data_size,
        result->db.present ? "true" : "false", result->db.data_size,
        result->dbx.present ? "true" : "false", result->dbx.data_size,
        result->risk_level == RISK_CRITICAL ? "CRITICAL" :
        result->risk_level == RISK_HIGH ? "HIGH" :
        result->risk_level == RISK_MEDIUM ? "MEDIUM" :
        result->risk_level == RISK_LOW ? "LOW" : "NONE",
        result->risk_reason,
        result->summary
    );

    return (written > 0 && (size_t)written < size) ? FG_SUCCESS : FG_ERROR;
}
