#include "smm_detect.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <cpuid.h>

/* Forward declarations for CPU detection */
static bool detect_is_intel(void);
static bool detect_is_amd(void);
static void add_finding(smm_scan_result_t *result, const char *finding);

int smm_detect_init(void) {
    FG_INFO("Initializing SMM detection subsystem...");

    /* Initialize MSR subsystem */
    int ret = msr_init();
    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        FG_WARN("MSR initialization failed - SMM detection will be limited");
        return ret;
    }

    FG_INFO("SMM detection subsystem initialized");
    return FG_SUCCESS;
}

void smm_detect_cleanup(void) {
    msr_cleanup();
    FG_INFO("SMM detection subsystem cleaned up");
}

static bool detect_is_intel(void) {
    unsigned int eax, ebx, ecx, edx;
    char vendor[13] = {0};

    if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
        return false;
    }

    /* Vendor string is EBX-EDX-ECX */
    memcpy(vendor, &ebx, 4);
    memcpy(vendor + 4, &edx, 4);
    memcpy(vendor + 8, &ecx, 4);

    return (strcmp(vendor, "GenuineIntel") == 0);
}

static bool detect_is_amd(void) {
    unsigned int eax, ebx, ecx, edx;
    char vendor[13] = {0};

    if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
        return false;
    }

    memcpy(vendor, &ebx, 4);
    memcpy(vendor + 4, &edx, 4);
    memcpy(vendor + 8, &ecx, 4);

    return (strcmp(vendor, "AuthenticAMD") == 0);
}

static void add_finding(smm_scan_result_t *result, const char *finding) {
    if (result->finding_count < 16) {
        strncpy(result->findings[result->finding_count], finding,
                sizeof(result->findings[0]) - 1);
        result->finding_count++;
    }
}

int smm_read_region_info(smm_region_info_t *info, bool is_amd) {
    uint64_t value;
    int ret;

    if (!info) {
        return FG_ERROR;
    }

    memset(info, 0, sizeof(smm_region_info_t));

    if (is_amd) {
        /* AMD: Read TSEG registers */
        ret = msr_read(0, MSR_SMM_ADDR, &value);
        if (ret == FG_SUCCESS) {
            info->smrr_base = value;
            info->smrr_valid = true;
        }

        ret = msr_read(0, MSR_SMM_MASK, &value);
        if (ret == FG_SUCCESS) {
            info->smrr_mask = value;
            /* AMD TSEG mask bit 0 indicates valid */
            info->smrr_locked = (value & 0x1) != 0;

            /* Calculate size from mask */
            if (info->smrr_mask & 0x1) {
                uint64_t mask = info->smrr_mask & 0xFFFFFFFFFFFFF000ULL;
                info->smram_size = (~mask + 1) & 0xFFFFFFFF;
            }
        }
    } else {
        /* Intel: Read SMRR registers */
        ret = msr_read(0, MSR_IA32_SMRR_PHYSBASE, &value);
        if (ret == FG_SUCCESS) {
            info->smrr_base = value & 0xFFFFFFFFFFFFF000ULL;
            info->smrr_valid = true;
        }

        ret = msr_read(0, MSR_IA32_SMRR_PHYSMASK, &value);
        if (ret == FG_SUCCESS) {
            info->smrr_mask = value;
            /* Intel SMRR valid bit is bit 11 */
            info->smrr_valid = (value & (1 << 11)) != 0;
            info->smrr_locked = true; /* SMRR is locked when valid on Intel */

            /* Calculate size from mask */
            if (info->smrr_valid) {
                uint64_t mask = value & 0xFFFFFFFFFFFFF000ULL;
                info->smram_size = (~mask + 1) & 0xFFFFFFFF;
            }
        }
    }

    /* Try to read SMBASE (may not be accessible from ring 0) */
    ret = msr_read(0, MSR_SMBASE, &value);
    if (ret == FG_SUCCESS) {
        info->smbase = value;
    } else {
        /* SMBASE is only readable in SMM, use default */
        info->smbase = 0x30000; /* Default SMM base address */
    }

    return info->smrr_valid ? FG_SUCCESS : FG_NOT_SUPPORTED;
}

int smm_read_smi_stats(smm_smi_stats_t *stats) {
    uint64_t value;
    int ret;

    if (!stats) {
        return FG_ERROR;
    }

    memset(stats, 0, sizeof(smm_smi_stats_t));

    /* Read SMI count MSR */
    ret = msr_read(0, MSR_SMI_COUNT, &value);
    if (ret == FG_SUCCESS) {
        stats->smi_count = value;
        stats->smi_count_supported = true;

        /* Estimate SMI rate (very rough) */
        /* This would need multiple samples over time for accuracy */
        stats->smi_rate_estimate = 0; /* Placeholder */

        return FG_SUCCESS;
    }

    stats->smi_count_supported = false;
    return FG_NOT_SUPPORTED;
}

int smm_read_security_config(smm_security_config_t *config) {
    uint64_t value;
    int ret;

    if (!config) {
        return FG_ERROR;
    }

    memset(config, 0, sizeof(smm_security_config_t));

    /* Read IA32_FEATURE_CONTROL */
    ret = msr_read(0, MSR_IA32_FEATURE_CONTROL, &value);
    if (ret == FG_SUCCESS) {
        config->feature_control_raw = value;
        config->feature_control_locked = (value & FEATURE_CONTROL_LOCK) != 0;
        config->vmx_in_smx_enabled = (value & FEATURE_CONTROL_VMX_SMX) != 0;
        config->vmx_outside_smx_enabled = (value & FEATURE_CONTROL_VMX_OUTSIDE) != 0;
        config->senter_enabled = (value & FEATURE_CONTROL_SENTER_GE) != 0;
        config->sgx_enabled = (value & FEATURE_CONTROL_SGX_GE) != 0;
    }

    /* Read SMM Monitor Control */
    ret = msr_read(0, MSR_IA32_SMM_MONITOR_CTL, &value);
    if (ret == FG_SUCCESS) {
        config->smm_monitor_valid = (value & 0x1) != 0;
    }

    return FG_SUCCESS;
}

smm_risk_t smm_assess_risk(const smm_scan_result_t *result) {
    int risk_score = 0;

    if (!result || !result->smm_present) {
        return SMM_RISK_NONE;
    }

    /* SMRR not configured: CRITICAL */
    if (!result->region.smrr_valid) {
        risk_score += 5;
    }

    /* SMRR not locked: HIGH */
    if (result->region.smrr_valid && !result->region.smrr_locked) {
        risk_score += 3;
    }

    /* Feature control not locked: MEDIUM */
    if (!result->security.feature_control_locked) {
        risk_score += 2;
    }

    /* High SMI count (potential SMM rootkit activity): MEDIUM */
    if (result->smi_stats.smi_count_supported && result->smi_stats.smi_count > 1000000) {
        risk_score += 2;
    }

    /* SMM Monitor valid but VMX not in SMX: potential vulnerability */
    if (result->security.smm_monitor_valid && !result->security.vmx_in_smx_enabled) {
        risk_score += 1;
    }

    /* Translate score to risk level */
    if (risk_score >= 5) {
        return SMM_RISK_CRITICAL;
    } else if (risk_score >= 3) {
        return SMM_RISK_HIGH;
    } else if (risk_score >= 2) {
        return SMM_RISK_MEDIUM;
    } else if (risk_score >= 1) {
        return SMM_RISK_LOW;
    }

    return SMM_RISK_NONE;
}

const char *smm_risk_to_string(smm_risk_t risk) {
    switch (risk) {
        case SMM_RISK_CRITICAL: return "CRITICAL";
        case SMM_RISK_HIGH:     return "HIGH";
        case SMM_RISK_MEDIUM:   return "MEDIUM";
        case SMM_RISK_LOW:      return "LOW";
        case SMM_RISK_NONE:     return "NONE";
        default:                return "UNKNOWN";
    }
}

int smm_scan(smm_scan_result_t *result) {
    if (!result) {
        return FG_ERROR;
    }

    memset(result, 0, sizeof(smm_scan_result_t));

    FG_INFO("Starting SMM security scan...");

    /* Detect CPU vendor */
    result->is_intel = detect_is_intel();
    result->is_amd = detect_is_amd();

    if (!result->is_intel && !result->is_amd) {
        FG_WARN("Unknown CPU vendor - SMM detection may be incomplete");
        add_finding(result, "Unknown CPU vendor detected");
    }

    /* Get CPU count */
    result->cpu_count = msr_get_cpu_count();
    FG_INFO("Detected %d CPU(s)", result->cpu_count);

    /* SMM is present on all x86 systems */
    result->smm_present = true;
    add_finding(result, "System Management Mode (SMM) is present");

    /* Read SMM region information */
    int ret = smm_read_region_info(&result->region, result->is_amd);
    if (ret == FG_SUCCESS) {
        if (result->is_intel) {
            add_finding(result, "Intel SMRR (System Management Range Register) configured");
        } else if (result->is_amd) {
            add_finding(result, "AMD TSEG (Top of SMM) configured");
        }

        if (result->region.smrr_locked) {
            add_finding(result, "SMRAM protection is locked (good)");
        } else {
            add_finding(result, "WARNING: SMRAM protection is NOT locked");
        }

        char size_str[64];
        snprintf(size_str, sizeof(size_str), "SMRAM size: %lu KB",
                 result->region.smram_size / 1024);
        add_finding(result, size_str);
    } else {
        add_finding(result, "WARNING: Could not read SMRR/TSEG configuration");
    }

    /* Read SMI statistics */
    ret = smm_read_smi_stats(&result->smi_stats);
    if (ret == FG_SUCCESS) {
        char smi_str[64];
        snprintf(smi_str, sizeof(smi_str), "SMI count: %lu",
                 result->smi_stats.smi_count);
        add_finding(result, smi_str);

        if (result->smi_stats.smi_count > 1000000) {
            add_finding(result, "WARNING: High SMI count detected");
        }
    } else {
        add_finding(result, "SMI count MSR not available");
    }

    /* Read security configuration */
    smm_read_security_config(&result->security);

    if (result->security.feature_control_locked) {
        add_finding(result, "IA32_FEATURE_CONTROL is locked (good)");
    } else {
        add_finding(result, "WARNING: IA32_FEATURE_CONTROL is NOT locked");
    }

    if (result->security.senter_enabled) {
        add_finding(result, "Intel TXT (SENTER) is enabled");
    }

    if (result->security.sgx_enabled) {
        add_finding(result, "Intel SGX is enabled");
    }

    /* Assess risk */
    result->risk_level = smm_assess_risk(result);

    /* Generate risk reason */
    if (result->risk_level >= SMM_RISK_HIGH) {
        if (!result->region.smrr_valid) {
            strncpy(result->risk_reason, "SMRR/TSEG not properly configured - SMRAM vulnerable",
                    sizeof(result->risk_reason) - 1);
        } else if (!result->region.smrr_locked) {
            strncpy(result->risk_reason, "SMRAM protection not locked - configuration vulnerable",
                    sizeof(result->risk_reason) - 1);
        } else if (!result->security.feature_control_locked) {
            strncpy(result->risk_reason, "Feature control not locked - security features can be modified",
                    sizeof(result->risk_reason) - 1);
        }
    } else {
        strncpy(result->risk_reason, "SMM configuration appears secure",
                sizeof(result->risk_reason) - 1);
    }

    /* Generate summary */
    snprintf(result->summary, sizeof(result->summary),
            "SMM Scan Complete: %s CPU, SMRR %s, SMRAM %s (%lu KB), Risk: %s",
            result->is_intel ? "Intel" : (result->is_amd ? "AMD" : "Unknown"),
            result->region.smrr_valid ? "configured" : "NOT configured",
            result->region.smrr_locked ? "locked" : "UNLOCKED",
            result->region.smram_size / 1024,
            smm_risk_to_string(result->risk_level));

    FG_INFO("%s", result->summary);

    return FG_SUCCESS;
}

int smm_scan_brief(smm_scan_result_t *result) {
    if (!result) {
        return FG_ERROR;
    }

    memset(result, 0, sizeof(smm_scan_result_t));

    /* Quick detection */
    result->is_intel = detect_is_intel();
    result->is_amd = detect_is_amd();
    result->smm_present = true;
    result->cpu_count = msr_get_cpu_count();

    /* Quick SMRR check */
    smm_read_region_info(&result->region, result->is_amd);

    /* Quick risk assessment */
    if (!result->region.smrr_valid) {
        result->risk_level = SMM_RISK_CRITICAL;
    } else if (!result->region.smrr_locked) {
        result->risk_level = SMM_RISK_HIGH;
    } else {
        result->risk_level = SMM_RISK_LOW;
    }

    snprintf(result->summary, sizeof(result->summary),
            "SMM: %s, SMRR: %s, Risk: %s",
            result->is_intel ? "Intel" : "AMD",
            result->region.smrr_valid ? "OK" : "MISSING",
            smm_risk_to_string(result->risk_level));

    return FG_SUCCESS;
}

void smm_print_result(const smm_scan_result_t *result, bool verbose) {
    if (!result) {
        return;
    }

    printf("\n");
    printf("============================================\n");
    printf("  SMM (System Management Mode) Scan Results\n");
    printf("============================================\n");
    printf("\n");

    printf("CPU Information:\n");
    printf("  Vendor: %s\n", result->is_intel ? "Intel" :
                            (result->is_amd ? "AMD" : "Unknown"));
    printf("  CPU Count: %d\n", result->cpu_count);
    printf("\n");

    printf("SMRAM Protection:\n");
    if (result->region.smrr_valid) {
        printf("  SMRR/TSEG Base: 0x%016lX\n", result->region.smrr_base);
        printf("  SMRR/TSEG Mask: 0x%016lX\n", result->region.smrr_mask);
        printf("  SMRAM Size: %lu KB (%lu MB)\n",
               result->region.smram_size / 1024,
               result->region.smram_size / (1024 * 1024));
        printf("  Protection Locked: %s\n",
               result->region.smrr_locked ? "Yes (Good)" : "NO (VULNERABLE)");
    } else {
        printf("  WARNING: SMRR/TSEG NOT CONFIGURED\n");
        printf("  SMRAM is potentially vulnerable to attacks\n");
    }
    printf("\n");

    if (result->smi_stats.smi_count_supported) {
        printf("SMI Statistics:\n");
        printf("  Total SMI Count: %lu\n", result->smi_stats.smi_count);
        if (result->smi_stats.smi_count > 1000000) {
            printf("  WARNING: High SMI count may indicate SMM activity\n");
        }
        printf("\n");
    }

    printf("Security Configuration:\n");
    printf("  IA32_FEATURE_CONTROL: 0x%016lX\n",
           result->security.feature_control_raw);
    printf("  Feature Control Locked: %s\n",
           result->security.feature_control_locked ? "Yes (Good)" : "NO");
    printf("  VMX in SMX Mode: %s\n",
           result->security.vmx_in_smx_enabled ? "Enabled" : "Disabled");
    printf("  VMX outside SMX: %s\n",
           result->security.vmx_outside_smx_enabled ? "Enabled" : "Disabled");
    printf("  Intel TXT (SENTER): %s\n",
           result->security.senter_enabled ? "Enabled" : "Disabled");
    printf("  Intel SGX: %s\n",
           result->security.sgx_enabled ? "Enabled" : "Disabled");
    printf("\n");

    printf("Risk Assessment:\n");
    printf("  Risk Level: %s\n", smm_risk_to_string(result->risk_level));
    printf("  Assessment: %s\n", result->risk_reason);
    printf("\n");

    if (verbose && result->finding_count > 0) {
        printf("Detailed Findings:\n");
        for (int i = 0; i < result->finding_count; i++) {
            printf("  [%d] %s\n", i + 1, result->findings[i]);
        }
        printf("\n");
    }

    /* Recommendations based on risk */
    if (result->risk_level >= SMM_RISK_HIGH) {
        printf("Recommendations:\n");
        if (!result->region.smrr_valid) {
            printf("  - CRITICAL: Update firmware to enable SMRR/TSEG protection\n");
            printf("  - Check for BIOS/UEFI updates from your vendor\n");
        }
        if (!result->region.smrr_locked) {
            printf("  - HIGH: SMRAM protection should be locked at boot\n");
            printf("  - This may indicate a firmware vulnerability\n");
        }
        if (!result->security.feature_control_locked) {
            printf("  - MEDIUM: IA32_FEATURE_CONTROL should be locked\n");
            printf("  - Security features can be modified by malware\n");
        }
        printf("\n");
    }

    printf("Summary: %s\n", result->summary);
    printf("\n");
}

int smm_result_to_json(const smm_scan_result_t *result, char *buffer, size_t size) {
    if (!result || !buffer || size == 0) {
        return FG_ERROR;
    }

    int written = snprintf(buffer, size,
        "{\n"
        "  \"smm_present\": %s,\n"
        "  \"cpu_vendor\": \"%s\",\n"
        "  \"cpu_count\": %d,\n"
        "  \"smram\": {\n"
        "    \"smrr_configured\": %s,\n"
        "    \"smrr_base\": \"0x%016lX\",\n"
        "    \"smrr_mask\": \"0x%016lX\",\n"
        "    \"size_bytes\": %lu,\n"
        "    \"locked\": %s\n"
        "  },\n"
        "  \"smi_stats\": {\n"
        "    \"supported\": %s,\n"
        "    \"count\": %lu\n"
        "  },\n"
        "  \"security\": {\n"
        "    \"feature_control_locked\": %s,\n"
        "    \"vmx_in_smx\": %s,\n"
        "    \"vmx_outside_smx\": %s,\n"
        "    \"senter_enabled\": %s,\n"
        "    \"sgx_enabled\": %s\n"
        "  },\n"
        "  \"risk\": {\n"
        "    \"level\": \"%s\",\n"
        "    \"reason\": \"%s\"\n"
        "  },\n"
        "  \"summary\": \"%s\"\n"
        "}\n",
        result->smm_present ? "true" : "false",
        result->is_intel ? "Intel" : (result->is_amd ? "AMD" : "Unknown"),
        result->cpu_count,
        result->region.smrr_valid ? "true" : "false",
        result->region.smrr_base,
        result->region.smrr_mask,
        result->region.smram_size,
        result->region.smrr_locked ? "true" : "false",
        result->smi_stats.smi_count_supported ? "true" : "false",
        result->smi_stats.smi_count,
        result->security.feature_control_locked ? "true" : "false",
        result->security.vmx_in_smx_enabled ? "true" : "false",
        result->security.vmx_outside_smx_enabled ? "true" : "false",
        result->security.senter_enabled ? "true" : "false",
        result->security.sgx_enabled ? "true" : "false",
        smm_risk_to_string(result->risk_level),
        result->risk_reason,
        result->summary
    );

    return (written > 0 && (size_t)written < size) ? FG_SUCCESS : FG_ERROR;
}
