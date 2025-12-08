#include "txt_sgx_detect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cpuid.h>
#include <sys/mman.h>

/* Forward declarations */
static void txt_add_finding(txt_config_t *result, const char *finding);
static void sgx_add_finding(sgx_config_t *result, const char *finding);
static void tpm_add_finding(tpm_measurement_t *result, const char *finding);
static void tb_add_finding(trusted_boot_result_t *result, const char *finding);
static bool check_cpu_smx_support(void);
static bool check_cpu_sgx_support(void);

int txt_sgx_init(void) {
    FG_INFO("Initializing TXT/SGX detection subsystem...");

    int ret = msr_init();
    if (ret != FG_SUCCESS && ret != FG_NOT_SUPPORTED) {
        FG_WARN("MSR initialization failed - TXT/SGX detection limited");
    }

    FG_INFO("TXT/SGX detection subsystem initialized");
    return FG_SUCCESS;
}

void txt_sgx_cleanup(void) {
    msr_cleanup();
    FG_INFO("TXT/SGX detection subsystem cleaned up");
}

static void txt_add_finding(txt_config_t *result, const char *finding) {
    if (result && result->finding_count < 16) {
        strncpy(result->findings[result->finding_count], finding,
                sizeof(result->findings[0]) - 1);
        result->finding_count++;
    }
}

static void sgx_add_finding(sgx_config_t *result, const char *finding) {
    if (result && result->finding_count < 16) {
        strncpy(result->findings[result->finding_count], finding,
                sizeof(result->findings[0]) - 1);
        result->finding_count++;
    }
}

static void tpm_add_finding(tpm_measurement_t *result, const char *finding) {
    if (result && result->finding_count < 16) {
        strncpy(result->findings[result->finding_count], finding,
                sizeof(result->findings[0]) - 1);
        result->finding_count++;
    }
}

static void tb_add_finding(trusted_boot_result_t *result, const char *finding) {
    if (result && result->finding_count < 32) {
        strncpy(result->findings[result->finding_count], finding,
                sizeof(result->findings[0]) - 1);
        result->finding_count++;
    }
}

static bool check_cpu_smx_support(void) {
    unsigned int eax, ebx, ecx, edx;

    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return false;
    }

    /* SMX is bit 6 of ECX */
    return (ecx & (1 << 6)) != 0;
}

static bool check_cpu_sgx_support(void) {
    unsigned int eax, ebx, ecx, edx;

    /* Check CPUID leaf 7 for SGX support */
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return false;
    }

    /* SGX is bit 2 of EBX */
    return (ebx & (1 << 2)) != 0;
}

risk_level_t txt_assess_risk(const txt_config_t *config) {
    int risk_score = 0;

    if (!config) return RISK_NONE;

    /* TXT supported but not enabled: MEDIUM */
    if (config->txt_supported && !config->txt_enabled) {
        risk_score += 2;
    }

    /* Feature control not locked: HIGH */
    if (!config->feature_control_locked) {
        risk_score += 3;
    }

    /* SINIT ACM not present: MEDIUM */
    if (config->txt_enabled && !config->sinit_present) {
        risk_score += 2;
    }

    /* DPR not locked: MEDIUM */
    if (config->txt_enabled && !config->dpr_locked) {
        risk_score += 2;
    }

    /* TXT error detected: HIGH */
    if (config->txt_error != 0) {
        risk_score += 3;
    }

    if (risk_score >= 5) return RISK_CRITICAL;
    if (risk_score >= 3) return RISK_HIGH;
    if (risk_score >= 2) return RISK_MEDIUM;
    if (risk_score >= 1) return RISK_LOW;

    return RISK_NONE;
}

risk_level_t sgx_assess_risk(const sgx_config_t *config) {
    int risk_score = 0;

    if (!config) return RISK_NONE;

    /* SGX supported but not enabled: LOW (feature choice) */
    if (config->sgx_supported && !config->sgx_enabled) {
        risk_score += 1;
    }

    /* No flexible launch control: MEDIUM (Intel controls enclaves) */
    if (config->sgx_enabled && !config->flexible_launch_control) {
        risk_score += 2;
    }

    /* Very small EPC: MEDIUM (limited enclave capability) */
    if (config->sgx_enabled && config->total_epc_size < 32 * 1024 * 1024) {
        risk_score += 1;
    }

    if (risk_score >= 4) return RISK_HIGH;
    if (risk_score >= 2) return RISK_MEDIUM;
    if (risk_score >= 1) return RISK_LOW;

    return RISK_NONE;
}

int txt_scan_config(txt_config_t *result) {
    uint64_t feature_control;
    int ret;

    if (!result) return FG_ERROR;

    memset(result, 0, sizeof(txt_config_t));

    FG_INFO("Scanning Intel TXT configuration...");

    /* Check CPU SMX support */
    result->smx_supported = check_cpu_smx_support();
    if (result->smx_supported) {
        txt_add_finding(result, "CPU supports SMX (Safer Mode Extensions)");
        result->txt_supported = true;
    } else {
        txt_add_finding(result, "CPU does NOT support SMX - TXT unavailable");
        result->txt_supported = false;
        result->risk_level = RISK_MEDIUM;
        strncpy(result->risk_reason, "TXT not supported on this CPU",
                sizeof(result->risk_reason) - 1);
        snprintf(result->summary, sizeof(result->summary),
                "TXT: Not supported (SMX not available)");
        return FG_SUCCESS;
    }

    /* Check VMX support */
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        result->vmx_supported = (ecx & (1 << 5)) != 0;
        if (result->vmx_supported) {
            txt_add_finding(result, "CPU supports VMX (Intel VT-x)");
        }
    }

    /* Read Feature Control MSR */
    ret = msr_read(0, MSR_IA32_FEATURE_CONTROL, &feature_control);
    if (ret == FG_SUCCESS) {
        result->feature_control_raw = feature_control;
        result->feature_control_locked = (feature_control & FC_LOCK_BIT) != 0;
        result->senter_enabled = (feature_control & FC_SENTER_GLOBAL_ENABLE) != 0;
        result->txt_enabled = result->senter_enabled && result->feature_control_locked;

        if (result->feature_control_locked) {
            txt_add_finding(result, "IA32_FEATURE_CONTROL is locked (good)");
        } else {
            txt_add_finding(result, "WARNING: IA32_FEATURE_CONTROL is NOT locked");
        }

        if (result->senter_enabled) {
            txt_add_finding(result, "SENTER (TXT) is enabled");
        } else {
            txt_add_finding(result, "SENTER (TXT) is disabled");
        }
    } else {
        txt_add_finding(result, "Cannot read Feature Control MSR");
    }

    /* Try to read TXT public config space */
    int mem_fd = open("/dev/mem", O_RDONLY);
    if (mem_fd >= 0) {
        void *txt_pub = mmap(NULL, 0x1000, PROT_READ, MAP_SHARED,
                             mem_fd, TXT_PUB_CONFIG_SPACE);
        if (txt_pub != MAP_FAILED) {
            result->txt_hardware_present = true;
            txt_add_finding(result, "TXT public config space accessible");

            /* Read TXT status */
            result->txt_status = *(volatile uint64_t *)((char *)txt_pub + TXT_STS);
            result->txt_error = *(volatile uint64_t *)((char *)txt_pub + TXT_ERRORCODE);
            result->txt_didvid = *(volatile uint32_t *)((char *)txt_pub + TXT_DIDVID);

            /* Read SINIT info */
            result->sinit_base = *(volatile uint64_t *)((char *)txt_pub + TXT_SINIT_BASE);
            result->sinit_size = *(volatile uint64_t *)((char *)txt_pub + TXT_SINIT_SIZE);
            result->sinit_present = (result->sinit_base != 0 && result->sinit_size != 0);

            if (result->sinit_present) {
                char finding[256];
                snprintf(finding, sizeof(finding),
                        "SINIT ACM present at 0x%lX (%lu KB)",
                        result->sinit_base, result->sinit_size / 1024);
                txt_add_finding(result, finding);
            }

            /* Read DPR */
            uint64_t dpr = *(volatile uint64_t *)((char *)txt_pub + TXT_DPR);
            result->dpr_base = dpr & 0xFFF00000ULL;
            result->dpr_size = ((dpr >> 4) & 0xFF) * 1024 * 1024;
            result->dpr_locked = (dpr & 0x1) != 0;

            if (result->dpr_locked) {
                txt_add_finding(result, "DMA Protected Range (DPR) is locked");
            }

            /* Read Heap info */
            result->heap_base = *(volatile uint64_t *)((char *)txt_pub + TXT_HEAP_BASE);
            result->heap_size = *(volatile uint64_t *)((char *)txt_pub + TXT_HEAP_SIZE);

            if (result->txt_error != 0) {
                char finding[256];
                snprintf(finding, sizeof(finding),
                        "WARNING: TXT error detected: 0x%lX", result->txt_error);
                txt_add_finding(result, finding);
            }

            munmap(txt_pub, 0x1000);
        } else {
            txt_add_finding(result, "Cannot map TXT config space (may need kernel support)");
        }
        close(mem_fd);
    } else {
        txt_add_finding(result, "Cannot access /dev/mem - TXT hardware detection limited");
    }

    /* Assess risk */
    result->risk_level = txt_assess_risk(result);

    /* Generate risk reason */
    if (!result->feature_control_locked) {
        strncpy(result->risk_reason, "Feature Control not locked - security features modifiable",
                sizeof(result->risk_reason) - 1);
    } else if (result->txt_supported && !result->txt_enabled) {
        strncpy(result->risk_reason, "TXT supported but not enabled",
                sizeof(result->risk_reason) - 1);
    } else if (result->txt_error != 0) {
        strncpy(result->risk_reason, "TXT error detected",
                sizeof(result->risk_reason) - 1);
    } else {
        strncpy(result->risk_reason, "TXT configuration OK",
                sizeof(result->risk_reason) - 1);
    }

    /* Generate summary */
    snprintf(result->summary, sizeof(result->summary),
            "TXT: %s, SENTER: %s, Locked: %s, SINIT: %s, Risk: %s",
            result->txt_supported ? "Supported" : "Not Supported",
            result->senter_enabled ? "Enabled" : "Disabled",
            result->feature_control_locked ? "Yes" : "No",
            result->sinit_present ? "Present" : "Absent",
            result->risk_level == RISK_CRITICAL ? "CRITICAL" :
            result->risk_level == RISK_HIGH ? "HIGH" :
            result->risk_level == RISK_MEDIUM ? "MEDIUM" :
            result->risk_level == RISK_LOW ? "LOW" : "NONE");

    FG_INFO("%s", result->summary);

    return FG_SUCCESS;
}

int sgx_scan_config(sgx_config_t *result) {
    unsigned int eax, ebx, ecx, edx;
    uint64_t feature_control;
    int ret;

    if (!result) return FG_ERROR;

    memset(result, 0, sizeof(sgx_config_t));

    FG_INFO("Scanning Intel SGX configuration...");

    /* Check CPU SGX support */
    result->sgx_supported = check_cpu_sgx_support();
    if (!result->sgx_supported) {
        sgx_add_finding(result, "CPU does NOT support SGX");
        result->risk_level = RISK_LOW;
        strncpy(result->risk_reason, "SGX not supported",
                sizeof(result->risk_reason) - 1);
        snprintf(result->summary, sizeof(result->summary),
                "SGX: Not supported");
        return FG_SUCCESS;
    }

    sgx_add_finding(result, "CPU supports Intel SGX");

    /* Check SGX CPUID leaf 0x12, subleaf 0 for SGX capabilities */
    if (__get_cpuid_count(SGX_CPUID_LEAF, 0, &eax, &ebx, &ecx, &edx)) {
        result->sgx1_supported = (eax & 0x1) != 0;
        result->sgx2_supported = (eax & 0x2) != 0;

        if (result->sgx1_supported) {
            sgx_add_finding(result, "SGX1 instructions supported");
        }
        if (result->sgx2_supported) {
            sgx_add_finding(result, "SGX2 instructions supported");
        }

        result->miscselect = ebx;
        result->max_enclave_size_32 = 1U << (edx & 0xFF);
        result->max_enclave_size_64 = 1ULL << ((edx >> 8) & 0xFF);
    }

    /* Check SGX CPUID leaf 0x12, subleaf 1 for SECS attributes */
    if (__get_cpuid_count(SGX_CPUID_LEAF, 1, &eax, &ebx, &ecx, &edx)) {
        result->kss_supported = (eax & (1 << 7)) != 0;
        if (result->kss_supported) {
            sgx_add_finding(result, "Key Separation and Sharing (KSS) supported");
        }
    }

    /* Enumerate EPC sections (subleaf 2+) */
    for (int i = 0; i < 8; i++) {
        if (__get_cpuid_count(SGX_CPUID_LEAF, 2 + i, &eax, &ebx, &ecx, &edx)) {
            uint32_t type = eax & 0xF;
            if (type == 0) break;  /* No more EPC sections */

            if (type == 1) {  /* Valid EPC section */
                sgx_epc_section_t *epc = &result->epc_sections[result->epc_section_count];
                epc->base = ((uint64_t)(eax & 0xFFFFF000) |
                            ((uint64_t)(ebx & 0xFFFFF) << 32));
                epc->size = ((uint64_t)(ecx & 0xFFFFF000) |
                            ((uint64_t)(edx & 0xFFFFF) << 32));
                epc->type = type;
                epc->valid = true;

                result->total_epc_size += epc->size;
                result->epc_section_count++;

                char finding[256];
                snprintf(finding, sizeof(finding),
                        "EPC section %d: base=0x%lX, size=%lu MB",
                        i, epc->base, epc->size / (1024 * 1024));
                sgx_add_finding(result, finding);
            }
        }
    }

    /* Check Feature Control MSR for SGX enable status */
    ret = msr_read(0, MSR_IA32_FEATURE_CONTROL, &feature_control);
    if (ret == FG_SUCCESS) {
        result->sgx_enabled = (feature_control & FC_SGX_GLOBAL_ENABLE) != 0;
        result->sgx_launch_control = (feature_control & FC_SGX_LAUNCH_CONTROL) != 0;
        result->flexible_launch_control = result->sgx_launch_control;

        if (result->sgx_enabled) {
            sgx_add_finding(result, "SGX is enabled in BIOS");
        } else {
            sgx_add_finding(result, "SGX is DISABLED in BIOS");
        }

        if (result->flexible_launch_control) {
            sgx_add_finding(result, "Flexible Launch Control enabled (good for privacy)");
        } else {
            sgx_add_finding(result, "Intel controls enclave launch policy");
        }
    }

    /* Check for SGX device nodes */
    struct stat st;
    if (stat("/dev/sgx_enclave", &st) == 0) {
        result->sgx_device_present = true;
        result->sgx_enclave_device = true;
        sgx_add_finding(result, "SGX enclave device present (/dev/sgx_enclave)");
    } else if (stat("/dev/sgx/enclave", &st) == 0) {
        result->sgx_device_present = true;
        result->sgx_enclave_device = true;
        sgx_add_finding(result, "SGX enclave device present (/dev/sgx/enclave)");
    } else if (stat("/dev/isgx", &st) == 0) {
        result->sgx_device_present = true;
        result->sgx_enclave_device = true;
        sgx_add_finding(result, "Legacy SGX driver present (/dev/isgx)");
    }

    if (stat("/dev/sgx_provision", &st) == 0 || stat("/dev/sgx/provision", &st) == 0) {
        result->sgx_provision_device = true;
        sgx_add_finding(result, "SGX provisioning device present");
    }

    /* Assess risk */
    result->risk_level = sgx_assess_risk(result);

    /* Generate risk reason */
    if (result->sgx_supported && !result->sgx_enabled) {
        strncpy(result->risk_reason, "SGX supported but disabled",
                sizeof(result->risk_reason) - 1);
    } else if (!result->flexible_launch_control) {
        strncpy(result->risk_reason, "No Flexible Launch Control - Intel controls enclaves",
                sizeof(result->risk_reason) - 1);
    } else {
        strncpy(result->risk_reason, "SGX configuration OK",
                sizeof(result->risk_reason) - 1);
    }

    /* Generate summary */
    snprintf(result->summary, sizeof(result->summary),
            "SGX: %s, Enabled: %s, EPC: %lu MB, FLC: %s, Risk: %s",
            result->sgx_supported ? "Supported" : "Not Supported",
            result->sgx_enabled ? "Yes" : "No",
            result->total_epc_size / (1024 * 1024),
            result->flexible_launch_control ? "Yes" : "No",
            result->risk_level == RISK_HIGH ? "HIGH" :
            result->risk_level == RISK_MEDIUM ? "MEDIUM" :
            result->risk_level == RISK_LOW ? "LOW" : "NONE");

    FG_INFO("%s", result->summary);

    return FG_SUCCESS;
}

int tpm_scan_measurements(tpm_measurement_t *result) {
    struct stat st;

    if (!result) return FG_ERROR;

    memset(result, 0, sizeof(tpm_measurement_t));

    FG_INFO("Scanning TPM measurements...");

    /* Check for TPM device */
    if (stat("/dev/tpm0", &st) == 0) {
        result->tpm_present = true;
        tpm_add_finding(result, "TPM device present (/dev/tpm0)");
    } else if (stat("/dev/tpmrm0", &st) == 0) {
        result->tpm_present = true;
        tpm_add_finding(result, "TPM resource manager present (/dev/tpmrm0)");
    } else {
        tpm_add_finding(result, "No TPM device found");
        result->risk_level = RISK_MEDIUM;
        strncpy(result->risk_reason, "No TPM device detected",
                sizeof(result->risk_reason) - 1);
        snprintf(result->summary, sizeof(result->summary),
                "TPM: Not detected");
        return FG_SUCCESS;
    }

    /* Check TPM version via sysfs */
    FILE *fp = fopen("/sys/class/tpm/tpm0/tpm_version_major", "r");
    if (fp) {
        int major;
        if (fscanf(fp, "%d", &major) == 1) {
            result->tpm_2_0 = (major == 2);
            snprintf(result->tpm_version, sizeof(result->tpm_version),
                    "TPM %d.x", major);
            if (result->tpm_2_0) {
                tpm_add_finding(result, "TPM 2.0 detected");
            } else {
                tpm_add_finding(result, "TPM 1.2 detected");
            }
        }
        fclose(fp);
    }

    /* Read TPM manufacturer */
    fp = fopen("/sys/class/tpm/tpm0/device/description", "r");
    if (fp) {
        if (fgets(result->tpm_manufacturer, sizeof(result->tpm_manufacturer) - 1, fp)) {
            /* Remove newline */
            char *nl = strchr(result->tpm_manufacturer, '\n');
            if (nl) *nl = '\0';
        }
        fclose(fp);
    }

    /* Check for event log */
    const char *event_log_paths[] = {
        "/sys/kernel/security/tpm0/binary_bios_measurements",
        "/sys/kernel/security/ima/binary_runtime_measurements",
        NULL
    };

    for (int i = 0; event_log_paths[i] != NULL; i++) {
        if (stat(event_log_paths[i], &st) == 0) {
            result->event_log_present = true;
            strncpy(result->event_log_path, event_log_paths[i],
                    sizeof(result->event_log_path) - 1);
            result->event_log_size = st.st_size;

            char finding[256];
            snprintf(finding, sizeof(finding),
                    "Event log found: %s (%zu bytes)",
                    event_log_paths[i], st.st_size);
            tpm_add_finding(result, finding);
            break;
        }
    }

    if (!result->event_log_present) {
        tpm_add_finding(result, "TPM event log not accessible");
    }

    /* Try to read PCR values via /sys/class/tpm/tpm0/pcr-sha256/X */
    result->pcr_count = 0;
    for (int i = 0; i < 24; i++) {
        char path[256];
        snprintf(path, sizeof(path), "/sys/class/tpm/tpm0/pcr-sha256/%d", i);

        fp = fopen(path, "r");
        if (fp) {
            tpm_pcr_t *pcr = &result->pcrs[result->pcr_count];
            pcr->pcr_index = i;

            char hex[65];
            if (fscanf(fp, "%64s", hex) == 1) {
                strncpy(pcr->sha256_hex, hex, sizeof(pcr->sha256_hex) - 1);
                pcr->valid = true;
                result->pcr_count++;

                /* PCRs 0-7 are SRTM measurements */
                if (i <= 7 && strcmp(hex, "0000000000000000000000000000000000000000000000000000000000000000") != 0) {
                    result->srtm_valid = true;
                }
            }
            fclose(fp);
        }
    }

    if (result->pcr_count > 0) {
        char finding[256];
        snprintf(finding, sizeof(finding), "Read %d PCR values", result->pcr_count);
        tpm_add_finding(result, finding);
    }

    if (result->srtm_valid) {
        tpm_add_finding(result, "Static Root of Trust measurements present");
    }

    /* Assess risk */
    if (!result->tpm_present) {
        result->risk_level = RISK_MEDIUM;
    } else if (!result->event_log_present) {
        result->risk_level = RISK_LOW;
    } else {
        result->risk_level = RISK_NONE;
    }

    /* Generate risk reason */
    if (!result->tpm_present) {
        strncpy(result->risk_reason, "No TPM detected",
                sizeof(result->risk_reason) - 1);
    } else if (!result->tpm_2_0) {
        strncpy(result->risk_reason, "TPM 1.2 has limited security features",
                sizeof(result->risk_reason) - 1);
    } else {
        strncpy(result->risk_reason, "TPM configuration OK",
                sizeof(result->risk_reason) - 1);
    }

    /* Generate summary */
    snprintf(result->summary, sizeof(result->summary),
            "TPM: %s, Version: %s, Event Log: %s, PCRs: %d, Risk: %s",
            result->tpm_present ? "Present" : "Not Found",
            result->tpm_version[0] ? result->tpm_version : "Unknown",
            result->event_log_present ? "Yes" : "No",
            result->pcr_count,
            result->risk_level == RISK_HIGH ? "HIGH" :
            result->risk_level == RISK_MEDIUM ? "MEDIUM" :
            result->risk_level == RISK_LOW ? "LOW" : "NONE");

    FG_INFO("%s", result->summary);

    return FG_SUCCESS;
}

int trusted_boot_full_scan(trusted_boot_result_t *result) {
    if (!result) return FG_ERROR;

    memset(result, 0, sizeof(trusted_boot_result_t));

    FG_INFO("Performing full Trusted Boot analysis...");

    /* TXT scan */
    if (txt_scan_config(&result->txt) == FG_SUCCESS) {
        result->txt_scan_done = true;
        tb_add_finding(result, "TXT configuration scanned");
    }

    /* SGX scan */
    if (sgx_scan_config(&result->sgx) == FG_SUCCESS) {
        result->sgx_scan_done = true;
        tb_add_finding(result, "SGX configuration scanned");
    }

    /* TPM scan */
    if (tpm_scan_measurements(&result->tpm) == FG_SUCCESS) {
        result->tpm_scan_done = true;
        tb_add_finding(result, "TPM measurements scanned");
    }

    /* Overall risk assessment */
    risk_level_t max_risk = RISK_NONE;
    if (result->txt.risk_level > max_risk) max_risk = result->txt.risk_level;
    if (result->sgx.risk_level > max_risk) max_risk = result->sgx.risk_level;
    if (result->tpm.risk_level > max_risk) max_risk = result->tpm.risk_level;
    result->overall_risk = max_risk;

    /* Generate overall risk reason */
    if (result->txt.risk_level == max_risk && max_risk > RISK_NONE) {
        strncpy(result->risk_reason, result->txt.risk_reason,
                sizeof(result->risk_reason) - 1);
    } else if (result->sgx.risk_level == max_risk && max_risk > RISK_NONE) {
        strncpy(result->risk_reason, result->sgx.risk_reason,
                sizeof(result->risk_reason) - 1);
    } else if (result->tpm.risk_level == max_risk && max_risk > RISK_NONE) {
        strncpy(result->risk_reason, result->tpm.risk_reason,
                sizeof(result->risk_reason) - 1);
    } else {
        strncpy(result->risk_reason, "Trusted Boot configuration OK",
                sizeof(result->risk_reason) - 1);
    }

    /* Generate summary */
    snprintf(result->summary, sizeof(result->summary),
            "Trusted Boot: TXT %s, SGX %s, TPM %s, Overall Risk: %s",
            result->txt.txt_enabled ? "Enabled" : "Disabled",
            result->sgx.sgx_enabled ? "Enabled" : "Disabled",
            result->tpm.tpm_present ? "Present" : "Absent",
            max_risk == RISK_CRITICAL ? "CRITICAL" :
            max_risk == RISK_HIGH ? "HIGH" :
            max_risk == RISK_MEDIUM ? "MEDIUM" :
            max_risk == RISK_LOW ? "LOW" : "NONE");

    FG_INFO("%s", result->summary);

    return FG_SUCCESS;
}

void txt_print_result(const txt_config_t *result, bool verbose) {
    if (!result) return;

    printf("\n");
    printf("==========================================\n");
    printf("  Intel TXT Configuration\n");
    printf("==========================================\n");
    printf("\n");

    printf("CPU Support:\n");
    printf("  SMX: %s\n", result->smx_supported ? "Yes" : "No");
    printf("  VMX: %s\n", result->vmx_supported ? "Yes" : "No");
    printf("  TXT Supported: %s\n", result->txt_supported ? "Yes" : "No");
    printf("\n");

    printf("TXT Status:\n");
    printf("  TXT Enabled: %s\n", result->txt_enabled ? "Yes" : "No");
    printf("  SENTER Enabled: %s\n", result->senter_enabled ? "Yes" : "No");
    printf("  Feature Control Locked: %s\n",
           result->feature_control_locked ? "Yes" : "No");
    printf("  Feature Control MSR: 0x%016lX\n", result->feature_control_raw);
    printf("\n");

    if (result->txt_hardware_present) {
        printf("TXT Hardware:\n");
        printf("  TXT Status: 0x%016lX\n", result->txt_status);
        printf("  TXT Error: 0x%016lX%s\n", result->txt_error,
               result->txt_error ? " (ERROR!)" : "");
        printf("  DID/VID: 0x%08X\n", result->txt_didvid);
        printf("\n");

        printf("SINIT ACM:\n");
        printf("  Present: %s\n", result->sinit_present ? "Yes" : "No");
        if (result->sinit_present) {
            printf("  Base: 0x%lX\n", result->sinit_base);
            printf("  Size: %lu KB\n", result->sinit_size / 1024);
        }
        printf("\n");

        printf("DMA Protected Range:\n");
        printf("  Base: 0x%lX\n", result->dpr_base);
        printf("  Size: %lu MB\n", result->dpr_size / (1024 * 1024));
        printf("  Locked: %s\n", result->dpr_locked ? "Yes" : "No");
        printf("\n");
    }

    printf("Risk Assessment:\n");
    printf("  Level: %s\n",
           result->risk_level == RISK_CRITICAL ? "CRITICAL" :
           result->risk_level == RISK_HIGH ? "HIGH" :
           result->risk_level == RISK_MEDIUM ? "MEDIUM" :
           result->risk_level == RISK_LOW ? "LOW" : "NONE");
    printf("  Reason: %s\n", result->risk_reason);
    printf("\n");

    if (verbose && result->finding_count > 0) {
        printf("Findings:\n");
        for (int i = 0; i < result->finding_count; i++) {
            printf("  [%d] %s\n", i + 1, result->findings[i]);
        }
        printf("\n");
    }

    printf("Summary: %s\n", result->summary);
    printf("\n");
}

void sgx_print_result(const sgx_config_t *result, bool verbose) {
    if (!result) return;

    printf("\n");
    printf("==========================================\n");
    printf("  Intel SGX Configuration\n");
    printf("==========================================\n");
    printf("\n");

    printf("SGX Support:\n");
    printf("  SGX Supported: %s\n", result->sgx_supported ? "Yes" : "No");
    printf("  SGX1: %s\n", result->sgx1_supported ? "Yes" : "No");
    printf("  SGX2: %s\n", result->sgx2_supported ? "Yes" : "No");
    printf("  SGX Enabled: %s\n", result->sgx_enabled ? "Yes" : "No");
    printf("\n");

    printf("Launch Control:\n");
    printf("  Flexible Launch Control: %s\n",
           result->flexible_launch_control ? "Yes" : "No");
    printf("  KSS Supported: %s\n", result->kss_supported ? "Yes" : "No");
    printf("\n");

    printf("EPC Configuration:\n");
    printf("  Total EPC Size: %lu MB\n", result->total_epc_size / (1024 * 1024));
    printf("  EPC Sections: %d\n", result->epc_section_count);
    if (verbose) {
        for (int i = 0; i < result->epc_section_count; i++) {
            printf("    Section %d: base=0x%lX, size=%lu MB\n",
                   i, result->epc_sections[i].base,
                   result->epc_sections[i].size / (1024 * 1024));
        }
    }
    printf("\n");

    printf("Enclave Limits:\n");
    printf("  Max 32-bit Enclave: %u bytes\n", result->max_enclave_size_32);
    printf("  Max 64-bit Enclave: %u bytes\n", result->max_enclave_size_64);
    printf("\n");

    printf("Device Nodes:\n");
    printf("  Enclave Device: %s\n", result->sgx_enclave_device ? "Yes" : "No");
    printf("  Provision Device: %s\n", result->sgx_provision_device ? "Yes" : "No");
    printf("\n");

    printf("Risk Assessment:\n");
    printf("  Level: %s\n",
           result->risk_level == RISK_HIGH ? "HIGH" :
           result->risk_level == RISK_MEDIUM ? "MEDIUM" :
           result->risk_level == RISK_LOW ? "LOW" : "NONE");
    printf("  Reason: %s\n", result->risk_reason);
    printf("\n");

    if (verbose && result->finding_count > 0) {
        printf("Findings:\n");
        for (int i = 0; i < result->finding_count; i++) {
            printf("  [%d] %s\n", i + 1, result->findings[i]);
        }
        printf("\n");
    }

    printf("Summary: %s\n", result->summary);
    printf("\n");
}

void tpm_print_result(const tpm_measurement_t *result, bool verbose) {
    if (!result) return;

    printf("\n");
    printf("==========================================\n");
    printf("  TPM Measurements\n");
    printf("==========================================\n");
    printf("\n");

    printf("TPM Status:\n");
    printf("  Present: %s\n", result->tpm_present ? "Yes" : "No");
    printf("  Version: %s\n", result->tpm_version[0] ? result->tpm_version : "Unknown");
    printf("  Manufacturer: %s\n",
           result->tpm_manufacturer[0] ? result->tpm_manufacturer : "Unknown");
    printf("\n");

    printf("Measurements:\n");
    printf("  Event Log: %s\n", result->event_log_present ? "Present" : "Not Found");
    if (result->event_log_present) {
        printf("  Event Log Path: %s\n", result->event_log_path);
        printf("  Event Log Size: %zu bytes\n", result->event_log_size);
    }
    printf("  PCRs Read: %d\n", result->pcr_count);
    printf("  SRTM Valid: %s\n", result->srtm_valid ? "Yes" : "No");
    printf("\n");

    if (verbose && result->pcr_count > 0) {
        printf("PCR Values (SHA-256):\n");
        for (int i = 0; i < result->pcr_count && i < 8; i++) {
            if (result->pcrs[i].valid) {
                printf("  PCR[%2d]: %s\n",
                       result->pcrs[i].pcr_index,
                       result->pcrs[i].sha256_hex);
            }
        }
        printf("\n");
    }

    printf("Risk Assessment:\n");
    printf("  Level: %s\n",
           result->risk_level == RISK_HIGH ? "HIGH" :
           result->risk_level == RISK_MEDIUM ? "MEDIUM" :
           result->risk_level == RISK_LOW ? "LOW" : "NONE");
    printf("  Reason: %s\n", result->risk_reason);
    printf("\n");

    printf("Summary: %s\n", result->summary);
    printf("\n");
}

void trusted_boot_print_result(const trusted_boot_result_t *result, bool verbose) {
    if (!result) return;

    printf("\n");
    printf("==========================================\n");
    printf("  Full Trusted Boot Analysis\n");
    printf("==========================================\n");
    printf("\n");

    if (result->txt_scan_done) {
        txt_print_result(&result->txt, verbose);
    }

    if (result->sgx_scan_done) {
        sgx_print_result(&result->sgx, verbose);
    }

    if (result->tpm_scan_done) {
        tpm_print_result(&result->tpm, verbose);
    }

    printf("==========================================\n");
    printf("  Overall Assessment\n");
    printf("==========================================\n");
    printf("\n");
    printf("Risk Level: %s\n",
           result->overall_risk == RISK_CRITICAL ? "CRITICAL" :
           result->overall_risk == RISK_HIGH ? "HIGH" :
           result->overall_risk == RISK_MEDIUM ? "MEDIUM" :
           result->overall_risk == RISK_LOW ? "LOW" : "NONE");
    printf("Reason: %s\n", result->risk_reason);
    printf("\n");
    printf("Summary: %s\n", result->summary);
    printf("\n");
}

int txt_to_json(const txt_config_t *result, char *buffer, size_t size) {
    if (!result || !buffer || size == 0) return FG_ERROR;

    int written = snprintf(buffer, size,
        "{\n"
        "  \"txt_supported\": %s,\n"
        "  \"txt_enabled\": %s,\n"
        "  \"smx_supported\": %s,\n"
        "  \"vmx_supported\": %s,\n"
        "  \"senter_enabled\": %s,\n"
        "  \"feature_control_locked\": %s,\n"
        "  \"sinit_present\": %s,\n"
        "  \"sinit_base\": \"0x%lX\",\n"
        "  \"sinit_size\": %lu,\n"
        "  \"dpr_locked\": %s,\n"
        "  \"txt_error\": \"0x%lX\",\n"
        "  \"risk\": { \"level\": \"%s\", \"reason\": \"%s\" },\n"
        "  \"summary\": \"%s\"\n"
        "}\n",
        result->txt_supported ? "true" : "false",
        result->txt_enabled ? "true" : "false",
        result->smx_supported ? "true" : "false",
        result->vmx_supported ? "true" : "false",
        result->senter_enabled ? "true" : "false",
        result->feature_control_locked ? "true" : "false",
        result->sinit_present ? "true" : "false",
        result->sinit_base,
        result->sinit_size,
        result->dpr_locked ? "true" : "false",
        result->txt_error,
        result->risk_level == RISK_CRITICAL ? "CRITICAL" :
        result->risk_level == RISK_HIGH ? "HIGH" :
        result->risk_level == RISK_MEDIUM ? "MEDIUM" :
        result->risk_level == RISK_LOW ? "LOW" : "NONE",
        result->risk_reason,
        result->summary
    );

    return (written > 0 && (size_t)written < size) ? FG_SUCCESS : FG_ERROR;
}

int sgx_to_json(const sgx_config_t *result, char *buffer, size_t size) {
    if (!result || !buffer || size == 0) return FG_ERROR;

    int written = snprintf(buffer, size,
        "{\n"
        "  \"sgx_supported\": %s,\n"
        "  \"sgx_enabled\": %s,\n"
        "  \"sgx1_supported\": %s,\n"
        "  \"sgx2_supported\": %s,\n"
        "  \"flexible_launch_control\": %s,\n"
        "  \"total_epc_size\": %lu,\n"
        "  \"epc_sections\": %d,\n"
        "  \"sgx_device_present\": %s,\n"
        "  \"risk\": { \"level\": \"%s\", \"reason\": \"%s\" },\n"
        "  \"summary\": \"%s\"\n"
        "}\n",
        result->sgx_supported ? "true" : "false",
        result->sgx_enabled ? "true" : "false",
        result->sgx1_supported ? "true" : "false",
        result->sgx2_supported ? "true" : "false",
        result->flexible_launch_control ? "true" : "false",
        result->total_epc_size,
        result->epc_section_count,
        result->sgx_device_present ? "true" : "false",
        result->risk_level == RISK_HIGH ? "HIGH" :
        result->risk_level == RISK_MEDIUM ? "MEDIUM" :
        result->risk_level == RISK_LOW ? "LOW" : "NONE",
        result->risk_reason,
        result->summary
    );

    return (written > 0 && (size_t)written < size) ? FG_SUCCESS : FG_ERROR;
}

int tpm_to_json(const tpm_measurement_t *result, char *buffer, size_t size) {
    if (!result || !buffer || size == 0) return FG_ERROR;

    int written = snprintf(buffer, size,
        "{\n"
        "  \"tpm_present\": %s,\n"
        "  \"tpm_2_0\": %s,\n"
        "  \"tpm_version\": \"%s\",\n"
        "  \"event_log_present\": %s,\n"
        "  \"pcr_count\": %d,\n"
        "  \"srtm_valid\": %s,\n"
        "  \"risk\": { \"level\": \"%s\", \"reason\": \"%s\" },\n"
        "  \"summary\": \"%s\"\n"
        "}\n",
        result->tpm_present ? "true" : "false",
        result->tpm_2_0 ? "true" : "false",
        result->tpm_version,
        result->event_log_present ? "true" : "false",
        result->pcr_count,
        result->srtm_valid ? "true" : "false",
        result->risk_level == RISK_HIGH ? "HIGH" :
        result->risk_level == RISK_MEDIUM ? "MEDIUM" :
        result->risk_level == RISK_LOW ? "LOW" : "NONE",
        result->risk_reason,
        result->summary
    );

    return (written > 0 && (size_t)written < size) ? FG_SUCCESS : FG_ERROR;
}

int trusted_boot_to_json(const trusted_boot_result_t *result, char *buffer, size_t size) {
    if (!result || !buffer || size == 0) return FG_ERROR;

    int written = snprintf(buffer, size,
        "{\n"
        "  \"txt_scan_done\": %s,\n"
        "  \"sgx_scan_done\": %s,\n"
        "  \"tpm_scan_done\": %s,\n"
        "  \"overall_risk\": \"%s\",\n"
        "  \"risk_reason\": \"%s\",\n"
        "  \"summary\": \"%s\"\n"
        "}\n",
        result->txt_scan_done ? "true" : "false",
        result->sgx_scan_done ? "true" : "false",
        result->tpm_scan_done ? "true" : "false",
        result->overall_risk == RISK_CRITICAL ? "CRITICAL" :
        result->overall_risk == RISK_HIGH ? "HIGH" :
        result->overall_risk == RISK_MEDIUM ? "MEDIUM" :
        result->overall_risk == RISK_LOW ? "LOW" : "NONE",
        result->risk_reason,
        result->summary
    );

    return (written > 0 && (size_t)written < size) ? FG_SUCCESS : FG_ERROR;
}
