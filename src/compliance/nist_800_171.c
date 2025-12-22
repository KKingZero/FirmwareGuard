/*
 * FirmwareGuard - NIST 800-171 Compliance Mappings
 *
 * Maps firmware security findings to NIST SP 800-171 Rev 2 controls
 * Focus areas: System & Information Integrity (SI),
 *              Configuration Management (CM),
 *              System & Communications Protection (SC)
 */

#include "compliance.h"
#include <string.h>
#include <stdio.h>

/* NIST 800-171 Control Definitions relevant to firmware security */

typedef struct {
    const char *control_id;
    const char *control_name;
    const char *control_desc;
    const char *family_id;
    const char *family_name;
    risk_level_t default_risk;
} nist_control_def_t;

/* Control definitions - firmware security relevant subset */
static const nist_control_def_t NIST_CONTROLS[] = {
    /* 3.4 - Configuration Management */
    {
        "3.4.1",
        "Baseline Configuration",
        "Establish and maintain baseline configurations and inventories of organizational systems",
        "3.4",
        "Configuration Management",
        RISK_HIGH
    },
    {
        "3.4.2",
        "Security Configuration Settings",
        "Establish and enforce security configuration settings for information technology products",
        "3.4",
        "Configuration Management",
        RISK_HIGH
    },
    {
        "3.4.5",
        "Access Restrictions for Change",
        "Define, document, approve, and enforce physical and logical access restrictions associated with changes",
        "3.4",
        "Configuration Management",
        RISK_HIGH
    },
    {
        "3.4.6",
        "Least Functionality",
        "Employ the principle of least functionality by configuring systems to provide only essential capabilities",
        "3.4",
        "Configuration Management",
        RISK_MEDIUM
    },
    {
        "3.4.7",
        "Nonessential Functionality",
        "Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services",
        "3.4",
        "Configuration Management",
        RISK_MEDIUM
    },
    {
        "3.4.8",
        "Application Execution Policy",
        "Apply deny-by-exception policy to prevent unauthorized software execution",
        "3.4",
        "Configuration Management",
        RISK_HIGH
    },

    /* 3.13 - System and Communications Protection */
    {
        "3.13.1",
        "Boundary Protection",
        "Monitor, control, and protect communications at external and key internal boundaries",
        "3.13",
        "System and Communications Protection",
        RISK_CRITICAL
    },
    {
        "3.13.2",
        "Security Architecture",
        "Employ architectural designs, development techniques, and engineering principles that promote effective security",
        "3.13",
        "System and Communications Protection",
        RISK_HIGH
    },
    {
        "3.13.3",
        "Role Separation",
        "Separate user functionality from system management functionality",
        "3.13",
        "System and Communications Protection",
        RISK_MEDIUM
    },
    {
        "3.13.4",
        "Shared Resource Control",
        "Prevent unauthorized and unintended information transfer via shared system resources",
        "3.13",
        "System and Communications Protection",
        RISK_HIGH
    },
    {
        "3.13.11",
        "CUI Encryption",
        "Employ FIPS-validated cryptography when used to protect confidentiality of CUI",
        "3.13",
        "System and Communications Protection",
        RISK_HIGH
    },

    /* 3.14 - System and Information Integrity */
    {
        "3.14.1",
        "Flaw Remediation",
        "Identify, report, and correct system flaws in a timely manner",
        "3.14",
        "System and Information Integrity",
        RISK_HIGH
    },
    {
        "3.14.2",
        "Malicious Code Protection",
        "Provide protection from malicious code at designated locations within organizational systems",
        "3.14",
        "System and Information Integrity",
        RISK_CRITICAL
    },
    {
        "3.14.3",
        "Security Alerts",
        "Monitor system security alerts and advisories and take action in response",
        "3.14",
        "System and Information Integrity",
        RISK_MEDIUM
    },
    {
        "3.14.4",
        "Update Malicious Code Protection",
        "Update malicious code protection mechanisms when new releases are available",
        "3.14",
        "System and Information Integrity",
        RISK_MEDIUM
    },
    {
        "3.14.6",
        "System Monitoring",
        "Monitor organizational systems to detect attacks and indicators of potential attacks",
        "3.14",
        "System and Information Integrity",
        RISK_HIGH
    },
    {
        "3.14.7",
        "Unauthorized Activity Detection",
        "Identify unauthorized use of organizational systems",
        "3.14",
        "System and Information Integrity",
        RISK_HIGH
    },

    /* 3.1 - Access Control (firmware-relevant subset) */
    {
        "3.1.1",
        "Account Management",
        "Limit system access to authorized users, processes, or devices",
        "3.1",
        "Access Control",
        RISK_HIGH
    },
    {
        "3.1.7",
        "Privileged Functions",
        "Prevent non-privileged users from executing privileged functions",
        "3.1",
        "Access Control",
        RISK_CRITICAL
    },

    /* Sentinel */
    {NULL, NULL, NULL, NULL, NULL, RISK_NONE}
};

/* Initialize NIST 800-171 controls in result structure */
int nist_init_controls(compliance_result_t *result) {
    if (!result) return FG_ERROR;

    result->framework = FRAMEWORK_NIST_800_171;
    snprintf(result->framework_name, sizeof(result->framework_name),
             "NIST SP 800-171");
    snprintf(result->framework_version, sizeof(result->framework_version),
             "Rev 2");

    result->num_controls = 0;

    for (int i = 0; NIST_CONTROLS[i].control_id != NULL; i++) {
        if (result->num_controls >= COMPLIANCE_MAX_CONTROLS) break;

        compliance_control_t *ctrl = &result->controls[result->num_controls];

        snprintf(ctrl->control_id, sizeof(ctrl->control_id),
                 "%s", NIST_CONTROLS[i].control_id);
        snprintf(ctrl->control_name, sizeof(ctrl->control_name),
                 "%s", NIST_CONTROLS[i].control_name);
        snprintf(ctrl->control_desc, sizeof(ctrl->control_desc),
                 "%s", NIST_CONTROLS[i].control_desc);
        snprintf(ctrl->family_id, sizeof(ctrl->family_id),
                 "%s", NIST_CONTROLS[i].family_id);
        snprintf(ctrl->family_name, sizeof(ctrl->family_name),
                 "%s", NIST_CONTROLS[i].family_name);

        ctrl->status = CONTROL_NOT_ASSESSED;
        ctrl->risk_impact = NIST_CONTROLS[i].default_risk;
        ctrl->evidence[0] = '\0';
        ctrl->finding_count = 0;

        result->num_controls++;
    }

    return FG_SUCCESS;
}

/* Find control by ID */
static compliance_control_t *find_control(compliance_result_t *result,
                                          const char *control_id) {
    for (int i = 0; i < result->num_controls; i++) {
        if (strcmp(result->controls[i].control_id, control_id) == 0) {
            return &result->controls[i];
        }
    }
    return NULL;
}

/* Add finding to control */
static void add_finding(compliance_control_t *ctrl, const char *finding) {
    if (!ctrl || !finding) {
        return;
    }
    if (ctrl->finding_count < COMPLIANCE_MAX_FINDINGS) {
        snprintf(ctrl->findings[ctrl->finding_count],
                 sizeof(ctrl->findings[0]), "%s", finding);
        ctrl->finding_count++;
    }
}

/* Map SMM scan results to NIST controls */
int nist_map_smm_findings(const smm_scan_result_t *smm,
                          compliance_result_t *result) {
    if (!smm || !result) return FG_ERROR;

    compliance_control_t *ctrl;

    /* 3.13.1 - Boundary Protection (SMM is a critical boundary) */
    ctrl = find_control(result, "3.13.1");
    if (ctrl) {
        if (smm->region.smrr_locked && smm->region.smrr_valid) {
            ctrl->status = CONTROL_PASS;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "SMRR configured and locked. SMM boundary protected.");
        } else if (smm->region.smrr_valid) {
            ctrl->status = CONTROL_PARTIAL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "SMRR configured but not locked. SMM boundary weakened.");
            add_finding(ctrl, "SMRR not locked - SMM vulnerable to reconfiguration");
        } else {
            ctrl->status = CONTROL_FAIL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "SMRR not properly configured. No SMM boundary protection.");
            add_finding(ctrl, "SMRR not valid - SMM memory unprotected");
        }
    }

    /* 3.4.2 - Security Configuration Settings */
    ctrl = find_control(result, "3.4.2");
    if (ctrl) {
        if (smm->security.feature_control_locked) {
            if (ctrl->status != CONTROL_FAIL) {
                ctrl->status = CONTROL_PASS;
                snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                         "IA32_FEATURE_CONTROL MSR locked. Security settings enforced.");
            }
        } else {
            ctrl->status = CONTROL_FAIL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "IA32_FEATURE_CONTROL MSR unlocked. Settings can be modified.");
            add_finding(ctrl, "CPU feature control register not locked");
        }
    }

    /* 3.1.7 - Privileged Functions (SMM is highest privilege) */
    ctrl = find_control(result, "3.1.7");
    if (ctrl) {
        if (smm->risk_level <= SMM_RISK_LOW) {
            ctrl->status = CONTROL_PASS;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "SMM protections in place. Privileged execution controlled.");
        } else if (smm->risk_level == SMM_RISK_MEDIUM) {
            ctrl->status = CONTROL_PARTIAL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "SMM partially protected. Some risk vectors present.");
            add_finding(ctrl, "Moderate SMM security risk detected");
        } else {
            ctrl->status = CONTROL_FAIL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "SMM inadequately protected. High privilege execution at risk.");
            add_finding(ctrl, smm->risk_reason);
        }
    }

    /* 3.14.6 - System Monitoring (SMI monitoring) */
    ctrl = find_control(result, "3.14.6");
    if (ctrl) {
        if (smm->smi_stats.smi_count_supported) {
            if (ctrl->status != CONTROL_FAIL) {
                ctrl->status = CONTROL_PASS;
                snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                         "SMI count monitoring available. %lu SMIs recorded.",
                         smm->smi_stats.smi_count);
            }
        } else {
            /* SMI monitoring not available is partial */
            if (ctrl->status == CONTROL_NOT_ASSESSED) {
                ctrl->status = CONTROL_PARTIAL;
                snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                         "SMI count monitoring not available on this platform.");
            }
        }
    }

    return FG_SUCCESS;
}

/* Map Boot Guard results to NIST controls */
int nist_map_bootguard_findings(const bootguard_status_t *bg,
                                compliance_result_t *result) {
    if (!bg || !result) return FG_ERROR;

    compliance_control_t *ctrl;

    /* 3.4.5 - Access Restrictions for Change */
    ctrl = find_control(result, "3.4.5");
    if (ctrl) {
        if (bg->bootguard_enabled && bg->verified_boot) {
            ctrl->status = CONTROL_PASS;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "Boot Guard enabled with verified boot. Firmware changes restricted.");
        } else if (bg->bootguard_capable) {
            ctrl->status = CONTROL_PARTIAL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "Boot Guard capable but not fully enabled.");
            add_finding(ctrl, "Boot Guard available but not enforcing verified boot");
        } else {
            ctrl->status = CONTROL_FAIL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "Boot Guard not available. No hardware firmware verification.");
            add_finding(ctrl, "No Boot Guard capability - firmware modification unrestricted");
        }
    }

    /* 3.14.2 - Malicious Code Protection */
    ctrl = find_control(result, "3.14.2");
    if (ctrl) {
        if (bg->bootguard_enabled && bg->acm_active) {
            ctrl->status = CONTROL_PASS;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "ACM active, Boot Guard enforced. Pre-boot malware protection enabled.");
        } else if (bg->measured_boot) {
            ctrl->status = CONTROL_PARTIAL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "Measured boot enabled but verified boot not enforced.");
            add_finding(ctrl, "Only measured boot - no verification enforcement");
        } else {
            ctrl->status = CONTROL_FAIL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "No pre-boot malware protection mechanisms active.");
            add_finding(ctrl, "Boot firmware vulnerable to persistent malware");
        }
    }

    /* 3.13.2 - Security Architecture */
    ctrl = find_control(result, "3.13.2");
    if (ctrl) {
        if (bg->bootguard_enabled) {
            if (ctrl->status != CONTROL_FAIL) {
                ctrl->status = CONTROL_PASS;
                snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                         "Hardware root of trust established via Boot Guard.");
            }
        } else {
            ctrl->status = CONTROL_PARTIAL;
            add_finding(ctrl, "No hardware root of trust for boot process");
        }
    }

    return FG_SUCCESS;
}

/* Map Secure Boot results to NIST controls */
int nist_map_secureboot_findings(const secureboot_audit_t *sb,
                                 compliance_result_t *result) {
    if (!sb || !result) return FG_ERROR;

    compliance_control_t *ctrl;

    /* 3.4.8 - Application Execution Policy */
    ctrl = find_control(result, "3.4.8");
    if (ctrl) {
        if (sb->secure_boot_enabled) {
            ctrl->status = CONTROL_PASS;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "UEFI Secure Boot enabled. Unsigned boot components blocked.");
        } else if (sb->setup_mode) {
            ctrl->status = CONTROL_PARTIAL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "Secure Boot in setup mode. Not enforcing signatures.");
            add_finding(ctrl, "Secure Boot in setup mode - easy to disable");
        } else {
            ctrl->status = CONTROL_FAIL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "Secure Boot disabled. Any boot code can execute.");
            add_finding(ctrl, "Secure Boot disabled - boot malware possible");
        }
    }

    /* 3.13.11 - CUI Encryption (Secure Boot uses crypto) */
    ctrl = find_control(result, "3.13.11");
    if (ctrl) {
        if (sb->secure_boot_enabled && sb->pk.present) {
            ctrl->status = CONTROL_PASS;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "Platform Key enrolled. Cryptographic boot chain established.");
        } else if (sb->pk.present) {
            ctrl->status = CONTROL_PARTIAL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "PK enrolled but Secure Boot not enforcing.");
        } else {
            if (ctrl->status == CONTROL_NOT_ASSESSED) {
                ctrl->status = CONTROL_PARTIAL;
                snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                         "No Platform Key. Cryptographic boot chain not established.");
            }
        }
    }

    /* 3.4.1 - Baseline Configuration */
    ctrl = find_control(result, "3.4.1");
    if (ctrl) {
        if (sb->db.cert_count > 0 || sb->dbx.cert_count > 0) {
            if (ctrl->status == CONTROL_NOT_ASSESSED) {
                ctrl->status = CONTROL_PASS;
                snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                         "Secure Boot key database configured. DB: %d entries, DBX: %d revocations.",
                         sb->db.cert_count, sb->dbx.cert_count);
            }
        }
    }

    return FG_SUCCESS;
}

/* Map implant scan results to NIST controls */
int nist_map_implant_findings(const implant_scan_result_t *implant,
                              compliance_result_t *result) {
    if (!implant || !result) return FG_ERROR;

    compliance_control_t *ctrl;

    /* 3.14.7 - Unauthorized Activity Detection */
    ctrl = find_control(result, "3.14.7");
    if (ctrl) {
        if (implant->finding_count == 0) {
            ctrl->status = CONTROL_PASS;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "No firmware implant indicators detected.");
        } else if (implant->iommu.unprotected_count > 0) {
            ctrl->status = CONTROL_FAIL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "Unprotected DMA devices detected. Potential for unauthorized activity.");
            add_finding(ctrl, "DMA attack surface present");
        } else {
            ctrl->status = CONTROL_PARTIAL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "%d potential issues found during implant scan.",
                     implant->finding_count);
        }
    }

    /* 3.13.4 - Shared Resource Control (DMA/IOMMU) */
    ctrl = find_control(result, "3.13.4");
    if (ctrl) {
        if (implant->iommu.iommu_enabled) {
            ctrl->status = CONTROL_PASS;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "IOMMU enabled (%s). DMA isolation protecting shared resources.",
                     implant->iommu.iommu_type);
        } else {
            ctrl->status = CONTROL_FAIL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "IOMMU not enabled. DMA can access any memory.");
            add_finding(ctrl, "No IOMMU - DMA attacks possible");
        }
    }

    /* 3.4.6 - Least Functionality */
    ctrl = find_control(result, "3.4.6");
    if (ctrl) {
        if (implant->iommu.dma_device_count == 0 || implant->iommu.iommu_enabled) {
            if (ctrl->status == CONTROL_NOT_ASSESSED) {
                ctrl->status = CONTROL_PASS;
                snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                         "External DMA interfaces secured or absent.");
            }
        } else {
            ctrl->status = CONTROL_PARTIAL;
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "%d DMA-capable devices without IOMMU protection.",
                     implant->iommu.unprotected_count);
            add_finding(ctrl, "DMA devices not restricted by IOMMU");
        }
    }

    /* 3.4.7 - Nonessential Functionality */
    ctrl = find_control(result, "3.4.7");
    if (ctrl) {
        if (implant->suspicious_pci_count == 0 && implant->firmware_anomaly_count == 0) {
            if (ctrl->status == CONTROL_NOT_ASSESSED) {
                ctrl->status = CONTROL_PASS;
                snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                         "No suspicious PCI devices or firmware anomalies detected.");
            }
        } else {
            ctrl->status = CONTROL_PARTIAL;
            if (implant->suspicious_pci_count > 0) {
                add_finding(ctrl, "Suspicious PCI device(s) detected");
            }
            if (implant->firmware_anomaly_count > 0) {
                add_finding(ctrl, "Firmware anomaly detected");
            }
            snprintf(ctrl->evidence, sizeof(ctrl->evidence),
                     "Potentially nonessential or suspicious firmware features detected.");
        }
    }

    return FG_SUCCESS;
}
