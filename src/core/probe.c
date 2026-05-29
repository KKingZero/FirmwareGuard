#include "probe.h"

static void add_component(audit_result_t *audit,
                          component_type_t type,
                          const char *name,
                          bool detected,
                          bool active,
                          bool blockable,
                          risk_level_t risk,
                          const char *details) {
    component_status_t *component;

    if (!audit || audit->num_components >= (int)(sizeof(audit->components) / sizeof(audit->components[0]))) {
        return;
    }

    component = &audit->components[audit->num_components++];
    memset(component, 0, sizeof(*component));
    component->type = type;
    snprintf(component->name, sizeof(component->name), "%s", name ? name : "Unknown");
    component->detected = detected;
    component->active = active;
    component->blockable = blockable;
    component->blocked = false;
    component->risk = risk;
    snprintf(component->details, sizeof(component->details), "%s", details ? details : "");
}

int probe_init(void) {
    FG_INFO("Probe subsystem initialized");
    return FG_SUCCESS;
}

void probe_cleanup(void) {
    /* No persistent state. */
}

risk_level_t probe_assess_risk(const probe_result_t *result) {
    int score = 0;

    if (!result) {
        return RISK_NONE;
    }

    if (result->intel_me.present && result->intel_me.active) {
        score += result->intel_me.amt_present ? 5 : 3;
    }
    if (result->amd_psp.present && result->amd_psp.active) {
        score += 2;
    }
    if (result->acpi.fpdt_present) {
        score += 1;
    }
    if (result->acpi.tpm2_present) {
        score += 2;
    }
    for (int i = 0; i < result->nic.count; i++) {
        if (result->nic.nics[i].intel_amt_hint) {
            score += 3;
        } else if (result->nic.nics[i].wake_on_lan) {
            score += 1;
        }
    }

    if (score >= 8) {
        return RISK_CRITICAL;
    }
    if (score >= 5) {
        return RISK_HIGH;
    }
    if (score >= 3) {
        return RISK_MEDIUM;
    }
    if (score >= 1) {
        return RISK_LOW;
    }
    return RISK_NONE;
}

int probe_to_audit(const probe_result_t *probe, audit_result_t *audit) {
    if (!probe || !audit) {
        return FG_ERROR;
    }

    memcpy(audit, &probe->audit, sizeof(*audit));
    return FG_SUCCESS;
}

int probe_scan_hardware(probe_result_t *result) {
    audit_result_t *audit;
    int detected = 0;

    if (!result) {
        return FG_ERROR;
    }

    memset(result, 0, sizeof(*result));
    audit = &result->audit;

    if (probe_intel_me(&result->intel_me) == FG_SUCCESS) {
        detected++;
    }
    add_component(audit, COMPONENT_INTEL_ME, "Intel Management Engine",
                  result->intel_me.present, result->intel_me.active,
                  result->intel_me.present, result->intel_me.amt_present ? RISK_HIGH : RISK_MEDIUM,
                  result->intel_me.details);

    if (probe_amd_psp(&result->amd_psp) == FG_SUCCESS) {
        detected++;
    }
    add_component(audit, COMPONENT_AMD_PSP, "AMD Platform Security Processor",
                  result->amd_psp.present, result->amd_psp.active,
                  false, result->amd_psp.present ? RISK_MEDIUM : RISK_NONE,
                  result->amd_psp.details);

    if (acpi_scan_telemetry(&result->acpi) == FG_SUCCESS) {
        char details[512];
        detected++;
        snprintf(details, sizeof(details),
                 "%d ACPI tables; FPDT=%s TPM2=%s DMAR=%s IVRS=%s OEM=%s",
                 result->acpi.table_count,
                 result->acpi.fpdt_present ? "yes" : "no",
                 result->acpi.tpm2_present ? "yes" : "no",
                 result->acpi.dmar_present ? "yes" : "no",
                 result->acpi.ivrs_present ? "yes" : "no",
                 result->acpi.suspicious_oem_tables ? "yes" : "no");
        add_component(audit, COMPONENT_ACPI_TABLE, "ACPI firmware tables",
                      true, true, false,
                      result->acpi.tpm2_present ? RISK_MEDIUM :
                      result->acpi.fpdt_present ? RISK_LOW : RISK_NONE,
                      details);
    } else {
        add_component(audit, COMPONENT_ACPI_TABLE, "ACPI firmware tables",
                      false, false, false, RISK_NONE, "ACPI table path not available");
    }

    if (nic_scan(&result->nic) == FG_SUCCESS) {
        detected += result->nic.count;
        for (int i = 0; i < result->nic.count; i++) {
            const nic_info_t *nic = &result->nic.nics[i];
            char name[128];
            char details[512];

            snprintf(name, sizeof(name), "NIC: %s", nic->name);
            snprintf(details, sizeof(details),
                     "vendor=%s device=%s driver=%s wake_on_lan=%s firmware_node=%s amt_hint=%s",
                     nic->vendor[0] ? nic->vendor : "unknown",
                     nic->device[0] ? nic->device : "unknown",
                     nic->driver[0] ? nic->driver : "unknown",
                     nic->wake_on_lan ? "yes" : "no",
                     nic->firmware_node ? "yes" : "no",
                     nic->intel_amt_hint ? "yes" : "no");
            add_component(audit, COMPONENT_NIC_TELEMETRY, name,
                          true, nic->wake_on_lan || nic->intel_amt_hint || nic->firmware_node,
                          nic->wake_on_lan,
                          nic->intel_amt_hint ? RISK_HIGH :
                          nic->wake_on_lan ? RISK_LOW : RISK_NONE,
                          details);
        }
    }

    audit->overall_risk = probe_assess_risk(result);
    snprintf(audit->summary, sizeof(audit->summary),
             "Read-only firmware audit completed: %d detected surface%s, %d report component%s.",
             detected, detected == 1 ? "" : "s",
             audit->num_components, audit->num_components == 1 ? "" : "s");

    return FG_SUCCESS;
}
