#include "sarif.h"
#include "reporter.h"
#include "cJSON.h"

/* Map FirmwareGuard risk level to a SARIF result level. */
static const char *risk_to_sarif_level(risk_level_t risk) {
    switch (risk) {
        case RISK_CRITICAL:
        case RISK_HIGH:    return "error";
        case RISK_MEDIUM:  return "warning";
        case RISK_LOW:
        case RISK_NONE:
        default:           return "note";
    }
}

/* Stable rule id per component type, e.g. "FG-INTEL-ME". */
static const char *component_rule_id(component_type_t type) {
    switch (type) {
        case COMPONENT_INTEL_ME:      return "FG-INTEL-ME";
        case COMPONENT_AMD_PSP:       return "FG-AMD-PSP";
        case COMPONENT_UEFI_NVRAM:    return "FG-UEFI-NVRAM";
        case COMPONENT_ACPI_TABLE:    return "FG-ACPI-TABLE";
        case COMPONENT_NIC_TELEMETRY: return "FG-NIC-TELEMETRY";
        case COMPONENT_CPU_FEATURE:   return "FG-CPU-FEATURE";
        case COMPONENT_ARM_FIRMWARE:  return "FG-ARM-FIRMWARE";
        default:                      return "FG-UNKNOWN";
    }
}

int sarif_generate(const audit_result_t *audit, FILE *output) {
    if (!audit || !output) {
        return FG_ERROR;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return FG_ERROR;
    }

    cJSON_AddStringToObject(root, "version", "2.1.0");
    cJSON_AddStringToObject(root, "$schema",
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");

    cJSON *runs = cJSON_AddArrayToObject(root, "runs");
    cJSON *run = cJSON_CreateObject();
    cJSON_AddItemToArray(runs, run);

    /* tool.driver with one rule per distinct component type encountered */
    cJSON *tool = cJSON_AddObjectToObject(run, "tool");
    cJSON *driver = cJSON_AddObjectToObject(tool, "driver");
    cJSON_AddStringToObject(driver, "name", "FirmwareGuard");
    cJSON_AddStringToObject(driver, "version", FG_VERSION);
    cJSON_AddStringToObject(driver, "informationUri",
                            "https://github.com/KKingZero/FirmwareGuard");
    cJSON *rules = cJSON_AddArrayToObject(driver, "rules");

    bool rule_emitted[COMPONENT_MAX] = {false};
    for (int i = 0; i < audit->num_components; i++) {
        component_type_t t = audit->components[i].type;
        if (t < 0 || t >= COMPONENT_MAX || rule_emitted[t]) {
            continue;
        }
        rule_emitted[t] = true;

        cJSON *rule = cJSON_CreateObject();
        cJSON_AddStringToObject(rule, "id", component_rule_id(t));
        cJSON_AddStringToObject(rule, "name",
                                reporter_component_type_to_string(t));
        cJSON *short_desc = cJSON_AddObjectToObject(rule, "shortDescription");
        cJSON_AddStringToObject(short_desc, "text",
                                reporter_component_type_to_string(t));
        cJSON_AddItemToArray(rules, rule);
    }

    /* results: one per detected component */
    cJSON *results = cJSON_AddArrayToObject(run, "results");
    for (int i = 0; i < audit->num_components; i++) {
        const component_status_t *comp = &audit->components[i];
        if (!comp->detected) {
            continue;
        }

        cJSON *result = cJSON_CreateObject();
        cJSON_AddStringToObject(result, "ruleId", component_rule_id(comp->type));
        cJSON_AddStringToObject(result, "level", risk_to_sarif_level(comp->risk));

        cJSON *message = cJSON_AddObjectToObject(result, "message");
        char text[700];
        snprintf(text, sizeof(text), "%s [%s] risk=%s: %s",
                 comp->name,
                 reporter_component_type_to_string(comp->type),
                 reporter_risk_to_string(comp->risk),
                 comp->details);
        cJSON_AddStringToObject(message, "text", text);

        /* Property bag carries the structured fields */
        cJSON *props = cJSON_AddObjectToObject(result, "properties");
        cJSON_AddBoolToObject(props, "active", comp->active);
        cJSON_AddBoolToObject(props, "blockable", comp->blockable);
        cJSON_AddBoolToObject(props, "blocked", comp->blocked);
        cJSON_AddStringToObject(props, "risk",
                                reporter_risk_to_string(comp->risk));

        cJSON_AddItemToArray(results, result);
    }

    char *out = cJSON_Print(root);
    cJSON_Delete(root);
    if (!out) {
        return FG_ERROR;
    }

    fprintf(output, "%s\n", out);
    free(out);
    return FG_SUCCESS;
}
