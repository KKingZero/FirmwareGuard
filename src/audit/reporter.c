#include "reporter.h"
#include <time.h>

int reporter_init(void) {
    FG_INFO("Reporter subsystem initialized");
    return FG_SUCCESS;
}

void reporter_cleanup(void) {
    /* Nothing to cleanup */
}

const char* reporter_risk_to_string(risk_level_t risk) {
    switch (risk) {
        case RISK_CRITICAL:  return "CRITICAL";
        case RISK_HIGH:      return "HIGH";
        case RISK_MEDIUM:    return "MEDIUM";
        case RISK_LOW:       return "LOW";
        case RISK_NONE:      return "NONE";
        default:             return "UNKNOWN";
    }
}

const char* reporter_component_type_to_string(component_type_t type) {
    switch (type) {
        case COMPONENT_INTEL_ME:        return "Intel ME";
        case COMPONENT_AMD_PSP:         return "AMD PSP";
        case COMPONENT_UEFI_NVRAM:      return "UEFI NVRAM";
        case COMPONENT_ACPI_TABLE:      return "ACPI Table";
        case COMPONENT_NIC_TELEMETRY:   return "NIC Telemetry";
        case COMPONENT_CPU_FEATURE:     return "CPU Feature";
        default:                        return "Unknown";
    }
}

static void json_escape_string(const char *input, char *output, size_t output_size) {
    size_t i, j = 0;
    for (i = 0; input[i] && j < output_size - 2; i++) {
        switch (input[i]) {
            case '"':  output[j++] = '\\'; output[j++] = '"'; break;
            case '\\': output[j++] = '\\'; output[j++] = '\\'; break;
            case '\n': output[j++] = '\\'; output[j++] = 'n'; break;
            case '\r': output[j++] = '\\'; output[j++] = 'r'; break;
            case '\t': output[j++] = '\\'; output[j++] = 't'; break;
            default:   output[j++] = input[i]; break;
        }
    }
    output[j] = '\0';
}

int reporter_generate_audit_report(const audit_result_t *audit,
                                   report_format_t format,
                                   FILE *output) {
    if (!audit || !output) {
        return FG_ERROR;
    }

    if (format == REPORT_FORMAT_JSON) {
        /* JSON format */
        fprintf(output, "{\n");
        fprintf(output, "  \"firmwareguard_version\": \"%s\",\n", FG_VERSION);
        fprintf(output, "  \"timestamp\": %ld,\n", time(NULL));
        fprintf(output, "  \"overall_risk\": \"%s\",\n",
                reporter_risk_to_string(audit->overall_risk));
        fprintf(output, "  \"num_components\": %d,\n", audit->num_components);
        fprintf(output, "  \"components\": [\n");

        for (int i = 0; i < audit->num_components; i++) {
            const component_status_t *comp = &audit->components[i];
            char escaped_details[1024];
            json_escape_string(comp->details, escaped_details, sizeof(escaped_details));

            fprintf(output, "    {\n");
            fprintf(output, "      \"type\": \"%s\",\n",
                    reporter_component_type_to_string(comp->type));
            fprintf(output, "      \"name\": \"%s\",\n", comp->name);
            fprintf(output, "      \"detected\": %s,\n", comp->detected ? "true" : "false");
            fprintf(output, "      \"active\": %s,\n", comp->active ? "true" : "false");
            fprintf(output, "      \"blockable\": %s,\n", comp->blockable ? "true" : "false");
            fprintf(output, "      \"blocked\": %s,\n", comp->blocked ? "true" : "false");
            fprintf(output, "      \"risk\": \"%s\",\n",
                    reporter_risk_to_string(comp->risk));
            fprintf(output, "      \"details\": \"%s\"\n", escaped_details);
            fprintf(output, "    }%s\n", i < audit->num_components - 1 ? "," : "");
        }

        fprintf(output, "  ],\n");
        fprintf(output, "  \"summary\": \"%s\"\n", audit->summary);
        fprintf(output, "}\n");

    } else {
        /* Text format */
        fprintf(output, "\n");
        fprintf(output, "========================================\n");
        fprintf(output, "  FIRMWAREGUARD AUDIT REPORT v%s\n", FG_VERSION);
        fprintf(output, "========================================\n");
        fprintf(output, "\n");
        fprintf(output, "Timestamp: %s", ctime(&(time_t){time(NULL)}));
        fprintf(output, "Overall Risk: %s\n", reporter_risk_to_string(audit->overall_risk));
        fprintf(output, "Components Found: %d\n", audit->num_components);
        fprintf(output, "\n");

        if (audit->num_components > 0) {
            fprintf(output, "DETECTED COMPONENTS:\n");
            fprintf(output, "--------------------\n\n");

            for (int i = 0; i < audit->num_components; i++) {
                const component_status_t *comp = &audit->components[i];

                fprintf(output, "[%d] %s\n", i + 1, comp->name);
                fprintf(output, "    Type:      %s\n",
                        reporter_component_type_to_string(comp->type));
                fprintf(output, "    Status:    %s\n",
                        comp->active ? "ACTIVE" : "Inactive");
                fprintf(output, "    Risk:      %s\n",
                        reporter_risk_to_string(comp->risk));
                fprintf(output, "    Blockable: %s\n",
                        comp->blockable ? "Yes" : "No");
                fprintf(output, "    Details:   %s\n", comp->details);
                fprintf(output, "\n");
            }
        } else {
            fprintf(output, "No telemetry components detected.\n\n");
        }

        fprintf(output, "SUMMARY:\n");
        fprintf(output, "--------\n");
        fprintf(output, "%s\n\n", audit->summary);
    }

    return FG_SUCCESS;
}

int reporter_generate_blocking_report(const blocking_results_t *results,
                                      report_format_t format,
                                      FILE *output) {
    if (!results || !output) {
        return FG_ERROR;
    }

    if (format == REPORT_FORMAT_JSON) {
        /* JSON format */
        fprintf(output, "{\n");
        fprintf(output, "  \"num_actions\": %d,\n", results->num_actions);
        fprintf(output, "  \"successful_blocks\": %d,\n", results->successful_blocks);
        fprintf(output, "  \"failed_blocks\": %d,\n", results->failed_blocks);
        fprintf(output, "  \"requires_reboot\": %s,\n",
                results->requires_reboot ? "true" : "false");
        fprintf(output, "  \"actions\": [\n");

        for (int i = 0; i < results->num_actions; i++) {
            const block_result_t *act = &results->actions[i];
            char esc_method[512], esc_details[1024], esc_rec[1024];

            json_escape_string(act->method, esc_method, sizeof(esc_method));
            json_escape_string(act->details, esc_details, sizeof(esc_details));
            json_escape_string(act->recommendation, esc_rec, sizeof(esc_rec));

            fprintf(output, "    {\n");
            fprintf(output, "      \"component\": \"%s\",\n", act->component_name);
            fprintf(output, "      \"attempted\": %s,\n", act->attempted ? "true" : "false");
            fprintf(output, "      \"successful\": %s,\n", act->successful ? "true" : "false");
            fprintf(output, "      \"method\": \"%s\",\n", esc_method);
            fprintf(output, "      \"details\": \"%s\",\n", esc_details);
            fprintf(output, "      \"recommendation\": \"%s\"\n", esc_rec);
            fprintf(output, "    }%s\n", i < results->num_actions - 1 ? "," : "");
        }

        fprintf(output, "  ],\n");
        fprintf(output, "  \"summary\": \"%s\"\n", results->summary);
        fprintf(output, "}\n");

    } else {
        /* Text format */
        fprintf(output, "\n");
        fprintf(output, "========================================\n");
        fprintf(output, "  BLOCKING ACTIONS REPORT\n");
        fprintf(output, "========================================\n");
        fprintf(output, "\n");
        fprintf(output, "Actions Generated: %d\n", results->num_actions);
        fprintf(output, "Successful: %d\n", results->successful_blocks);
        fprintf(output, "Failed/Recommendations: %d\n", results->failed_blocks);
        fprintf(output, "Reboot Required: %s\n",
                results->requires_reboot ? "Yes" : "No");
        fprintf(output, "\n");

        if (results->num_actions > 0) {
            fprintf(output, "ACTIONS:\n");
            fprintf(output, "--------\n\n");

            for (int i = 0; i < results->num_actions; i++) {
                const block_result_t *act = &results->actions[i];

                fprintf(output, "[%d] %s\n", i + 1, act->component_name);
                fprintf(output, "    Status:         %s\n",
                        act->successful ? "SUCCESS" :
                        act->attempted ? "FAILED" : "RECOMMENDATION");
                fprintf(output, "    Method:         %s\n", act->method);
                fprintf(output, "    Details:        %s\n", act->details);
                if (strlen(act->recommendation) > 0) {
                    fprintf(output, "    Recommendation: %s\n", act->recommendation);
                }
                fprintf(output, "\n");
            }
        }

        fprintf(output, "SUMMARY:\n");
        fprintf(output, "--------\n");
        fprintf(output, "%s\n\n", results->summary);
    }

    return FG_SUCCESS;
}

int reporter_generate_combined_report(const audit_result_t *audit,
                                      const blocking_results_t *blocking,
                                      report_format_t format,
                                      FILE *output) {
    if (!audit || !blocking || !output) {
        return FG_ERROR;
    }

    if (format == REPORT_FORMAT_JSON) {
        fprintf(output, "{\n");
        fprintf(output, "  \"firmwareguard_version\": \"%s\",\n", FG_VERSION);
        fprintf(output, "  \"timestamp\": %ld,\n", time(NULL));
        fprintf(output, "  \"audit\": ");

        /* Temporarily redirect to string buffer for nested JSON */
        char *audit_json = NULL;
        size_t audit_json_size = 0;
        FILE *temp = open_memstream(&audit_json, &audit_json_size);
        if (temp) {
            reporter_generate_audit_report(audit, REPORT_FORMAT_JSON, temp);
            fclose(temp);
            fprintf(output, "%s,\n", audit_json);
            free(audit_json);
        }

        fprintf(output, "  \"blocking\": ");
        char *blocking_json = NULL;
        size_t blocking_json_size = 0;
        temp = open_memstream(&blocking_json, &blocking_json_size);
        if (temp) {
            reporter_generate_blocking_report(blocking, REPORT_FORMAT_JSON, temp);
            fclose(temp);
            fprintf(output, "%s\n", blocking_json);
            free(blocking_json);
        }

        fprintf(output, "}\n");
    } else {
        reporter_generate_audit_report(audit, format, output);
        reporter_generate_blocking_report(blocking, format, output);
    }

    return FG_SUCCESS;
}
