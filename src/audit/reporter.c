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
        case COMPONENT_ARM_FIRMWARE:    return "ARM Firmware";
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

static void html_escape_string(const char *input, char *output, size_t output_size) {
    size_t i, j = 0;
    for (i = 0; input[i] && j + 7 < output_size; i++) {
        switch (input[i]) {
            case '&':  j += (size_t)snprintf(output + j, output_size - j, "&amp;");  break;
            case '<':  j += (size_t)snprintf(output + j, output_size - j, "&lt;");   break;
            case '>':  j += (size_t)snprintf(output + j, output_size - j, "&gt;");   break;
            case '"':  j += (size_t)snprintf(output + j, output_size - j, "&quot;"); break;
            case '\'': j += (size_t)snprintf(output + j, output_size - j, "&#39;");  break;
            default:   output[j++] = input[i]; break;
        }
    }
    output[j] = '\0';
}

/* Lowercase CSS class for a risk level, used for color coding */
static const char* risk_css_class(risk_level_t risk) {
    switch (risk) {
        case RISK_CRITICAL: return "critical";
        case RISK_HIGH:     return "high";
        case RISK_MEDIUM:   return "medium";
        case RISK_LOW:      return "low";
        default:            return "none";
    }
}

static void html_doc_header(FILE *output, const char *title) {
    fprintf(output,
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<title>%s</title>\n"
        "<style>\n"
        "  body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}\n"
        "  .wrap{max-width:960px;margin:0 auto;padding:2rem}\n"
        "  h1{font-size:1.5rem;margin:0 0 .25rem}\n"
        "  h2{font-size:1.1rem;margin:2rem 0 .5rem;border-bottom:1px solid #2a2f3a;padding-bottom:.3rem}\n"
        "  .meta{color:#8a93a2;font-size:.85rem;margin-bottom:1rem}\n"
        "  .banner{padding:.75rem 1rem;border-radius:6px;font-weight:600;margin:1rem 0}\n"
        "  table{width:100%%;border-collapse:collapse;font-size:.9rem}\n"
        "  th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid #232833;vertical-align:top}\n"
        "  th{color:#8a93a2;font-weight:600;text-transform:uppercase;font-size:.72rem;letter-spacing:.04em}\n"
        "  .pill{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:.75rem;font-weight:600}\n"
        "  .critical{background:#4a1020;color:#ff6b8a} .high{background:#4a2410;color:#ff9d54}\n"
        "  .medium{background:#4a4310;color:#ffe14d} .low{background:#10324a;color:#5cc0ff}\n"
        "  .none{background:#1a2b1a;color:#7fd47f}\n"
        "  .summary{background:#161a22;border:1px solid #232833;border-radius:6px;padding:1rem;white-space:pre-wrap}\n"
        "</style>\n</head>\n<body>\n<div class=\"wrap\">\n",
        title);
}

static void html_doc_footer(FILE *output) {
    fprintf(output, "</div>\n</body>\n</html>\n");
}

static void html_audit_section(FILE *output, const audit_result_t *audit) {
    char esc[1024];

    fprintf(output, "<h1>FirmwareGuard Audit Report</h1>\n");
    fprintf(output, "<div class=\"meta\">Version %s &middot; %s</div>\n",
            FG_VERSION, ctime(&(time_t){time(NULL)}));
    fprintf(output, "<div class=\"banner %s\">Overall Risk: %s &middot; %d component(s)</div>\n",
            risk_css_class(audit->overall_risk),
            reporter_risk_to_string(audit->overall_risk),
            audit->num_components);

    if (audit->num_components > 0) {
        fprintf(output, "<h2>Detected Components</h2>\n<table>\n"
            "<tr><th>#</th><th>Name</th><th>Type</th><th>Status</th>"
            "<th>Risk</th><th>Blockable</th><th>Details</th></tr>\n");
        for (int i = 0; i < audit->num_components; i++) {
            const component_status_t *comp = &audit->components[i];
            html_escape_string(comp->details, esc, sizeof(esc));
            char esc_name[256];
            html_escape_string(comp->name, esc_name, sizeof(esc_name));
            fprintf(output,
                "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td>"
                "<td><span class=\"pill %s\">%s</span></td><td>%s</td><td>%s</td></tr>\n",
                i + 1, esc_name,
                reporter_component_type_to_string(comp->type),
                comp->active ? "ACTIVE" : "Inactive",
                risk_css_class(comp->risk), reporter_risk_to_string(comp->risk),
                comp->blockable ? "Yes" : "No", esc);
        }
        fprintf(output, "</table>\n");
    } else {
        fprintf(output, "<p>No telemetry components detected.</p>\n");
    }

    html_escape_string(audit->summary, esc, sizeof(esc));
    fprintf(output, "<h2>Summary</h2>\n<div class=\"summary\">%s</div>\n", esc);
}

static void html_blocking_section(FILE *output, const blocking_results_t *results) {
    char esc[1024];

    fprintf(output, "<h2>Blocking Actions</h2>\n");
    fprintf(output, "<div class=\"meta\">%d action(s) &middot; %d successful &middot; "
            "%d failed/recommended &middot; reboot %s</div>\n",
            results->num_actions, results->successful_blocks,
            results->failed_blocks, results->requires_reboot ? "required" : "not required");

    if (results->num_actions > 0) {
        fprintf(output, "<table>\n<tr><th>#</th><th>Component</th><th>Status</th>"
            "<th>Method</th><th>Details</th><th>Recommendation</th></tr>\n");
        for (int i = 0; i < results->num_actions; i++) {
            const block_result_t *act = &results->actions[i];
            char esc_method[512], esc_rec[1024], esc_comp[256];
            html_escape_string(act->component_name, esc_comp, sizeof(esc_comp));
            html_escape_string(act->method, esc_method, sizeof(esc_method));
            html_escape_string(act->details, esc, sizeof(esc));
            html_escape_string(act->recommendation, esc_rec, sizeof(esc_rec));
            fprintf(output,
                "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
                i + 1, esc_comp,
                act->successful ? "SUCCESS" : act->attempted ? "FAILED" : "RECOMMENDATION",
                esc_method, esc, esc_rec);
        }
        fprintf(output, "</table>\n");
    }

    html_escape_string(results->summary, esc, sizeof(esc));
    fprintf(output, "<div class=\"summary\">%s</div>\n", esc);
}

int reporter_generate_audit_report(const audit_result_t *audit,
                                   report_format_t format,
                                   FILE *output) {
    if (!audit || !output) {
        return FG_ERROR;
    }

    if (format == REPORT_FORMAT_HTML) {
        html_doc_header(output, "FirmwareGuard Audit Report");
        html_audit_section(output, audit);
        html_doc_footer(output);
        return FG_SUCCESS;
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

    if (format == REPORT_FORMAT_HTML) {
        html_doc_header(output, "FirmwareGuard Blocking Report");
        html_blocking_section(output, results);
        html_doc_footer(output);
        return FG_SUCCESS;
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

    if (format == REPORT_FORMAT_HTML) {
        html_doc_header(output, "FirmwareGuard Report");
        html_audit_section(output, audit);
        html_blocking_section(output, blocking);
        html_doc_footer(output);
        return FG_SUCCESS;
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
