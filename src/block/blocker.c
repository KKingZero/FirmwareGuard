#include "blocker.h"

int blocker_init(void) {
    FG_INFO("Blocker subsystem initialized (MVP: non-destructive mode)");
    return FG_SUCCESS;
}

void blocker_cleanup(void) {
    /* Nothing to cleanup */
}

int blocker_disable_intel_me(block_result_t *result) {
    if (!result) {
        return FG_ERROR;
    }

    memset(result, 0, sizeof(block_result_t));
    result->action = BLOCK_ACTION_DISABLE_ME;
    strncpy(result->component_name, "Intel Management Engine",
            sizeof(result->component_name) - 1);
    result->attempted = true;

    /* MVP: Provide recommendations instead of actual blocking */
    result->successful = false;
    result->requires_reboot = true;

    snprintf(result->method, sizeof(result->method),
            "Soft-disable via HAP bit or me_cleaner");

    snprintf(result->details, sizeof(result->details),
            "Intel ME can be disabled through several methods:\n"
            "1. HAP/AltMeDisable bit (if supported by vendor)\n"
            "2. me_cleaner tool (requires firmware modification)\n"
            "3. UEFI settings (vendor-specific)");

    snprintf(result->recommendation, sizeof(result->recommendation),
            "To disable Intel ME:\n"
            "- Check BIOS/UEFI settings for 'Intel ME' or 'AMT' options\n"
            "- Use me_cleaner: https://github.com/corna/me_cleaner\n"
            "- WARNING: Disabling ME may cause system instability on some platforms");

    FG_INFO("Generated Intel ME blocking recommendations");
    return FG_SUCCESS;
}

int blocker_disable_amd_psp(block_result_t *result) {
    if (!result) {
        return FG_ERROR;
    }

    memset(result, 0, sizeof(block_result_t));
    result->action = BLOCK_ACTION_DISABLE_PSP;
    strncpy(result->component_name, "AMD Platform Security Processor",
            sizeof(result->component_name) - 1);
    result->attempted = true;
    result->successful = false;
    result->requires_reboot = true;

    snprintf(result->method, sizeof(result->method),
            "Limited to UEFI settings or kernel parameters");

    snprintf(result->details, sizeof(result->details),
            "AMD PSP is deeply integrated and difficult to disable:\n"
            "1. Some ASUS motherboards have 'PSP fTPM' option in BIOS\n"
            "2. Kernel parameter: psp.psp_disabled=1\n"
            "3. No official AMD disable mechanism");

    snprintf(result->recommendation, sizeof(result->recommendation),
            "To limit AMD PSP:\n"
            "- Check BIOS for PSP/fTPM options\n"
            "- Add kernel parameter: psp.psp_disabled=1\n"
            "- WARNING: Complete PSP disable is generally not possible");

    FG_INFO("Generated AMD PSP blocking recommendations");
    return FG_SUCCESS;
}

int blocker_disable_wol(const char *interface, block_result_t *result) {
    char cmd[256];
    int ret;

    if (!interface || !result) {
        return FG_ERROR;
    }

    memset(result, 0, sizeof(block_result_t));
    result->action = BLOCK_ACTION_DISABLE_WOL;
    snprintf(result->component_name, sizeof(result->component_name),
            "Wake-on-LAN (%s)", interface);
    result->attempted = true;

    /* Try to disable WoL using ethtool */
    snprintf(cmd, sizeof(cmd), "ethtool -s %s wol d 2>/dev/null", interface);
    ret = system(cmd);

    if (ret == 0) {
        result->successful = true;
        snprintf(result->method, sizeof(result->method),
                "Disabled via ethtool");
        snprintf(result->details, sizeof(result->details),
                "Wake-on-LAN disabled for %s (not persistent across reboots)",
                interface);
        snprintf(result->recommendation, sizeof(result->recommendation),
                "To make persistent, add 'ethtool -s %s wol d' to startup scripts",
                interface);
        FG_INFO("Disabled Wake-on-LAN for %s", interface);
    } else {
        result->successful = false;
        snprintf(result->method, sizeof(result->method),
                "Attempted via ethtool (failed)");
        snprintf(result->details, sizeof(result->details),
                "Failed to disable Wake-on-LAN (may not be supported or need root)");
        snprintf(result->recommendation, sizeof(result->recommendation),
                "Try manually: sudo ethtool -s %s wol d", interface);
        FG_WARN("Failed to disable Wake-on-LAN for %s", interface);
    }

    return result->successful ? FG_SUCCESS : FG_ERROR;
}

int blocker_generate_recommendations(const audit_result_t *audit,
                                     blocking_results_t *results) {
    int idx = 0;

    if (!audit || !results) {
        return FG_ERROR;
    }

    memset(results, 0, sizeof(blocking_results_t));

    FG_INFO("Generating blocking recommendations...");

    /* Analyze each component and generate recommendations */
    for (int i = 0; i < audit->num_components; i++) {
        const component_status_t *comp = &audit->components[i];

        if (!comp->detected || !comp->active) {
            continue;
        }

        switch (comp->type) {
            case COMPONENT_INTEL_ME:
                if (comp->blockable) {
                    blocker_disable_intel_me(&results->actions[idx++]);
                }
                break;

            case COMPONENT_AMD_PSP:
                /* Generate recommendations even though not blockable */
                blocker_disable_amd_psp(&results->actions[idx++]);
                break;

            case COMPONENT_NIC_TELEMETRY:
                /* Extract interface name from component name */
                if (strstr(comp->name, "NIC:")) {
                    const char *iface = strchr(comp->name, ':');
                    if (iface) {
                        iface += 2;  /* Skip ": " */
                        if (comp->blockable) {
                            /* Only try WoL disable if component is blockable */
                            blocker_disable_wol(iface, &results->actions[idx++]);
                        }
                    }
                }
                break;

            default:
                /* For other components, provide generic recommendations */
                if (comp->blockable) {
                    block_result_t *res = &results->actions[idx++];
                    res->action = BLOCK_ACTION_KERNEL_PARAM;
                    strncpy(res->component_name, comp->name,
                           sizeof(res->component_name) - 1);
                    res->attempted = false;
                    snprintf(res->recommendation, sizeof(res->recommendation),
                            "Check BIOS settings or kernel parameters for %s",
                            comp->name);
                }
                break;
        }
    }

    results->num_actions = idx;

    /* Count successful blocks */
    for (int i = 0; i < results->num_actions; i++) {
        if (results->actions[i].successful) {
            results->successful_blocks++;
        } else if (results->actions[i].attempted) {
            results->failed_blocks++;
        }
        if (results->actions[i].requires_reboot) {
            results->requires_reboot = true;
        }
    }

    snprintf(results->summary, sizeof(results->summary),
            "%d blocking action%s generated: %d successful, %d failed/recommendations%s",
            results->num_actions,
            results->num_actions == 1 ? "" : "s",
            results->successful_blocks,
            results->failed_blocks,
            results->requires_reboot ? " (reboot required)" : "");

    FG_INFO("%s", results->summary);
    return FG_SUCCESS;
}

int blocker_attempt_blocking(const audit_result_t *audit,
                              blocking_results_t *results) {
    /* For MVP, blocking is non-destructive - just generate recommendations */
    return blocker_generate_recommendations(audit, results);
}
