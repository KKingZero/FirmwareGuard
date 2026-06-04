/*
 * FirmwareGuard CLI - reversible Tier-1 hardening and rollback.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "cli.h"
#include "../block/blocker_v2.h"
#include "../config/config.h"
#include "../core/probe.h"
#include "../safety/safety.h"

static void harden_build_config(const cli_opts_t *o, fg_config_t *config) {
    bool has_selector;

    config_get_defaults(config);
    config_load(config);

    has_selector = o->iommu || o->wol || o->no_wol || o->amt;

    config->block_intel_me = false;
    config->block_amd_psp = false;
    config->me_use_hap_bit = false;

    if (has_selector) {
        config->block_iommu = o->iommu;
        config->block_nic_wol = o->wol;
        config->block_intel_amt = o->amt;
    } else {
        config->block_iommu = true;
        config->block_nic_wol = true;
        config->block_intel_amt = true;
    }

    if (o->no_wol) {
        config->block_nic_wol = false;
    }

    if (o->dangerous) {
        config->block_intel_me = true;
        config->me_use_hap_bit = true;
    }

    config->safety_mode = o->apply
        ? (o->yes ? SAFETY_MODE_AUTO : SAFETY_MODE_CONFIRM)
        : SAFETY_MODE_DRY_RUN;
    config->require_confirmation = (config->safety_mode == SAFETY_MODE_CONFIRM);
}

static int harden_run(const cli_opts_t *o, bool apply_defaults) {
    fg_config_t config;
    fg_state_t state;
    safety_context_t safety;
    blocker_v2_context_t blocker;
    probe_result_t probe;
    FILE *output = stdout;
    int ret = FG_ERROR;

    if (fg_require_root() != FG_SUCCESS) {
        return FG_NO_PERMISSION;
    }

    harden_build_config(o, &config);
    if (apply_defaults) {
        config.block_iommu = true;
        if (!o->no_wol) {
            config.block_nic_wol = true;
        }
        config.block_intel_amt = true;
    }

    if (safety_init(&safety, config.safety_mode) != FG_SUCCESS) {
        return FG_ERROR;
    }

    if (probe_init() != FG_SUCCESS) {
        safety_cleanup(&safety);
        return FG_ERROR;
    }

    memset(&probe, 0, sizeof(probe));
    if (probe_scan_hardware(&probe) != FG_SUCCESS) {
        FG_WARN("Hardware scan failed; continuing with direct hardening probes");
    }

    if (blocker_v2_init(&blocker, &safety, &config) != FG_SUCCESS) {
        goto cleanup_probe;
    }

    ret = blocker_v2_execute(&blocker, &probe);

    if (o->output_file) {
        output = fopen(o->output_file, "w");
        if (!output) {
            FG_LOG_ERROR("Failed to open output file: %s", o->output_file);
            ret = FG_ERROR;
            goto cleanup_blocker;
        }
    }

    blocker_v2_generate_report(&blocker, output);

    if (output != stdout) {
        fclose(output);
        output = stdout;
    }

    if (ret == FG_SUCCESS && o->apply) {
        memset(&state, 0, sizeof(state));
        config_load_state(&state);
        state.psp_blocked = config.block_amd_psp;
        state.nic_wol_blocked = config.block_nic_wol;
        state.me_blocked = config.block_intel_me || config.block_intel_amt;
        state.last_apply_timestamp = (int)time(NULL);
        config_save_state(&state);
    }

cleanup_blocker:
    blocker_v2_cleanup(&blocker);
cleanup_probe:
    probe_cleanup();
    safety_cleanup(&safety);
    return ret;
}

int cmd_harden(int argc, char **argv, const cli_opts_t *o) {
    if (o->rollback || o->list_backups) {
        return cmd_rollback(argc, argv, o);
    }

    (void)argc;
    (void)argv;
    return harden_run(o, false);
}

int cmd_rollback(int argc, char **argv, const cli_opts_t *o) {
    safety_context_t safety;
    int ret;

    (void)argc;
    (void)argv;

    if (fg_require_root() != FG_SUCCESS) {
        return FG_NO_PERMISSION;
    }

    ret = safety_init(&safety, SAFETY_MODE_AUTO);
    if (ret != FG_SUCCESS) {
        return ret;
    }

    if (o->list_backups) {
        ret = safety_list_backups(&safety, stdout);
    } else {
        ret = safety_rollback(&safety);
    }

    safety_cleanup(&safety);
    return ret;
}
