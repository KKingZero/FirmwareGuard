/*
 * FirmwareGuard - Tier-1 reversible remediation engine (Phase 2 blocker)
 *
 * Fulfills blocker_v2.h. Performs REVERSIBLE, OS-level hardening only - never
 * firmware flashing. Every mutating action:
 *   1. is skipped (logged as "[DRY-RUN] would") when safety_is_dry_run(),
 *   2. otherwise creates a backup + rollback point BEFORE acting,
 *   3. carries a human-readable warning surfaced in the report,
 *   4. is undone by safety_rollback() (real restore lives in safety/grub/uefi).
 *
 * v1 actions: kernel-cmdline (IOMMU / psp_disabled via GRUB), Wake-on-LAN
 * (ethtool + persistent systemd unit), Intel AMT (mask the LMS service).
 * ME HAP-bit is wired but only runs when explicitly enabled (dangerous tier).
 */

#include "blocker_v2.h"
#include "../grub/grub_config.h"
#include "../core/nic.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define WOL_UNIT_PATH "/etc/systemd/system/fwguard-wol@.service"

/* ---- local exec/validation helpers (no shell, clean env) -------------- */

static int v2_secure_execute(const char *program, char *const argv[]) {
    char *clean_env[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    pid_t pid = fork();
    if (pid < 0) {
        FG_LOG_ERROR("fork() failed: %s", strerror(errno));
        return FG_ERROR;
    }
    if (pid == 0) {
        execve(program, argv, clean_env);
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        return FG_ERROR;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return FG_ERROR;
}

static bool v2_valid_iface(const char *iface) {
    if (!iface || !*iface) return false;
    size_t len = strlen(iface);
    if (len > 15) return false;
    for (size_t i = 0; i < len; i++) {
        char c = iface[i];
        if (!isalnum((unsigned char)c) && c != '-' && c != '_' && c != ':' && c != '.') {
            return false;
        }
    }
    return true;
}

static bool v2_confirm_if_needed(blocker_v2_context_t *ctx,
                                 const char *action,
                                 const char *warning,
                                 risk_level_t risk) {
    if (!ctx || !ctx->safety_ctx || !ctx->safety_ctx->require_confirmation) {
        return true;
    }
    return safety_confirm_action(action, warning, risk);
}

static int v2_backup_file(safety_context_t *safety_ctx,
                          backup_type_t type,
                          const char *name,
                          const char *path) {
    struct stat st;
    FILE *fp;
    void *data;
    int ret;

    if (!safety_ctx || !name || !path) {
        return FG_ERROR;
    }

    if (stat(path, &st) != 0 || st.st_size <= 0 || st.st_size > MAX_BACKUP_SIZE) {
        FG_LOG_ERROR("Cannot backup %s: invalid file", path);
        return FG_ERROR;
    }

    data = malloc((size_t)st.st_size);
    if (!data) {
        return FG_ERROR;
    }

    fp = fopen(path, "rb");
    if (!fp) {
        free(data);
        return FG_ERROR;
    }

    if (fread(data, 1, (size_t)st.st_size, fp) != (size_t)st.st_size) {
        fclose(fp);
        free(data);
        return FG_ERROR;
    }
    fclose(fp);

    ret = safety_create_backup(safety_ctx, type, name, data, (size_t)st.st_size);
    free(data);
    return ret;
}

/* True if this host's CPU is AMD (selects amd_iommu / psp params). */
static bool v2_cpu_is_amd(void) {
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) return false;
    char line[256];
    bool amd = false;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "AuthenticAMD")) { amd = true; break; }
        if (strstr(line, "GenuineIntel")) { amd = false; break; }
    }
    fclose(fp);
    return amd;
}

/* Allocate the next operation slot (zeroed). NULL if full. */
static block_operation_t *v2_new_op(blocker_v2_context_t *ctx,
                                    block_method_t method,
                                    component_type_t target) {
    if (ctx->num_operations >= 32) return NULL;
    block_operation_t *op = &ctx->operations[ctx->num_operations++];
    memset(op, 0, sizeof(*op));
    op->method = method;
    op->target = target;
    return op;
}

/* ---- generic kernel cmdline action ------------------------------------ */

static int v2_add_kernel_param(blocker_v2_context_t *ctx,
                               component_type_t target,
                               const char *param,
                               const char *desc,
                               const char *warning) {
    block_operation_t *op = v2_new_op(ctx, BLOCK_METHOD_GRUB_CONFIG, target);
    if (!op) return FG_ERROR;
    op->reversible = true;
    op->requires_reboot = true;
    snprintf(op->description, sizeof(op->description), "%s (%s)", desc, param);
    snprintf(op->warning, sizeof(op->warning), "%s", warning);

    grub_config_t g;
    if (grub_init(&g) != FG_SUCCESS) {
        op->attempted = true;
        snprintf(op->error_message, sizeof(op->error_message),
                 "GRUB config not found (/etc/default/grub)");
        return FG_SUCCESS;
    }
    grub_read_config(&g);

    if (grub_has_kernel_param(&g, param)) {
        op->attempted = true;
        op->successful = true;
        snprintf(op->description, sizeof(op->description),
                 "%s — already present (%s)", desc, param);
        grub_cleanup(&g);
        return FG_SUCCESS;
    }

    op->attempted = true;
    if (safety_is_dry_run(ctx->safety_ctx)) {
        FG_INFO("[DRY-RUN] would add kernel param '%s' to %s", param, g.grub_file);
        op->successful = true;        /* simulated */
        grub_cleanup(&g);
        return FG_SUCCESS;
    }

    if (!v2_confirm_if_needed(ctx, op->description, op->warning, RISK_MEDIUM)) {
        snprintf(op->error_message, sizeof(op->error_message),
                 "User cancelled operation");
        grub_cleanup(&g);
        return FG_SUCCESS;
    }

    if (v2_backup_file(ctx->safety_ctx, BACKUP_TYPE_GRUB_CONFIG,
                       "grub_default", g.grub_file) != FG_SUCCESS ||
        safety_create_rollback_point(ctx->safety_ctx,
                                     "harden: kernel cmdline") != FG_SUCCESS) {
        snprintf(op->error_message, sizeof(op->error_message),
                 "Failed to create GRUB backup/rollback point");
        grub_cleanup(&g);
        return FG_SUCCESS;
    }

    /* grub_* respect safety_ctx; update regenerates bootloader config */
    if (grub_add_kernel_param(ctx->safety_ctx, &g, param) != FG_SUCCESS ||
        grub_write_config(ctx->safety_ctx, &g) != FG_SUCCESS ||
        grub_update(ctx->safety_ctx) != FG_SUCCESS) {
        snprintf(op->error_message, sizeof(op->error_message),
                 "Failed to apply '%s' to GRUB", param);
        grub_cleanup(&g);
        return FG_SUCCESS;
    }
    op->successful = true;
    grub_cleanup(&g);
    return FG_SUCCESS;
}

int blocker_v2_enable_iommu(blocker_v2_context_t *ctx) {
    if (!ctx) return FG_ERROR;
    const char *param = v2_cpu_is_amd() ? "amd_iommu=on" : "intel_iommu=on";
    int ret = v2_add_kernel_param(
        ctx, COMPONENT_CPU_FEATURE, param,
        "Enable IOMMU (DMA-attack protection)",
        "Takes effect after reboot. On rare platforms IOMMU can affect "
        "passthrough/GPU/Thunderbolt device behavior; reversible via rollback.");
    if (ret != FG_SUCCESS) {
        return ret;
    }
    return v2_add_kernel_param(
        ctx, COMPONENT_CPU_FEATURE, IOMMU_PT_PARAM,
        "Enable IOMMU passthrough mode",
        "Takes effect after reboot. Keeps IOMMU enabled while reducing "
        "performance impact; reversible via rollback.");
}

int blocker_v2_mitigate_psp_kernel(blocker_v2_context_t *ctx) {
    if (!ctx) return FG_ERROR;
    return v2_add_kernel_param(
        ctx, COMPONENT_AMD_PSP, PSP_DISABLE_PARAM,
        "Disable AMD PSP via kernel parameter",
        "Takes effect after reboot. May disable fTPM (BitLocker/measured boot "
        "depending on PSP); reversible via rollback.");
}

int blocker_v2_mitigate_psp_grub(blocker_v2_context_t *ctx) {
    /* Same mechanism as the kernel-param path (GRUB is where it persists). */
    return blocker_v2_mitigate_psp_kernel(ctx);
}

/* ---- Wake-on-LAN: runtime + persistent systemd unit ------------------- */

static int v2_read_wol_state(const char *iface, char *out, size_t n) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/device/power/wakeup", iface);
    FILE *fp = fopen(path, "r");
    if (!fp) return FG_ERROR;
    if (!fgets(out, (int)n, fp)) { fclose(fp); return FG_ERROR; }
    fclose(fp);
    out[strcspn(out, "\n")] = '\0';
    return FG_SUCCESS;
}

static int v2_write_wol_unit(void) {
    /* Idempotent template unit; %i is the interface instance name. */
    int fd = open(WOL_UNIT_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return FG_ERROR;
    static const char unit[] =
        "[Unit]\n"
        "Description=FirmwareGuard disable Wake-on-LAN for %i\n"
        "After=network-pre.target\n"
        "Wants=network-pre.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/sbin/ethtool -s %i wol d\n"
        "RemainAfterExit=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";
    ssize_t w = write(fd, unit, sizeof(unit) - 1);
    close(fd);
    return (w == (ssize_t)(sizeof(unit) - 1)) ? FG_SUCCESS : FG_ERROR;
}

int blocker_v2_disable_wol_persistent(blocker_v2_context_t *ctx,
                                      const char *interface) {
    if (!ctx || !v2_valid_iface(interface)) return FG_ERROR;

    block_operation_t *op = v2_new_op(ctx, BLOCK_METHOD_NIC_PERSISTENT,
                                      COMPONENT_NIC_TELEMETRY);
    if (!op) return FG_ERROR;
    op->reversible = true;
    snprintf(op->description, sizeof(op->description),
             "Disable Wake-on-LAN on %s (runtime + persistent)", interface);
    snprintf(op->warning, sizeof(op->warning),
             "Disables remote wake for %s. Reversible via rollback "
             "(restores prior WoL mode and removes the systemd unit).", interface);

    char prior[32] = "enabled";
    v2_read_wol_state(interface, prior, sizeof(prior));

    op->attempted = true;
    if (safety_is_dry_run(ctx->safety_ctx)) {
        FG_INFO("[DRY-RUN] would disable WoL on %s (prior=%s) and install %s",
                interface, prior, WOL_UNIT_PATH);
        op->successful = true;
        return FG_SUCCESS;
    }

    if (!v2_confirm_if_needed(ctx, op->description, op->warning, RISK_LOW)) {
        snprintf(op->error_message, sizeof(op->error_message),
                 "User cancelled operation");
        return FG_SUCCESS;
    }

    /* Back up prior state so rollback can restore it, then checkpoint. */
    char backup_name[256];
    char backup_payload[128];
    snprintf(backup_name, sizeof(backup_name), "wol-%s", interface);
    snprintf(backup_payload, sizeof(backup_payload),
             "iface=%s\nwol=%s\n", interface, prior);
    if (safety_create_backup(ctx->safety_ctx, BACKUP_TYPE_NIC_CONFIG, backup_name,
                             backup_payload, strlen(backup_payload) + 1) != FG_SUCCESS ||
        safety_create_rollback_point(ctx->safety_ctx,
                                     "harden: disable Wake-on-LAN") != FG_SUCCESS) {
        snprintf(op->error_message, sizeof(op->error_message),
                 "Failed to create WoL backup/rollback point");
        return FG_SUCCESS;
    }

    /* Runtime disable. */
    char ifbuf[16];
    snprintf(ifbuf, sizeof(ifbuf), "%s", interface);
    char *ethargv[] = { "/usr/sbin/ethtool", "-s", ifbuf, "wol", "d", NULL };
    int eret = v2_secure_execute("/usr/sbin/ethtool", ethargv);

    /* Persistent disable across reboots. */
    if (v2_write_wol_unit() == FG_SUCCESS) {
        char inst[64];
        snprintf(inst, sizeof(inst), "fwguard-wol@%s.service", interface);
        char *rl[] = { "/usr/bin/systemctl", "daemon-reload", NULL };
        v2_secure_execute("/usr/bin/systemctl", rl);
        char *en[] = { "/usr/bin/systemctl", "enable", inst, NULL };
        v2_secure_execute("/usr/bin/systemctl", en);
    }

    op->successful = (eret == 0);
    if (eret != 0) {
        snprintf(op->error_message, sizeof(op->error_message),
                 "ethtool returned %d (interface may not support WoL)", eret);
    }
    safety_log_operation(ctx->safety_ctx, "disable_wol",
                         op->successful, interface);
    return FG_SUCCESS;
}

static int v2_backup_service_state(safety_context_t *safety_ctx,
                                   const char *service) {
    char payload[256];
    char service_buf[128];
    int masked;
    int enabled;
    int active;
    char path[256];
    char link_target[256];
    ssize_t link_len;

    snprintf(service_buf, sizeof(service_buf), "%s", service);
    snprintf(path, sizeof(path), "/etc/systemd/system/%s", service);
    link_len = readlink(path, link_target, sizeof(link_target) - 1);
    if (link_len > 0) {
        link_target[link_len] = '\0';
        masked = (strcmp(link_target, "/dev/null") == 0);
    } else {
        masked = 0;
    }

    char *is_enabled[] = { "/usr/bin/systemctl", "is-enabled", "--quiet",
                           service_buf, NULL };
    enabled = (v2_secure_execute("/usr/bin/systemctl", is_enabled) == 0);

    char *is_active[] = { "/usr/bin/systemctl", "is-active", "--quiet",
                          service_buf, NULL };
    active = (v2_secure_execute("/usr/bin/systemctl", is_active) == 0);

    snprintf(payload, sizeof(payload),
             "service=%s\nmasked=%d\nenabled=%d\nactive=%d\n",
             service, masked ? 1 : 0, enabled ? 1 : 0, active ? 1 : 0);

    return safety_create_backup(safety_ctx, BACKUP_TYPE_SYSTEM_STATE,
                                "service_lms", payload, strlen(payload) + 1);
}

/* ---- Intel AMT: OS-side LMS service mask (firmware needs MEBx) --------- */

int blocker_v2_disable_amt(blocker_v2_context_t *ctx) {
    if (!ctx) return FG_ERROR;
    block_operation_t *op = v2_new_op(ctx, BLOCK_METHOD_SERVICE_MASK,
                                      COMPONENT_NIC_TELEMETRY);
    if (!op) return FG_ERROR;
    op->reversible = true;
    snprintf(op->description, sizeof(op->description),
             "Disable Intel AMT (mask the LMS manageability service)");
    snprintf(op->warning, sizeof(op->warning),
             "OS-side only: masks the Intel LMS service. FULL AMT disable "
             "requires MEBx (Ctrl-P at boot) or firmware — cannot be done from "
             "the OS. Reversible via rollback (unmask).");
    op->attempted = true;

    if (safety_is_dry_run(ctx->safety_ctx)) {
        FG_INFO("[DRY-RUN] would mask the 'lms' service (if present)");
        op->successful = true;
        return FG_SUCCESS;
    }

    /* Only mask if the unit exists. */
    char *chk[] = { "/usr/bin/systemctl", "list-unit-files", "lms.service", NULL };
    int present = v2_secure_execute("/usr/bin/systemctl", chk);
    if (present != 0) {
        op->successful = true;   /* nothing to mask is success */
        snprintf(op->description, sizeof(op->description),
                 "Intel LMS service not present — no OS-side AMT service to mask");
        return FG_SUCCESS;
    }

    if (!v2_confirm_if_needed(ctx, op->description, op->warning, RISK_MEDIUM)) {
        snprintf(op->error_message, sizeof(op->error_message),
                 "User cancelled operation");
        return FG_SUCCESS;
    }

    if (v2_backup_service_state(ctx->safety_ctx, "lms.service") != FG_SUCCESS ||
        safety_create_rollback_point(ctx->safety_ctx,
                                     "harden: mask Intel LMS (AMT)") != FG_SUCCESS) {
        snprintf(op->error_message, sizeof(op->error_message),
                 "Failed to create AMT service backup/rollback point");
        return FG_SUCCESS;
    }

    char *mask[] = { "/usr/bin/systemctl", "mask", "--now", "lms.service", NULL };
    int r = v2_secure_execute("/usr/bin/systemctl", mask);
    op->successful = (r == 0);
    if (r != 0) {
        snprintf(op->error_message, sizeof(op->error_message),
                 "systemctl mask lms returned %d", r);
    }
    safety_log_operation(ctx->safety_ctx, "disable_amt_lms", op->successful, NULL);
    return FG_SUCCESS;
}

/* ---- ME HAP bit (dangerous tier - only when explicitly enabled) ------- */

int blocker_v2_disable_me_hap(blocker_v2_context_t *ctx) {
    if (!ctx) return FG_ERROR;
    block_operation_t *op = v2_new_op(ctx, BLOCK_METHOD_HAP_BIT, COMPONENT_INTEL_ME);
    if (!op) return FG_ERROR;
    op->reversible = true;
    op->requires_reboot = true;
    snprintf(op->description, sizeof(op->description),
             "Set Intel ME HAP/AltMeDisable bit via UEFI variable");
    snprintf(op->warning, sizeof(op->warning),
             "DANGEROUS: modifies a UEFI variable. Requires Skylake+ and Secure "
             "Boot OFF; blocked otherwise. Recovery may need firmware reset.");
    op->attempted = true;

    /* uefi_set_me_hap_bit enforces Secure Boot gate + interactive confirm +
     * backup + rollback point internally, and honors dry-run via safety_ctx. */
    int r = uefi_set_me_hap_bit(ctx->safety_ctx, true);
    op->successful = (r == FG_SUCCESS);
    if (r != FG_SUCCESS) {
        snprintf(op->error_message, sizeof(op->error_message),
                 "HAP bit not set (unsupported platform, Secure Boot on, or cancelled)");
    }
    return FG_SUCCESS;
}

int blocker_v2_disable_me_uefi(blocker_v2_context_t *ctx) {
    /* Alias to the HAP-bit path for now (same UEFI-variable mechanism). */
    return blocker_v2_disable_me_hap(ctx);
}

/* ---- lifecycle / orchestration ---------------------------------------- */

int blocker_v2_init(blocker_v2_context_t *ctx, safety_context_t *safety_ctx,
                    fg_config_t *config) {
    if (!ctx || !safety_ctx || !config) return FG_ERROR;
    memset(ctx, 0, sizeof(*ctx));
    ctx->safety_ctx = safety_ctx;
    ctx->config = config;
    uefi_init(&ctx->uefi_state);   /* best-effort; HAP path checks support */
    return FG_SUCCESS;
}

void blocker_v2_cleanup(blocker_v2_context_t *ctx) {
    if (!ctx) return;
    uefi_cleanup(&ctx->uefi_state);
}

int blocker_v2_execute(blocker_v2_context_t *ctx, const probe_result_t *probe) {
    (void)probe;
    if (!ctx || !ctx->config) return FG_ERROR;
    fg_config_t *c = ctx->config;

    if (c->block_iommu) {
        blocker_v2_enable_iommu(ctx);
    }

    /* AMD PSP kernel mitigation, only on AMD and when requested. */
    if (c->block_amd_psp && c->psp_kernel_param && v2_cpu_is_amd()) {
        blocker_v2_mitigate_psp_kernel(ctx);
    }

    /* Wake-on-LAN: disable on every NIC that currently has it enabled. */
    if (c->block_nic_wol) {
        nic_scan_result_t nics;
        if (nic_scan(&nics) == FG_SUCCESS) {
            for (int i = 0; i < nics.count; i++) {
                if (nics.nics[i].wake_on_lan) {
                    blocker_v2_disable_wol_persistent(ctx, nics.nics[i].name);
                }
            }
        }
    }

    /* Intel AMT (OS-side LMS mask + firmware warning). */
    if (c->block_intel_amt) {
        blocker_v2_disable_amt(ctx);
    }

    /* ME HAP bit only when explicitly enabled (dangerous tier). */
    if (c->block_intel_me && c->me_use_hap_bit) {
        blocker_v2_disable_me_hap(ctx);
    }

    return FG_SUCCESS;
}

int blocker_v2_verify_operations(blocker_v2_context_t *ctx) {
    if (!ctx) return FG_ERROR;
    int ok = 0;
    for (int i = 0; i < ctx->num_operations; i++) {
        if (ctx->operations[i].successful) ok++;
    }
    return ok;
}

int blocker_v2_rollback(blocker_v2_context_t *ctx) {
    if (!ctx || !ctx->safety_ctx) return FG_ERROR;
    return safety_rollback(ctx->safety_ctx);
}

int blocker_v2_generate_report(const blocker_v2_context_t *ctx, FILE *output) {
    if (!ctx || !output) return FG_ERROR;
    bool dry = safety_is_dry_run(ctx->safety_ctx);
    fprintf(output, "\n=== FirmwareGuard Hardening %s ===\n",
            dry ? "Plan (dry-run - no changes made)" : "Results");
    if (ctx->num_operations == 0) {
        fprintf(output, "  No applicable hardening actions for this system.\n\n");
        return FG_SUCCESS;
    }
    bool reboot = false;
    for (int i = 0; i < ctx->num_operations; i++) {
        const block_operation_t *op = &ctx->operations[i];
        const char *state = dry ? "WOULD APPLY"
                          : (op->successful ? "OK" : "FAILED");
        fprintf(output, "\n[%s] %s\n", state, op->description);
        if (op->warning[0]) {
            fprintf(output, "    WARNING: %s\n", op->warning);
        }
        if (!op->successful && op->error_message[0]) {
            fprintf(output, "    error: %s\n", op->error_message);
        }
        if (op->requires_reboot) reboot = true;
    }
    fprintf(output, "\n");
    if (reboot) {
        fprintf(output, "Some changes require a REBOOT to take effect.\n");
    }
    if (dry) {
        fprintf(output, "Run again with --apply to perform these changes "
                        "(a backup + rollback point is created first).\n");
    } else {
        fprintf(output, "Undo everything with: firmwareguard rollback\n");
    }
    fprintf(output, "\n");
    return FG_SUCCESS;
}
