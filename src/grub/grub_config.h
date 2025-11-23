#ifndef FG_GRUB_CONFIG_H
#define FG_GRUB_CONFIG_H

#include "../../include/firmwareguard.h"
#include "../safety/safety.h"

/* GRUB configuration paths */
#define GRUB_DEFAULT_FILE "/etc/default/grub"
#define GRUB_CONFIG_FILE  "/boot/grub/grub.cfg"
#define GRUB_UPDATE_CMD   "update-grub"
#define GRUB2_UPDATE_CMD  "grub2-mkconfig -o /boot/grub2/grub.cfg"

/* Kernel parameter to add/remove */
#define PSP_DISABLE_PARAM "psp.psp_disabled=1"
#define IOMMU_PT_PARAM    "iommu=pt"
#define INTEL_IOMMU_OFF   "intel_iommu=off"

/* GRUB configuration state */
typedef struct {
    bool grub_exists;
    bool grub2_exists;
    char grub_file[256];
    char cmdline_current[1024];
    char cmdline_linux_default[1024];
    bool is_modified;
} grub_config_t;

/* Initialize GRUB subsystem */
int grub_init(grub_config_t *config);

/* Cleanup GRUB subsystem */
void grub_cleanup(grub_config_t *config);

/* Read current GRUB configuration */
int grub_read_config(grub_config_t *config);

/* Backup GRUB configuration */
int grub_backup_config(safety_context_t *safety_ctx);

/* Add kernel parameter */
int grub_add_kernel_param(safety_context_t *safety_ctx,
                          grub_config_t *config,
                          const char *param);

/* Remove kernel parameter */
int grub_remove_kernel_param(safety_context_t *safety_ctx,
                             grub_config_t *config,
                             const char *param);

/* Check if kernel parameter exists */
bool grub_has_kernel_param(const grub_config_t *config, const char *param);

/* Write modified GRUB configuration */
int grub_write_config(safety_context_t *safety_ctx,
                      const grub_config_t *config);

/* Update GRUB (run update-grub or grub2-mkconfig) */
int grub_update(safety_context_t *safety_ctx);

/* Restore GRUB configuration from backup */
int grub_restore_config(safety_context_t *safety_ctx);

/* Verify GRUB configuration syntax */
bool grub_verify_config(const grub_config_t *config);

/* PHASE 3: Enhanced dry-run validation */
int grub_dry_run_validate(const grub_config_t *config);

/* List all GRUB backups */
int grub_list_backups(FILE *output);

#endif /* FG_GRUB_CONFIG_H */
