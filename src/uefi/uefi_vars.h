#ifndef FG_UEFI_VARS_H
#define FG_UEFI_VARS_H

#include "../../include/firmwareguard.h"
#include "../safety/safety.h"

/* UEFI variable paths */
#define UEFI_VARS_PATH "/sys/firmware/efi/efivars"
#define UEFI_VARS_ALT_PATH "/sys/firmware/efi/vars"

/* Known UEFI variable GUIDs */
#define EFI_GLOBAL_VARIABLE_GUID "8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define INTEL_ME_SETUP_GUID      "c9806f36-0f6a-4024-87c3-c8d65d862c73"

/* UEFI variable attributes (from UEFI spec 2.9) */
#define EFI_VARIABLE_NON_VOLATILE                          0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS                    0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS                        0x00000004
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD                 0x00000008
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS            0x00000010
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x00000020
#define EFI_VARIABLE_APPEND_WRITE                          0x00000040

/* UEFI variable data */
typedef struct {
    char name[256];
    char guid[64];
    char full_path[512];
    uint32_t attributes;
    size_t data_size;
    uint8_t *data;
    bool exists;
} uefi_variable_t;

/* UEFI subsystem state */
typedef struct {
    bool efi_supported;
    bool vars_accessible;
    char vars_path[256];
    bool efivars_mounted;
} uefi_state_t;

/* Initialize UEFI subsystem */
int uefi_init(uefi_state_t *state);

/* Cleanup UEFI subsystem */
void uefi_cleanup(uefi_state_t *state);

/* Check if UEFI is supported on this system */
bool uefi_is_supported(void);

/* Check if efivars is mounted and writable */
bool uefi_vars_is_writable(void);

/* Read UEFI variable */
int uefi_read_variable(const char *name, const char *guid,
                       uefi_variable_t *var);

/* Write UEFI variable (with safety context) */
int uefi_write_variable(safety_context_t *safety_ctx,
                        const char *name, const char *guid,
                        uint32_t attributes, const void *data, size_t data_size);

/* Delete UEFI variable */
int uefi_delete_variable(safety_context_t *safety_ctx,
                         const char *name, const char *guid);

/* Backup UEFI variable */
int uefi_backup_variable(safety_context_t *safety_ctx,
                         const uefi_variable_t *var);

/* Restore UEFI variable from backup */
int uefi_restore_variable(safety_context_t *safety_ctx,
                          const char *backup_name);

/* List all UEFI variables */
int uefi_list_variables(FILE *output);

/* Parse Intel ME HAP (High Assurance Platform) variable */
int uefi_parse_me_hap_variable(const uefi_variable_t *var, bool *hap_enabled);

/* Set Intel ME HAP bit */
int uefi_set_me_hap_bit(safety_context_t *safety_ctx, bool enable);

/* Check if Intel ME HAP is available */
bool uefi_is_me_hap_available(void);

/* Free UEFI variable data */
void uefi_free_variable(uefi_variable_t *var);

#endif /* FG_UEFI_VARS_H */
