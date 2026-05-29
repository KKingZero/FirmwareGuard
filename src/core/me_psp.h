#ifndef FG_ME_PSP_H
#define FG_ME_PSP_H

#include "../../include/firmwareguard.h"

typedef struct {
    bool present;
    bool active;
    bool amt_present;
    bool hap_available;
    char version[64];
    char device_id[32];
    char details[256];
} intel_me_info_t;

typedef struct {
    bool present;
    bool active;
    bool sev_supported;
    bool ftpm_hint;
    char version[64];
    char details[256];
} amd_psp_info_t;

int probe_intel_me(intel_me_info_t *info);
int probe_amd_psp(amd_psp_info_t *info);

/* Human-readable text output */
void intel_me_print(const intel_me_info_t *info, bool verbose);
void amd_psp_print(const amd_psp_info_t *info, bool verbose);

/* JSON serialization. Returns FG_SUCCESS on success. */
int intel_me_to_json(const intel_me_info_t *info, char *buffer, size_t size);
int amd_psp_to_json(const amd_psp_info_t *info, char *buffer, size_t size);

#endif /* FG_ME_PSP_H */
