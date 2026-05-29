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

#endif /* FG_ME_PSP_H */
