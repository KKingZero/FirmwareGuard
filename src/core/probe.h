#ifndef FG_PROBE_H
#define FG_PROBE_H

#include "../../include/firmwareguard.h"
#include "me_psp.h"
#include "acpi.h"
#include "nic.h"

typedef struct {
    intel_me_info_t intel_me;
    amd_psp_info_t amd_psp;
    acpi_scan_result_t acpi;
    nic_scan_result_t nic;
    audit_result_t audit;
} probe_result_t;

int probe_init(void);
void probe_cleanup(void);

int probe_scan_hardware(probe_result_t *result);
int probe_to_audit(const probe_result_t *probe, audit_result_t *audit);
risk_level_t probe_assess_risk(const probe_result_t *result);

#endif /* FG_PROBE_H */
