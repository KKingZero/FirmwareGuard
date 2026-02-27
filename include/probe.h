#ifndef PROBE_H
#define PROBE_H

#include <stdint.h>
#include <stdbool.h>
#include "firmwareguard.h"

// Main probe orchestrator
int run_full_probe(void);

// Individual probe functions
int detect_intel_me(void);
int detect_amd_psp(void);
int parse_acpi_tables(void);
int scan_network_interfaces(void);

// Probe result structure
typedef struct {
    int num_components;
    component_status_t components[32];
    risk_level_t overall_risk;
    char summary[1024];
} probe_result_t;

// Function to convert probe results to audit format
int probe_to_audit(const probe_result_t *probe, audit_result_t *audit);

// Initialize probe subsystem
int probe_init(void);

// Cleanup probe subsystem
void probe_cleanup(void);

// Scan hardware for telemetry components
int probe_scan_hardware(probe_result_t *result);

#endif // PROBE_H