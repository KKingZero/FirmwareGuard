#ifndef FG_ARM_DETECT_H
#define FG_ARM_DETECT_H

#include "firmwareguard.h"

typedef struct {
    bool efivars_present;
    bool acpi_tables_present;
    bool devicetree_present;
    bool tee_present;
    bool optee_present;
    bool secure_monitor_hint;
    bool nic_firmware_paths;
    char kernel_release[128];
    char machine_model[256];
} arm_detect_result_t;

int arm_detect_run(arm_detect_result_t *out);
void arm_detect_print(const arm_detect_result_t *r, bool verbose);
int arm_detect_to_json(const arm_detect_result_t *r, char *buf, size_t n);

#endif /* FG_ARM_DETECT_H */
