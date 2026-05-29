#ifndef FG_NIC_H
#define FG_NIC_H

#include "../../include/firmwareguard.h"

#define FG_MAX_NICS 16

typedef struct {
    char name[32];
    char vendor[32];
    char device[32];
    char driver[64];
    bool wake_on_lan;
    bool intel_amt_hint;
    bool firmware_node;
} nic_info_t;

typedef struct {
    int count;
    nic_info_t nics[FG_MAX_NICS];
} nic_scan_result_t;

int nic_scan(nic_scan_result_t *result);

/* Print scan result in human-readable text form */
void nic_print_result(const nic_scan_result_t *result, bool verbose);

/* Serialize scan result to JSON. Returns FG_SUCCESS on success. */
int nic_result_to_json(const nic_scan_result_t *result, char *buffer, size_t size);

#endif /* FG_NIC_H */
