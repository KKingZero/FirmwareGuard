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

#endif /* FG_NIC_H */
