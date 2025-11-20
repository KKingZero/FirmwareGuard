#ifndef FIRMWAREGUARD_H
#define FIRMWAREGUARD_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Version */
#define FG_VERSION "0.1.0-MVP"

/* Return codes */
#define FG_SUCCESS          0
#define FG_ERROR           -1
#define FG_NO_PERMISSION   -2
#define FG_NOT_FOUND       -3
#define FG_NOT_SUPPORTED   -4

/* Risk levels */
typedef enum {
    RISK_NONE = 0,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL
} risk_level_t;

/* Telemetry component types */
typedef enum {
    COMPONENT_INTEL_ME = 0,
    COMPONENT_AMD_PSP,
    COMPONENT_UEFI_NVRAM,
    COMPONENT_ACPI_TABLE,
    COMPONENT_NIC_TELEMETRY,
    COMPONENT_CPU_FEATURE,
    COMPONENT_MAX
} component_type_t;

/* Component status */
typedef struct {
    component_type_t type;
    char name[128];
    bool detected;
    bool active;
    bool blockable;
    bool blocked;
    risk_level_t risk;
    char details[512];
} component_status_t;

/* System audit results */
typedef struct {
    int num_components;
    component_status_t components[32];
    risk_level_t overall_risk;
    char summary[1024];
} audit_result_t;

/* Utility macros */
#define FG_LOG(level, fmt, ...) \
    fprintf(stderr, "[%s] " fmt "\n", level, ##__VA_ARGS__)

#define FG_DEBUG(fmt, ...) FG_LOG("DEBUG", fmt, ##__VA_ARGS__)
#define FG_INFO(fmt, ...)  FG_LOG("INFO", fmt, ##__VA_ARGS__)
#define FG_WARN(fmt, ...)  FG_LOG("WARN", fmt, ##__VA_ARGS__)
#define FG_LOG_ERROR(fmt, ...) FG_LOG("ERROR", fmt, ##__VA_ARGS__)

/* Require root privileges */
static inline int fg_require_root(void) {
    if (geteuid() != 0) {
        FG_LOG_ERROR("This operation requires root privileges");
        return FG_NO_PERMISSION;
    }
    return FG_SUCCESS;
}

#endif /* FIRMWAREGUARD_H */
