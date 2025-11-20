#ifndef FG_BLOCKER_H
#define FG_BLOCKER_H

#include "../core/probe.h"

/* Blocking action types */
typedef enum {
    BLOCK_ACTION_NONE = 0,
    BLOCK_ACTION_DISABLE_ME,
    BLOCK_ACTION_DISABLE_PSP,
    BLOCK_ACTION_DISABLE_WOL,
    BLOCK_ACTION_KERNEL_PARAM,
    BLOCK_ACTION_UEFI_VAR,
    BLOCK_ACTION_MAX
} block_action_t;

/* Blocking result for a single action */
typedef struct {
    block_action_t action;
    char component_name[128];
    bool attempted;
    bool successful;
    bool requires_reboot;
    char method[256];
    char details[512];
    char recommendation[512];
} block_result_t;

/* Overall blocking results */
typedef struct {
    int num_actions;
    block_result_t actions[32];
    int successful_blocks;
    int failed_blocks;
    bool requires_reboot;
    char summary[1024];
} blocking_results_t;

/* Initialize blocker subsystem */
int blocker_init(void);

/* Cleanup blocker subsystem */
void blocker_cleanup(void);

/* Attempt to block telemetry components (non-destructive in MVP) */
int blocker_attempt_blocking(const audit_result_t *audit,
                              blocking_results_t *results);

/* Generate recommendations without actually blocking */
int blocker_generate_recommendations(const audit_result_t *audit,
                                     blocking_results_t *results);

/* Attempt to disable Intel ME (soft disable only) */
int blocker_disable_intel_me(block_result_t *result);

/* Attempt to disable AMD PSP */
int blocker_disable_amd_psp(block_result_t *result);

/* Disable Wake-on-LAN for a specific interface */
int blocker_disable_wol(const char *interface, block_result_t *result);

#endif /* FG_BLOCKER_H */
