#ifndef FG_BLOCKER_V2_H
#define FG_BLOCKER_V2_H

#include "../core/probe.h"
#include "../safety/safety.h"
#include "../uefi/uefi_vars.h"
#include "../config/config.h"

/* Phase 2 blocking capabilities */
typedef enum {
    BLOCK_METHOD_HAP_BIT = 0,
    BLOCK_METHOD_UEFI_VAR,
    BLOCK_METHOD_KERNEL_PARAM,
    BLOCK_METHOD_GRUB_CONFIG,
    BLOCK_METHOD_NIC_PERSISTENT,
    BLOCK_METHOD_ME_CLEANER,
    BLOCK_METHOD_MAX
} block_method_t;

/* Blocking operation status */
typedef struct {
    block_method_t method;
    component_type_t target;
    bool attempted;
    bool successful;
    bool requires_reboot;
    bool reversible;
    char description[256];
    char error_message[512];
} block_operation_t;

/* Phase 2 blocker context */
typedef struct {
    safety_context_t *safety_ctx;
    fg_config_t *config;
    uefi_state_t uefi_state;
    int num_operations;
    block_operation_t operations[32];
} blocker_v2_context_t;

/* Initialize Phase 2 blocker */
int blocker_v2_init(blocker_v2_context_t *ctx, safety_context_t *safety_ctx,
                    fg_config_t *config);

/* Cleanup Phase 2 blocker */
void blocker_v2_cleanup(blocker_v2_context_t *ctx);

/* Execute blocking operations based on configuration */
int blocker_v2_execute(blocker_v2_context_t *ctx, const probe_result_t *probe);

/* Intel ME blocking via HAP bit */
int blocker_v2_disable_me_hap(blocker_v2_context_t *ctx);

/* Intel ME blocking via UEFI variable modification */
int blocker_v2_disable_me_uefi(blocker_v2_context_t *ctx);

/* AMD PSP mitigation via kernel parameters */
int blocker_v2_mitigate_psp_kernel(blocker_v2_context_t *ctx);

/* AMD PSP mitigation via GRUB configuration */
int blocker_v2_mitigate_psp_grub(blocker_v2_context_t *ctx);

/* NIC persistent Wake-on-LAN disable */
int blocker_v2_disable_wol_persistent(blocker_v2_context_t *ctx,
                                      const char *interface);

/* Intel AMT complete disable */
int blocker_v2_disable_amt(blocker_v2_context_t *ctx);

/* Generate Phase 2 blocking report */
int blocker_v2_generate_report(const blocker_v2_context_t *ctx, FILE *output);

/* Verify that blocking operations were successful */
int blocker_v2_verify_operations(blocker_v2_context_t *ctx);

/* Rollback all blocking operations */
int blocker_v2_rollback(blocker_v2_context_t *ctx);

#endif /* FG_BLOCKER_V2_H */
