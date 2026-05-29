#ifndef MSR_H
#define MSR_H

#include <sys/types.h>
#include <stdint.h>

// MSR access functions
int msr_init(void);
void msr_cleanup(void);
int msr_read(uint32_t cpu, uint32_t msr, uint64_t *value);
int msr_write(uint32_t cpu, uint32_t msr, uint64_t value);
int msr_get_cpu_count(void);

// MSR constants
#define MSR_IA32_FEATURE_CONTROL     0x3A
#define MSR_IA32_PLATFORM_ID        0x17
#define MSR_IA32_SMM_MONITOR_CTL     0x9B

// Intel ME detection MSRs
#define ME_STATUS_REG               0x40
#define ME_HAP_BIT                  (1 << 0)

#endif // MSR_H