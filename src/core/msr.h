#ifndef FG_MSR_H
#define FG_MSR_H

#include "../../include/firmwareguard.h"

int msr_init(void);
void msr_cleanup(void);

int msr_read(uint32_t cpu, uint32_t msr, uint64_t *value);
int msr_write(uint32_t cpu, uint32_t msr, uint64_t value);

bool msr_is_supported(void);
int msr_get_cpu_count(void);

#endif /* FG_MSR_H */
