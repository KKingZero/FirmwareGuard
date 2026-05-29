#ifndef ME_PSP_H
#define ME_PSP_H

#include <stdint.h>

// Intel ME detection
int detect_intel_me(void);
char *get_me_version(void);

// AMD PSP detection  
int detect_amd_psp(void);
char *get_psp_version(void);

#endif // ME_PSP_H