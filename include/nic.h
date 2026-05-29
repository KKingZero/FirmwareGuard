#ifndef NIC_H
#define NIC_H

#include <stdint.h>

// Network interface scanning
int scan_network_interfaces(void);
char *get_nic_capabilities(const char *interface);

#endif // NIC_H