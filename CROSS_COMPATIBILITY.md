# FirmwareGuard Cross-Compatibility Guide

## Overview

FirmwareGuard is a highly portable firmware integrity and anomaly detection framework that works across multiple Linux distributions. The tool is designed to be distribution-agnostic, focusing on hardware and firmware-level interfaces that are consistent across Linux systems.

## Supported Distributions

### Arch Linux
- ✅ **Fully Supported**
- Dependencies: `sqlite openssl base-devel libcpuid`
- Installation: Available via AUR (`yay -S firmwareguard-git`)
- Kernel modules: `msr` (Model Specific Register access)

### Debian/Ubuntu
- ✅ **Fully Supported**
- Dependencies: `libsqlite3-dev libssl-dev build-essential git`
- Installation: Build from source
- Kernel modules: `msr` (usually pre-installed)

### Fedora/RHEL/CentOS
- ✅ **Fully Supported**
- Dependencies: `sqlite-devel openssl-devel gcc make git`
- Installation: Build from source
- Kernel modules: `msr`

### Other Linux Distributions
- ✅ **Expected to Work**
- Requires standard Linux kernel with MSR support
- Compatible with any distribution that provides the necessary dependencies

## Building on Different Distributions

### Arch Linux
```bash
# Install dependencies
sudo pacman -S sqlite openssl base-devel gcc make git

# Enable MSR module
echo "msr" | sudo tee -a /etc/modules
sudo modprobe msr

# Build
git clone https://github.com/KKingZero/FirmwareGuard.git
cd FirmwareGuard
make
```

### Debian/Ubuntu
```bash
# Install dependencies
sudo apt update
sudo apt install libsqlite3-dev libssl-dev build-essential git

# Enable MSR module (usually already available)
sudo modprobe msr

# Build
git clone https://github.com/KKingZero/FirmwareGuard.git
cd FirmwareGuard
make
```

### Fedora/RHEL/CentOS
```bash
# Install dependencies
sudo dnf install sqlite-devel openssl-devel gcc make git

# Enable MSR module
sudo modprobe msr

# Build
git clone https://github.com/KKingZero/FirmwareGuard.git
cd FirmwareGuard
make
```

## System Requirements

### Minimum Requirements
- **Architecture**: x86_64 (Intel/AMD)
- **Kernel**: 4.15 or later (for MSR support)
- **Memory**: 64MB available RAM
- **Storage**: 5MB for binary + 10MB for temporary files

### Required Kernel Modules
- `msr` - Model Specific Register access (for CPU-level telemetry detection)
- `pci` - PCI configuration space access (for device telemetry detection)

### Required System Access
- Root privileges for hardware access
- `/dev/cpu/*/msr` device files
- `/sys/firmware/acpi/` access
- PCI configuration space access

## Distribution-Specific Notes

### Arch Linux
- MSR module usually available by default
- Dependencies available in main repositories
- AUR package available for easy installation

### Debian/Ubuntu
- MSR module typically available but may need to be loaded manually
- Dependencies available in main repositories
- May require adding `msr` to `/etc/modules` for persistence

### Fedora/RHEL/CentOS
- MSR module available in kernel
- Dependencies available in main repositories
- SELinux policies may need adjustment for hardware access

## Compatibility Features

### Hardware Abstraction Layer
- Uses standard Linux system calls for hardware access
- Compatible with different CPU vendors (Intel, AMD)
- Works with various chipsets and motherboards

### Firmware Interface Compatibility
- ACPI table parsing works across vendors
- UEFI variable access compatible with different implementations
- PCI ID database works with all vendors

### Security Model Compatibility
- Works with different security modules (AppArmor, SELinux, Smack)
- Compatible with various privilege escalation methods
- Designed for root-only operation (consistent across distributions)

## Known Limitations

### Distribution-Specific Issues
- Some distributions may have stricter security policies
- Kernel configurations may vary between distributions
- Hardware access permissions may differ

### Hardware Compatibility
- Requires Intel or AMD x86_64 processor
- Some older hardware may lack certain telemetry features
- Virtualized environments may have limited hardware access

## Testing Matrix

| Distribution | Build Status | Runtime Status | Notes |
|--------------|--------------|----------------|-------|
| Arch Linux latest | ✅ Working | ✅ Working | Primary development platform |
| Ubuntu 20.04+ | ✅ Working | ✅ Working | Tested regularly |
| Debian 11+ | ✅ Working | ✅ Working | Tested regularly |
| Fedora 35+ | ✅ Working | ✅ Working | Tested regularly |
| CentOS 8+ | ✅ Working | ✅ Working | Limited testing |

## Troubleshooting

### Common Issues
1. **MSR Access Denied**: Ensure `msr` module is loaded and running with `sudo`
2. **Missing Dependencies**: Install the appropriate development packages for your distribution
3. **PCI Access Issues**: Run with root privileges

### Verification Steps
```bash
# Check MSR availability
ls /dev/cpu/*/msr

# Check required kernel modules
lsmod | grep msr

# Verify basic functionality
sudo ./firmwareguard --help
```

## Conclusion

FirmwareGuard is designed with portability in mind and should work consistently across different Linux distributions. The core functionality relies on standard Linux kernel interfaces that are available across distributions, making it a reliable tool regardless of your specific Linux distribution choice.