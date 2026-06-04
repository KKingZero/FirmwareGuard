# FirmwareGuard
### Open-Source Firmware Integrity & Anomaly Detection Framework

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![Security](https://img.shields.io/badge/security-hardened-brightgreen)
![Privacy](https://img.shields.io/badge/privacy-offline--only-purple)

FirmwareGuard is a **low-level, vendor-independent framework** for detecting and analyzing firmware-level telemetry on x86/x64 systems. It provides deep visibility into chipset telemetry mechanisms like Intel ME, AMD PSP, ACPI tables, and NIC firmware capabilities.

Built for **security researchers, hardware engineers, and privacy-focused operators** who need transparent, auditable firmware security.

## Current Verified Status

The current tree is in build-stabilization state. The default userspace CLI,
ARM-safe test target, safety tests, and kernel module build have been restored,
but several Phase 4 research modules remain source-present prototypes until
they are wired into the main CLI and CI.

See [STATUS.md](STATUS.md) for the verified command surface and prototype list.

---

## 🔥 Why FirmwareGuard Matters

Firmware-level telemetry bypasses traditional OS-level privacy controls:
- **Intel ME** can access network interfaces independent of the OS
- **AMD PSP** controls boot security and attestation
- **ACPI firmware** collects performance metrics
- **NIC firmware** enables remote management (AMT, DASH)

Traditional security tools operate at the OS level and **cannot detect or control firmware telemetry**.

FirmwareGuard fills this gap.

---

## 🔒 Privacy-First: 100% Offline-Only

**FirmwareGuard operates with ZERO network dependencies.**

### Why Offline-Only?
- **Your firmware data never leaves your machine** - No cloud, no telemetry, no "phoning home"
- **Perfect for air-gapped systems** - Works on completely isolated networks (government, military, research)
- **No trust required** - We can't collect your data if we never connect
- **Verifiable privacy** - 100% open source, auditable code, zero network syscalls

### What This Means:
- ✅ All operations are local-only
- ✅ All reports stored on your filesystem
- ✅ No update servers or cloud dependencies
- ✅ No usage analytics or crash reporting
- ✅ Works completely offline
- ❌ No central management server (Enterprise-only feature)
- ❌ No network communication of any kind
- ❌ No HTTP, TCP, UDP, or any network protocols

**Enforcement:**
- Makefile checks block networking code at build time
- Pre-commit hooks prevent accidental network code
- CI/CD validates offline-only architecture

---

## ⚙️ Core Features

### ✅ Hardware Probe & Audit
- **CPU & Chipset Analysis**: Detects Intel ME, AMD PSP, and associated firmware versions.
- **ACPI Table Parsing**: Analyzes tables like FPDT, TPM2, DMAR, and IVRS for telemetry indicators.
- **NIC Firmware Capabilities**: Identifies Wake-on-LAN, Intel AMT, and remote stats reporting.
- **Risk Assessment**: Classifies system risk (LOW to CRITICAL) based on detected components.
- **Audit Reports**: Generates JSON and human-readable reports with actionable recommendations.

### ✅ Active Hardening & Blocking
- **Intel ME Control**: Disables ME via HAP bit manipulation in UEFI variables, with analysis and validation.
- **AMD PSP Mitigation**: Neutralizes PSP activity by injecting kernel parameters through GRUB configuration.
- **Persistent Blocking**: Enforces configurations at boot time using a systemd service.
- **Enhanced NIC Control**: Persistently disables Wake-on-LAN and mitigates Intel AMT/vPro.

### ✅ Safety & Reliability
- **Security Hardened**: Built with stack protection, PIE, RELRO, and `_FORTIFY_SOURCE` to prevent exploitation.
- **Safety Framework**: Includes a dry-run mode, automatic backups with checksums, and rollback points for safe testing.
- **User Confirmation**: Requires explicit user approval for critical, potentially destructive operations.
- **Failsafe Rollback**: Integrates with the bootloader to revert changes in case of boot failure.

### Tier-1 Reversible Hardening

FirmwareGuard is still audit-first. Mutating hardening is opt-in and dry-run by
default:

```bash
sudo ./firmwareguard harden              # plan only, no changes
sudo ./firmwareguard harden --apply      # apply with confirmations
sudo ./firmwareguard harden --apply --yes
sudo ./firmwareguard rollback            # restore latest rollback point
sudo ./firmwareguard rollback --list-backups
```

Tier-1 actions are OS-level and reversible: IOMMU kernel command-line hardening,
Wake-on-LAN disable with a persistent systemd unit, and OS-side Intel AMT/LMS
service masking. Backups live under `/var/lib/firmwareguard/backups`; rollback
points are checksum-verified before restore. Firmware flashing, `flashrom -w`,
MSR writes, and ME-cleaner style firmware modification are not part of Tier 1.

### ✅ Extensible Architecture
- **Kernel Module (Optional)**: Provides a mechanism for kernel-level MMIO region tracking and DMA restriction.
- **Configuration System**: Manages settings and state via a clear configuration file (`/etc/firmwareguard/config.conf`).

### ✅ Enhanced Security & CI/CD (Build Stabilization)
- **CI Coverage**: GitHub Actions builds the default CLI and runs available unit tests.
- **Secure Boot Detection**: Pre-flight checks prevent UEFI modification failures on Secure Boot systems.
- **HAP Platform Validation**: CPU generation detection prevents Intel ME disable attempts on unsupported hardware.
- **HAP Platform Validation**: CPU generation detection prevents system bricking on unsupported platforms.
- **Enhanced GRUB Safety**: Comprehensive dry-run validation and timestamped backups.

---

## 🧩 Architecture Overview

```
FirmwareGuard/
├── src/
│   ├── core/              # Hardware probing modules
│   │   ├── msr.c          # Model-Specific Register access
│   │   ├── me_psp.c       # Intel ME / AMD PSP detection
│   │   ├── acpi.c         # ACPI table parsing
│   │   ├── nic.c          # Network interface telemetry detection
│   │   └── probe.c        # Orchestrator for all probes
│   ├── block/             # Blocking implementations
│   │   ├── blocker.c      # Phase 1 blocking recommendations
│   │   └── blocker_v2.h   # Phase 2 active blocking interface
│   ├── audit/
│   │   └── reporter.c     # Report generation (JSON/text)
│   ├── safety/            # Phase 2: Safety framework
│   │   ├── safety.c       # Backup, restore, rollback
│   │   └── safety.h       # Safety context and operations
│   ├── config/            # Phase 2: Configuration management
│   │   ├── config.c       # Config file parsing and state
│   │   └── config.h       # Configuration structures
│   ├── uefi/              # Phase 2: UEFI variable manipulation
│   │   ├── uefi_vars.c    # UEFI variable read/write
│   │   └── uefi_vars.h    # UEFI structures
│   ├── grub/              # Phase 2: GRUB configuration
│   │   ├── grub_config.c  # GRUB config management
│   │   └── grub_config.h  # GRUB structures
│   └── main.c             # CLI interface
├── kernel/                # Phase 2: Kernel module (optional)
│   ├── fwguard_km.c       # MMIO/DMA protection module
│   ├── fwguard_km.h       # Module headers
│   └── Makefile           # Kernel build system
├── systemd/               # Phase 2: System integration
│   └── firmwareguard.service  # Boot-time service
├── docs/                  # Documentation
│   ├── PHASE2.md          # Phase 2 user guide
│   ├── SECURITY.md        # Security analysis
│   └── ...                # Additional guides
├── include/
│   └── firmwareguard.h    # Common headers and definitions
├── Makefile               # Build system (with security hardening)
└── README.md              # This file
```

---

## 📦 Installation

### Prerequisites

- **Linux kernel** with MSR support (CONFIG_X86_MSR)
- **GCC** or compatible C compiler
- **Root privileges** for hardware access
- **ethtool** (optional, for NIC control)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/KKingZero/FirmwareGuard.git
cd FirmwareGuard

# Build userspace binary (with security hardening)
make

# Build kernel module (optional - for MMIO/DMA protection)
make kernel

# Test
./firmwareguard --help

# Install system-wide (optional)
sudo make install

# Install systemd service (optional - for boot-time enforcement)
sudo cp systemd/firmwareguard.service /etc/systemd/system/
sudo systemctl daemon-reload
```

**Note**: Phase 2 build includes security hardening flags:
- Stack protection (`-fstack-protector-strong`)
- Buffer overflow detection (`-D_FORTIFY_SOURCE=2`)
- Position independent executable (`-fPIE -pie`)
- Full RELRO (`-Wl,-z,relro,-z,now`)
- Non-executable stack (`-Wl,-z,noexecstack`)

### Kernel Module Requirements

FirmwareGuard requires the `msr` kernel module for CPU register access:

```bash
# Load MSR module
sudo modprobe msr

# Verify
ls /dev/cpu/0/msr
```

To load automatically on boot, add `msr` to `/etc/modules`.

---

## 🚀 Quick Start

### 1. Scan Your System

```bash
sudo ./firmwareguard scan
```

**Output:**
```
========================================
  FIRMWAREGUARD AUDIT REPORT v0.1.0-MVP
========================================

Overall Risk: HIGH
Components Found: 5

DETECTED COMPONENTS:
--------------------

[1] Intel Management Engine
    Type:      Intel ME
    Status:    ACTIVE
    Risk:      HIGH
    Blockable: Yes
    Details:   Version: Unknown, Capabilities: Normal operation mode

[2] Firmware Performance Data Table
    Type:      ACPI Table
    Status:    ACTIVE
    Risk:      LOW
    Blockable: No
    Details:   Firmware collects boot performance metrics

...
```

### 2. Generate Blocking Recommendations

```bash
sudo ./firmwareguard block
```

**Output:**
```
========================================
  BLOCKING ACTIONS REPORT
========================================

Actions Generated: 3
Successful: 0
Failed/Recommendations: 3
Reboot Required: Yes

ACTIONS:
--------

[1] Intel Management Engine
    Status:         RECOMMENDATION
    Method:         Soft-disable via HAP bit or me_cleaner
    Recommendation: To disable Intel ME:
                   - Check BIOS/UEFI settings for 'Intel ME' or 'AMT' options
                   - Use me_cleaner: https://github.com/corna/me_cleaner
                   - WARNING: Disabling ME may cause system instability
```

### 3. Apply Persistent Blocking

To apply the recommended blocking actions persistently (e.g., disable Intel ME HAP bit, set PSP kernel parameters):

```bash
sudo ./firmwareguard apply --persistent
```

**Output:**
```
========================================
  APPLYING FIRMWAREGUARD CONFIGURATION
========================================

Actions to Apply: 2
Successful: 2

[1] Intel Management Engine
    Status:   SUCCESS
    Method:   HAP bit set via UEFI variable
    Details:  Intel ME successfully soft-disabled. Reboot required.

[2] AMD PSP Mitigation
    Status:   SUCCESS
    Method:   Kernel parameter 'psp.psp_disabled=1' added to GRUB
    Details:  AMD PSP mitigation configured. Reboot required.
```

### 4. JSON Output for Automation

```bash
sudo ./firmwareguard scan --json -o report.json
```

**Output (report.json):**
```json
{
  "firmwareguard_version": "0.1.0-MVP",
  "timestamp": 1731974400,
  "overall_risk": "HIGH",
  "num_components": 5,
  "components": [
    {
      "type": "Intel ME",
      "name": "Intel Management Engine",
      "detected": true,
      "active": true,
      "blockable": true,
      "blocked": false,
      "risk": "HIGH",
      "details": "Version: Unknown, Capabilities: Normal operation mode"
    }
  ]
}
```

### 4. Panic Mode (Emergency Mitigation Guide)

```bash
./firmwareguard panic
```

Shows comprehensive mitigation strategies for all detected telemetry components.

---

## 🔬 Technical Details

### What FirmwareGuard Detects

#### Intel Management Engine (ME)
- **Detection Method:** PCI configuration space scan (bus 0, device 22, function 0)
- **Capability Analysis:** MMIO register reads from MEI base address
- **Version Extraction:** sysfs `/sys/kernel/debug/mei/mei0/devstate`
- **AMT Detection:** Heuristic based on ME device ID ranges

#### AMD Platform Security Processor (PSP)
- **Detection Method:** CPUID leaf 0x8000001F (SEV capability)
- **Version:** AMD microcode patch level MSR
- **Secure Boot:** CPUID 0x80000001 ECX bit 2

#### ACPI Tables
- **Source:** `/sys/firmware/acpi/tables/`
- **Analyzed Tables:**
  - **FPDT:** Firmware Performance Data (boot metrics)
  - **TPM2:** Trusted Platform Module 2.0
  - **DMAR:** Intel VT-d (DMA remapping)
  - **IVRS:** AMD IOMMU
  - **Custom OEM tables**

#### Network Interfaces
- **Detection:** sysfs `/sys/class/net/` enumeration
- **PCI IDs:** Vendor/device ID extraction
- **Driver Info:** ethtool GDRVINFO ioctl
- **Capabilities:**
  - Wake-on-LAN (sysfs power/wakeup)
  - Intel AMT (device ID heuristics)
  - Statistics reporting (driver presence)

### Risk Assessment Algorithm

Risk scores are calculated based on:
- **Intel ME active + AMT:** +5 points → HIGH/CRITICAL
- **AMD PSP active:** +2 points → MEDIUM
- **TPM present:** +2 points → MEDIUM
- **NIC with remote mgmt:** +3 points → HIGH
- **FPDT table:** +1 point → LOW

**Risk Levels:**
- CRITICAL: ≥8 points
- HIGH: 5-7 points
- MEDIUM: 3-4 points
- LOW: 1-2 points
- NONE: 0 points

---

## 🛡️ Security Considerations

### Permissions Required

FirmwareGuard requires **root** for:
- `/dev/mem` access (MMIO reads)
- `/dev/cpu/*/msr` access (MSR reads)
- `/sys/firmware/acpi/tables/` (ACPI parsing)
- PCI configuration space (I/O ports 0xCF8/0xCFC)

### Safety Guarantees

FirmwareGuard now incorporates a comprehensive **safety framework** to protect against system instability and bricking:
- ✅ **Automatic Backup & Restore**: Critical modifications are preceded by backups with checksums.
- ✅ **Dry-Run Mode**: All destructive operations can be simulated without making actual changes.
- ✅ **Rollback Capability**: Changes can be reverted to previous states using defined rollback points.
- ✅ **User Confirmation**: Explicit user approval is required for all critical and potentially destructive actions.
- ✅ **Failsafe Mechanisms**: Integration with GRUB for boot failure recovery and automatic reapplication prevention.

### Future Phases

- **Phase 3:** Advanced local analysis, offline anomaly detection (see ROADMAP.md for details)
- **Phase 4:** Research & Innovation

**Note:** Fleet management and networking features are available only in FirmwareGuard Enterprise (separate commercial product).

---

## 📊 Use Cases

### 1. Security Auditing
```bash
# Generate compliance report
sudo ./firmwareguard scan --json -o audit-$(date +%F).json

# Analyze trends over time
diff audit-2025-01-01.json audit-2025-02-01.json
```

### 2. Pre-Deployment Validation
```bash
# Check new hardware before deployment
sudo ./firmwareguard scan

# Verify ME is disabled (if required by security policy)
sudo ./firmwareguard scan --json | jq '.components[] | select(.type=="Intel ME" and .active==true)'
```

### 3. Incident Response
```bash
# Quick compromise assessment
sudo ./firmwareguard scan --json | jq '.overall_risk'

# Check for active remote management
sudo ./firmwareguard scan --json | jq '.components[] | select(.name | contains("Remote"))'
```

### 4. Privacy Hardening
```bash
# Get mitigation roadmap
sudo ./firmwareguard block -o hardening-plan.txt

# Apply safe mitigations
sudo ./firmwareguard block --json | jq -r '.actions[] | select(.successful==true)'
```

---

## 🗺️ Roadmap

### Phase 1 - MVP ✅ (Complete)
- [x] Hardware probe module
- [x] Non-destructive blocking recommendations
- [x] Audit report generation

### Phase 2 - Deep Control ✅ (Complete)
- [x] Kernel module for MMIO write protection
- [x] DMA window restriction
- [x] UEFI variable modification (HAP bit)
- [x] Persistent configuration
- [x] All Phase 2 known limitations fixed

### Phase 3 - Bug Fixes & CI/CD ⚠️ (Partially Verified)
- [x] Secure Boot detection and warnings
- [x] HAP platform support validation
- [x] Enhanced GRUB backup and dry-run
- [ ] Kernel module conflict detection
- [ ] Agent architecture (CLI-based daemon, caching, scheduling)
- [x] GitHub Actions CI/CD integration for current build/test targets
- [x] All known limitations from Phase 2 resolved

**Note:** Web-based management features are not planned. FirmwareGuard remains a CLI security tool.

### Phase 4 - Research & Innovation (Prototype/Planned)
- [ ] AI-powered anomaly detection in firmware behavior
- [ ] Automated firmware binary analysis
- [ ] Supply chain integrity verification

---

## 🏢 Enterprise Version

**Need fleet management and central visibility?**

FirmwareGuard is 100% free and open source, designed for personal use and offline environments. For organizations that need to manage firmware security across 100-10,000+ endpoints, we offer **FirmwareGuard Enterprise** as a separate commercial product.

### FirmwareGuard (This Project) vs Enterprise

| Feature | FirmwareGuard (FOSS) | FirmwareGuard Enterprise |
|---------|---------------------|-------------------------|
| **License** | MIT (100% open) | Proprietary (open-core) |
| **Network** | ❌ Offline-only | ✅ Optional (TLS 1.3)   |
| **Architecture** | Single-system CLI | Central server + agents |
| **Management** | Local only   | Web dashboard + API     |
| **Scalability** | 1 system    | 100-10,000+ endpoints   |
| **Use Cases** | Personal, research, air-gap | Enterprise IT, MSPs |
| **Cost** | **Free forever**   | Commercial licensing    |

### Enterprise Features
- Central management server with web dashboard
- Fleet-wide policy distribution and enforcement
- Real-time risk monitoring across all endpoints
- Compliance reporting (NIST, GDPR, SOC2)
- Multi-tenancy for MSPs
- High availability and failover
- Commercial support with SLA

**Learn More:** See `FirmwareGuard-Enterprise/` directory or contact enterprise@firmwareguard.dev

**Commitment:** The core FirmwareGuard (this project) will remain 100% free, open source, and offline-only forever. No bait-and-switch. No feature removal. No upselling pressure.

---

## 🤝 Contributing

FirmwareGuard is open for contributions. Areas of interest:

- **Platform Support:** ARM, RISC-V detection
- **Additional Probes:** SMM, UEFI drivers, Boot Guard
- **Blocking Methods:** Safe ME disable techniques
- **Testing:** Hardware compatibility reports

---

## 📜 License

MIT License - See LICENSE file for details.

---

## ⚠️ Disclaimer

FirmwareGuard is a **research and auditing tool**. Firmware modification carries inherent risks:

- Bricking is possible with aggressive blocking methods
- Vendor support may be voided
- Some system features may break (e.g., BitLocker with TPM disable)

**Always maintain firmware backups and recovery mechanisms.**

The authors are not responsible for hardware damage resulting from misuse.

---

## 📚 References

- [Intel ME Analysis by Igor Skochinsky](https://www.blackhat.com/docs/us-17/thursday/us-17-Skochinsky-Intel-ME-Myths-And-Realities.pdf)
- [AMD PSP Documentation](https://developer.amd.com/resources/epyc-resources/)
- [me_cleaner Project](https://github.com/corna/me_cleaner)
- [Coreboot Documentation](https://doc.coreboot.org/)
- [ACPI Specification](https://uefi.org/specifications)

---

## 💬 Contact

For questions, issues, or contributions:
- GitHub Issues: [FirmwareGuard Issues](https://github.com/yourusername/firmwareguard/issues)
- Email: contact@firmwareguard.dev

---

**Built with precision. Secured by design.**
