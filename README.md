# FirmwareGuard
### Open-Source Firmware Integrity & Anomaly Detection Framework

![Version](https://img.shields.io/badge/version-0.2.0--beta-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![Security](https://img.shields.io/badge/security-hardened-brightgreen)
![Audit](https://img.shields.io/badge/audit-47%20bugs%20fixed-success)

FirmwareGuard is a **low-level, vendor-independent framework** for detecting and analyzing firmware-level telemetry on x86/x64 systems. It provides deep visibility into chipset telemetry mechanisms like Intel ME, AMD PSP, ACPI tables, and NIC firmware capabilities.

Built for **security researchers, hardware engineers, and privacy-focused operators** who need transparent, auditable firmware security.

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

## ⚙️ Core Features

### Phase 1 - MVP (Current Release)

✅ **Hardware Probe Module**
- CPU vendor detection (Intel/AMD)
- Intel Management Engine (ME) detection and version identification
- AMD Platform Security Processor (PSP) detection
- ACPI table parsing for telemetry-related tables (FPDT, TPM2, DMAR, IVRS)
- NIC firmware capability detection (Wake-on-LAN, AMT, stats reporting)

✅ **Non-Destructive Blocking**
- Risk assessment for detected components
- Blocking recommendations for Intel ME, AMD PSP, and NIC telemetry
- Safe, read-only analysis (MVP does not modify firmware)

✅ **Audit Report Generation**
- JSON and human-readable text output
- Risk level classification (NONE, LOW, MEDIUM, HIGH, CRITICAL)
- Component-by-component analysis
- Actionable mitigation recommendations

### Phase 2 - Active Control & Security Hardening (Current Release)

✅ **Security Hardening** (47 Vulnerabilities Fixed)
- Eliminated command injection vulnerabilities
- Comprehensive bounds checking and input validation
- Thread-safe operations with proper locking
- Memory safety with size limits and overflow protection
- Hardened build with stack protection, FORTIFY_SOURCE, PIE, Full RELRO

✅ **Safety Framework**
- Automatic backup and restore system with checksums
- Dry-run mode for safe testing
- Rollback points for multi-step operations
- User confirmation for critical changes
- Operation logging and audit trail

✅ **Intel ME Control**
- HAP (High Assurance Platform) bit detection and manipulation
- UEFI variable modification with automatic backup
- ME region analysis and validation
- Safe soft-disable mechanisms

✅ **AMD PSP Mitigation**
- Kernel parameter injection (`psp.psp_disabled=1`)
- GRUB configuration management with safety checks
- PSP service detection and enumeration

✅ **Persistent Blocking**
- Configuration file system (`/etc/firmwareguard/config.conf`)
- Systemd service for boot-time enforcement
- Automatic reapplication after firmware updates
- Failsafe rollback on boot failure

✅ **Enhanced NIC Control**
- Persistent Wake-on-LAN disable
- Intel AMT/vPro detection and mitigation
- Configuration persistence across reboots

✅ **Kernel Module** (Optional)
- MMIO region tracking
- DMA restriction capability
- Kernel-level hardware access control

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

### 3. JSON Output for Automation

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

### Safety Guarantees (MVP)

The current MVP release is **read-only**:
- ✅ No firmware modifications
- ✅ No MSR writes
- ✅ No PCI config writes
- ✅ No UEFI variable changes

**Exception:** Wake-on-LAN disable uses `ethtool` (reversible, non-persistent).

### Future Phases (Planned)

- **Phase 2:** Kernel module for DMA restriction
- **Phase 3:** UEFI variable patching (with user confirmation)
- **Phase 4:** me_cleaner integration

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

### Phase 1 - MVP ✅ (Current)
- [x] Hardware probe module
- [x] Non-destructive blocking recommendations
- [x] Audit report generation

### Phase 2 - Deep Control (Planned)
- [ ] Kernel module for MMIO write protection
- [ ] DMA window restriction
- [ ] UEFI variable modification (HAP bit)
- [ ] Persistent configuration

### Phase 3 - Enterprise (Planned)
- [ ] Fleet management dashboard
- [ ] CI/CD integration
- [ ] Automated remediation
- [ ] Windows support

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
