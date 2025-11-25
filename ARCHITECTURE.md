# FirmwareGuard Architecture
**Offline-Only Privacy-First Design**

## Table of Contents
- [Design Philosophy](#design-philosophy)
- [Architectural Principles](#architectural-principles)
- [System Architecture](#system-architecture)
- [Component Overview](#component-overview)
- [Data Flow](#data-flow)
- [Security Model](#security-model)
- [Privacy Guarantees](#privacy-guarantees)
- [Deployment Models](#deployment-models)

---

## Design Philosophy

### Core Mission
FirmwareGuard is a **personal hardware sovereignty tool** that gives individuals complete control over their CPU firmware and telemetry systems. It operates with **zero network dependencies** to ensure that your hardware privacy is never compromised by external communications.

### Why Offline-Only?

**Privacy by Architecture:**
- **No Cloud, No Trust Issues:** Your firmware data never leaves your machine
- **No Attack Surface:** Network-based attacks are impossible
- **Air-Gap Compatible:** Works on completely isolated systems
- **Zero Telemetry:** We can't collect data if we never connect

**Use Cases:**
1. **Personal Privacy Hardening** - Individuals securing their own systems
2. **Air-Gapped Environments** - Government, military, research labs
3. **High-Security Operations** - Journalists, activists, security researchers
4. **Paranoid Computing** - Users who trust no cloud services
5. **Offline Research** - Academic firmware analysis without network

### Design Constraints

**Hard Requirements:**
1. ✅ **Zero network I/O** - No HTTP, TCP, UDP, or any network protocols
2. ✅ **Local-only storage** - All data stored on local filesystem
3. ✅ **Standalone operation** - No dependencies on external services
4. ✅ **Offline documentation** - Man pages and local HTML docs
5. ✅ **No telemetry** - No usage analytics or crash reporting

**Allowed Network Interactions:**
- ❌ **Outbound connections** to any server (even for updates)
- ❌ **Inbound connections** listening on network sockets
- ✅ **CPU telemetry blocking** - Preventing CPU from phoning home (that's the point!)
- ✅ **NIC firmware inspection** - Reading NIC firmware to detect telemetry
- ✅ **Package manager** - Users can install via apt/yum/pacman (that's OS-level)

---

## Architectural Principles

### 1. Privacy-First
**Every architectural decision prioritizes user privacy over convenience.**

- **Local Data Only:** All reports, logs, and configurations stored locally
- **No Cloud Dependencies:** Never phone home for updates, analytics, or features
- **User Control:** User explicitly controls when scans run and what data is generated
- **Transparent Code:** 100% open source - no hidden networking code

### 2. Minimalism
**Do one thing well: detect and block firmware-level telemetry.**

- **Focused Scope:** Firmware privacy only, not general system hardening
- **Small Binary:** Target < 500KB for main binary
- **Minimal Dependencies:** Avoid bloated libraries
- **No Feature Creep:** Resist adding network features "just in case"

### 3. Safety
**Never brick the user's system.**

- **Dry-Run by Default:** Preview all changes before applying
- **Automatic Backups:** Back up all firmware/UEFI modifications
- **Rollback Support:** Easy recovery from failed operations
- **Conservative Defaults:** Err on the side of safety

### 4. Transparency
**User should understand exactly what FirmwareGuard does.**

- **Verbose Logging:** Explain every operation in plain language
- **No Magic:** Document all hardware interactions
- **Audit Trail:** Log all modifications with timestamps
- **Open Source:** Code speaks for itself

### 5. Portability
**Run on as many platforms as possible (offline).**

- **Cross-Platform:** Linux (primary), Windows/macOS (detection)
- **Architecture Support:** x86-64 (primary), ARM, RISC-V (future)
- **Minimal Runtime:** No GUI, no X11, works in SSH/serial console
- **Static Linking:** Optional static builds for maximum portability

---

## System Architecture

### High-Level Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                         User Space                            │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              FirmwareGuard CLI                          │ │
│  │  (firmwareguard scan/block/report/panic/restore)       │ │
│  └─────────────────────────────────────────────────────────┘ │
│         │                  │                 │                │
│         ▼                  ▼                 ▼                │
│  ┌──────────┐      ┌──────────┐     ┌──────────┐            │
│  │ Hardware │      │   UEFI   │     │   GRUB   │            │
│  │  Probe   │      │   Vars   │     │  Config  │            │
│  │  Engine  │      │  Module  │     │  Module  │            │
│  └──────────┘      └──────────┘     └──────────┘            │
│         │                  │                 │                │
│         └──────────────────┴─────────────────┘                │
│                            │                                   │
│                            ▼                                   │
│                   ┌──────────────┐                            │
│                   │ Risk Engine  │                            │
│                   └──────────────┘                            │
│                            │                                   │
│                            ▼                                   │
│                   ┌──────────────┐                            │
│                   │   Reports    │                            │
│                   │ (JSON/Text/  │                            │
│                   │  PDF/HTML)   │                            │
│                   └──────────────┘                            │
│                            │                                   │
│                            ▼                                   │
│                   ┌──────────────┐                            │
│                   │ Local Files  │                            │
│                   │ /var/log/    │                            │
│                   │ /etc/        │                            │
│                   └──────────────┘                            │
└───────────────────────────────────────────────────────────────┘
                             │
═════════════════════════════╪═════════════════════════════════
                             │
┌────────────────────────────▼──────────────────────────────────┐
│                      Kernel Space                             │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │          FirmwareGuard Kernel Module                    │ │
│  │              (fwguard_km.ko)                            │ │
│  └─────────────────────────────────────────────────────────┘ │
│         │                  │                 │                │
│         ▼                  ▼                 ▼                │
│  ┌──────────┐      ┌──────────┐     ┌──────────┐            │
│  │   MMIO   │      │   DMA    │     │   MSR    │            │
│  │  Write   │      │ Restrict │     │  Access  │            │
│  │ Protect  │      │  Engine  │     │  Layer   │            │
│  └──────────┘      └──────────┘     └──────────┘            │
└───────────────────────────────────────────────────────────────┘
                             │
═════════════════════════════╪═════════════════════════════════
                             │
┌────────────────────────────▼──────────────────────────────────┐
│                     Hardware Layer                            │
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │   CPU    │  │  Intel   │  │   AMD    │  │   NIC    │    │
│  │   MSRs   │  │    ME    │  │   PSP    │  │ Firmware │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │   PCI    │  │  ACPI    │  │   UEFI   │  │   SPI    │    │
│  │  Config  │  │  Tables  │  │   Vars   │  │  Flash   │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
└───────────────────────────────────────────────────────────────┘
```

### Component Layers

**Layer 1: Hardware Interaction**
- Direct MSR (Model-Specific Register) access via `/dev/cpu/*/msr`
- PCI configuration space via `/sys/bus/pci/devices/*/config`
- ACPI table reading via `/sys/firmware/acpi/tables/`
- UEFI variable access via `/sys/firmware/efi/efivars/`
- Memory-mapped I/O (MMIO) via `/dev/mem`

**Layer 2: Kernel Module**
- Privileged operations requiring kernel mode
- MMIO write filtering and protection
- DMA window restrictions
- MSR write interception (optional)
- No network code whatsoever

**Layer 3: User Space Detection**
- Hardware probing and enumeration
- Telemetry pattern matching
- Risk assessment algorithms
- Report generation
- Configuration management

**Layer 4: User Interface**
- CLI commands (scan, block, report, etc.)
- Interactive confirmations
- Dry-run mode
- Status display

---

## Component Overview

### 1. Hardware Probe Engine

**Purpose:** Detect firmware components and telemetry mechanisms

**Components:**
- `src/core/me_psp.c` - Intel ME and AMD PSP detection
- `src/hardware/msrs.c` - CPU Model-Specific Register probing
- `src/hardware/pci.c` - PCI device enumeration and analysis
- `src/hardware/acpi.c` - ACPI table parsing and telemetry detection
- `src/hardware/nic.c` - Network card firmware analysis

**How It Works:**
1. Read CPU MSRs to detect ME/PSP status
2. Enumerate PCI devices for embedded controllers
3. Parse ACPI tables for telemetry descriptors
4. Inspect NIC firmware for AMT/vPro/remote management
5. Generate findings with risk scores

**Data Sources (All Local):**
- `/dev/cpu/*/msr` - CPU registers
- `/sys/bus/pci/devices/` - PCI device tree
- `/sys/firmware/acpi/tables/` - ACPI tables
- `/sys/class/net/*/device/` - NIC information
- `/dev/mem` - Physical memory (with caution)

### 2. UEFI Variable Module

**Purpose:** Read and modify UEFI variables for firmware control

**Components:**
- `src/uefi/uefi_vars.c` - UEFI variable manipulation
- Secure Boot detection
- HAP (High Assurance Platform) bit control
- Platform security policy configuration

**How It Works:**
1. Read UEFI variables via `/sys/firmware/efi/efivars/`
2. Detect Secure Boot status (blocks modification if enabled)
3. Set HAP bit to disable Intel ME (on supported platforms)
4. Backup original values before modification
5. Provide rollback on failure

**Safety Features:**
- Pre-flight Secure Boot check
- Automatic backup to `/var/lib/firmwareguard/backups/`
- Platform compatibility validation
- User confirmation for CRITICAL changes

### 3. GRUB Configuration Module

**Purpose:** Modify bootloader configuration for persistent blocking

**Components:**
- `src/grub/grub_config.c` - GRUB config parser and modifier
- AMD PSP kernel parameter injection
- Boot-time validation hooks

**How It Works:**
1. Parse `/etc/default/grub` and `/boot/grub/grub.cfg`
2. Add kernel parameters: `psp.psp_disabled=1`, `intel_iommu=on`
3. Backup original configuration with timestamp
4. Validate syntax before applying
5. Run `grub-mkconfig` to regenerate bootloader

**Safety Features:**
- Syntax validation before modification
- Timestamped backups (e.g., `grub.2025-11-25-143022.bak`)
- Dry-run mode (preview changes)
- Automatic rollback on boot failure (GRUB fallback menu)

### 4. Kernel Module (fwguard_km.ko)

**Purpose:** Enforce low-level hardware protections

**Components:**
- `kernel/fwguard_km.c` - Kernel module implementation
- MMIO write filtering
- DMA restriction engine
- MSR access logging (optional)

**How It Works:**
1. Register as kernel module with `insmod fwguard_km.ko`
2. Hook into memory subsystem for MMIO protection
3. Filter writes to known telemetry regions
4. Restrict DMA windows to prevent firmware access
5. Log suspicious activity to kernel ring buffer

**Protected Regions:**
- Intel ME communication registers (MMIO)
- AMD PSP mailbox interfaces
- NIC management regions (AMT, vPro)
- ACPI operation regions used for telemetry

### 5. Risk Assessment Engine

**Purpose:** Score detected telemetry and prioritize mitigations

**Risk Levels:**
- **CRITICAL:** Active remote management, exposed ME/PSP
- **HIGH:** Enabled telemetry with network access
- **MEDIUM:** Telemetry present but disabled
- **LOW:** Hardware capable but no active telemetry
- **NONE:** Clean system

**Scoring Factors:**
- ME/PSP enabled status (highest weight)
- Network-capable firmware (high weight)
- ACPI telemetry tables present (medium weight)
- Vendor telemetry drivers loaded (medium weight)
- Known telemetry patterns matched (variable)

### 6. Report Generation

**Purpose:** Generate actionable reports for users

**Output Formats:**
- **JSON:** Machine-readable, for CI/CD integration
- **Text:** Human-readable terminal output
- **PDF:** Professional reports (future, via libharu)
- **HTML:** Interactive offline reports (future)
- **Markdown:** Documentation-friendly format

**Report Contents:**
- Executive summary with risk score
- Detailed findings per component
- Remediation recommendations
- Hardware inventory
- Compliance mapping (NIST, GDPR)
- Timestamps and system info

**Storage:**
- `/var/log/firmwareguard/scan-YYYYMMDD-HHMMSS.json`
- `/var/log/firmwareguard/report-YYYYMMDD-HHMMSS.txt`
- User-specified output paths via CLI flags

### 7. Configuration Management

**Purpose:** Persistent settings and policy definitions

**Config Files:**
- `/etc/firmwareguard/config.yaml` - Main configuration
- `/etc/firmwareguard/policies/*.yaml` - Policy definitions
- `/var/lib/firmwareguard/baseline.json` - System baseline
- `/var/lib/firmwareguard/backups/` - Firmware backups

**Config Schema:**
```yaml
# /etc/firmwareguard/config.yaml
version: 1
settings:
  scan_interval: 86400  # seconds (daily)
  auto_block: false     # require user confirmation
  backup_dir: /var/lib/firmwareguard/backups
  log_level: info       # debug, info, warn, error

blocking:
  intel_me:
    enabled: true
    method: hap_bit     # hap_bit, me_cleaner, none
  amd_psp:
    enabled: true
    method: kernel_param  # kernel_param, none
  nic_telemetry:
    enabled: true
    disable_amt: true
    disable_wol: true

reporting:
  format: json          # json, text, both
  output_dir: /var/log/firmwareguard
  retention_days: 90

compliance:
  frameworks:
    - nist_800_171
    - gdpr_art32
  custom_policies:
    - /etc/firmwareguard/policies/custom.yaml
```

---

## Data Flow

### Scan Operation

```
User executes: firmwareguard scan

1. CLI parses arguments
   ↓
2. Load configuration from /etc/firmwareguard/config.yaml
   ↓
3. Initialize hardware probe engine
   ↓
4. Probe hardware (parallel):
   ├─ Read CPU MSRs → Detect ME/PSP status
   ├─ Enumerate PCI devices → Find controllers
   ├─ Parse ACPI tables → Detect telemetry
   └─ Inspect NIC firmware → Check AMT/vPro
   ↓
5. Aggregate findings
   ↓
6. Run risk assessment algorithm
   ↓
7. Generate report (JSON + text)
   ↓
8. Write to /var/log/firmwareguard/scan-*.json
   ↓
9. Display summary to user
   ↓
10. Exit with status code (0=clean, 1=findings, 2=critical)
```

### Block Operation

```
User executes: firmwareguard block --persistent

1. CLI parses arguments, check --dry-run flag
   ↓
2. Load previous scan results (if any)
   ↓
3. If no scan, run scan first
   ↓
4. For each finding with risk >= MEDIUM:
   ├─ Intel ME detected?
   │  ├─ Check Secure Boot status
   │  ├─ Check CPU platform (HAP support?)
   │  ├─ Backup UEFI variables → /var/lib/firmwareguard/backups/
   │  └─ Set HAP bit via UEFI variable
   │
   ├─ AMD PSP detected?
   │  ├─ Backup GRUB config → /var/lib/firmwareguard/backups/
   │  ├─ Inject kernel parameter: psp.psp_disabled=1
   │  └─ Regenerate GRUB config
   │
   └─ NIC telemetry detected?
      ├─ Disable Wake-on-LAN via ethtool
      ├─ Disable AMT via UEFI variable (if present)
      └─ Persist settings to /etc/systemd/system/firmwareguard.service
   ↓
5. If --persistent:
   ├─ Install systemd service
   ├─ Enable service at boot
   └─ Load kernel module (if not loaded)
   ↓
6. Verify changes (re-scan)
   ↓
7. Generate verification report
   ↓
8. Display summary and reboot prompt
   ↓
9. Exit (reboot required for some changes)
```

### Report Operation

```
User executes: firmwareguard report --format pdf --output ~/firmware-audit.pdf

1. CLI parses arguments
   ↓
2. Load most recent scan results from /var/log/firmwareguard/
   ↓
3. Load system baseline (if exists) from /var/lib/firmwareguard/baseline.json
   ↓
4. Perform differential analysis (current vs baseline)
   ↓
5. Generate report based on format:
   ├─ JSON: Machine-readable structured data
   ├─ Text: Colored terminal output
   ├─ PDF: Professional report with charts (via libharu)
   └─ HTML: Interactive offline viewer with JavaScript
   ↓
6. Include sections:
   ├─ Executive Summary (risk score, TL;DR)
   ├─ Detailed Findings (per-component analysis)
   ├─ Remediation Steps (prioritized recommendations)
   ├─ Hardware Inventory (CPU, MB, NIC, firmware versions)
   ├─ Compliance Mapping (NIST, GDPR, custom)
   └─ Appendices (raw data, logs)
   ↓
7. Write to specified output file
   ↓
8. Display "Report saved to: ~/firmware-audit.pdf"
   ↓
9. Exit
```

---

## Security Model

### Threat Model

**In Scope:**
- ✅ Firmware-level telemetry and remote management
- ✅ Vendor backdoors (ME, PSP, AMT, vPro)
- ✅ Hardware-based data collection
- ✅ Unauthorized firmware updates
- ✅ BIOS/UEFI rootkits and implants

**Out of Scope:**
- ❌ Operating system vulnerabilities
- ❌ Application-level security
- ❌ Network-based attacks (we're offline!)
- ❌ Social engineering
- ❌ Physical access attacks (we can't stop someone with a screwdriver)

### Privilege Model

**User Privileges Required:**
- `sudo` or `root` for most operations (firmware access requires privileges)
- Kernel module loading requires `CAP_SYS_MODULE`
- UEFI variable modification requires `root` + writable efivars
- MSR access requires `/dev/cpu/*/msr` read/write

**Privilege Separation:**
- Report viewing: **No root required**
- Scanning: **Root required** (hardware probing)
- Blocking: **Root required** (system modification)
- Service management: **Root required** (systemd)

### Attack Surface

**Minimized by Design:**
- ❌ **No network attack surface** (offline-only)
- ❌ **No remote code execution** (no network listeners)
- ❌ **No web vulnerabilities** (no web server)
- ❌ **No cloud dependencies** (no third-party services)

**Remaining Risks:**
- ⚠️ **Local privilege escalation** - Bugs in privileged code
- ⚠️ **Kernel module vulnerabilities** - Memory corruption in fwguard_km.ko
- ⚠️ **TOCTOU bugs** - Race conditions in file operations
- ⚠️ **Logic bugs** - Incorrect risk assessment or blocking

**Mitigations:**
- Static analysis (clang-tidy, cppcheck, scan-build)
- Manual code review (all PRs require 2 approvals)
- Fuzzing (AFL++ for parsing code)
- Third-party security audits (annual)
- Defensive coding (bounds checking, safe string functions)

---

## Privacy Guarantees

### What We Collect: NOTHING

FirmwareGuard **never** collects, transmits, or stores any data beyond your local filesystem.

**Explicitly NO:**
- ❌ No usage analytics
- ❌ No crash reporting (even opt-in)
- ❌ No update checks phoning home
- ❌ No hardware telemetry to developers
- ❌ No error reporting to cloud
- ❌ No user identification
- ❌ No IP address logging

**What We Store (Locally):**
- ✅ Scan results in `/var/log/firmwareguard/` (your system only)
- ✅ Configuration in `/etc/firmwareguard/` (your system only)
- ✅ Backups in `/var/lib/firmwareguard/backups/` (your system only)
- ✅ Logs in `/var/log/firmwareguard/` (your system only)

### Data Retention

**User Controlled:**
- You control retention via `config.yaml` (default: 90 days)
- You can delete logs anytime: `rm -rf /var/log/firmwareguard/*`
- Backups persist until you delete them (we don't auto-delete safety backups)
- No data ever leaves your machine

### Transparency

**Verifiable Privacy:**
- 100% open source code on GitHub
- No obfuscated binaries
- No proprietary dependencies with telemetry
- Static analysis results published
- Network code forbidden in codebase

**Audit Instructions:**
```bash
# Verify no network code in codebase
grep -r "socket\|connect\|listen\|bind\|http\|curl" src/
# (Should only find comments or this documentation)

# Check for phone-home in binaries
strings firmwareguard | grep -i "http\|\.com\|\.net\|api"
# (Should find nothing suspicious)

# Monitor network activity (should be zero)
sudo strace -e trace=network firmwareguard scan
# (Should show: No network syscalls)
```

---

## Deployment Models

### 1. Personal Desktop/Laptop

**Use Case:** Individual securing their personal computer

**Setup:**
```bash
# Install from package manager
sudo apt install firmwareguard  # Debian/Ubuntu
sudo dnf install firmwareguard  # Fedora/RHEL
yay -S firmwareguard-git        # Arch Linux

# Or build from source
git clone https://github.com/KKingZero/FirmwareGuard
cd FirmwareGuard
make
sudo make install

# Run initial scan
sudo firmwareguard scan

# Review findings
cat /var/log/firmwareguard/scan-latest.txt

# Apply blocking (dry-run first)
sudo firmwareguard block --dry-run
sudo firmwareguard block --persistent

# Reboot
sudo reboot
```

**Result:** System is hardened against firmware telemetry

### 2. Air-Gapped System

**Use Case:** Completely isolated network (government, military, research)

**Setup:**
```bash
# On internet-connected system:
git clone https://github.com/KKingZero/FirmwareGuard
tar czf firmwareguard.tar.gz FirmwareGuard/

# Transfer via USB/CD to air-gapped system
# On air-gapped system:
tar xzf firmwareguard.tar.gz
cd FirmwareGuard
make
sudo make install

# Run scan
sudo firmwareguard scan

# Apply blocking (no network required)
sudo firmwareguard block --persistent
```

**Result:** Even air-gapped systems are protected from firmware exfiltration attempts

### 3. Multi-System via Ansible

**Use Case:** Manage 10-100 systems (privacy-focused org)

**Setup:**
```yaml
# ansible/playbook.yml
- hosts: all
  become: yes
  tasks:
    - name: Install FirmwareGuard
      package:
        name: firmwareguard
        state: present

    - name: Run firmware scan
      command: firmwareguard scan
      register: scan_result

    - name: Fetch scan results
      fetch:
        src: /var/log/firmwareguard/scan-latest.json
        dest: ./reports/{{ inventory_hostname }}.json
        flat: yes

    - name: Apply blocking (if approved)
      command: firmwareguard block --persistent
      when: auto_block_approved

    - name: Reboot if needed
      reboot:
        when: scan_result.changed
```

**Run:**
```bash
ansible-playbook -i inventory.ini playbook.yml
```

**Result:** Centralized report collection without FirmwareGuard doing any networking (Ansible does the file transfer)

### 4. CI/CD Integration

**Use Case:** Validate firmware before deploying bare metal servers

**Setup:**
```yaml
# .github/workflows/hardware-validation.yml
name: Hardware Validation
on: [push, pull_request]
jobs:
  firmware-scan:
    runs-on: self-hosted  # Must be self-hosted (needs hardware access)
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Install FirmwareGuard
        run: |
          make
          sudo make install

      - name: Scan firmware
        run: |
          sudo firmwareguard scan --format json --output scan.json

      - name: Check risk level
        run: |
          RISK=$(jq -r '.risk_level' scan.json)
          if [ "$RISK" == "CRITICAL" ]; then
            echo "CRITICAL firmware telemetry detected!"
            exit 1
          fi

      - name: Upload scan results
        uses: actions/upload-artifact@v3
        with:
          name: firmware-scan
          path: scan.json
```

**Result:** Block deployments if firmware telemetry detected

### 5. Qubes OS Integration (Future)

**Use Case:** Privacy-focused OS with VM isolation

**Concept:**
- Run FirmwareGuard in `dom0` (hardware access)
- Scan firmware on boot
- Alert user if telemetry detected
- Integrate with Qubes updater (verify firmware integrity)

**Benefits:**
- Firmware privacy matches Qubes' VM security model
- No network access from dom0 (perfect fit for offline-only tool)
- Built-in to privacy-focused OS

---

## Comparison: FirmwareGuard vs FirmwareGuard Enterprise

| Feature | FirmwareGuard (FOSS) | FirmwareGuard Enterprise |
|---------|---------------------|-------------------------|
| **License** | MIT (100% open) | Proprietary (open-core) |
| **Network** | ❌ Offline-only | ✅ Optional (TLS 1.3) |
| **Deployment** | Single-system | Fleet (100-10,000+ endpoints) |
| **Management** | CLI only | Web dashboard + API |
| **Reports** | Local (JSON/text/PDF) | Centralized aggregation |
| **Policies** | Local YAML files | Central policy engine |
| **Agents** | ❌ No agent | Lightweight agent (< 10MB) |
| **Server** | ❌ No server | Central server (optional) |
| **Use Cases** | Personal, research, air-gap | Enterprise IT, MSPs |
| **Cost** | Free forever | Commercial (pricing TBD) |
| **Support** | Community (GitHub) | SLA + consulting |

**Commitment:** FirmwareGuard (FOSS) will **never** gain network features. Enterprise version is a separate product.

---

## Future Architecture Evolution

### Phase 3: Advanced Local Analysis (2025)

**New Components:**
- SMM enumeration engine
- UEFI driver extraction tool
- Local telemetry pattern database (SQLite)
- Offline anomaly detection
- PDF report generator (libharu)

**Architecture Changes:**
- Add `/usr/share/firmwareguard/patterns.db` (SQLite database)
- Add `/var/lib/firmwareguard/baseline.json` (system baseline)
- Add libharu dependency for PDF generation
- Still 100% offline

### Phase 4: AI & Binary Analysis (2026+)

**New Components:**
- Local ML models (TensorFlow Lite / ONNX Runtime)
- Ghidra integration for firmware analysis
- Advanced rootkit detection
- Supply chain integrity verification

**Architecture Changes:**
- Add `/usr/share/firmwareguard/models/` (ML models)
- Add Ghidra bridge for automated analysis
- Add radare2 integration for binary pattern matching
- Still 100% offline (models trained offline, run locally)

---

## Conclusion

FirmwareGuard's architecture is **purpose-built for privacy**. By eliminating network dependencies entirely, we ensure that your firmware data never leaves your control. This offline-only design makes FirmwareGuard ideal for:

- Privacy-conscious individuals
- Air-gapped environments
- High-security operations
- Research and academia
- Anyone who doesn't trust cloud services

**The architecture will never include:**
- Network protocols (HTTP, TCP, UDP)
- Cloud services or APIs
- Telemetry or analytics
- Remote management
- Update servers

**FirmwareGuard is, and always will be, offline-only.**

---

**Document Version:** 1.0
**Last Updated:** 2025-11-25
**Next Review:** 2026-03-01
